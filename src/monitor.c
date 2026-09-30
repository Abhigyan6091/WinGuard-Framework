#include "monitor.h"
#include "logger.h"
#include "adaptive_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <psapi.h>

static DWORD WINAPI monitor_worker_thread(LPVOID param) {
    MonitorContext* mon = (MonitorContext*)param;
    if (!mon || !mon->target_proc) return 1;

    FILETIME now_ft;
    GetSystemTimeAsFileTime(&now_ft);
    ULARGE_INTEGER start_time;
    start_time.LowPart = now_ft.dwLowDateTime;
    start_time.HighPart = now_ft.dwHighDateTime;

    mon->prev_wall_clock_100ns = start_time.QuadPart;
    mon->prev_job_cpu_100ns = 0;

    /* Write CSV Header */
    if (mon->csv_file) {
        fprintf(mon->csv_file, "sample_id,timestamp_ms,elapsed_sec,active_processes,total_processes,cpu_percent,kernel_time_ms,user_time_ms,peak_memory_mb,status\n");
        fflush(mon->csv_file);
    }

    uint32_t sample_id = 0;

    while (TRUE) {
        DWORD wait_res = WaitForSingleObject(mon->hStopEvent, mon->interval_ms);
        if (wait_res == WAIT_OBJECT_0) {
            /* Stop event was signaled */
            break;
        }

        GetSystemTimeAsFileTime(&now_ft);
        ULARGE_INTEGER current_time;
        current_time.LowPart = now_ft.dwLowDateTime;
        current_time.HighPart = now_ft.dwHighDateTime;

        double elapsed_sec = (double)(current_time.QuadPart - start_time.QuadPart) / 10000000.0;
        uint64_t timestamp_ms = current_time.QuadPart / 10000;

        uint32_t active_procs = 0;
        uint32_t total_procs = 0;
        uint64_t kernel_time_100ns = 0;
        uint64_t user_time_100ns = 0;
        uint64_t peak_memory_bytes = 0;
        double cpu_pct = 0.0;
        const char* status = "OK";

        EnterCriticalSection(&mon->cs);

        /* Query metrics from Job Object if attached */
        if (mon->target_proc->job) {
            JobStats stats;
            if (jm_query_stats(mon->target_proc->job, &stats)) {
                active_procs = stats.active_processes;
                total_procs = stats.total_processes;
                kernel_time_100ns = stats.total_kernel_time_100ns;
                user_time_100ns = stats.total_user_time_100ns;
                peak_memory_bytes = stats.peak_job_memory_bytes;

                uint64_t current_cpu_100ns = kernel_time_100ns + user_time_100ns;
                uint64_t delta_cpu_100ns = (current_cpu_100ns >= mon->prev_job_cpu_100ns) ?
                                           (current_cpu_100ns - mon->prev_job_cpu_100ns) : 0;
                uint64_t delta_wall_100ns = current_time.QuadPart - mon->prev_wall_clock_100ns;

                if (delta_wall_100ns > 0 && mon->num_processors > 0) {
                    cpu_pct = ((double)delta_cpu_100ns / (double)(delta_wall_100ns * mon->num_processors)) * 100.0;
                    if (cpu_pct > 100.0) cpu_pct = 100.0;
                }

                mon->prev_job_cpu_100ns = current_cpu_100ns;

                /* Threshold & Policy Violation Check */
                JobLimits* lim = &mon->target_proc->job->current_limits;
                if (lim->active_process_limit > 0 && active_procs > lim->active_process_limit) {
                    status = "VIOLATION_PROCESS_LIMIT";
                    mon->summary.total_violations++;
                    if (mon->engine) {
                        adaptive_record_violation(mon->engine, "PROCESS_QUOTA_EXCEEDED", "Concurrent process count exceeded limit");
                    }
                } else if (lim->job_memory_bytes > 0 && peak_memory_bytes >= (uint64_t)((double)lim->job_memory_bytes * 0.90)) {
                    status = "VIOLATION_MEMORY_LIMIT";
                    mon->summary.total_violations++;
                    if (mon->engine) {
                        adaptive_record_violation(mon->engine, "MEMORY_QUOTA_PRESSURE", "Committed memory reached 90% quota threshold");
                    }
                } else if (lim->cpu_rate_limit_percent > 0 && cpu_pct > 8.0 && cpu_pct > (double)lim->cpu_rate_limit_percent) {
                    status = "THROTTLED_CPU_LIMIT";
                    mon->summary.total_violations++;
                    if (mon->engine) {
                        adaptive_record_violation(mon->engine, "CPU_SPIKE", "CPU utilization spiked above configured rate cap");
                    }
                } else if (mon->engine) {
                    adaptive_check_decay(mon->engine);
                    status = security_level_to_string(mon->engine->current_level);
                }
            }
        } else if (mon->target_proc->hProcess) {
            /* Fallback: Direct process accounting */
            active_procs = 1;
            total_procs = 1;

            FILETIME create_ft, exit_ft, kern_ft, usr_ft;
            if (GetProcessTimes(mon->target_proc->hProcess, &create_ft, &exit_ft, &kern_ft, &usr_ft)) {
                ULARGE_INTEGER k_val, u_val;
                k_val.LowPart = kern_ft.dwLowDateTime;
                k_val.HighPart = kern_ft.dwHighDateTime;
                u_val.LowPart = usr_ft.dwLowDateTime;
                u_val.HighPart = usr_ft.dwHighDateTime;
                kernel_time_100ns = k_val.QuadPart;
                user_time_100ns = u_val.QuadPart;

                uint64_t current_cpu_100ns = kernel_time_100ns + user_time_100ns;
                uint64_t delta_cpu_100ns = (current_cpu_100ns >= mon->prev_job_cpu_100ns) ?
                                           (current_cpu_100ns - mon->prev_job_cpu_100ns) : 0;
                uint64_t delta_wall_100ns = current_time.QuadPart - mon->prev_wall_clock_100ns;

                if (delta_wall_100ns > 0 && mon->num_processors > 0) {
                    cpu_pct = ((double)delta_cpu_100ns / (double)(delta_wall_100ns * mon->num_processors)) * 100.0;
                    if (cpu_pct > 100.0) cpu_pct = 100.0;
                }
                mon->prev_job_cpu_100ns = current_cpu_100ns;
            }

            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(mon->target_proc->hProcess, &pmc, sizeof(pmc))) {
                peak_memory_bytes = (uint64_t)pmc.PeakWorkingSetSize;
            }
        }

        mon->prev_wall_clock_100ns = current_time.QuadPart;

        /* Update Aggregated Telemetry */
        sample_id++;
        mon->summary.total_samples++;
        mon->summary.duration_sec = elapsed_sec;
        if (cpu_pct > mon->summary.peak_cpu_percent) {
            mon->summary.peak_cpu_percent = cpu_pct;
        }
        mon->sum_cpu_samples += cpu_pct;
        if (peak_memory_bytes > mon->summary.peak_memory_bytes) {
            mon->summary.peak_memory_bytes = peak_memory_bytes;
        }
        if (active_procs > mon->summary.max_active_processes) {
            mon->summary.max_active_processes = active_procs;
        }

        /* Write row to CSV stream */
        if (mon->csv_file) {
            double mem_mb = (double)peak_memory_bytes / (1024.0 * 1024.0);
            fprintf(mon->csv_file, "%u,%llu,%.3f,%u,%u,%.2f,%llu,%llu,%.2f,%s\n",
                    sample_id,
                    (unsigned long long)timestamp_ms,
                    elapsed_sec,
                    active_procs,
                    total_procs,
                    cpu_pct,
                    (unsigned long long)(kernel_time_100ns / 10000),
                    (unsigned long long)(user_time_100ns / 10000),
                    mem_mb,
                    status);
            fflush(mon->csv_file);
        }

        LeaveCriticalSection(&mon->cs);

        /* Check if process has terminated */
        if (mon->target_proc->hProcess &&
            WaitForSingleObject(mon->target_proc->hProcess, 0) == WAIT_OBJECT_0) {
            break;
        }
    }

    if (mon->summary.total_samples > 0) {
        mon->summary.avg_cpu_percent = mon->sum_cpu_samples / mon->summary.total_samples;
    }

    return 0;
}

BOOL monitor_create(ProcessContext* proc, AdaptiveEngine* engine, DWORD interval_ms, const WCHAR* csv_filename, MonitorContext** out_mon) {
    if (!proc || !out_mon) return FALSE;

    MonitorContext* mon = (MonitorContext*)calloc(1, sizeof(MonitorContext));
    if (!mon) return FALSE;

    mon->target_proc = proc;
    mon->engine = engine;
    mon->interval_ms = (interval_ms > 0) ? interval_ms : DEFAULT_MONITOR_INTERVAL_MS;
    mon->is_running = FALSE;

    InitializeCriticalSection(&mon->cs);

    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    mon->num_processors = (sys_info.dwNumberOfProcessors > 0) ? sys_info.dwNumberOfProcessors : 1;

    mon->hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!mon->hStopEvent) {
        DeleteCriticalSection(&mon->cs);
        free(mon);
        return FALSE;
    }

    /* Ensure results/ directory exists */
    CreateDirectoryW(L"results", NULL);

    /* Formulate CSV file path */
    if (csv_filename && wcslen(csv_filename) > 0) {
        wcsncpy(mon->csv_path, csv_filename, MAX_TELEMETRY_PATH_LEN - 1);
    } else {
        swprintf(mon->csv_path, MAX_TELEMETRY_PATH_LEN, L"results\\telemetry_pid%lu_%llu.csv",
                 proc->pid, (unsigned long long)GetTickCount64());
    }

    mon->csv_file = _wfopen(mon->csv_path, L"w");
    if (!mon->csv_file) {
        LOG_WARN("Could not open telemetry CSV file '%ls' for writing. Continuing without file logging.", mon->csv_path);
    } else {
        LOG_INFO("Telemetry stream destination: %ls", mon->csv_path);
    }

    *out_mon = mon;
    return TRUE;
}

BOOL monitor_start(MonitorContext* mon) {
    if (!mon || mon->is_running) return FALSE;

    ResetEvent(mon->hStopEvent);
    mon->hThread = CreateThread(NULL, 0, monitor_worker_thread, mon, 0, NULL);
    if (!mon->hThread) {
        DWORD err = GetLastError();
        LOG_ERROR("Failed to create monitor background thread with Win32 Error %lu.", err);
        return FALSE;
    }

    mon->is_running = TRUE;
    LOG_INFO("Behavior monitoring thread active (Polling Interval: %lu ms, Target PID: %lu)",
             mon->interval_ms, mon->target_proc->pid);
    return TRUE;
}

BOOL monitor_stop(MonitorContext* mon) {
    if (!mon || !mon->is_running) return FALSE;

    SetEvent(mon->hStopEvent);

    if (mon->hThread) {
        WaitForSingleObject(mon->hThread, 3000);
        CloseHandle(mon->hThread);
        mon->hThread = NULL;
    }

    if (mon->csv_file) {
        fflush(mon->csv_file);
        fclose(mon->csv_file);
        mon->csv_file = NULL;
    }

    mon->is_running = FALSE;
    LOG_INFO("Behavior monitoring thread terminated cleanly.");
    return TRUE;
}

BOOL monitor_attach_pid(DWORD pid, DWORD interval_ms, const WCHAR* csv_filename) {
    HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        DWORD err = GetLastError();
        LOG_ERROR("Failed to open process PID %lu (Win32 Error %lu)", pid, err);
        return FALSE;
    }

    ProcessContext dummy_ctx;
    ZeroMemory(&dummy_ctx, sizeof(dummy_ctx));
    dummy_ctx.pid = pid;
    dummy_ctx.hProcess = hProcess;

    MonitorContext* mon = NULL;
    if (!monitor_create(&dummy_ctx, NULL, interval_ms, csv_filename, &mon)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!monitor_start(mon)) {
        monitor_free(mon);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("\nAttached to PID %lu for live telemetry. Press Ctrl+C or wait for exit...\n", pid);

    /* Wait for process termination */
    WaitForSingleObject(hProcess, INFINITE);

    monitor_stop(mon);
    monitor_print_summary(mon);
    monitor_free(mon);
    CloseHandle(hProcess);
    return TRUE;
}

void monitor_print_summary(const MonitorContext* mon) {
    if (!mon) return;

    printf("\n=======================================================\n");
    printf(" WinGuard Behavioral Telemetry & Monitoring Summary\n");
    printf("=======================================================\n");
    printf(" Monitoring Duration        : %.2f seconds\n", mon->summary.duration_sec);
    printf(" High-Frequency Samples     : %u samples (%lu ms interval)\n",
           mon->summary.total_samples, mon->interval_ms);
    printf(" Peak CPU Utilization       : %.2f%%\n", mon->summary.peak_cpu_percent);
    printf(" Average CPU Utilization    : %.2f%%\n", mon->summary.avg_cpu_percent);
    printf(" Peak Memory Consumption    : %.2f MB (%llu bytes)\n",
           (double)mon->summary.peak_memory_bytes / (1024.0 * 1024.0),
           (unsigned long long)mon->summary.peak_memory_bytes);
    printf(" Max Concurrent Processes   : %u\n", mon->summary.max_active_processes);
    printf(" Policy Violations Detected : %u\n", mon->summary.total_violations);
    if (wcslen(mon->csv_path) > 0) {
        printf(" Telemetry CSV Export       : %ls\n", mon->csv_path);
    }
    printf("=======================================================\n\n");
}

void monitor_free(MonitorContext* mon) {
    if (!mon) return;

    if (mon->is_running) {
        monitor_stop(mon);
    }

    if (mon->hStopEvent) {
        CloseHandle(mon->hStopEvent);
        mon->hStopEvent = NULL;
    }

    if (mon->csv_file) {
        fclose(mon->csv_file);
        mon->csv_file = NULL;
    }

    DeleteCriticalSection(&mon->cs);
    free(mon);
}
