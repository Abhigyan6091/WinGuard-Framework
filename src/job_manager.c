#include "job_manager.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

BOOL jm_create_job(const WCHAR* job_name, JobContext** out_job) {
    if (!out_job) {
        LOG_ERROR("jm_create_job: Invalid output pointer.");
        return FALSE;
    }

    *out_job = NULL;

    JobContext* ctx = (JobContext*)calloc(1, sizeof(JobContext));
    if (!ctx) {
        LOG_ERROR("jm_create_job: Memory allocation failed.");
        return FALSE;
    }

    HANDLE hJob = CreateJobObjectW(NULL, job_name);
    if (!hJob) {
        DWORD err = GetLastError();
        LOG_ERROR("CreateJobObjectW failed with Win32 Error %lu.", err);
        free(ctx);
        return FALSE;
    }

    ctx->hJob = hJob;
    if (job_name) {
        wcsncpy(ctx->job_name, job_name, sizeof(ctx->job_name) / sizeof(WCHAR) - 1);
    } else {
        wcscpy(ctx->job_name, L"(anonymous_job)");
    }

    /* By default in sandboxing, kill child processes if supervisor or job closes */
    jm_set_kill_on_close(ctx, TRUE);

    LOG_INFO("Created Windows Job Object '%ls' [Handle: %p]", ctx->job_name, ctx->hJob);
    *out_job = ctx;
    return TRUE;
}

BOOL jm_set_process_limit(JobContext* job, uint32_t max_processes) {
    if (!job || !job->hJob) {
        LOG_ERROR("jm_set_process_limit: Invalid job context.");
        return FALSE;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
    ZeroMemory(&jeli, sizeof(jeli));

    if (!QueryInformationJobObject(
            job->hJob,
            JobObjectExtendedLimitInformation,
            &jeli,
            sizeof(jeli),
            NULL)) {
        DWORD err = GetLastError();
        LOG_WARN("QueryInformationJobObject failed with error %lu.", err);
        ZeroMemory(&jeli, sizeof(jeli));
    }

    if (max_processes > 0) {
        jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        jeli.BasicLimitInformation.ActiveProcessLimit = max_processes;
        LOG_INFO("Configuring Job Object: Active Process Limit = %u", max_processes);
    } else {
        jeli.BasicLimitInformation.LimitFlags &= ~JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        jeli.BasicLimitInformation.ActiveProcessLimit = 0;
        LOG_INFO("Configuring Job Object: Active Process Limit = UNLIMITED");
    }

    if (!SetInformationJobObject(
            job->hJob,
            JobObjectExtendedLimitInformation,
            &jeli,
            sizeof(jeli))) {
        DWORD err = GetLastError();
        LOG_ERROR("SetInformationJobObject (process limit) failed with Win32 Error %lu.", err);
        return FALSE;
    }

    job->current_limits.active_process_limit = max_processes;
    return TRUE;
}

BOOL jm_set_memory_limits(JobContext* job, uint64_t per_process_bytes, uint64_t job_bytes) {
    if (!job || !job->hJob) {
        LOG_ERROR("jm_set_memory_limits: Invalid job context.");
        return FALSE;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
    ZeroMemory(&jeli, sizeof(jeli));

    QueryInformationJobObject(
        job->hJob,
        JobObjectExtendedLimitInformation,
        &jeli,
        sizeof(jeli),
        NULL
    );

    if (per_process_bytes > 0) {
        jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        jeli.ProcessMemoryLimit = (SIZE_T)per_process_bytes;
        LOG_INFO("Configuring Job Object: Per-Process Memory Limit = %llu MB",
                 (unsigned long long)(per_process_bytes / (1024 * 1024)));
    } else {
        jeli.BasicLimitInformation.LimitFlags &= ~JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        jeli.ProcessMemoryLimit = 0;
    }

    if (job_bytes > 0) {
        jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        jeli.JobMemoryLimit = (SIZE_T)job_bytes;
        LOG_INFO("Configuring Job Object: Total Job Memory Limit = %llu MB",
                 (unsigned long long)(job_bytes / (1024 * 1024)));
    } else {
        jeli.BasicLimitInformation.LimitFlags &= ~JOB_OBJECT_LIMIT_JOB_MEMORY;
        jeli.JobMemoryLimit = 0;
    }

    if (!SetInformationJobObject(
            job->hJob,
            JobObjectExtendedLimitInformation,
            &jeli,
            sizeof(jeli))) {
        DWORD err = GetLastError();
        LOG_ERROR("SetInformationJobObject (memory limits) failed with Win32 Error %lu.", err);
        return FALSE;
    }

    job->current_limits.per_process_memory_bytes = per_process_bytes;
    job->current_limits.job_memory_bytes = job_bytes;
    return TRUE;
}

BOOL jm_set_cpu_rate(JobContext* job, uint32_t cpu_percent, BOOL hard_cap) {
    if (!job || !job->hJob) {
        LOG_ERROR("jm_set_cpu_rate: Invalid job context.");
        return FALSE;
    }

    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu_info;
    ZeroMemory(&cpu_info, sizeof(cpu_info));

    if (cpu_percent > 0) {
        if (cpu_percent > 100) cpu_percent = 100;

        cpu_info.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE;
        if (hard_cap) {
            cpu_info.ControlFlags |= JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        }

        /*
         * In Windows Job Objects, CpuRate is in units of 1/100 of 1% (i.e. 10000 = 100%).
         */
        cpu_info.CpuRate = cpu_percent * 100;
        LOG_INFO("Configuring Job Object: CPU Rate Limit = %u%% (%s Cap, RateVal: %lu)",
                 cpu_percent, hard_cap ? "HARD" : "SOFT", cpu_info.CpuRate);
    } else {
        cpu_info.ControlFlags = 0;
        LOG_INFO("Configuring Job Object: CPU Rate Limit = UNLIMITED");
    }

    if (!SetInformationJobObject(
            job->hJob,
            JobObjectCpuRateControlInformation,
            &cpu_info,
            sizeof(cpu_info))) {
        DWORD err = GetLastError();
        LOG_ERROR("SetInformationJobObject (CPU rate control) failed with Win32 Error %lu.", err);
        return FALSE;
    }

    job->current_limits.cpu_rate_limit_percent = cpu_percent;
    job->current_limits.cpu_hard_cap = hard_cap;
    return TRUE;
}

BOOL jm_apply_limits(JobContext* job, const JobLimits* limits) {
    if (!job || !limits) return FALSE;

    BOOL ok = TRUE;

    if (limits->active_process_limit > 0) {
        ok = ok && jm_set_process_limit(job, limits->active_process_limit);
    }

    if (limits->per_process_memory_bytes > 0 || limits->job_memory_bytes > 0) {
        ok = ok && jm_set_memory_limits(job, limits->per_process_memory_bytes, limits->job_memory_bytes);
    }

    if (limits->cpu_rate_limit_percent > 0) {
        ok = ok && jm_set_cpu_rate(job, limits->cpu_rate_limit_percent, limits->cpu_hard_cap);
    }

    return ok;
}

BOOL jm_set_kill_on_close(JobContext* job, BOOL enable) {
    if (!job || !job->hJob) return FALSE;

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
    ZeroMemory(&jeli, sizeof(jeli));

    QueryInformationJobObject(
        job->hJob,
        JobObjectExtendedLimitInformation,
        &jeli,
        sizeof(jeli),
        NULL
    );

    if (enable) {
        jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    } else {
        jeli.BasicLimitInformation.LimitFlags &= ~JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    }

    if (!SetInformationJobObject(
            job->hJob,
            JobObjectExtendedLimitInformation,
            &jeli,
            sizeof(jeli))) {
        DWORD err = GetLastError();
        LOG_ERROR("SetInformationJobObject (kill_on_close) failed with Win32 Error %lu.", err);
        return FALSE;
    }

    job->current_limits.kill_on_job_close = enable;
    return TRUE;
}

BOOL jm_assign_process(JobContext* job, HANDLE hProcess) {
    if (!job || !job->hJob || !hProcess) {
        LOG_ERROR("jm_assign_process: Invalid parameters.");
        return FALSE;
    }

    if (!AssignProcessToJobObject(job->hJob, hProcess)) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            LOG_ERROR("AssignProcessToJobObject failed (Access Denied). Process may already be assigned to an un-nested Job.");
        } else {
            LOG_ERROR("AssignProcessToJobObject failed with Win32 Error %lu.", err);
        }
        return FALSE;
    }

    LOG_INFO("Successfully assigned process handle %p to Job Object %p", hProcess, job->hJob);
    return TRUE;
}

BOOL jm_query_stats(JobContext* job, JobStats* out_stats) {
    if (!job || !job->hJob || !out_stats) return FALSE;
    ZeroMemory(out_stats, sizeof(JobStats));

    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION jbai;
    if (QueryInformationJobObject(
            job->hJob,
            JobObjectBasicAccountingInformation,
            &jbai,
            sizeof(jbai),
            NULL)) {
        out_stats->active_processes = jbai.ActiveProcesses;
        out_stats->total_processes = jbai.TotalProcesses;
        out_stats->total_terminated_processes = jbai.TotalTerminatedProcesses;
        out_stats->total_kernel_time_100ns = (uint64_t)jbai.TotalKernelTime.QuadPart;
        out_stats->total_user_time_100ns = (uint64_t)jbai.TotalUserTime.QuadPart;
    } else {
        DWORD err = GetLastError();
        LOG_ERROR("QueryInformationJobObject (accounting) failed with Win32 Error %lu.", err);
        return FALSE;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
    if (QueryInformationJobObject(
            job->hJob,
            JobObjectExtendedLimitInformation,
            &jeli,
            sizeof(jeli),
            NULL)) {
        out_stats->peak_process_memory_bytes = (uint64_t)jeli.PeakProcessMemoryUsed;
        out_stats->peak_job_memory_bytes = (uint64_t)jeli.PeakJobMemoryUsed;
    }

    return TRUE;
}

BOOL jm_terminate_job(JobContext* job, UINT exit_code) {
    if (!job || !job->hJob) return FALSE;

    LOG_WARN("Terminating all processes in Job Object %p with exit code %u...", job->hJob, exit_code);
    if (!TerminateJobObject(job->hJob, exit_code)) {
        DWORD err = GetLastError();
        LOG_ERROR("TerminateJobObject failed with Win32 Error %lu.", err);
        return FALSE;
    }

    LOG_INFO("Job Object processes terminated successfully.");
    return TRUE;
}

void jm_print_stats(const JobStats* stats, const JobLimits* limits) {
    if (!stats) return;

    printf("\n-------------------------------------------------------\n");
    printf(" Windows Job Object Resource Accounting\n");
    printf("-------------------------------------------------------\n");
    if (limits) {
        if (limits->active_process_limit > 0) {
            printf(" Process Limit Configured : %u max concurrent\n", limits->active_process_limit);
        } else {
            printf(" Process Limit Configured : UNLIMITED\n");
        }

        if (limits->cpu_rate_limit_percent > 0) {
            printf(" CPU Rate Limit           : %u%% (%s Cap)\n",
                   limits->cpu_rate_limit_percent, limits->cpu_hard_cap ? "HARD" : "SOFT");
        } else {
            printf(" CPU Rate Limit           : UNLIMITED\n");
        }

        if (limits->per_process_memory_bytes > 0) {
            printf(" Per-Process Memory Limit : %llu MB\n",
                   (unsigned long long)(limits->per_process_memory_bytes / (1024 * 1024)));
        } else {
            printf(" Per-Process Memory Limit : UNLIMITED\n");
        }

        if (limits->job_memory_bytes > 0) {
            printf(" Total Job Memory Limit   : %llu MB\n",
                   (unsigned long long)(limits->job_memory_bytes / (1024 * 1024)));
        } else {
            printf(" Total Job Memory Limit   : UNLIMITED\n");
        }

        printf(" Kill On Job Close        : %s\n", limits->kill_on_job_close ? "YES" : "NO");
    }
    printf(" Active Processes (Live)  : %u\n", stats->active_processes);
    printf(" Total Processes Spawned  : %u\n", stats->total_processes);
    printf(" Terminated Processes     : %u\n", stats->total_terminated_processes);
    printf(" Total Kernel CPU Time    : %llu ms\n", (unsigned long long)(stats->total_kernel_time_100ns / 10000ULL));
    printf(" Total User CPU Time      : %llu ms\n", (unsigned long long)(stats->total_user_time_100ns / 10000ULL));
    printf(" Peak Process Memory      : %llu KB (%llu MB)\n",
           (unsigned long long)(stats->peak_process_memory_bytes / 1024ULL),
           (unsigned long long)(stats->peak_process_memory_bytes / (1024 * 1024)));
    printf(" Peak Job Memory          : %llu KB (%llu MB)\n",
           (unsigned long long)(stats->peak_job_memory_bytes / 1024ULL),
           (unsigned long long)(stats->peak_job_memory_bytes / (1024 * 1024)));
    printf("-------------------------------------------------------\n\n");
    fflush(stdout);
}

void jm_close_job(JobContext* job) {
    if (!job) return;

    if (job->hJob && job->hJob != INVALID_HANDLE_VALUE) {
        LOG_DEBUG("Closing Job Object handle %p", job->hJob);
        CloseHandle(job->hJob);
        job->hJob = NULL;
    }

    free(job);
}
