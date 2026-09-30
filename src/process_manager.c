#include "process_manager.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

BOOL pm_init(void) {
    LOG_DEBUG("Process Manager subsystem initialized.");
    return TRUE;
}

void pm_cleanup(void) {
    LOG_DEBUG("Process Manager subsystem cleaned up.");
}

BOOL pm_launch_process(
    const WCHAR* command_line,
    const char* policy_name,
    SecurityLevel initial_level,
    const JobLimits* limits,
    BOOL use_restricted_token,
    BOOL low_integrity,
    ProcessContext** out_ctx
) {
    if (!command_line || !out_ctx) {
        LOG_ERROR("pm_launch_process: Invalid parameters.");
        return FALSE;
    }

    *out_ctx = NULL;

    /* Allocate process context */
    ProcessContext* ctx = (ProcessContext*)calloc(1, sizeof(ProcessContext));
    if (!ctx) {
        LOG_ERROR("pm_launch_process: Memory allocation failed for ProcessContext.");
        return FALSE;
    }

    /* CreateProcessW requires a mutable command line buffer */
    WCHAR cmd_buffer[MAX_COMMAND_LINE_LEN];
    wcsncpy(cmd_buffer, command_line, MAX_COMMAND_LINE_LEN - 1);
    cmd_buffer[MAX_COMMAND_LINE_LEN - 1] = L'\0';

    wcsncpy(ctx->command_line, command_line, MAX_COMMAND_LINE_LEN - 1);
    ctx->command_line[MAX_COMMAND_LINE_LEN - 1] = L'\0';

    if (policy_name) {
        strncpy(ctx->policy_name, policy_name, MAX_POLICY_NAME_LEN - 1);
        ctx->policy_name[MAX_POLICY_NAME_LEN - 1] = '\0';
    } else {
        strncpy(ctx->policy_name, "default", MAX_POLICY_NAME_LEN - 1);
    }

    ctx->security_level = initial_level;
    ctx->violation_count = 0;
    ctx->is_active = FALSE;
    ctx->exit_code = 0;

    /* Create Windows Job Object and configure limits before execution */
    WCHAR job_name_buf[128];
    static DWORD s_job_counter = 1;
    swprintf(job_name_buf, sizeof(job_name_buf) / sizeof(WCHAR), L"WinGuard_Job_%lu_%lu", GetCurrentProcessId(), s_job_counter++);

    if (!jm_create_job(job_name_buf, &ctx->job)) {
        LOG_ERROR("Failed to create Job Object for process sandbox.");
        free(ctx);
        return FALSE;
    }

    if (limits) {
        jm_apply_limits(ctx->job, limits);
    }

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    LOG_INFO("Creating process with command line: %ls", command_line);
    LOG_INFO("Binding policy '%s' at %s (Restricted Token: %s, Low Integrity: %s)",
             ctx->policy_name,
             security_level_to_string(ctx->security_level),
             use_restricted_token ? "YES" : "NO",
             low_integrity ? "YES" : "NO");

    BOOL success = FALSE;
    HANDLE hRestrictedPrimary = NULL;

    if (use_restricted_token) {
        /*
         * Milestone 4: Create a restricted primary token with stripped privileges
         * and Low Integrity, then launch via CreateProcessAsUserW.
         */
        if (tm_create_restricted_token(NULL, TRUE, low_integrity, &hRestrictedPrimary)) {
            success = CreateProcessAsUserW(
                hRestrictedPrimary,
                NULL,
                cmd_buffer,
                NULL,
                NULL,
                FALSE,
                CREATE_SUSPENDED,
                NULL,
                NULL,
                &si,
                &pi
            );
            CloseHandle(hRestrictedPrimary);

            if (!success) {
                DWORD err = GetLastError();
                LOG_WARN("CreateProcessAsUserW failed with error %lu. Falling back to CreateProcessW.", err);
            }
        }
    }

    if (!success) {
        /* Standard creation path suspended */
        success = CreateProcessW(
            NULL,
            cmd_buffer,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            &si,
            &pi
        );
    }

    if (!success) {
        DWORD err = GetLastError();
        LOG_ERROR("Process creation failed with Win32 Error %lu.", err);
        jm_close_job(ctx->job);
        free(ctx);
        return FALSE;
    }

    ctx->pid = pi.dwProcessId;
    ctx->tid = pi.dwThreadId;
    ctx->hProcess = pi.hProcess;
    ctx->hThread = pi.hThread;
    ctx->is_active = TRUE;

    /* Assign target process to Job Object */
    if (!jm_assign_process(ctx->job, ctx->hProcess)) {
        LOG_ERROR("Failed to assign process PID %lu to Job Object. Aborting.", ctx->pid);
        TerminateProcess(ctx->hProcess, 1);
        CloseHandle(ctx->hThread);
        CloseHandle(ctx->hProcess);
        jm_close_job(ctx->job);
        free(ctx);
        return FALSE;
    }

    /* Resume primary thread now that Job Object boundaries are locked in */
    DWORD resume_count = ResumeThread(ctx->hThread);
    if (resume_count == (DWORD)-1) {
        DWORD err = GetLastError();
        LOG_ERROR("ResumeThread failed with Win32 Error %lu.", err);
    } else {
        LOG_DEBUG("Resumed primary thread TID %lu (previous suspend count: %lu).", ctx->tid, resume_count);
    }

    /* Query process creation time */
    FILETIME creation, exit_t, kernel_t, user_t;
    if (GetProcessTimes(ctx->hProcess, &creation, &exit_t, &kernel_t, &user_t)) {
        ctx->resource_state.creation_time = creation;
        FILETIME local_creation;
        FileTimeToLocalFileTime(&creation, &local_creation);
        FileTimeToSystemTime(&local_creation, &ctx->creation_system_time);
    } else {
        GetLocalTime(&ctx->creation_system_time);
    }

    /* Inspect token state */
    tm_inspect_process_token(ctx->hProcess, &ctx->token_context);

    LOG_INFO("Process successfully created and sandboxed [PID: %lu, TID: %lu]", ctx->pid, ctx->tid);

    *out_ctx = ctx;
    return TRUE;
}

BOOL pm_wait_for_process(
    ProcessContext* ctx,
    DWORD timeout_ms,
    DWORD* out_exit_code
) {
    if (!ctx || ctx->hProcess == INVALID_HANDLE_VALUE || ctx->hProcess == NULL) {
        LOG_ERROR("pm_wait_for_process: Invalid process context or handle.");
        return FALSE;
    }

    LOG_INFO("Waiting for process PID %lu to terminate (timeout: %lu ms)...", ctx->pid, timeout_ms);

    DWORD wait_result = WaitForSingleObject(ctx->hProcess, timeout_ms);

    if (wait_result == WAIT_OBJECT_0) {
        DWORD exit_code = 0;
        if (GetExitCodeProcess(ctx->hProcess, &exit_code)) {
            ctx->exit_code = exit_code;
            ctx->is_active = FALSE;
            if (out_exit_code) {
                *out_exit_code = exit_code;
            }
            LOG_INFO("Process PID %lu terminated with exit code %lu (0x%08lX).", ctx->pid, exit_code, exit_code);
            pm_refresh_state(ctx);
            return TRUE;
        } else {
            DWORD err = GetLastError();
            LOG_ERROR("GetExitCodeProcess failed with Win32 Error %lu.", err);
            return FALSE;
        }
    } else if (wait_result == WAIT_TIMEOUT) {
        LOG_WARN("Wait for process PID %lu timed out.", ctx->pid);
        return FALSE;
    } else {
        DWORD err = GetLastError();
        LOG_ERROR("WaitForSingleObject failed with code %lu (Win32 Error: %lu).", wait_result, err);
        return FALSE;
    }
}

BOOL pm_refresh_state(ProcessContext* ctx) {
    if (!ctx || !ctx->hProcess) return FALSE;

    DWORD exit_code = 0;
    if (GetExitCodeProcess(ctx->hProcess, &exit_code)) {
        if (exit_code == STILL_ACTIVE) {
            ctx->is_active = TRUE;
        } else {
            ctx->is_active = FALSE;
            ctx->exit_code = exit_code;
        }
    }

    FILETIME creation, exit_t, kernel_t, user_t;
    if (GetProcessTimes(ctx->hProcess, &creation, &exit_t, &kernel_t, &user_t)) {
        ctx->resource_state.creation_time = creation;
        ctx->resource_state.exit_time = exit_t;
        ctx->resource_state.kernel_time = kernel_t;
        ctx->resource_state.user_time = user_t;
    }

    return TRUE;
}

BOOL pm_terminate_process(ProcessContext* ctx, DWORD exit_code) {
    if (!ctx) return FALSE;

    LOG_WARN("Terminating managed process PID %lu and Job Object with exit code %lu...", ctx->pid, exit_code);

    if (ctx->job) {
        jm_terminate_job(ctx->job, (UINT)exit_code);
    }

    if (ctx->hProcess) {
        TerminateProcess(ctx->hProcess, exit_code);
    }

    ctx->is_active = FALSE;
    ctx->exit_code = exit_code;
    LOG_INFO("Process PID %lu terminated.", ctx->pid);
    return TRUE;
}

BOOL pm_terminate_by_pid(DWORD pid, DWORD exit_code) {
    LOG_WARN("Attempting to open and terminate process PID %lu...", pid);

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (!hProcess) {
        DWORD err = GetLastError();
        LOG_ERROR("OpenProcess for PID %lu failed with Win32 Error %lu.", pid, err);
        return FALSE;
    }

    BOOL ok = TerminateProcess(hProcess, exit_code);
    if (!ok) {
        DWORD err = GetLastError();
        LOG_ERROR("TerminateProcess failed with Win32 Error %lu.", err);
    } else {
        LOG_INFO("Successfully terminated PID %lu.", pid);
    }

    CloseHandle(hProcess);
    return ok;
}

BOOL pm_inspect_process(DWORD pid, ProcessContext* out_ctx) {
    if (!out_ctx) return FALSE;
    ZeroMemory(out_ctx, sizeof(ProcessContext));

    out_ctx->pid = pid;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
        FALSE,
        pid
    );

    if (!hProcess) {
        hProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            FALSE,
            pid
        );
    }

    if (!hProcess) {
        DWORD err = GetLastError();
        LOG_ERROR("OpenProcess failed for PID %lu with Win32 Error %lu.", pid, err);
        return FALSE;
    }

    out_ctx->hProcess = hProcess;

    DWORD exit_code = 0;
    if (GetExitCodeProcess(hProcess, &exit_code)) {
        if (exit_code == STILL_ACTIVE) {
            out_ctx->is_active = TRUE;
        } else {
            out_ctx->is_active = FALSE;
            out_ctx->exit_code = exit_code;
        }
    }

    FILETIME creation, exit_t, kernel_t, user_t;
    if (GetProcessTimes(hProcess, &creation, &exit_t, &kernel_t, &user_t)) {
        out_ctx->resource_state.creation_time = creation;
        out_ctx->resource_state.exit_time = exit_t;
        out_ctx->resource_state.kernel_time = kernel_t;
        out_ctx->resource_state.user_time = user_t;

        FILETIME local_creation;
        FileTimeToLocalFileTime(&creation, &local_creation);
        FileTimeToSystemTime(&local_creation, &out_ctx->creation_system_time);
    }

    /* Inspect access token of process */
    tm_inspect_process_token(hProcess, &out_ctx->token_context);

    return TRUE;
}

static uint64_t filetime_to_ms(const FILETIME* ft) {
    ULARGE_INTEGER uli;
    uli.LowPart = ft->dwLowDateTime;
    uli.HighPart = ft->dwHighDateTime;
    return (uli.QuadPart / 10000ULL);
}

void pm_print_context(const ProcessContext* ctx) {
    if (!ctx) return;

    printf("\n=======================================================\n");
    printf(" WinGuard Process Context\n");
    printf("=======================================================\n");
    printf(" PID                 : %lu\n", ctx->pid);
    printf(" Primary Thread TID  : %lu\n", ctx->tid);
    printf(" Process Handle      : %p\n", ctx->hProcess);
    printf(" Thread Handle       : %p\n", ctx->hThread);
    printf(" Active State        : %s\n", ctx->is_active ? "RUNNING" : "TERMINATED");
    if (!ctx->is_active) {
        printf(" Exit Code           : %lu (0x%08lX)\n", ctx->exit_code, ctx->exit_code);
    }
    printf(" Security Level      : %s\n", security_level_to_string(ctx->security_level));
    printf(" Bound Policy        : %s\n", ctx->policy_name);
    printf(" Violation Count     : %u\n", ctx->violation_count);
    printf(" Creation Time       : %04d-%02d-%02d %02d:%02d:%02d.%03d\n",
           ctx->creation_system_time.wYear,
           ctx->creation_system_time.wMonth,
           ctx->creation_system_time.wDay,
           ctx->creation_system_time.wHour,
           ctx->creation_system_time.wMinute,
           ctx->creation_system_time.wSecond,
           ctx->creation_system_time.wMilliseconds);

    uint64_t kernel_ms = filetime_to_ms(&ctx->resource_state.kernel_time);
    uint64_t user_ms = filetime_to_ms(&ctx->resource_state.user_time);
    printf(" CPU Kernel Time     : %llu ms\n", (unsigned long long)kernel_ms);
    printf(" CPU User Time       : %llu ms\n", (unsigned long long)user_ms);
    printf(" Total CPU Time      : %llu ms\n", (unsigned long long)(kernel_ms + user_ms));
    printf(" Command Line        : %ls\n", ctx->command_line[0] ? ctx->command_line : L"(external PID)");

    /* Print Token Context */
    tm_print_security_context(&ctx->token_context);

    if (ctx->job) {
        JobStats stats;
        if (jm_query_stats(ctx->job, &stats)) {
            jm_print_stats(&stats, &ctx->job->current_limits);
        }
    }
    printf("=======================================================\n\n");
    fflush(stdout);
}

void pm_free_context(ProcessContext* ctx) {
    if (!ctx) return;

    if (ctx->hThread && ctx->hThread != INVALID_HANDLE_VALUE) {
        LOG_DEBUG("Closing thread handle %p for PID %lu", ctx->hThread, ctx->pid);
        CloseHandle(ctx->hThread);
        ctx->hThread = NULL;
    }

    if (ctx->hProcess && ctx->hProcess != INVALID_HANDLE_VALUE) {
        LOG_DEBUG("Closing process handle %p for PID %lu", ctx->hProcess, ctx->pid);
        CloseHandle(ctx->hProcess);
        ctx->hProcess = NULL;
    }

    if (ctx->job) {
        jm_close_job(ctx->job);
        ctx->job = NULL;
    }

    free(ctx);
}
