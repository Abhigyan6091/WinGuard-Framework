#ifndef WINGUARD_PROCESS_MANAGER_H
#define WINGUARD_PROCESS_MANAGER_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include "policy.h"
#include "job_manager.h"
#include "token_manager.h"

#define MAX_COMMAND_LINE_LEN 2048
#define MAX_POLICY_NAME_LEN  64

/**
 * ResourceUsageSnapshot tracks process-level timing and execution states.
 */
typedef struct {
    FILETIME creation_time;
    FILETIME exit_time;
    FILETIME kernel_time;
    FILETIME user_time;
    uint64_t working_set_bytes;
    uint32_t process_count;
} ResourceState;

/**
 * ProcessContext stores tracking state, OS handles, and security context
 * for a sandboxed process.
 */
typedef struct {
    DWORD pid;
    DWORD tid;
    HANDLE hProcess;
    HANDLE hThread;
    
    /* Associated Windows Job Object */
    JobContext* job;

    /* Windows Access Token & Security Context */
    TokenContext token_context;

    /* Security and adaptive policy state */
    SecurityLevel security_level;
    char policy_name[MAX_POLICY_NAME_LEN];
    uint32_t violation_count;

    /* Execution and resource state */
    BOOL is_active;
    DWORD exit_code;
    ResourceState resource_state;
    WCHAR command_line[MAX_COMMAND_LINE_LEN];

    /* Windows timestamp */
    SYSTEMTIME creation_system_time;
} ProcessContext;

/**
 * Global initialization and cleanup for process manager subsystem.
 */
BOOL pm_init(void);
void pm_cleanup(void);

/**
 * Launches an untrusted process with the specified command line and policy,
 * optionally sandboxing it within a Windows Job Object and/or restricted access token.
 * 
 * @param command_line Unicode command line to execute.
 * @param policy_name Name of the policy to bind.
 * @param initial_level Starting SecurityLevel in the state machine.
 * @param limits Pointer to JobLimits configuring CPU, memory, and process limits.
 * @param use_restricted_token If TRUE, launches process using CreateRestrictedToken and CreateProcessAsUserW.
 * @param low_integrity If TRUE, lowers the token integrity level to Low Integrity.
 * @param out_ctx Pointer to receive the allocated ProcessContext pointer.
 * @return TRUE if process was created successfully, FALSE otherwise.
 */
BOOL pm_launch_process(
    const WCHAR* command_line,
    const char* policy_name,
    SecurityLevel initial_level,
    const JobLimits* limits,
    BOOL use_restricted_token,
    BOOL low_integrity,
    ProcessContext** out_ctx
);

/**
 * Waits for the process to exit or until timeout occurs.
 */
BOOL pm_wait_for_process(
    ProcessContext* ctx,
    DWORD timeout_ms,
    DWORD* out_exit_code
);

/**
 * Inspects a live process by PID using OpenProcess, querying token,
 * exit code, and creation time.
 */
BOOL pm_inspect_process(
    DWORD pid,
    ProcessContext* out_ctx
);

/**
 * Explicitly terminates a managed process context and its Job Object members.
 */
BOOL pm_terminate_process(
    ProcessContext* ctx,
    DWORD exit_code
);

/**
 * Terminates any process by PID using OpenProcess and TerminateProcess.
 */
BOOL pm_terminate_by_pid(
    DWORD pid,
    DWORD exit_code
);

/**
 * Refreshes process resource statistics and Job Object accounting.
 */
BOOL pm_refresh_state(ProcessContext* ctx);

/**
 * Pretty-prints process context details, security context, and Job Object statistics.
 */
void pm_print_context(const ProcessContext* ctx);

/**
 * Closes process, thread, and Job Object handles, and frees the context memory.
 */
void pm_free_context(ProcessContext* ctx);

#endif /* WINGUARD_PROCESS_MANAGER_H */
