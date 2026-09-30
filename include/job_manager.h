#ifndef WINGUARD_JOB_MANAGER_H
#define WINGUARD_JOB_MANAGER_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * JobLimits defines resource boundaries configured on a Windows Job Object.
 */
typedef struct {
    uint32_t active_process_limit;     /* Max simultaneous processes in job (0 = unlimited) */
    uint32_t cpu_rate_limit_percent;  /* CPU cap 1-100% (0 = unlimited) */
    BOOL cpu_hard_cap;                 /* TRUE = hard throttle, FALSE = soft share */
    uint64_t per_process_memory_bytes; /* Max virtual/commit memory per process (0 = unlimited) */
    uint64_t job_memory_bytes;         /* Max collective memory across all processes in job (0 = unlimited) */
    BOOL kill_on_job_close;            /* Terminate all child processes if job handle closes */
} JobLimits;

/**
 * JobStats captures live accounting and process counts from Windows kernel.
 */
typedef struct {
    uint32_t active_processes;
    uint32_t total_processes;
    uint32_t total_terminated_processes;
    uint64_t total_kernel_time_100ns;
    uint64_t total_user_time_100ns;
    uint64_t peak_process_memory_bytes;
    uint64_t peak_job_memory_bytes;
} JobStats;

/**
 * JobContext manages the Windows Job Object handle and its operational configuration.
 */
typedef struct {
    HANDLE hJob;
    WCHAR job_name[128];
    JobLimits current_limits;
} JobContext;

/**
 * Creates and initializes a new Windows Job Object.
 */
BOOL jm_create_job(const WCHAR* job_name, JobContext** out_job);

/**
 * Sets the active process limit on the Job Object.
 */
BOOL jm_set_process_limit(JobContext* job, uint32_t max_processes);

/**
 * Sets process and job-wide committed memory boundaries on the Job Object.
 * 
 * @param job Valid JobContext.
 * @param per_process_bytes Maximum bytes a single process may commit (0 = unlimited).
 * @param job_bytes Maximum collective bytes across all processes in Job (0 = unlimited).
 * @return TRUE on success, FALSE otherwise.
 */
BOOL jm_set_memory_limits(JobContext* job, uint64_t per_process_bytes, uint64_t job_bytes);

/**
 * Sets CPU rate control (throttling) on the Job Object.
 * 
 * @param job Valid JobContext.
 * @param cpu_percent CPU limit percentage (1 to 100, 0 = unlimited).
 * @param hard_cap TRUE = hard throttle (capped even if CPU idle), FALSE = soft share.
 * @return TRUE on success, FALSE otherwise.
 */
BOOL jm_set_cpu_rate(JobContext* job, uint32_t cpu_percent, BOOL hard_cap);

/**
 * Applies a comprehensive JobLimits structure to the Job Object.
 */
BOOL jm_apply_limits(JobContext* job, const JobLimits* limits);

/**
 * Configures the Job Object to automatically terminate all member processes
 * when the Job Object handle is closed.
 */
BOOL jm_set_kill_on_close(JobContext* job, BOOL enable);

/**
 * Assigns an existing process handle to the Job Object.
 */
BOOL jm_assign_process(JobContext* job, HANDLE hProcess);

/**
 * Queries real-time accounting and process count statistics from the kernel.
 */
BOOL jm_query_stats(JobContext* job, JobStats* out_stats);

/**
 * Terminates all processes assigned to the Job Object immediately.
 */
BOOL jm_terminate_job(JobContext* job, UINT exit_code);

/**
 * Prints current Job Object statistics and limit configuration.
 */
void jm_print_stats(const JobStats* stats, const JobLimits* limits);

/**
 * Destroys the JobContext and closes the Windows Job Object handle.
 */
void jm_close_job(JobContext* job);

#endif /* WINGUARD_JOB_MANAGER_H */
