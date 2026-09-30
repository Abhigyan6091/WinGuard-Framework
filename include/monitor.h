#ifndef WINGUARD_MONITOR_H
#define WINGUARD_MONITOR_H

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "process_manager.h"
#include "job_manager.h"
#include "adaptive_engine.h"

#define DEFAULT_MONITOR_INTERVAL_MS 50
#define MAX_TELEMETRY_PATH_LEN 512

/**
 * BehaviorViolation records a single detected policy violation event.
 */
typedef struct {
    uint64_t timestamp_ms;
    double elapsed_sec;
    char violation_type[32];   /* "PROCESS_LIMIT", "CPU_SPIKE", "MEMORY_LIMIT", etc. */
    char details[128];
} BehaviorViolation;

/**
 * MonitorSummary stores aggregated telemetry metrics across the monitoring duration.
 */
typedef struct {
    uint32_t total_samples;
    double duration_sec;
    double peak_cpu_percent;
    double avg_cpu_percent;
    uint64_t peak_memory_bytes;
    uint32_t max_active_processes;
    uint32_t total_violations;
} MonitorSummary;

/**
 * MonitorContext controls the state, background thread, and loggers for behavior monitoring.
 */
typedef struct {
    HANDLE hThread;
    HANDLE hStopEvent;
    ProcessContext* target_proc;
    AdaptiveEngine* engine;
    DWORD interval_ms;
    WCHAR csv_path[MAX_TELEMETRY_PATH_LEN];
    FILE* csv_file;
    CRITICAL_SECTION cs;
    BOOL is_running;
    
    /* Aggregated behavioral statistics */
    MonitorSummary summary;
    
    /* System CPU baseline tracking */
    DWORD num_processors;
    uint64_t prev_job_cpu_100ns;
    uint64_t prev_wall_clock_100ns;
    double sum_cpu_samples;
} MonitorContext;

/**
 * Creates and initializes a new Behavior Monitor for a target process.
 * 
 * @param proc Target sandboxed ProcessContext.
 * @param engine Optional AdaptiveEngine instance for dynamic escalation/decay.
 * @param interval_ms Polling interval in milliseconds (e.g. 50ms). If 0, defaults to 50ms.
 * @param csv_filename Optional custom path for CSV log file. If NULL, auto-generates under results/.
 * @param out_mon Output pointer to newly allocated MonitorContext.
 * @return TRUE on success, FALSE otherwise.
 */
BOOL monitor_create(ProcessContext* proc, AdaptiveEngine* engine, DWORD interval_ms, const WCHAR* csv_filename, MonitorContext** out_mon);

/**
 * Starts the background behavior monitoring thread.
 */
BOOL monitor_start(MonitorContext* mon);

/**
 * Signals the background thread to stop, waits for clean exit, and flushes log files.
 */
BOOL monitor_stop(MonitorContext* mon);

/**
 * Attaches live console behavior monitoring to an arbitrary running PID until it terminates.
 */
BOOL monitor_attach_pid(DWORD pid, DWORD interval_ms, const WCHAR* csv_filename);

/**
 * Prints a formatted telemetry summary table to stdout.
 */
void monitor_print_summary(const MonitorContext* mon);

/**
 * Frees all resources and closes handles associated with the monitor context.
 */
void monitor_free(MonitorContext* mon);

#endif /* WINGUARD_MONITOR_H */
