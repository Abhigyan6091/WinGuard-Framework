#ifndef WINGUARD_EXPERIMENT_H
#define WINGUARD_EXPERIMENT_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * ExperimentResult captures empirical benchmarking metrics for a single run mode.
 */
typedef struct {
    char mode_name[32];          /* "Permissive Baseline", "Static Strict", "Adaptive WinGuard" */
    char policy_used[64];
    double wall_time_sec;
    uint64_t cpu_kernel_ms;
    uint64_t cpu_user_ms;
    double peak_cpu_pct;
    double avg_cpu_pct;
    double peak_mem_mb;
    uint32_t active_procs_peak;
    uint32_t violations_logged;
    uint32_t escalations;
    uint32_t demotions;
    double adaptation_latency_ms;
    BOOL contained;
    DWORD exit_code;
} ExperimentResult;

/**
 * Executes a comparative 3-way experiment (Permissive vs Static Strict vs Adaptive)
 * against an identical target workload and outputs metrics to console, CSV, and Markdown.
 * 
 * @param workload_cmd Command line of the target program to evaluate.
 * @param out_csv_path Path for exported CSV comparison table (optional, defaults to results/experiment_comparison.csv).
 * @param out_md_path Path for exported Markdown report (optional, defaults to results/benchmark_report.md).
 * @return TRUE on success, FALSE otherwise.
 */
BOOL experiment_run_comparison(const WCHAR* workload_cmd, const WCHAR* out_csv_path, const WCHAR* out_md_path);

/**
 * Pretty-prints comparative experiment metrics to stdout.
 */
void experiment_print_table(const ExperimentResult* results, size_t count);

/**
 * Exports comparative metrics to structured CSV.
 */
BOOL experiment_export_csv(const ExperimentResult* results, size_t count, const WCHAR* csv_path);

/**
 * Exports comparative metrics and narrative evaluation to Markdown.
 */
BOOL experiment_export_markdown(const ExperimentResult* results, size_t count, const WCHAR* md_path, const WCHAR* workload_cmd);

#endif /* WINGUARD_EXPERIMENT_H */
