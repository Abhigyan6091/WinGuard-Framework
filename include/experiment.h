#ifndef WINGUARD_EXPERIMENT_H
#define WINGUARD_EXPERIMENT_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#define BENCHMARK_DEFAULT_RUNS 10

/**
 * MetricStats holds statistical aggregation (mean, stddev, min, max) across multiple benchmark runs.
 */
typedef struct {
    double mean;
    double stddev;
    double min_val;
    double max_val;
} MetricStats;

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
 * AggregatedExperimentResult captures averaged multi-run metrics with statistical variation.
 */
typedef struct {
    char mode_name[32];
    char policy_used[64];
    uint32_t run_count;
    MetricStats wall_time;
    MetricStats cpu_user;
    MetricStats cpu_kernel;
    MetricStats peak_cpu;
    MetricStats avg_cpu;
    MetricStats peak_mem;
    MetricStats active_procs;
    MetricStats violations;
    MetricStats escalations;
    MetricStats demotions;
    MetricStats adaptation_latency;
    BOOL contained;
    DWORD typical_exit_code;
} AggregatedExperimentResult;

/**
 * Executes a comparative 3-way experiment (Permissive vs Static Strict vs Adaptive)
 * across multiple runs (default 10) to compute statistical mean and variation.
 */
BOOL experiment_run_comparison_runs(const WCHAR* workload_cmd, const WCHAR* out_csv_path, const WCHAR* out_md_path, uint32_t num_runs);

/**
 * Executes a comparative 3-way experiment with default 10 runs.
 */
BOOL experiment_run_comparison(const WCHAR* workload_cmd, const WCHAR* out_csv_path, const WCHAR* out_md_path);

/**
 * Pretty-prints aggregated comparative experiment metrics with mean and stddev to stdout.
 */
void experiment_print_aggregated_table(const AggregatedExperimentResult* results, size_t count);

/**
 * Pretty-prints comparative experiment metrics for single runs to stdout.
 */
void experiment_print_table(const ExperimentResult* results, size_t count);

/**
 * Exports comparative metrics to structured CSV (including per-run and summary statistics).
 */
BOOL experiment_export_csv_multi(const ExperimentResult* raw_results, size_t mode_count, size_t run_count,
                                 const AggregatedExperimentResult* agg_results, const WCHAR* csv_path);

BOOL experiment_export_csv(const ExperimentResult* results, size_t count, const WCHAR* csv_path);

/**
 * Exports comparative metrics and narrative evaluation to Markdown with mean and standard deviation.
 */
BOOL experiment_export_markdown_aggregated(const AggregatedExperimentResult* agg_results, size_t count,
                                           const WCHAR* md_path, const WCHAR* workload_cmd);

BOOL experiment_export_markdown(const ExperimentResult* results, size_t count, const WCHAR* md_path, const WCHAR* workload_cmd);

#endif /* WINGUARD_EXPERIMENT_H */
