#ifndef WINGUARD_ADAPTIVE_ENGINE_H
#define WINGUARD_ADAPTIVE_ENGINE_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include "policy.h"
#include "process_manager.h"

/**
 * StateTransitionRecord captures an audit log of a single adaptive transition.
 */
typedef struct {
    uint64_t timestamp_ms;
    SecurityLevel from_level;
    SecurityLevel to_level;
    char trigger_reason[128];
    char actions_taken[256];
} StateTransitionRecord;

#define MAX_TRANSITION_HISTORY 64

/**
 * AdaptiveEngine manages dynamic runtime security level promotion, demotion (decay),
 * and dynamic kernel reconfiguration of live Job Objects and process priorities.
 */
typedef struct {
    ProcessContext* target_proc;
    PolicyConfig policy;

    SecurityLevel current_level;
    uint32_t current_violation_count;
    uint32_t total_violations;
    uint32_t total_escalations;
    uint32_t total_demotions;

    uint64_t last_violation_tick_ms;
    uint64_t last_decay_tick_ms;
    CRITICAL_SECTION cs;

    /* Transition audit trail */
    uint32_t transition_count;
    StateTransitionRecord transitions[MAX_TRANSITION_HISTORY];
} AdaptiveEngine;

/**
 * Initializes an AdaptiveEngine for a sandboxed process context.
 * 
 * @param proc Active ProcessContext.
 * @param policy Compiled PolicyConfig.
 * @param out_engine Output pointer to allocated AdaptiveEngine.
 * @return TRUE on success, FALSE otherwise.
 */
BOOL adaptive_engine_init(ProcessContext* proc, const PolicyConfig* policy, AdaptiveEngine** out_engine);

/**
 * Records a behavioral violation, incrementing the counter and triggering
 * level escalation if the configured escalation_threshold is reached.
 * 
 * @param engine Active AdaptiveEngine.
 * @param violation_type Short category string (e.g., "CPU_SPIKE", "PROCESS_EXHAUSTION").
 * @param details Descriptive context of the violation.
 * @return TRUE if violation was processed, FALSE otherwise.
 */
BOOL adaptive_record_violation(AdaptiveEngine* engine, const char* violation_type, const char* details);

/**
 * Periodically called (e.g. by monitor thread) to evaluate time-based decay.
 * If elapsed benign time >= decay_interval_sec, demotes security level.
 * 
 * @param engine Active AdaptiveEngine.
 * @return TRUE if a demotion occurred, FALSE otherwise.
 */
BOOL adaptive_check_decay(AdaptiveEngine* engine);

/**
 * Escalates the security level by 1 tier and applies tightened OS controls.
 */
BOOL adaptive_escalate(AdaptiveEngine* engine, const char* reason);

/**
 * Demotes the security level by decay_step tiers and relaxes OS controls.
 */
BOOL adaptive_demote(AdaptiveEngine* engine, const char* reason);

/**
 * Applies OS-level primitives matching the specified security level
 * (Job CPU rate caps, active process limits, priority class, working set trims).
 */
BOOL adaptive_apply_level_limits(AdaptiveEngine* engine, SecurityLevel target_level, const char* reason);

/**
 * Prints a comprehensive adaptive state transition summary table to stdout.
 */
void adaptive_print_summary(const AdaptiveEngine* engine);

/**
 * Frees resources associated with the AdaptiveEngine.
 */
void adaptive_engine_free(AdaptiveEngine* engine);

#endif /* WINGUARD_ADAPTIVE_ENGINE_H */
