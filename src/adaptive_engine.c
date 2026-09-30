#include "adaptive_engine.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>

BOOL adaptive_engine_init(ProcessContext* proc, const PolicyConfig* policy, AdaptiveEngine** out_engine) {
    if (!proc || !policy || !out_engine) return FALSE;

    AdaptiveEngine* engine = (AdaptiveEngine*)calloc(1, sizeof(AdaptiveEngine));
    if (!engine) return FALSE;

    engine->target_proc = proc;
    memcpy(&engine->policy, policy, sizeof(PolicyConfig));

    engine->current_level = policy->initial_level;
    proc->security_level = policy->initial_level;

    engine->current_violation_count = 0;
    engine->total_violations = 0;
    engine->total_escalations = 0;
    engine->total_demotions = 0;
    engine->transition_count = 0;

    uint64_t now_ms = GetTickCount64();
    engine->last_violation_tick_ms = now_ms;
    engine->last_decay_tick_ms = now_ms;

    InitializeCriticalSection(&engine->cs);

    LOG_INFO("Adaptive State Machine initialized for PID %lu (Initial Tier: %s, Escalation Threshold: %u, Decay Interval: %u s)",
             proc->pid, security_level_to_string(engine->current_level),
             engine->policy.escalation_threshold, engine->policy.decay_interval_sec);

    *out_engine = engine;
    return TRUE;
}

static void record_transition(AdaptiveEngine* engine, SecurityLevel from_level, SecurityLevel to_level,
                              const char* reason, const char* actions) {
    if (!engine) return;

    if (engine->transition_count < MAX_TRANSITION_HISTORY) {
        StateTransitionRecord* rec = &engine->transitions[engine->transition_count++];
        rec->timestamp_ms = GetTickCount64();
        rec->from_level = from_level;
        rec->to_level = to_level;
        strncpy(rec->trigger_reason, reason ? reason : "Unknown", sizeof(rec->trigger_reason) - 1);
        strncpy(rec->actions_taken, actions ? actions : "None", sizeof(rec->actions_taken) - 1);
    }

    char transition_str[64];
    snprintf(transition_str, sizeof(transition_str), "%s -> %s",
             security_level_to_string(from_level),
             security_level_to_string(to_level));

    DWORD pid = engine->target_proc ? engine->target_proc->pid : 0;
    log_explain_decision(pid,
                         transition_str,
                         reason ? reason : "State Machine Transition",
                         actions ? actions : "None");
}

BOOL adaptive_apply_level_limits(AdaptiveEngine* engine, SecurityLevel target_level, const char* reason) {
    if (!engine || !engine->target_proc) return FALSE;

    ProcessContext* proc = engine->target_proc;
    SecurityLevel from_level = engine->current_level;
    char actions[256] = {0};

    switch (target_level) {
        case LEVEL_0_OBSERVE:
            if (proc->job) {
                jm_set_cpu_rate(proc->job, engine->policy.cpu_limit_percent, engine->policy.cpu_hard_cap);
                jm_set_process_limit(proc->job, engine->policy.process_limit);
            }
            if (proc->hProcess) {
                SetPriorityClass(proc->hProcess, NORMAL_PRIORITY_CLASS);
            }
            snprintf(actions, sizeof(actions),
                     "CPU rate set to %u%%, active process limit set to %u, priority NORMAL",
                     engine->policy.cpu_limit_percent, engine->policy.process_limit);
            break;

        case LEVEL_1_RESTRICTED:
            if (proc->job) {
                uint32_t cpu_cap = (engine->policy.cpu_limit_percent < 35) ? engine->policy.cpu_limit_percent : 35;
                uint32_t proc_lim = (engine->policy.process_limit < 4) ? engine->policy.process_limit : 4;
                jm_set_cpu_rate(proc->job, cpu_cap, TRUE);
                jm_set_process_limit(proc->job, proc_lim);
            }
            if (proc->hProcess) {
                SetPriorityClass(proc->hProcess, BELOW_NORMAL_PRIORITY_CLASS);
            }
            snprintf(actions, sizeof(actions),
                     "CPU rate clamped to 35%% (HARD), active process limit clamped to 4, priority BELOW_NORMAL");
            break;

        case LEVEL_2_CONTAINED:
            if (proc->job) {
                jm_set_cpu_rate(proc->job, 15, TRUE);
                jm_set_process_limit(proc->job, 2);
            }
            if (proc->hProcess) {
                SetPriorityClass(proc->hProcess, IDLE_PRIORITY_CLASS);
                EmptyWorkingSet(proc->hProcess);
            }
            snprintf(actions, sizeof(actions),
                     "CPU rate clamped to 15%% (HARD), active process limit clamped to 2, priority IDLE, EmptyWorkingSet() invoked");
            break;

        case LEVEL_3_QUARANTINED:
            if (engine->policy.auto_terminate_on_l3) {
                snprintf(actions, sizeof(actions),
                         "QUARANTINE ENFORCED: Immediate termination of Job Object processes (ExitCode 0xC0000420)");
                if (proc->job) {
                    jm_terminate_job(proc->job, 0xC0000420);
                } else if (proc->hProcess) {
                    TerminateProcess(proc->hProcess, 0xC0000420);
                }
            } else {
                if (proc->job) {
                    jm_set_cpu_rate(proc->job, 5, TRUE);
                    jm_set_process_limit(proc->job, 1);
                }
                if (proc->hProcess) {
                    SetPriorityClass(proc->hProcess, IDLE_PRIORITY_CLASS);
                    EmptyWorkingSet(proc->hProcess);
                }
                snprintf(actions, sizeof(actions),
                         "CPU rate clamped to 5%% (HARD), active process limit clamped to 1, priority IDLE");
            }
            break;

        default:
            return FALSE;
    }

    engine->current_level = target_level;
    proc->security_level = target_level;
    record_transition(engine, from_level, target_level, reason, actions);
    return TRUE;
}

BOOL adaptive_escalate(AdaptiveEngine* engine, const char* reason) {
    if (!engine) return FALSE;

    EnterCriticalSection(&engine->cs);

    if (engine->current_level >= LEVEL_3_QUARANTINED) {
        LeaveCriticalSection(&engine->cs);
        return FALSE;
    }

    SecurityLevel next_level = (SecurityLevel)((int)engine->current_level + 1);
    engine->total_escalations++;

    char full_reason[256];
    snprintf(full_reason, sizeof(full_reason), "Violation threshold reached: %s", reason ? reason : "anomaly");

    BOOL ok = adaptive_apply_level_limits(engine, next_level, full_reason);

    engine->last_violation_tick_ms = GetTickCount64();
    engine->last_decay_tick_ms = engine->last_violation_tick_ms;

    LeaveCriticalSection(&engine->cs);
    return ok;
}

BOOL adaptive_demote(AdaptiveEngine* engine, const char* reason) {
    if (!engine) return FALSE;

    EnterCriticalSection(&engine->cs);

    if (engine->current_level <= LEVEL_0_OBSERVE) {
        LeaveCriticalSection(&engine->cs);
        return FALSE;
    }

    int step = (engine->policy.decay_step > 0) ? (int)engine->policy.decay_step : 1;
    int target_int = (int)engine->current_level - step;
    if (target_int < 0) target_int = 0;

    SecurityLevel target_level = (SecurityLevel)target_int;
    engine->total_demotions++;

    char full_reason[256];
    snprintf(full_reason, sizeof(full_reason), "Benign decay: %s", reason ? reason : "no violations observed");

    BOOL ok = adaptive_apply_level_limits(engine, target_level, full_reason);

    engine->last_decay_tick_ms = GetTickCount64();

    LeaveCriticalSection(&engine->cs);
    return ok;
}

BOOL adaptive_record_violation(AdaptiveEngine* engine, const char* violation_type, const char* details) {
    if (!engine) return FALSE;

    EnterCriticalSection(&engine->cs);

    engine->total_violations++;
    engine->current_violation_count++;
    engine->last_violation_tick_ms = GetTickCount64();
    engine->last_decay_tick_ms = engine->last_violation_tick_ms;

    LOG_WARN("Adaptive Engine: Behavioral violation [%s] on PID %lu: %s (Count: %u / Threshold: %u)",
             violation_type ? violation_type : "VIOLATION",
             engine->target_proc ? engine->target_proc->pid : 0,
             details ? details : "No details",
             engine->current_violation_count,
             engine->policy.escalation_threshold);

    if (engine->target_proc) {
        engine->target_proc->violation_count = engine->total_violations;
    }

    if (engine->current_violation_count >= engine->policy.escalation_threshold) {
        engine->current_violation_count = 0;
        adaptive_escalate(engine, violation_type);
    }

    LeaveCriticalSection(&engine->cs);
    return TRUE;
}

BOOL adaptive_check_decay(AdaptiveEngine* engine) {
    if (!engine) return FALSE;

    EnterCriticalSection(&engine->cs);

    if (engine->current_level <= LEVEL_0_OBSERVE) {
        LeaveCriticalSection(&engine->cs);
        return FALSE;
    }

    uint64_t now_ms = GetTickCount64();
    uint64_t decay_ms = (uint64_t)engine->policy.decay_interval_sec * 1000;

    if ((now_ms - engine->last_violation_tick_ms >= decay_ms) &&
        (now_ms - engine->last_decay_tick_ms >= decay_ms)) {
        LOG_INFO("Adaptive Engine: Process PID %lu exhibited benign behavior for %u s. Triggering decay relaxation.",
                 engine->target_proc ? engine->target_proc->pid : 0,
                 engine->policy.decay_interval_sec);
        BOOL demoted = adaptive_demote(engine, "Benign behavior interval elapsed");
        LeaveCriticalSection(&engine->cs);
        return demoted;
    }

    LeaveCriticalSection(&engine->cs);
    return FALSE;
}

void adaptive_print_summary(const AdaptiveEngine* engine) {
    if (!engine) return;

    printf("\n=======================================================\n");
    printf(" WinGuard Adaptive State Machine Engine Summary\n");
    printf("=======================================================\n");
    printf(" Final Security Level    : %s\n", security_level_to_string(engine->current_level));
    printf(" Total Violations Audited: %u\n", engine->total_violations);
    printf(" Dynamic Escalations     : %u\n", engine->total_escalations);
    printf(" Dynamic Decay Demotions : %u\n", engine->total_demotions);
    printf(" State Transitions Logged: %u\n", engine->transition_count);
    printf("-------------------------------------------------------\n");
    printf(" Transition Audit Trail:\n");
    for (uint32_t i = 0; i < engine->transition_count; ++i) {
        const StateTransitionRecord* rec = &engine->transitions[i];
        printf("  [%u] %s -> %s\n", i + 1,
               security_level_to_string(rec->from_level),
               security_level_to_string(rec->to_level));
        printf("      Trigger : %s\n", rec->trigger_reason);
        printf("      Actions : %s\n", rec->actions_taken);
    }
    printf("=======================================================\n\n");
}

void adaptive_engine_free(AdaptiveEngine* engine) {
    if (!engine) return;
    DeleteCriticalSection(&engine->cs);
    free(engine);
}
