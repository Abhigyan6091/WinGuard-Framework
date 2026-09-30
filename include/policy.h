#ifndef WINGUARD_POLICY_H
#define WINGUARD_POLICY_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * SecurityLevel represents discrete tiers in the adaptive security state machine.
 */
typedef enum {
    LEVEL_0_OBSERVE    = 0,  /* Baseline permissive level: observation only */
    LEVEL_1_RESTRICTED = 1,  /* First-tier restrictions: suspicious behavior */
    LEVEL_2_CONTAINED  = 2,  /* High containment: repeated violations */
    LEVEL_3_QUARANTINED = 3  /* Maximum containment / pre-termination */
} SecurityLevel;

/**
 * Converts a SecurityLevel enum to a human-readable string.
 */
const char* security_level_to_string(SecurityLevel level);

/**
 * Parses a string into a SecurityLevel enum.
 */
BOOL string_to_security_level(const char* str, SecurityLevel* out_level);

/**
 * PolicyConfig holds complete runtime configuration compiled from a .policy file.
 */
typedef struct {
    /* Metadata */
    char name[64];
    char version[32];
    char author[64];
    char description[256];

    /* Initial state machine tier */
    SecurityLevel initial_level;

    /* Static Job Object Limits */
    uint32_t process_limit;            /* Max concurrent child processes (0 = unlimited) */
    uint64_t memory_limit_bytes;       /* Committed memory limit in bytes */
    uint32_t cpu_limit_percent;        /* CPU quota percentage (1-100) */
    BOOL cpu_hard_cap;                 /* TRUE = hard throttle */

    /* Token & Privilege Settings */
    BOOL use_restricted_token;         /* TRUE = launch with restricted token */
    BOOL strip_admin_sids;             /* TRUE = strip admin/privileged SIDs */
    BOOL disable_all_privileges;       /* TRUE = drop all held privileges */
    char integrity_level[32];          /* "Untrusted", "Low", "Medium", "High" */

    /* Filesystem Workspace Paths */
    WCHAR sandbox_root[MAX_PATH];
    WCHAR read_only_paths[MAX_PATH];
    WCHAR read_write_paths[MAX_PATH];
    WCHAR denied_paths[MAX_PATH];

    /* Adaptive Escalation Rules */
    uint32_t escalation_threshold;     /* Violations needed to promote to next level */
    uint32_t decay_interval_sec;       /* Benign seconds required before demoting level */
    uint32_t decay_step;               /* Levels to demote per decay tick */
    BOOL auto_terminate_on_l3;         /* TRUE = terminate workload upon reaching LEVEL 3 */
} PolicyConfig;

/**
 * Parses a .policy specification file from disk into a PolicyConfig struct.
 * 
 * @param file_path Path to the .policy file.
 * @param out_config Output compiled PolicyConfig struct.
 * @param error_buf Buffer for error messages if parsing fails.
 * @param error_buf_len Size of error_buf.
 * @return TRUE if parsing succeeded, FALSE otherwise.
 */
BOOL policy_parse_file(const WCHAR* file_path, PolicyConfig* out_config, char* error_buf, size_t error_buf_len);

/**
 * Validates semantic integrity of a PolicyConfig struct.
 * 
 * @param config Pointer to PolicyConfig to validate.
 * @param error_buf Buffer for validation error description.
 * @param error_buf_len Size of error_buf.
 * @return TRUE if policy is valid, FALSE otherwise.
 */
BOOL policy_validate(const PolicyConfig* config, char* error_buf, size_t error_buf_len);

/**
 * Loads a policy by name (built-in) or by file path (.policy).
 * Searches local directory and policies/ folder.
 */
BOOL policy_load(const char* name_or_path, PolicyConfig* out_config);

/**
 * Retrieves a default built-in policy configuration.
 */
BOOL policy_get_default(const char* name, PolicyConfig* out_config);

/**
 * Pretty-prints a compiled policy configuration to stdout.
 */
void policy_print(const PolicyConfig* config);

#endif /* WINGUARD_POLICY_H */
