#include "policy.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

const char* security_level_to_string(SecurityLevel level) {
    switch (level) {
        case LEVEL_0_OBSERVE:     return "LEVEL 0 (OBSERVE)";
        case LEVEL_1_RESTRICTED:  return "LEVEL 1 (RESTRICTED)";
        case LEVEL_2_CONTAINED:   return "LEVEL 2 (CONTAINED)";
        case LEVEL_3_QUARANTINED: return "LEVEL 3 (QUARANTINED)";
        default:                  return "UNKNOWN LEVEL";
    }
}

BOOL string_to_security_level(const char* str, SecurityLevel* out_level) {
    if (!str || !out_level) return FALSE;

    if (_stricmp(str, "LEVEL_0_OBSERVE") == 0 || _stricmp(str, "LEVEL_0") == 0 ||
        _stricmp(str, "OBSERVE") == 0 || strcmp(str, "0") == 0) {
        *out_level = LEVEL_0_OBSERVE;
        return TRUE;
    }
    if (_stricmp(str, "LEVEL_1_RESTRICTED") == 0 || _stricmp(str, "LEVEL_1") == 0 ||
        _stricmp(str, "RESTRICTED") == 0 || strcmp(str, "1") == 0) {
        *out_level = LEVEL_1_RESTRICTED;
        return TRUE;
    }
    if (_stricmp(str, "LEVEL_2_CONTAINED") == 0 || _stricmp(str, "LEVEL_2") == 0 ||
        _stricmp(str, "CONTAINED") == 0 || strcmp(str, "2") == 0) {
        *out_level = LEVEL_2_CONTAINED;
        return TRUE;
    }
    if (_stricmp(str, "LEVEL_3_QUARANTINED") == 0 || _stricmp(str, "LEVEL_3") == 0 ||
        _stricmp(str, "QUARANTINED") == 0 || strcmp(str, "3") == 0) {
        *out_level = LEVEL_3_QUARANTINED;
        return TRUE;
    }

    return FALSE;
}

static char* trim_whitespace(char* str) {
    if (!str) return NULL;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;

    char* end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static BOOL parse_bool(const char* val) {
    if (!val) return FALSE;
    return (_stricmp(val, "true") == 0 || _stricmp(val, "yes") == 0 ||
            _stricmp(val, "1") == 0 || _stricmp(val, "enable") == 0);
}

BOOL policy_validate(const PolicyConfig* config, char* error_buf, size_t error_buf_len) {
    if (!config) {
        if (error_buf) snprintf(error_buf, error_buf_len, "Policy configuration pointer is NULL.");
        return FALSE;
    }

    if (strlen(config->name) == 0) {
        if (error_buf) snprintf(error_buf, error_buf_len, "Validation Error: Policy name is required.");
        return FALSE;
    }

    if (config->cpu_limit_percent == 0 || config->cpu_limit_percent > 100) {
        if (error_buf) snprintf(error_buf, error_buf_len,
            "Validation Error: cpu_limit_percent must be between 1 and 100 (got: %u).",
            config->cpu_limit_percent);
        return FALSE;
    }

    if (config->memory_limit_bytes == 0) {
        if (error_buf) snprintf(error_buf, error_buf_len,
            "Validation Error: max_memory_mb must be greater than 0.");
        return FALSE;
    }

    if (config->process_limit == 0) {
        if (error_buf) snprintf(error_buf, error_buf_len,
            "Validation Error: max_processes must be greater than 0.");
        return FALSE;
    }

    if (config->escalation_threshold == 0) {
        if (error_buf) snprintf(error_buf, error_buf_len,
            "Validation Error: escalation_threshold must be at least 1 violation.");
        return FALSE;
    }

    if (config->decay_interval_sec == 0) {
        if (error_buf) snprintf(error_buf, error_buf_len,
            "Validation Error: decay_interval_sec must be greater than 0 seconds.");
        return FALSE;
    }

    if (config->initial_level > LEVEL_3_QUARANTINED) {
        if (error_buf) snprintf(error_buf, error_buf_len,
            "Validation Error: initial_level must be between LEVEL_0 and LEVEL_3.");
        return FALSE;
    }

    return TRUE;
}

BOOL policy_parse_file(const WCHAR* file_path, PolicyConfig* out_config, char* error_buf, size_t error_buf_len) {
    if (!file_path || !out_config) {
        if (error_buf) snprintf(error_buf, error_buf_len, "Invalid arguments passed to policy_parse_file.");
        return FALSE;
    }

    FILE* fp = _wfopen(file_path, L"r");
    if (!fp) {
        if (error_buf) snprintf(error_buf, error_buf_len, "Unable to open policy file for reading.");
        return FALSE;
    }

    /* Initialize with clean defaults */
    memset(out_config, 0, sizeof(PolicyConfig));
    out_config->initial_level = LEVEL_0_OBSERVE;
    out_config->cpu_limit_percent = 60;
    out_config->cpu_hard_cap = TRUE;
    out_config->memory_limit_bytes = 256 * 1024 * 1024;
    out_config->process_limit = 20;
    out_config->escalation_threshold = 2;
    out_config->decay_interval_sec = 10;
    out_config->decay_step = 1;
    out_config->auto_terminate_on_l3 = TRUE;
    strncpy(out_config->integrity_level, "Medium", sizeof(out_config->integrity_level) - 1);

    char line[1024];
    char current_section[64] = "";
    int line_number = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_number++;
        char* trimmed = trim_whitespace(line);

        /* Skip comments and empty lines */
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
            continue;
        }

        /* Section header [section] */
        if (*trimmed == '[') {
            char* close_bracket = strchr(trimmed, ']');
            if (!close_bracket) {
                if (error_buf) snprintf(error_buf, error_buf_len,
                    "Syntax Error at line %d: Unclosed section header '%s'", line_number, trimmed);
                fclose(fp);
                return FALSE;
            }
            *close_bracket = '\0';
            strncpy(current_section, trim_whitespace(trimmed + 1), sizeof(current_section) - 1);
            continue;
        }

        /* Key = Value pair */
        char* equal_sign = strchr(trimmed, '=');
        if (!equal_sign) {
            if (error_buf) snprintf(error_buf, error_buf_len,
                "Syntax Error at line %d: Missing '=' in key-value statement '%s'", line_number, trimmed);
            fclose(fp);
            return FALSE;
        }

        *equal_sign = '\0';
        char* key = trim_whitespace(trimmed);
        char* val = trim_whitespace(equal_sign + 1);

        if (_stricmp(current_section, "metadata") == 0) {
            if (_stricmp(key, "name") == 0) {
                strncpy(out_config->name, val, sizeof(out_config->name) - 1);
            } else if (_stricmp(key, "version") == 0) {
                strncpy(out_config->version, val, sizeof(out_config->version) - 1);
            } else if (_stricmp(key, "author") == 0) {
                strncpy(out_config->author, val, sizeof(out_config->author) - 1);
            } else if (_stricmp(key, "description") == 0) {
                strncpy(out_config->description, val, sizeof(out_config->description) - 1);
            }
        } else if (_stricmp(current_section, "security") == 0) {
            if (_stricmp(key, "initial_level") == 0) {
                if (!string_to_security_level(val, &out_config->initial_level)) {
                    if (error_buf) snprintf(error_buf, error_buf_len,
                        "Syntax Error at line %d: Unknown security level '%s'", line_number, val);
                    fclose(fp);
                    return FALSE;
                }
            }
        } else if (_stricmp(current_section, "limits") == 0) {
            if (_stricmp(key, "max_processes") == 0) {
                out_config->process_limit = (uint32_t)atoi(val);
            } else if (_stricmp(key, "max_memory_mb") == 0) {
                uint64_t mb = (uint64_t)atoll(val);
                out_config->memory_limit_bytes = mb * 1024 * 1024;
            } else if (_stricmp(key, "cpu_rate_cap_percent") == 0) {
                out_config->cpu_limit_percent = (uint32_t)atoi(val);
            } else if (_stricmp(key, "cpu_hard_cap") == 0) {
                out_config->cpu_hard_cap = parse_bool(val);
            }
        } else if (_stricmp(current_section, "token") == 0) {
            if (_stricmp(key, "use_restricted_token") == 0) {
                out_config->use_restricted_token = parse_bool(val);
            } else if (_stricmp(key, "strip_admin_sids") == 0) {
                out_config->strip_admin_sids = parse_bool(val);
            } else if (_stricmp(key, "disable_all_privileges") == 0) {
                out_config->disable_all_privileges = parse_bool(val);
            } else if (_stricmp(key, "integrity_level") == 0) {
                strncpy(out_config->integrity_level, val, sizeof(out_config->integrity_level) - 1);
            }
        } else if (_stricmp(current_section, "filesystem") == 0) {
            if (_stricmp(key, "sandbox_root") == 0) {
                MultiByteToWideChar(CP_UTF8, 0, val, -1, out_config->sandbox_root, MAX_PATH);
            } else if (_stricmp(key, "read_only_paths") == 0) {
                MultiByteToWideChar(CP_UTF8, 0, val, -1, out_config->read_only_paths, MAX_PATH);
            } else if (_stricmp(key, "read_write_paths") == 0) {
                MultiByteToWideChar(CP_UTF8, 0, val, -1, out_config->read_write_paths, MAX_PATH);
            } else if (_stricmp(key, "denied_paths") == 0) {
                MultiByteToWideChar(CP_UTF8, 0, val, -1, out_config->denied_paths, MAX_PATH);
            }
        } else if (_stricmp(current_section, "adaptive") == 0) {
            if (_stricmp(key, "escalation_threshold") == 0) {
                out_config->escalation_threshold = (uint32_t)atoi(val);
            } else if (_stricmp(key, "decay_interval_sec") == 0) {
                out_config->decay_interval_sec = (uint32_t)atoi(val);
            } else if (_stricmp(key, "decay_step") == 0) {
                out_config->decay_step = (uint32_t)atoi(val);
            } else if (_stricmp(key, "auto_terminate_on_l3") == 0) {
                out_config->auto_terminate_on_l3 = parse_bool(val);
            }
        }
    }

    fclose(fp);

    /* Validate compiled semantics */
    return policy_validate(out_config, error_buf, error_buf_len);
}

BOOL policy_get_default(const char* name, PolicyConfig* out_config) {
    if (!name || !out_config) return FALSE;

    memset(out_config, 0, sizeof(PolicyConfig));

    if (_stricmp(name, "strict") == 0) {
        strncpy(out_config->name, "strict", sizeof(out_config->name) - 1);
        strncpy(out_config->version, "1.0.0", sizeof(out_config->version) - 1);
        strncpy(out_config->author, "WinGuard Core", sizeof(out_config->author) - 1);
        strncpy(out_config->description, "Strict containment: Low Integrity, 25% CPU cap, 128 MB RAM, 5 processes", sizeof(out_config->description) - 1);
        out_config->initial_level = LEVEL_2_CONTAINED;
        out_config->cpu_limit_percent = 25;
        out_config->cpu_hard_cap = TRUE;
        out_config->memory_limit_bytes = 128 * 1024 * 1024;
        out_config->process_limit = 5;
        out_config->use_restricted_token = TRUE;
        out_config->strip_admin_sids = TRUE;
        out_config->disable_all_privileges = TRUE;
        strncpy(out_config->integrity_level, "Low", sizeof(out_config->integrity_level) - 1);
        out_config->escalation_threshold = 1;
        out_config->decay_interval_sec = 60;
        out_config->decay_step = 1;
        out_config->auto_terminate_on_l3 = TRUE;
        return TRUE;
    } else if (_stricmp(name, "permissive") == 0) {
        strncpy(out_config->name, "permissive", sizeof(out_config->name) - 1);
        strncpy(out_config->version, "1.0.0", sizeof(out_config->version) - 1);
        strncpy(out_config->author, "WinGuard Core", sizeof(out_config->author) - 1);
        strncpy(out_config->description, "Permissive observation: Medium Integrity, 90% CPU, 1024 MB RAM, 50 processes", sizeof(out_config->description) - 1);
        out_config->initial_level = LEVEL_0_OBSERVE;
        out_config->cpu_limit_percent = 90;
        out_config->cpu_hard_cap = FALSE;
        out_config->memory_limit_bytes = 1024ULL * 1024 * 1024;
        out_config->process_limit = 50;
        out_config->use_restricted_token = FALSE;
        out_config->strip_admin_sids = FALSE;
        out_config->disable_all_privileges = FALSE;
        strncpy(out_config->integrity_level, "Medium", sizeof(out_config->integrity_level) - 1);
        out_config->escalation_threshold = 10;
        out_config->decay_interval_sec = 5;
        out_config->decay_step = 1;
        out_config->auto_terminate_on_l3 = FALSE;
        return TRUE;
    } else {
        /* Default: adaptive policy */
        strncpy(out_config->name, "adaptive", sizeof(out_config->name) - 1);
        strncpy(out_config->version, "1.0.0", sizeof(out_config->version) - 1);
        strncpy(out_config->author, "WinGuard Core", sizeof(out_config->author) - 1);
        strncpy(out_config->description, "Adaptive dynamic policy: starts in LEVEL 0, dynamically escalates to LEVEL 3", sizeof(out_config->description) - 1);
        out_config->initial_level = LEVEL_0_OBSERVE;
        out_config->cpu_limit_percent = 50;
        out_config->cpu_hard_cap = TRUE;
        out_config->memory_limit_bytes = 256 * 1024 * 1024;
        out_config->process_limit = 10;
        out_config->use_restricted_token = FALSE;
        out_config->strip_admin_sids = TRUE;
        out_config->disable_all_privileges = FALSE;
        strncpy(out_config->integrity_level, "Medium", sizeof(out_config->integrity_level) - 1);
        out_config->escalation_threshold = 2;
        out_config->decay_interval_sec = 10;
        out_config->decay_step = 1;
        out_config->auto_terminate_on_l3 = TRUE;
        return TRUE;
    }
}

BOOL policy_load(const char* name_or_path, PolicyConfig* out_config) {
    if (!name_or_path || !out_config) return FALSE;

    WCHAR wpath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, name_or_path, -1, wpath, MAX_PATH);

    char error_buf[256] = {0};

    /* 1. Try directly as given file path */
    if (GetFileAttributesW(wpath) != INVALID_FILE_ATTRIBUTES) {
        if (policy_parse_file(wpath, out_config, error_buf, sizeof(error_buf))) {
            LOG_INFO("Loaded and compiled security policy from: %ls", wpath);
            return TRUE;
        } else {
            LOG_ERROR("Failed to compile policy file '%ls': %s", wpath, error_buf);
            return FALSE;
        }
    }

    /* 2. Try looking in policies/<name_or_path>.policy */
    WCHAR candidate[MAX_PATH];
    swprintf(candidate, MAX_PATH, L"policies\\%ls.policy", wpath);
    if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) {
        if (policy_parse_file(candidate, out_config, error_buf, sizeof(error_buf))) {
            LOG_INFO("Loaded and compiled security policy from: %ls", candidate);
            return TRUE;
        } else {
            LOG_ERROR("Failed to compile policy file '%ls': %s", candidate, error_buf);
            return FALSE;
        }
    }

    /* 3. Fallback: Check built-in policy names */
    if (policy_get_default(name_or_path, out_config)) {
        LOG_INFO("Loaded built-in default policy: '%s'", name_or_path);
        return TRUE;
    }

    LOG_ERROR("Unable to find or compile policy '%s'. (Not a file, not in policies/, not built-in).", name_or_path);
    return FALSE;
}

void policy_print(const PolicyConfig* config) {
    if (!config) return;

    printf("\n=======================================================\n");
    printf(" WinGuard Security Policy Specification\n");
    printf("=======================================================\n");
    printf(" Name                    : %s\n", config->name);
    printf(" Version                 : %s\n", config->version);
    printf(" Author                  : %s\n", config->author);
    printf(" Description             : %s\n", config->description);
    printf("-------------------------------------------------------\n");
    printf(" Initial Security Level  : %s\n", security_level_to_string(config->initial_level));
    printf(" Process Quota Limit     : %u max concurrent\n", config->process_limit);
    printf(" Committed Memory Limit  : %llu MB (%llu bytes)\n",
           (unsigned long long)(config->memory_limit_bytes / (1024 * 1024)),
           (unsigned long long)config->memory_limit_bytes);
    printf(" CPU Rate Limit          : %u%% (%s)\n",
           config->cpu_limit_percent, config->cpu_hard_cap ? "HARD Cap" : "Soft Share");
    printf("-------------------------------------------------------\n");
    printf(" Restricted Token        : %s\n", config->use_restricted_token ? "ENABLED" : "DISABLED");
    printf(" Strip Admin SIDs        : %s\n", config->strip_admin_sids ? "YES" : "NO");
    printf(" Disable All Privileges  : %s\n", config->disable_all_privileges ? "YES" : "NO");
    printf(" Target Integrity Level  : %s\n", config->integrity_level);
    printf("-------------------------------------------------------\n");
    printf(" Escalation Threshold    : %u violations -> promote level\n", config->escalation_threshold);
    printf(" Adaptive Decay Interval : %u seconds -> demote %u level(s)\n",
           config->decay_interval_sec, config->decay_step);
    printf(" Auto-Terminate on L3    : %s\n", config->auto_terminate_on_l3 ? "YES" : "NO");
    printf("=======================================================\n\n");
}
