#ifndef WINGUARD_TOKEN_MANAGER_H
#define WINGUARD_TOKEN_MANAGER_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    INTEGRITY_UNKNOWN   = 0,
    INTEGRITY_UNTRUSTED = 1,  /* S-1-16-0 */
    INTEGRITY_LOW       = 2,  /* S-1-16-4096 */
    INTEGRITY_MEDIUM    = 3,  /* S-1-16-8192 */
    INTEGRITY_HIGH      = 4,  /* S-1-16-12288 */
    INTEGRITY_SYSTEM    = 5   /* S-1-16-16384 */
} IntegrityLevel;

typedef struct {
    WCHAR name[64];
    DWORD attributes;
    BOOL is_enabled;
} PrivilegeInfo;

#define MAX_TOKEN_PRIVILEGES 64

/**
 * TokenContext contains the inspected security posture of a process token.
 */
typedef struct {
    WCHAR user_sid[128];
    WCHAR user_name[128];
    WCHAR domain_name[128];
    IntegrityLevel integrity_level;
    const char* integrity_string;
    BOOL is_restricted;
    uint32_t privilege_count;
    PrivilegeInfo privileges[MAX_TOKEN_PRIVILEGES];
} TokenContext;

/**
 * Inspects the access token associated with a process handle.
 * Dynamically queries User SID, Integrity Level, Restricted status,
 * and enumerates all held privileges without assuming names.
 * 
 * @param hProcess Process handle with PROCESS_QUERY_LIMITED_INFORMATION or PROCESS_QUERY_INFORMATION.
 * @param out_ctx Pointer to TokenContext structure to receive details.
 * @return TRUE on success, FALSE otherwise.
 */
BOOL tm_inspect_process_token(HANDLE hProcess, TokenContext* out_ctx);

/**
 * Creates a restricted primary token derived from a base token (or current process).
 * Strips all unnecessary privileges and optionally lowers integrity level to Low.
 * 
 * @param hBaseToken Base token to restrict (NULL uses current process token).
 * @param drop_all_privileges If TRUE, drops all privileges via DISABLE_MAX_PRIVILEGE.
 * @param low_integrity If TRUE, lowers Mandatory Label to Low Integrity (S-1-16-4096).
 * @param out_primary_token Receives duplicated TokenPrimary handle ready for CreateProcessAsUserW.
 * @return TRUE on success, FALSE otherwise.
 */
BOOL tm_create_restricted_token(
    HANDLE hBaseToken,
    BOOL drop_all_privileges,
    BOOL low_integrity,
    HANDLE* out_primary_token
);

/**
 * Converts IntegrityLevel enum to display string.
 */
const char* tm_integrity_to_string(IntegrityLevel level);

/**
 * Pretty-prints security context according to specification.
 */
void tm_print_security_context(const TokenContext* ctx);

#endif /* WINGUARD_TOKEN_MANAGER_H */
