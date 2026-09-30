#include "token_manager.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <sddl.h>

const char* tm_integrity_to_string(IntegrityLevel level) {
    switch (level) {
        case INTEGRITY_UNTRUSTED: return "UNTRUSTED";
        case INTEGRITY_LOW:       return "LOW";
        case INTEGRITY_MEDIUM:    return "MEDIUM";
        case INTEGRITY_HIGH:      return "HIGH";
        case INTEGRITY_SYSTEM:    return "SYSTEM";
        default:                  return "UNKNOWN";
    }
}

BOOL tm_inspect_process_token(HANDLE hProcess, TokenContext* out_ctx) {
    if (!hProcess || !out_ctx) return FALSE;
    ZeroMemory(out_ctx, sizeof(TokenContext));

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        DWORD err = GetLastError();
        LOG_WARN("OpenProcessToken (TOKEN_QUERY) failed with error %lu.", err);
        return FALSE;
    }

    /* 1. Query User SID & Name */
    DWORD needed = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &needed);
    if (needed > 0) {
        BYTE* buffer = (BYTE*)malloc(needed);
        if (buffer && GetTokenInformation(hToken, TokenUser, buffer, needed, &needed)) {
            PTOKEN_USER pUser = (PTOKEN_USER)buffer;
            LPWSTR sid_str = NULL;
            if (ConvertSidToStringSidW(pUser->User.Sid, &sid_str)) {
                wcsncpy(out_ctx->user_sid, sid_str, sizeof(out_ctx->user_sid) / sizeof(WCHAR) - 1);
                LocalFree(sid_str);
            }

            DWORD name_len = sizeof(out_ctx->user_name) / sizeof(WCHAR);
            DWORD domain_len = sizeof(out_ctx->domain_name) / sizeof(WCHAR);
            SID_NAME_USE sid_use;
            LookupAccountSidW(
                NULL,
                pUser->User.Sid,
                out_ctx->user_name,
                &name_len,
                out_ctx->domain_name,
                &domain_len,
                &sid_use
            );
        }
        free(buffer);
    }

    /* 2. Query Restricted Token Status */
    out_ctx->is_restricted = IsTokenRestricted(hToken);

    /* 3. Query Token Integrity Level */
    needed = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &needed);
    if (needed > 0) {
        BYTE* buffer = (BYTE*)malloc(needed);
        if (buffer && GetTokenInformation(hToken, TokenIntegrityLevel, buffer, needed, &needed)) {
            PTOKEN_MANDATORY_LABEL pLabel = (PTOKEN_MANDATORY_LABEL)buffer;
            UCHAR* sub_auth_count = GetSidSubAuthorityCount(pLabel->Label.Sid);
            if (sub_auth_count && *sub_auth_count > 0) {
                DWORD rid = *GetSidSubAuthority(pLabel->Label.Sid, *sub_auth_count - 1);
                if (rid < 0x1000) {
                    out_ctx->integrity_level = INTEGRITY_UNTRUSTED;
                } else if (rid < 0x2000) {
                    out_ctx->integrity_level = INTEGRITY_LOW;
                } else if (rid < 0x3000) {
                    out_ctx->integrity_level = INTEGRITY_MEDIUM;
                } else if (rid < 0x4000) {
                    out_ctx->integrity_level = INTEGRITY_HIGH;
                } else {
                    out_ctx->integrity_level = INTEGRITY_SYSTEM;
                }
            }
        }
        free(buffer);
    } else {
        out_ctx->integrity_level = INTEGRITY_MEDIUM;
    }
    out_ctx->integrity_string = tm_integrity_to_string(out_ctx->integrity_level);

    /* 4. Query Privileges Dynamically */
    needed = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &needed);
    if (needed > 0) {
        BYTE* buffer = (BYTE*)malloc(needed);
        if (buffer && GetTokenInformation(hToken, TokenPrivileges, buffer, needed, &needed)) {
            PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)buffer;
            out_ctx->privilege_count = pPrivs->PrivilegeCount;
            if (out_ctx->privilege_count > MAX_TOKEN_PRIVILEGES) {
                out_ctx->privilege_count = MAX_TOKEN_PRIVILEGES;
            }

            for (DWORD i = 0; i < out_ctx->privilege_count; i++) {
                DWORD name_len = sizeof(out_ctx->privileges[i].name) / sizeof(WCHAR);
                if (LookupPrivilegeNameW(NULL, &pPrivs->Privileges[i].Luid, out_ctx->privileges[i].name, &name_len)) {
                    out_ctx->privileges[i].attributes = pPrivs->Privileges[i].Attributes;
                    out_ctx->privileges[i].is_enabled = (pPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                } else {
                    swprintf(out_ctx->privileges[i].name, sizeof(out_ctx->privileges[i].name) / sizeof(WCHAR),
                             L"LUID_{%08lx-%08lx}", pPrivs->Privileges[i].Luid.HighPart, pPrivs->Privileges[i].Luid.LowPart);
                }
            }
        }
        free(buffer);
    }

    CloseHandle(hToken);
    return TRUE;
}

BOOL tm_create_restricted_token(
    HANDLE hBaseToken,
    BOOL drop_all_privileges,
    BOOL low_integrity,
    HANDLE* out_primary_token
) {
    if (!out_primary_token) return FALSE;
    *out_primary_token = NULL;

    HANDLE hBase = hBaseToken;
    BOOL opened_own_token = FALSE;

    if (!hBase) {
        if (!OpenProcessToken(GetCurrentProcess(),
                              TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                              &hBase)) {
            DWORD err = GetLastError();
            LOG_ERROR("OpenProcessToken (current) failed with Win32 Error %lu.", err);
            return FALSE;
        }
        opened_own_token = TRUE;
    }

    DWORD flags = 0;
    if (drop_all_privileges) {
        flags |= DISABLE_MAX_PRIVILEGE;
    }

    PSID pRestrictedSid = NULL;
    SID_AND_ATTRIBUTES sids_to_restrict[1];
    DWORD num_sids_to_restrict = 0;

    if (ConvertStringSidToSidW(L"S-1-5-12", &pRestrictedSid)) { /* SECURITY_RESTRICTED_CODE_RID */
        sids_to_restrict[0].Sid = pRestrictedSid;
        sids_to_restrict[0].Attributes = 0;
        num_sids_to_restrict = 1;
    }

    HANDLE hRestricted = NULL;
    BOOL crt_ok = CreateRestrictedToken(
        hBase,
        flags,
        0, NULL,
        0, NULL,
        num_sids_to_restrict, sids_to_restrict,
        &hRestricted
    );

    if (pRestrictedSid) {
        LocalFree(pRestrictedSid);
    }

    if (!crt_ok) {
        DWORD err = GetLastError();
        LOG_ERROR("CreateRestrictedToken failed with Win32 Error %lu.", err);
        if (opened_own_token) CloseHandle(hBase);
        return FALSE;
    }

    LOG_INFO("Created restricted token [Handle: %p, Flags: 0x%lX]", hRestricted, flags);

    /* Lower Integrity Level if requested */
    if (low_integrity) {
        PSID pLowSid = NULL;
        if (ConvertStringSidToSidW(L"S-1-16-4096", &pLowSid)) {
            TOKEN_MANDATORY_LABEL tml;
            ZeroMemory(&tml, sizeof(tml));
            tml.Label.Attributes = SE_GROUP_INTEGRITY;
            tml.Label.Sid = pLowSid;

            if (SetTokenInformation(
                    hRestricted,
                    TokenIntegrityLevel,
                    &tml,
                    sizeof(tml) + GetLengthSid(pLowSid))) {
                LOG_INFO("Configured Token: Integrity Level lowered to LOW (S-1-16-4096).");
            } else {
                DWORD err = GetLastError();
                LOG_WARN("SetTokenInformation (Low Integrity) failed with Win32 Error %lu.", err);
            }
            LocalFree(pLowSid);
        }
    }

    /* Duplicate into a primary token suitable for CreateProcessAsUserW */
    HANDLE hPrimary = NULL;
    if (!DuplicateTokenEx(
            hRestricted,
            MAXIMUM_ALLOWED,
            NULL,
            SecurityImpersonation,
            TokenPrimary,
            &hPrimary)) {
        DWORD err = GetLastError();
        LOG_ERROR("DuplicateTokenEx (TokenPrimary) failed with Win32 Error %lu.", err);
        CloseHandle(hRestricted);
        if (opened_own_token) CloseHandle(hBase);
        return FALSE;
    }

    /* Apply Low Integrity to the duplicated primary token as well */
    if (low_integrity) {
        PSID pLowSid = NULL;
        if (ConvertStringSidToSidW(L"S-1-16-4096", &pLowSid)) {
            TOKEN_MANDATORY_LABEL tml;
            ZeroMemory(&tml, sizeof(tml));
            tml.Label.Attributes = SE_GROUP_INTEGRITY;
            tml.Label.Sid = pLowSid;

            SetTokenInformation(
                hPrimary,
                TokenIntegrityLevel,
                &tml,
                sizeof(tml) + GetLengthSid(pLowSid)
            );
            LocalFree(pLowSid);
        }
    }

    CloseHandle(hRestricted);
    if (opened_own_token) CloseHandle(hBase);

    LOG_INFO("Duplicated restricted primary token ready for process creation [Handle: %p]", hPrimary);
    *out_primary_token = hPrimary;
    return TRUE;
}

void tm_print_security_context(const TokenContext* ctx) {
    if (!ctx) return;

    printf("\n-------------------------------------------------------\n");
    printf(" Windows Security Context\n");
    printf("-------------------------------------------------------\n");
    if (ctx->domain_name[0] && ctx->user_name[0]) {
        printf(" User Account      : %ls\\%ls\n", ctx->domain_name, ctx->user_name);
    }
    printf(" User SID          : %ls\n", ctx->user_sid[0] ? ctx->user_sid : L"(unknown)");
    printf(" Restricted Token  : %s\n", ctx->is_restricted ? "YES (Privileges Stripped)" : "NO (Standard Token)");
    printf(" Integrity Level   : %s\n", ctx->integrity_string ? ctx->integrity_string : "UNKNOWN");
    printf("\n Privileges (%u total)\n", ctx->privilege_count);
    printf(" -----------------------------------------------------\n");

    if (ctx->privilege_count == 0) {
        printf("   (None - all privileges completely stripped)\n");
    } else {
        for (uint32_t i = 0; i < ctx->privilege_count; i++) {
            const char* status = ctx->privileges[i].is_enabled ? "ENABLED" : "DISABLED";
            printf("   %-34ls %s\n", ctx->privileges[i].name, status);
        }
    }
    printf("-------------------------------------------------------\n\n");
    fflush(stdout);
}
