#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <sddl.h>

int main(void) {
    DWORD pid = GetCurrentProcessId();
    printf("   [Privilege Probe] Starting security token & privilege audit for PID %lu...\n", pid);

    HANDLE hToken = NULL;
    BOOL is_restricted = FALSE;
    /* Open with TOKEN_QUERY to inspect self */
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD err = GetLastError();
        printf("   [Privilege Probe] OpenProcessToken failed with Win32 Error %lu\n", err);
        printf("   [Note] Process is running in Low Integrity sandbox; direct token query blocked by kernel MIC.\n");
        is_restricted = TRUE;
    } else {
        /* 1. Audit Token Restricted Flag */
        is_restricted = IsTokenRestricted(hToken);
        printf("   [Audit] Is Restricted Token   : %s\n", is_restricted ? "YES (Restricted SIDs Active)" : "NO (Standard Token)");

        /* 2. Audit Integrity Level */
        DWORD needed = 0;
        GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &needed);
        if (needed > 0) {
            BYTE* buf = (BYTE*)malloc(needed);
            if (buf && GetTokenInformation(hToken, TokenIntegrityLevel, buf, needed, &needed)) {
                PTOKEN_MANDATORY_LABEL pLabel = (PTOKEN_MANDATORY_LABEL)buf;
                DWORD count = *GetSidSubAuthorityCount(pLabel->Label.Sid);
                DWORD rid = *GetSidSubAuthority(pLabel->Label.Sid, count - 1);
                printf("   [Audit] Integrity Level RID   : 0x%04lX (%s)\n",
                       rid,
                       (rid < 0x1000) ? "UNTRUSTED" :
                       (rid < 0x2000) ? "LOW" :
                       (rid < 0x3000) ? "MEDIUM" : "HIGH/SYSTEM");
            }
            free(buf);
        }

        /* 3. Enumerate Held Privileges */
        needed = 0;
        GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &needed);
        int priv_count = 0;
        if (needed > 0) {
            BYTE* buf = (BYTE*)malloc(needed);
            if (buf && GetTokenInformation(hToken, TokenPrivileges, buf, needed, &needed)) {
                PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)buf;
                priv_count = (int)pPrivs->PrivilegeCount;
                printf("   [Audit] Held Privileges Count : %d\n", priv_count);
                for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
                    WCHAR name[64];
                    DWORD name_len = sizeof(name) / sizeof(WCHAR);
                    if (LookupPrivilegeNameW(NULL, &pPrivs->Privileges[i].Luid, name, &name_len)) {
                        printf("      - %ls (%s)\n", name,
                               (pPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "ENABLED" : "DISABLED");
                    }
                }
            }
            free(buf);
        }
    }

    printf("\n   [Privilege Probe: Testing Controlled Operations]\n");

    /* Test Operation A: Attempt to acquire TOKEN_ADJUST_PRIVILEGES and enable SeShutdownPrivilege */
    printf("   Probe A: Attempting to acquire TOKEN_ADJUST_PRIVILEGES... ");
    HANDLE hAdjustToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hAdjustToken)) {
        TOKEN_PRIVILEGES tp;
        ZeroMemory(&tp, sizeof(tp));
        if (LookupPrivilegeValueW(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            SetLastError(0);
            AdjustTokenPrivileges(hAdjustToken, FALSE, &tp, sizeof(tp), NULL, NULL);
            DWORD err = GetLastError();

            if (err == ERROR_SUCCESS) {
                printf("ENABLED (SeShutdownPrivilege acquired)\n");
            } else if (err == ERROR_NOT_ALL_ASSIGNED) {
                printf("BLOCKED (Win32 1300 ERROR_NOT_ALL_ASSIGNED - Privilege stripped from token!)\n");
            } else {
                printf("DENIED (Win32 Error %lu)\n", err);
            }
        } else {
            printf("FAILED lookup\n");
        }
        CloseHandle(hAdjustToken);
    } else {
        DWORD err = GetLastError();
        printf("BLOCKED / ACCESS DENIED (Win32 Error %lu: Token rights stripped!)\n", err);
    }

    /* Test Operation B: Attempt to open protected System process (PID 4) with PROCESS_ALL_ACCESS */
    printf("   Probe B: Attempting OpenProcess(PROCESS_ALL_ACCESS, PID 4 [System])... ");
    HANDLE hSystem = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 4);
    if (hSystem) {
        printf("UNEXPECTED SUCCESS (Handle %p)\n", hSystem);
        CloseHandle(hSystem);
    } else {
        DWORD err = GetLastError();
        printf("BLOCKED / DENIED (Win32 Error %lu: %s)\n",
               err, (err == ERROR_ACCESS_DENIED) ? "ERROR_ACCESS_DENIED" : "FAILED");
    }

    /* Test Operation C: Attempt to write to protected System32 hosts file */
    printf("   Probe C: Attempting CreateFileW(GENERIC_WRITE, C:\\Windows\\System32\\drivers\\etc\\hosts)... ");
    HANDLE hFile = CreateFileW(
        L"C:\\Windows\\System32\\drivers\\etc\\hosts",
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        printf("UNEXPECTED SUCCESS (Write access obtained!)\n");
        CloseHandle(hFile);
    } else {
        DWORD err = GetLastError();
        printf("BLOCKED / DENIED (Win32 Error %lu: %s)\n",
               err, (err == ERROR_ACCESS_DENIED) ? "ERROR_ACCESS_DENIED" : "FAILED");
    }

    if (hToken) {
        CloseHandle(hToken);
    }

    printf("\n   [Privilege Probe Summary]\n");
    printf("   Security Posture : %s\n", is_restricted ? "STRICT RESTRICTED SANDBOX" : "PERMISSIVE STANDARD TOKEN");
    printf("   [Privilege Probe] Completed.\n");
    return 0;
}
