#include <windows.h>
#include <stdio.h>
#include <sddl.h>

int main(void) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &hToken)) {
        printf("OpenProcessToken failed: %lu\n", GetLastError());
        return 1;
    }

    HANDLE hRestricted = NULL;
    if (!CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &hRestricted)) {
        printf("CreateRestrictedToken failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return 1;
    }
    printf("CreateRestrictedToken succeeded! Handle: %p\n", hRestricted);

    /* Lower integrity to Low (S-1-16-4096) */
    PSID pLowSid = NULL;
    if (ConvertStringSidToSidW(L"S-1-16-4096", &pLowSid)) {
        TOKEN_MANDATORY_LABEL tml;
        tml.Label.Attributes = SE_GROUP_INTEGRITY;
        tml.Label.Sid = pLowSid;
        if (SetTokenInformation(hRestricted, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(pLowSid))) {
            printf("SetTokenInformation (Low Integrity) succeeded!\n");
        } else {
            printf("SetTokenInformation failed: %lu\n", GetLastError());
        }
        LocalFree(pLowSid);
    }

    /* Test DuplicateTokenEx to primary token */
    HANDLE hPrimary = NULL;
    if (DuplicateTokenEx(hRestricted, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hPrimary)) {
        printf("DuplicateTokenEx to TokenPrimary succeeded! Handle: %p\n", hPrimary);
        
        STARTUPINFOW si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(pi));

        WCHAR cmd[] = L"cmd.exe /c echo HelloFromRestricted";
        BOOL cp_ok = CreateProcessAsUserW(
            hPrimary,
            NULL,
            cmd,
            NULL,
            NULL,
            FALSE,
            0,
            NULL,
            NULL,
            &si,
            &pi
        );

        if (cp_ok) {
            printf("CreateProcessAsUserW succeeded! PID: %lu\n", pi.dwProcessId);
            WaitForSingleObject(pi.hProcess, 3000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        } else {
            DWORD err = GetLastError();
            printf("CreateProcessAsUserW returned error: %lu (0x%lX)\n", err, err);
        }
        CloseHandle(hPrimary);
    } else {
        printf("DuplicateTokenEx failed: %lu\n", GetLastError());
    }

    CloseHandle(hRestricted);
    CloseHandle(hToken);
    return 0;
}
