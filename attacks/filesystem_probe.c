#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static void test_read(const WCHAR* path, const char* label) {
    printf("   Probe [%s] READ '%ls'... ", label, path);
    HANDLE hFile = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        char buffer[128];
        DWORD read = 0;
        ReadFile(hFile, buffer, sizeof(buffer) - 1, &read, NULL);
        buffer[read < sizeof(buffer) ? read : sizeof(buffer) - 1] = '\0';
        CloseHandle(hFile);
        printf("SUCCESS (Read %lu bytes: \"%.30s...\")\n", read, buffer);
    } else {
        DWORD err = GetLastError();
        printf("FAILED (Win32 Error %lu: %s)\n",
               err, (err == ERROR_ACCESS_DENIED) ? "ACCESS_DENIED" : "FILE_NOT_FOUND");
    }
}

static BOOL test_write(const WCHAR* path, const char* label, BOOL expect_block) {
    printf("   Probe [%s] WRITE '%ls'... ", label, path);
    HANDLE hFile = CreateFileW(
        path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        const char test_data[] = "Malicious or unauthorized data write attempt.";
        DWORD written = 0;
        WriteFile(hFile, test_data, (DWORD)strlen(test_data), &written, NULL);
        CloseHandle(hFile);

        if (expect_block) {
            printf("UNEXPECTED SUCCESS (Write was permitted!)\n");
            return FALSE;
        } else {
            printf("SUCCESS (Authorized write completed)\n");
            return TRUE;
        }
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            printf("BLOCKED / ACCESS DENIED (Win32 Error 5: Blocked by Windows NTFS / MIC!)\n");
            return TRUE;
        } else {
            printf("FAILED (Win32 Error %lu)\n", err);
            return FALSE;
        }
    }
}

int main(void) {
    DWORD pid = GetCurrentProcessId();
    printf("   [Filesystem Probe] Initiating filesystem boundary access audit for PID %lu...\n\n", pid);

    BOOL all_blocked = TRUE;

    /* Probe 1: Read authorized input data */
    test_read(L"sandbox\\input\\sample_input.txt", "1. Authorized Read");

    /* Probe 2: Attempt unauthorized write into input/ (Expect Blocked) */
    if (!test_write(L"sandbox\\input\\unauthorized_write.txt", "2. Input Dir Write (Tampering)", TRUE)) {
        all_blocked = FALSE;
    }

    /* Probe 3: Attempt authorized write into output/ (Expect Allowed) */
    test_write(L"sandbox\\output\\test_output.txt", "3. Output Dir Write", FALSE);

    /* Probe 4: Attempt authorized write into temp/ (Expect Allowed) */
    test_write(L"sandbox\\temp\\test_temp.tmp", "4. Temp Dir Write", FALSE);

    /* Probe 5: Attempt unauthorized escape write outside sandbox (Expect Blocked) */
    if (!test_write(L"escape_attempt.txt", "5. Outside Sandbox Write (Escape)", TRUE)) {
        all_blocked = FALSE;
    }

    /* Verify physical side effects on disk */
    BOOL escape_file_written = (GetFileAttributesW(L"escape_attempt.txt") != INVALID_FILE_ATTRIBUTES);
    BOOL input_tamper_written = (GetFileAttributesW(L"sandbox\\input\\unauthorized_write.txt") != INVALID_FILE_ATTRIBUTES);

    if (escape_file_written) {
        DeleteFileW(L"escape_attempt.txt");
        all_blocked = FALSE;
    }
    if (input_tamper_written) {
        DeleteFileW(L"sandbox\\input\\unauthorized_write.txt");
        all_blocked = FALSE;
    }

    printf("\n   [Filesystem Probe Summary]\n");
    printf("   Input Integrity Protection  : %s\n", !input_tamper_written ? "VERIFIED (Tampering Blocked)" : "FAILED (Tampered)");
    printf("   Workspace Isolation (MIC)   : %s\n", !escape_file_written ? "VERIFIED (Escape Blocked)" : "FAILED (Escape Succeeded)");
    printf("   Containment Assessment      : %s\n", all_blocked ? "CONTAINED [PASS]" : "UNCONTAINED [ESCAPE]");
    printf("   [Filesystem Probe] Completed.\n");

    /* Return 2 if contained, 1 if boundary escaped */
    return all_blocked ? 2 : 1;
}
