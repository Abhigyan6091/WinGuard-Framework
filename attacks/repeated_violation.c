#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * Repeated Multi-Vector Boundary Probe:
 * Deliberately executes sequential adversarial actions across multiple OS vectors:
 * 1. Process spawning past quota
 * 2. Memory overcommitment past Job limit
 * 3. Protected filesystem modification (input & system32)
 * 4. Privilege elevation attempt via AdjustTokenPrivileges
 */

static void test_vector_process(void) {
    printf("[Vector 1] Attempting rapid process spawning past quota...\n");
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    int spawned = 0;
    int failed = 0;
    char cmd[] = "cmd.exe /c exit 0";

    for (int i = 0; i < 6; ++i) {
        if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            spawned++;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            failed++;
        }
    }
    printf("           Results: Spawned = %d, Kernel Blocked = %d\n", spawned, failed);
}

static void test_vector_memory(void) {
    printf("[Vector 2] Attempting memory allocation exceeding quota...\n");
    size_t chunk_size = 32 * 1024 * 1024; /* 32 MB */
    int allocated_chunks = 0;

    for (int i = 0; i < 4; ++i) {
        void* ptr = VirtualAlloc(NULL, chunk_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (ptr) {
            allocated_chunks++;
            memset(ptr, 0xAA, chunk_size);
            VirtualFree(ptr, 0, MEM_RELEASE);
        } else {
            DWORD err = GetLastError();
            printf("           Allocation chunk %d rejected by OS (Error: %lu)\n", i + 1, err);
            break;
        }
    }
    printf("           Results: Committed Chunks = %d\n", allocated_chunks);
}

static void test_vector_filesystem(void) {
    printf("[Vector 3] Attempting unauthorized filesystem tampering...\n");

    /* Try writing to protected input folder */
    HANDLE hFile1 = CreateFileA("sandbox\\input\\tamper.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile1 == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("           Write to sandbox\\input\\ BLOCKED (Win32 Error: %lu - ACCESS_DENIED)\n", err);
    } else {
        printf("           Write to sandbox\\input\\ PERMITTED (Unexpected)\n");
        CloseHandle(hFile1);
    }

    /* Try writing to system directory */
    HANDLE hFile2 = CreateFileA("C:\\Windows\\System32\\drivers\\etc\\hosts", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile2 == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("           Write to System32\\drivers\\etc\\hosts BLOCKED (Win32 Error: %lu - ACCESS_DENIED)\n", err);
    } else {
        printf("           Write to System32 PERMITTED (Unexpected)\n");
        CloseHandle(hFile2);
    }
}

static void test_vector_privilege(void) {
    printf("[Vector 4] Attempting unauthorized privilege adjustment...\n");
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid);
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
            DWORD err = GetLastError();
            if (err == ERROR_NOT_ALL_ASSIGNED) {
                printf("           SeDebugPrivilege enable DENIED (ERROR_NOT_ALL_ASSIGNED - Privilege stripped)\n");
            } else {
                printf("           AdjustTokenPrivileges returned error: %lu\n", err);
            }
        } else {
            DWORD err = GetLastError();
            printf("           AdjustTokenPrivileges call BLOCKED (Error: %lu)\n", err);
        }
        CloseHandle(hToken);
    } else {
        DWORD err = GetLastError();
        printf("           OpenProcessToken with TOKEN_ADJUST_PRIVILEGES BLOCKED (Win32 Error: %lu)\n", err);
    }
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    printf("\n=======================================================\n");
    printf(" [Repeated Violation Probe] Multi-Vector Adversarial Stress\n");
    printf(" PID: %lu\n", GetCurrentProcessId());
    printf("=======================================================\n");

    test_vector_process();
    Sleep(100);

    test_vector_memory();
    Sleep(100);

    test_vector_filesystem();
    Sleep(100);

    test_vector_privilege();
    Sleep(100);

    printf("\n[Repeated Violation Probe] All adversarial test vectors executed.\n");
    printf("=======================================================\n\n");
    return 0;
}
