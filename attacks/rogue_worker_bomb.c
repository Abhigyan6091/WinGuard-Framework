#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
    DWORD pid = GetCurrentProcessId();

    if (argc > 2 && _stricmp(argv[1], "--worker") == 0) {
        if (_stricmp(argv[2], "benign") == 0) {
            printf("   [BENIGN WORKER] Started (PID %lu). Performing low-memory background tasks...\n", pid);
            for (int i = 0; i < 5; ++i) {
                Sleep(500);
                printf("   [BENIGN WORKER] PID %lu heartbeat %d/5 OK\n", pid, i + 1);
            }
            printf("   [BENIGN WORKER] PID %lu finished successfully.\n", pid);
            return 0;
        } else if (_stricmp(argv[2], "rogue") == 0) {
            printf("   [ROGUE WORKER] Started (PID %lu). Commencing massive memory expansion...\n", pid);
            size_t chunk_size = 20 * 1024 * 1024; /* 20 MB */
            for (int i = 0; i < 8; ++i) {
                void* ptr = VirtualAlloc(NULL, chunk_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (ptr) {
                    volatile char* p = (volatile char*)ptr;
                    for (size_t off = 0; off < chunk_size; off += 4096) {
                        p[off] = (char)0xAA;
                    }
                    printf("   [ROGUE WORKER] PID %lu committed %d MB...\n", pid, (i + 1) * 20);
                } else {
                    printf("   [ROGUE WORKER] PID %lu allocation failed (OS limit)\n", pid);
                    break;
                }
                Sleep(150);
            }
            Sleep(3000);
            return 0;
        }
    }

    /* Coordinator mode */
    printf("\n=======================================================\n");
    printf(" [COORDINATOR] Process Hierarchy Manager (PID %lu)\n", pid);
    printf(" Spawning 1 benign worker and 1 rogue memory-hog worker\n");
    printf("=======================================================\n");

    WCHAR self_path[MAX_PATH];
    GetModuleFileNameW(NULL, self_path, MAX_PATH);

    WCHAR cmdline_benign[MAX_PATH + 64];
    WCHAR cmdline_rogue[MAX_PATH + 64];
    swprintf(cmdline_benign, MAX_PATH + 64, L"\"%s\" --worker benign", self_path);
    swprintf(cmdline_rogue, MAX_PATH + 64, L"\"%s\" --worker rogue", self_path);

    STARTUPINFOW si1;
    PROCESS_INFORMATION pi1;
    STARTUPINFOW si2;
    PROCESS_INFORMATION pi2;
    ZeroMemory(&si1, sizeof(si1));
    ZeroMemory(&pi1, sizeof(pi1));
    ZeroMemory(&si2, sizeof(si2));
    ZeroMemory(&pi2, sizeof(pi2));
    si1.cb = sizeof(si1);
    si2.cb = sizeof(si2);

    BOOL ok1 = CreateProcessW(NULL, cmdline_benign, NULL, NULL, FALSE, 0, NULL, NULL, &si1, &pi1);
    BOOL ok2 = CreateProcessW(NULL, cmdline_rogue, NULL, NULL, FALSE, 0, NULL, NULL, &si2, &pi2);

    if (!ok1 || !ok2) {
        printf("Failed to spawn child worker processes!\n");
        return 1;
    }

    printf(" [COORDINATOR] Spawned Benign Worker PID: %lu, Rogue Worker PID: %lu\n",
           pi1.dwProcessId, pi2.dwProcessId);

    HANDLE handles[2] = { pi1.hProcess, pi2.hProcess };
    WaitForMultipleObjects(2, handles, TRUE, 8000);

    DWORD exit1 = 0, exit2 = 0;
    GetExitCodeProcess(pi1.hProcess, &exit1);
    GetExitCodeProcess(pi2.hProcess, &exit2);

    printf("\n [COORDINATOR SUMMARY]\n");
    printf(" Benign Worker Exit Code: 0x%08lX (%s)\n", exit1, (exit1 == 0) ? "SURVIVED / CLEAN EXIT" : "TERMINATED");
    printf(" Rogue Worker Exit Code : 0x%08lX (%s)\n", exit2, (exit2 == 0xC000012D) ? "SELECTIVELY TRIAGED (STATUS_COMMITMENT_LIMIT)" : "OTHER");

    CloseHandle(pi1.hProcess);
    CloseHandle(pi1.hThread);
    CloseHandle(pi2.hProcess);
    CloseHandle(pi2.hThread);

    printf(" [COORDINATOR] Master process execution complete.\n");
    return 0;
}
