#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    /* If launched with --child flag, this is a child process that sleeps briefly and exits */
    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        DWORD pid = GetCurrentProcessId();
        printf("      [Child PID %lu] Started. Sleeping 3 seconds...\n", pid);
        Sleep(3000);
        printf("      [Child PID %lu] Exiting.\n", pid);
        return 0;
    }

    int target_count = 10;
    if (argc > 1) {
        target_count = atoi(argv[1]);
        if (target_count <= 0) target_count = 10;
    }

    DWORD parent_pid = GetCurrentProcessId();
    printf("   [Process Stress] Parent PID %lu attempting to spawn %d child processes...\n",
           parent_pid, target_count);

    /* Get our own executable path to spawn child instances */
    WCHAR module_path[MAX_PATH];
    if (!GetModuleFileNameW(NULL, module_path, MAX_PATH)) {
        printf("   [Process Stress] GetModuleFileNameW failed with error %lu\n", GetLastError());
        return 1;
    }

    WCHAR cmd_line[MAX_PATH + 32];
    swprintf(cmd_line, sizeof(cmd_line) / sizeof(WCHAR), L"\"%ls\" --child", module_path);

    HANDLE child_handles[64];
    int spawned = 0;
    int blocked = 0;

    for (int i = 0; i < target_count; i++) {
        STARTUPINFOW si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);

        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(pi));

        WCHAR current_cmd[MAX_PATH + 32];
        wcscpy(current_cmd, cmd_line);

        printf("   [Process Stress] Spawning child #%d... ", i + 1);

        BOOL ok = CreateProcessW(
            NULL,
            current_cmd,
            NULL,
            NULL,
            FALSE,
            0,
            NULL,
            NULL,
            &si,
            &pi
        );

        if (ok) {
            printf("SUCCESS (PID: %lu)\n", pi.dwProcessId);
            CloseHandle(pi.hThread);
            if (spawned < 64) {
                child_handles[spawned] = pi.hProcess;
            } else {
                CloseHandle(pi.hProcess);
            }
            spawned++;
        } else {
            DWORD err = GetLastError();
            printf("BLOCKED / FAILED! Win32 Error %lu ", err);
            if (err == ERROR_NOT_ENOUGH_QUOTA) {
                printf("(ERROR_NOT_ENOUGH_QUOTA - Job Object process limit reached!)\n");
            } else if (err == ERROR_ACCESS_DENIED) {
                printf("(ERROR_ACCESS_DENIED)\n");
            } else {
                printf("\n");
            }
            blocked++;
        }

        Sleep(200); /* Small delay between spawns */
    }

    printf("\n   [Process Stress Summary]\n");
    printf("   Attempted : %d\n", target_count);
    printf("   Spawned   : %d\n", spawned);
    printf("   Blocked   : %d\n", blocked);

    /* Wait for spawned children to finish */
    if (spawned > 0) {
        int wait_count = (spawned > 64) ? 64 : spawned;
        printf("   Waiting for %d spawned child processes to terminate...\n", wait_count);
        WaitForMultipleObjects(wait_count, child_handles, TRUE, 5000);
        for (int i = 0; i < wait_count; i++) {
            CloseHandle(child_handles[i]);
        }
    }

    printf("   [Process Stress] Completed.\n");
    return (blocked > 0) ? 2 : 0;
}
