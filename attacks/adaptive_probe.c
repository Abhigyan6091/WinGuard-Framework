#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

static volatile BOOL g_running = TRUE;

static DWORD WINAPI cpu_burst_worker(LPVOID param) {
    (void)param;
    double val = 1.0001;
    while (g_running) {
        val = sin(val) * cos(val) + 1.0001;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    DWORD pid = GetCurrentProcessId();

    printf("\n=======================================================\n");
    printf(" [Adaptive Probe] Adversarial Dynamic Workload (PID: %lu)\n", pid);
    printf("=======================================================\n");

    /* Phase 1: Benign Baseline */
    printf("[Phase 1: Benign Start] Process running in initial baseline...\n");
    Sleep(200);

    /* Phase 2: CPU Burst - Triggering Level Escalation */
    printf("[Phase 2: CPU Burst] Spawning high-intensity compute threads...\n");
    g_running = TRUE;
    HANDLE hThreads[2];
    for (int i = 0; i < 2; ++i) {
        hThreads[i] = CreateThread(NULL, 0, cpu_burst_worker, NULL, 0, NULL);
    }
    Sleep(400); /* Burn CPU to generate telemetry spike */
    g_running = FALSE;
    WaitForMultipleObjects(2, hThreads, TRUE, 1000);
    for (int i = 0; i < 2; ++i) {
        CloseHandle(hThreads[i]);
    }
    printf("[Phase 2 Complete] CPU burst completed. Escalation to LEVEL 1 triggered.\n");

    /* Phase 3: Secondary Pressure - Triggering Level 2 Escalation */
    printf("[Phase 3: Repeated Violation] Committing memory rapidly...\n");
    void* ptrs[5];
    for (int i = 0; i < 5; ++i) {
        ptrs[i] = VirtualAlloc(NULL, 10 * 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (ptrs[i]) {
            memset(ptrs[i], 0xCC, 10 * 1024 * 1024);
        }
        Sleep(50);
    }
    printf("[Phase 3 Complete] Repeated pressure applied. Escalation to LEVEL 2 triggered.\n");

    /* Clean up allocated memory */
    for (int i = 0; i < 5; ++i) {
        if (ptrs[i]) VirtualFree(ptrs[i], 0, MEM_RELEASE);
    }

    /* Phase 4: Benign Behavior to allow Decay */
    printf("[Phase 4: Cooldown & Decay] Entering quiescent state for decay timeout...\n");
    Sleep(1200);
    printf("[Phase 4 Complete] Quiescent period elapsed. Checking dynamic state decay.\n");

    printf("[Adaptive Probe] Workload successfully completed all phases.\n\n");
    return 0;
}
