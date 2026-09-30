#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static volatile BOOL g_burn = FALSE;

static DWORD WINAPI burn_thread(LPVOID param) {
    (void)param;
    double x = 1.0001;
    while (TRUE) {
        if (g_burn) {
            x = sin(x) * cos(x) + 1.0001;
        } else {
            Sleep(5);
        }
    }
    return 0;
}

int main(int argc, char* argv[]) {
    const char* mode = (argc > 1) ? argv[1] : "burst";
    int iterations = (argc > 2) ? atoi(argv[2]) : 4;
    if (iterations <= 0) iterations = 4;

    printf("\n=======================================================\n");
    printf(" [CPU Pattern Probe] Mode: %s, Iterations: %d, PID: %lu\n",
           mode, iterations, GetCurrentProcessId());
    printf("=======================================================\n");

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD thread_count = (si.dwNumberOfProcessors > 0) ? si.dwNumberOfProcessors : 2;
    if (thread_count > 4) thread_count = 4;

    HANDLE* threads = (HANDLE*)malloc(thread_count * sizeof(HANDLE));
    for (DWORD i = 0; i < thread_count; ++i) {
        threads[i] = CreateThread(NULL, 0, burn_thread, NULL, 0, NULL);
    }

    if (_stricmp(mode, "creep") == 0) {
        /* Creep Mode: Gradually increasing duty cycles */
        printf("[Creep Mode] Starting gradual resource creep pattern...\n");
        for (int i = 0; i < iterations; ++i) {
            int duty_pct = (i + 1) * (100 / iterations);
            printf("  -> Cycle %d/%d: Target Duty Cycle ~%d%%\n", i + 1, iterations, duty_pct);
            
            DWORD active_ms = (DWORD)(duty_pct * 5);
            DWORD idle_ms = (DWORD)((100 - duty_pct) * 5);

            for (int tick = 0; tick < 5; ++tick) {
                g_burn = TRUE;
                Sleep(active_ms);
                g_burn = FALSE;
                Sleep(idle_ms);
            }
        }
    } else {
        /* Burst Mode: Intermittent sharp spikes */
        printf("[Burst Mode] Starting intermittent sharp CPU burst pattern...\n");
        for (int i = 0; i < iterations; ++i) {
            printf("  -> Burst %d/%d: Burning CPU (250ms ON)...\n", i + 1, iterations);
            g_burn = TRUE;
            Sleep(250);

            printf("  -> Burst %d/%d: Quiescent pause (350ms OFF)...\n", i + 1, iterations);
            g_burn = FALSE;
            Sleep(350);
        }
    }

    /* Terminate burn threads */
    for (DWORD i = 0; i < thread_count; ++i) {
        TerminateThread(threads[i], 0);
        CloseHandle(threads[i]);
    }
    free(threads);

    printf("\n[CPU Pattern Probe] Completed execution successfully.\n");
    printf("=======================================================\n\n");
    return 0;
}
