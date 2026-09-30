#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    int duration_sec = 2;
    if (argc > 1) {
        duration_sec = atoi(argv[1]);
        if (duration_sec <= 0) duration_sec = 2;
    }

    DWORD pid = GetCurrentProcessId();
    printf("   [Workload] Hello from target workload! (PID: %lu)\n", pid);
    printf("   [Workload] Simulating computational workload for %d second(s)...\n", duration_sec);

    /* Burn some CPU cycles to produce measurable user/kernel CPU time */
    volatile double dummy = 0.0;
    DWORD start = GetTickCount();
    while ((GetTickCount() - start) < (DWORD)(duration_sec * 1000)) {
        for (int i = 0; i < 100000; i++) {
            dummy += i * 0.001;
        }
        Sleep(50);
    }

    printf("   [Workload] Work completed (accumulated dummy: %f). Exiting cleanly.\n", dummy);
    return 0;
}
