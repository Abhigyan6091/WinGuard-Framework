#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct {
    volatile BOOL* running;
    DWORD thread_id;
    uint64_t iterations;
} WorkerContext;

DWORD WINAPI worker_thread_proc(LPVOID lpParam) {
    WorkerContext* ctx = (WorkerContext*)lpParam;
    volatile double accumulator = 1.0001;
    uint64_t count = 0;

    while (*(ctx->running)) {
        for (int i = 0; i < 50000; i++) {
            accumulator = accumulator * 1.0000001 + 0.0000001;
        }
        count += 50000;
    }

    ctx->iterations = count;
    return (DWORD)accumulator;
}

int main(int argc, char* argv[]) {
    int duration_sec = 2;
    int thread_count = 2;

    if (argc > 1) {
        duration_sec = atoi(argv[1]);
        if (duration_sec <= 0) duration_sec = 2;
    }
    if (argc > 2) {
        thread_count = atoi(argv[2]);
        if (thread_count <= 0) thread_count = 2;
        if (thread_count > 16) thread_count = 16;
    }

    DWORD pid = GetCurrentProcessId();
    printf("   [CPU Stress] PID %lu initiating continuous CPU pressure (%d threads, %d seconds)...\n",
           pid, thread_count, duration_sec);

    volatile BOOL running = TRUE;
    HANDLE threads[16];
    WorkerContext contexts[16];

    for (int i = 0; i < thread_count; i++) {
        contexts[i].running = &running;
        contexts[i].iterations = 0;
        threads[i] = CreateThread(
            NULL,
            0,
            worker_thread_proc,
            &contexts[i],
            0,
            &contexts[i].thread_id
        );
    }

    DWORD start_tick = GetTickCount();
    Sleep(duration_sec * 1000);
    running = FALSE;
    DWORD elapsed_wall_ms = GetTickCount() - start_tick;

    WaitForMultipleObjects(thread_count, threads, TRUE, 5000);

    for (int i = 0; i < thread_count; i++) {
        CloseHandle(threads[i]);
    }

    /* Query process CPU times */
    FILETIME creation, exit_t, kernel_t, user_t;
    ULARGE_INTEGER ktime, utime;
    ZeroMemory(&ktime, sizeof(ktime));
    ZeroMemory(&utime, sizeof(utime));

    if (GetProcessTimes(GetCurrentProcess(), &creation, &exit_t, &kernel_t, &user_t)) {
        ktime.LowPart = kernel_t.dwLowDateTime;
        ktime.HighPart = kernel_t.dwHighDateTime;
        utime.LowPart = user_t.dwLowDateTime;
        utime.HighPart = user_t.dwHighDateTime;
    }

    uint64_t cpu_kernel_ms = ktime.QuadPart / 10000ULL;
    uint64_t cpu_user_ms = utime.QuadPart / 10000ULL;
    uint64_t total_cpu_ms = cpu_kernel_ms + cpu_user_ms;

    printf("\n   [CPU Stress Summary]\n");
    printf("   Elapsed Wall-Clock Time : %lu ms\n", elapsed_wall_ms);
    printf("   Consumed CPU Kernel Time: %llu ms\n", (unsigned long long)cpu_kernel_ms);
    printf("   Consumed CPU User Time  : %llu ms\n", (unsigned long long)cpu_user_ms);
    printf("   Total CPU Time Consumed : %llu ms\n", (unsigned long long)total_cpu_ms);

    if (elapsed_wall_ms > 0) {
        double effective_cpu_pct = ((double)total_cpu_ms / (double)elapsed_wall_ms) * 100.0;
        printf("   Effective CPU Rate      : %.1f%% of a single core\n", effective_cpu_pct);
    }

    printf("   [CPU Stress] Finished cleanly.\n");
    return 0;
}
