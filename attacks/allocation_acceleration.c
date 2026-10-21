#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    int total_mb = 180;
    int chunk_mb = 30;

    if (argc > 1) {
        total_mb = atoi(argv[1]);
        if (total_mb <= 0) total_mb = 180;
    }

    printf("\n=======================================================\n");
    printf(" [ALLOCATION ACCELERATION] Memory Velocity Bomb (PID %lu)\n", GetCurrentProcessId());
    printf(" Committing %d MB at ultra-high velocity (>150 MB/s)...\n", total_mb);
    printf("=======================================================\n");

    int chunks = total_mb / chunk_mb;
    size_t chunk_bytes = (size_t)chunk_mb * 1024 * 1024;
    void* ptrs[32] = {0};

    DWORD start_ms = GetTickCount();

    for (int i = 0; i < chunks && i < 32; ++i) {
        void* ptr = VirtualAlloc(NULL, chunk_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (ptr) {
            volatile char* p = (volatile char*)ptr;
            /* Touch 1 byte per page to force commit */
            for (size_t off = 0; off < chunk_bytes; off += 4096) {
                p[off] = (char)(i + 1);
            }
            ptrs[i] = ptr;
            printf("  -> Rapid burst commit: chunk %d/%d (%d MB committed)\n", i + 1, chunks, (i + 1) * chunk_mb);
        } else {
            printf("  -> VirtualAlloc blocked! Error: %lu\n", GetLastError());
            break;
        }
        Sleep(20); /* ~1500 MB/s theoretical burst rate */
    }

    DWORD elapsed_ms = GetTickCount() - start_ms;
    double elapsed_s = (elapsed_ms > 0) ? ((double)elapsed_ms / 1000.0) : 0.001;
    double velocity_mb_s = (double)total_mb / elapsed_s;

    printf("\n [ALLOCATION SUMMARY]\n");
    printf(" Elapsed Time       : %lu ms\n", elapsed_ms);
    printf(" Allocation Velocity: %.2f MB/s\n", velocity_mb_s);
    printf("=======================================================\n");

    /* Hold for a short duration so monitor samples velocity */
    Sleep(1000);

    for (int i = 0; i < chunks && i < 32; ++i) {
        if (ptrs[i]) VirtualFree(ptrs[i], 0, MEM_RELEASE);
    }

    return 0;
}
