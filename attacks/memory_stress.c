#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_CHUNKS 512

int main(int argc, char* argv[]) {
    int target_mb = 200;
    int chunk_mb = 20;

    if (argc > 1) {
        target_mb = atoi(argv[1]);
        if (target_mb <= 0) target_mb = 200;
    }
    if (argc > 2) {
        chunk_mb = atoi(argv[2]);
        if (chunk_mb <= 0) chunk_mb = 20;
    }

    DWORD pid = GetCurrentProcessId();
    printf("   [Memory Stress] Parent PID %lu attempting to allocate %d MB in %d MB chunks...\n",
           pid, target_mb, chunk_mb);

    size_t chunk_bytes = (size_t)chunk_mb * 1024 * 1024;
    int num_chunks = target_mb / chunk_mb;
    if (num_chunks > MAX_CHUNKS) num_chunks = MAX_CHUNKS;

    void* chunks[MAX_CHUNKS] = {0};
    int allocated_chunks = 0;
    BOOL blocked = FALSE;

    for (int i = 0; i < num_chunks; i++) {
        printf("   [Memory Stress] Allocating chunk #%d (%d MB)... ", i + 1, chunk_mb);

        /*
         * VirtualAlloc with MEM_COMMIT | MEM_RESERVE.
         * The Windows Job Object directly intercepts commitment requests against
         * the process and job memory quotas.
         */
        void* ptr = VirtualAlloc(
            NULL,
            chunk_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (ptr) {
            /* Touch memory across each 4KB page to force physical memory commit */
            volatile char* p = (volatile char*)ptr;
            for (size_t offset = 0; offset < chunk_bytes; offset += 4096) {
                p[offset] = (char)(i & 0xFF);
            }

            chunks[allocated_chunks++] = ptr;
            printf("COMMITTED (Total: %d MB)\n", allocated_chunks * chunk_mb);
        } else {
            DWORD err = GetLastError();
            printf("BLOCKED / FAILED! Win32 Error %lu ", err);
            if (err == ERROR_NOT_ENOUGH_MEMORY || err == ERROR_COMMITMENT_LIMIT) {
                printf("(Quotas exceeded - Job Object memory limit enforced!)\n");
            } else {
                printf("\n");
            }
            blocked = TRUE;
            break;
        }

        Sleep(100);
    }

    printf("\n   [Memory Stress Summary]\n");
    printf("   Target Memory     : %d MB\n", target_mb);
    printf("   Committed Memory  : %d MB\n", allocated_chunks * chunk_mb);
    printf("   Quota Enforcement : %s\n", blocked ? "BLOCKED BY OS LIMIT" : "UNCONSTRAINED");

    /* Hold memory briefly so monitor/accounting can observe peak memory */
    Sleep(500);

    /* Free all allocated chunks */
    for (int i = 0; i < allocated_chunks; i++) {
        if (chunks[i]) {
            VirtualFree(chunks[i], 0, MEM_RELEASE);
        }
    }

    printf("   [Memory Stress] Memory released. Exiting.\n");
    return blocked ? 2 : 0;
}
