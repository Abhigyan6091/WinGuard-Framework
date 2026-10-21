#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define BUFFER_SIZE (1024 * 1024) /* 1 MB buffer */

static volatile BOOL g_running = TRUE;

static DWORD WINAPI compute_thread(LPVOID param) {
    (void)param;
    volatile double acc = 1.0001;
    while (g_running) {
        for (int i = 0; i < 50000; i++) {
            acc = acc * 1.0000001 + 0.0000001;
        }
    }
    return (DWORD)acc;
}

int main(int argc, char* argv[]) {
    int duration_sec = 3;
    if (argc > 1) {
        duration_sec = atoi(argv[1]);
        if (duration_sec <= 0) duration_sec = 3;
    }

    printf("[COMPILER SIMULATOR] Starting simulated build/simulation workload (PID %lu, Duration: %d s)...\n",
           GetCurrentProcessId(), duration_sec);

    /* Spawn compute worker threads */
    HANDLE hThread = CreateThread(NULL, 0, compute_thread, NULL, 0, NULL);

    /* Allocate buffer for active disk I/O generation */
    char* buffer = (char*)malloc(BUFFER_SIZE);
    if (!buffer) {
        g_running = FALSE;
        if (hThread) {
            WaitForSingleObject(hThread, 1000);
            CloseHandle(hThread);
        }
        return 1;
    }
    for (int i = 0; i < BUFFER_SIZE; i++) {
        buffer[i] = (char)(i & 0xFF);
    }

    /* Create temporary file in sandbox\\output or current directory */
    CreateDirectoryW(L"sandbox", NULL);
    CreateDirectoryW(L"sandbox\\output", NULL);
    const WCHAR* temp_filename = L"sandbox\\output\\compiler_io_temp.dat";

    HANDLE hFile = CreateFileW(
        temp_filename,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
        NULL
    );

    uint64_t total_bytes_written = 0;
    DWORD start_ms = GetTickCount();

    while ((GetTickCount() - start_ms) < (DWORD)(duration_sec * 1000)) {
        DWORD bytes_written = 0;
        if (hFile != INVALID_HANDLE_VALUE) {
            SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
            if (WriteFile(hFile, buffer, BUFFER_SIZE, &bytes_written, NULL)) {
                total_bytes_written += bytes_written;
                FlushFileBuffers(hFile);
            }
        }
        Sleep(50); /* Generates ~20 MB/s sustained productive I/O */
    }

    g_running = FALSE;
    if (hThread) {
        WaitForSingleObject(hThread, 2000);
        CloseHandle(hThread);
    }

    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
    free(buffer);

    double elapsed_s = (double)(GetTickCount() - start_ms) / 1000.0;
    double io_rate_mb_s = (elapsed_s > 0) ? ((double)total_bytes_written / (1024.0 * 1024.0)) / elapsed_s : 0.0;

    printf("[COMPILER SIMULATOR] Finished cleanly. Total I/O: %.2f MB (Rate: %.2f MB/s)\n",
           (double)total_bytes_written / (1024.0 * 1024.0), io_rate_mb_s);

    return 0;
}
