#include "logger.h"
#include <stdarg.h>
#include <time.h>

static BOOL g_verbose = FALSE;

void log_init(void) {
    /* Set console to support colors if attached */
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(hOut, &mode)) {
            SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

void log_set_verbose(BOOL verbose) {
    g_verbose = verbose;
}

static void get_timestamp(char* buffer, size_t buf_len) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buffer, buf_len, "%02d:%02d:%02d.%03d",
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

void log_write(LogLevel level, const char* format, ...) {
    if (level == LOG_LEVEL_DEBUG && !g_verbose) {
        return;
    }

    char ts[32];
    get_timestamp(ts, sizeof(ts));

    const char* prefix = "";
    const char* color_code = "";
    const char* reset_code = "\x1b[0m";

    switch (level) {
        case LOG_LEVEL_DEBUG:
            prefix = "DEBUG";
            color_code = "\x1b[90m"; /* Gray */
            break;
        case LOG_LEVEL_INFO:
            prefix = "INFO ";
            color_code = "\x1b[36m"; /* Cyan */
            break;
        case LOG_LEVEL_WARN:
            prefix = "WARN ";
            color_code = "\x1b[33m"; /* Yellow */
            break;
        case LOG_LEVEL_ERROR:
            prefix = "ERROR";
            color_code = "\x1b[31m"; /* Red */
            break;
        case LOG_LEVEL_DECISION:
            prefix = "STATE";
            color_code = "\x1b[35m"; /* Magenta */
            break;
    }

    printf("%s[%s] [%s]%s ", color_code, ts, prefix, reset_code);

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
    fflush(stdout);
}

void log_write_w(LogLevel level, const WCHAR* format, ...) {
    if (level == LOG_LEVEL_DEBUG && !g_verbose) {
        return;
    }

    char ts[32];
    get_timestamp(ts, sizeof(ts));

    const char* prefix = "";
    switch (level) {
        case LOG_LEVEL_DEBUG: prefix = "DEBUG"; break;
        case LOG_LEVEL_INFO:  prefix = "INFO "; break;
        case LOG_LEVEL_WARN:  prefix = "WARN "; break;
        case LOG_LEVEL_ERROR: prefix = "ERROR"; break;
        case LOG_LEVEL_DECISION: prefix = "STATE"; break;
    }

    wprintf(L"[%hs] [%hs] ", ts, prefix);

    va_list args;
    va_start(args, format);
    vwprintf(format, args);
    va_end(args);

    wprintf(L"\n");
    fflush(stdout);
}

void log_explain_decision(DWORD pid, const char* transition, const char* reason, const char* action) {
    char ts[32];
    get_timestamp(ts, sizeof(ts));

    printf("\n\x1b[35m[EXPLAIN] [%s] PID %lu: %s\x1b[0m\n", ts, pid, transition);
    printf("          Reason : %s\n", reason);
    printf("          Action : %s\n\n", action);
    fflush(stdout);
}
