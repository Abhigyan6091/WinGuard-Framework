#ifndef WINGUARD_LOGGER_H
#define WINGUARD_LOGGER_H

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_DECISION = 4
} LogLevel;

void log_init(void);
void log_set_verbose(BOOL verbose);
void log_write(LogLevel level, const char* format, ...);
void log_write_w(LogLevel level, const WCHAR* format, ...);
void log_explain_decision(DWORD pid, const char* transition, const char* reason, const char* action);

#define LOG_DEBUG(...) log_write(LOG_LEVEL_DEBUG, __VA_ARGS__)
#define LOG_INFO(...)  log_write(LOG_LEVEL_INFO, __VA_ARGS__)
#define LOG_WARN(...)  log_write(LOG_LEVEL_WARN, __VA_ARGS__)
#define LOG_ERROR(...) log_write(LOG_LEVEL_ERROR, __VA_ARGS__)
#define LOG_DECISION(...) log_write(LOG_LEVEL_DECISION, __VA_ARGS__)

#endif /* WINGUARD_LOGGER_H */
