@echo off
setlocal

set "CLANG_PATH=C:\Users\Abhigyan Sharma\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260616-ucrt-x86_64\bin"
set "PATH=%CLANG_PATH%;%PATH%"

if not exist bin mkdir bin

echo [BUILD] Compiling WinGuard (Milestones 10 and 11 - Experiments and Benchmarking)...
clang -std=c11 -Wall -Wextra -Wpedantic -municode -mconsole -DUNICODE -D_UNICODE -Iinclude ^
    src/main.c src/process_manager.c src/job_manager.c src/token_manager.c src/fs_manager.c src/monitor.c src/adaptive_engine.c src/logger.c src/policy.c src/experiment.c ^
    -o bin/WinGuard.exe -lkernel32 -ladvapi32 -lpsapi

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] WinGuard compilation failed.
    exit /b %ERRORLEVEL%
)

echo [BUILD] Compiling test workload (dummy_workload.exe)...
clang -std=c11 -Wall -Wextra -mconsole -DUNICODE -D_UNICODE ^
    tests/dummy_workload.c -o bin/dummy_workload.exe -lkernel32

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] dummy_workload compilation failed.
    exit /b %ERRORLEVEL%
)

echo [BUILD] Compiling attack workload 1 (process_stress.exe)...
clang -std=c11 -Wall -Wextra -mconsole -DUNICODE -D_UNICODE ^
    attacks/process_stress.c -o bin/process_stress.exe -lkernel32

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] process_stress compilation failed.
    exit /b %ERRORLEVEL%
)

echo [BUILD] Compiling attack workload 2 (memory_stress.exe)...
clang -std=c11 -Wall -Wextra -mconsole -DUNICODE -D_UNICODE ^
    attacks/memory_stress.c -o bin/memory_stress.exe -lkernel32

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] memory_stress compilation failed.
    exit /b %ERRORLEVEL%
)

echo [BUILD] Compiling attack workload 3 (cpu_stress.exe)...
clang -std=c11 -Wall -Wextra -mconsole -DUNICODE -D_UNICODE ^
    attacks/cpu_stress.c -o bin/cpu_stress.exe -lkernel32

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] cpu_stress compilation failed.
    exit /b %ERRORLEVEL%
)

echo [BUILD] Compiling attack workload 4 (filesystem_probe.exe)...
clang -std=c11 -Wall -Wextra -mconsole -DUNICODE -D_UNICODE ^
    attacks/filesystem_probe.c -o bin/filesystem_probe.exe -lkernel32

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] filesystem_probe compilation failed.
    exit /b %ERRORLEVEL%
)

echo [BUILD] Compiling attack workload 5 (privilege_probe.exe)...
clang -std=c11 -Wall -Wextra -mconsole -DUNICODE -D_UNICODE ^
    attacks/privilege_probe.c -o bin/privilege_probe.exe -lkernel32 -ladvapi32

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] privilege_probe compilation failed.
    exit /b %ERRORLEVEL%
)

echo [BUILD] Compiling attack workload 6 (adaptive_probe.exe)...
clang -std=c11 -Wall -Wextra -mconsole -DUNICODE -D_UNICODE ^
    attacks/adaptive_probe.c -o bin/adaptive_probe.exe -lkernel32

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] adaptive_probe compilation failed.
    exit /b %ERRORLEVEL%
)

echo [BUILD] Compiling attack workload 7 (repeated_violation.exe)...
clang -std=c11 -Wall -Wextra -mconsole -DUNICODE -D_UNICODE ^
    attacks/repeated_violation.c -o bin/repeated_violation.exe -lkernel32 -ladvapi32

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] repeated_violation compilation failed.
    exit /b %ERRORLEVEL%
)

echo [BUILD] Compiling attack workload 8 (burst_cpu.exe)...
clang -std=c11 -Wall -Wextra -mconsole -DUNICODE -D_UNICODE ^
    attacks/burst_cpu.c -o bin/burst_cpu.exe -lkernel32

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] burst_cpu compilation failed.
    exit /b %ERRORLEVEL%
)

echo [BUILD] Compiling workload 9 (compiler_simulator.exe)...
clang -std=c11 -Wall -Wextra -mconsole -DUNICODE -D_UNICODE ^
    attacks/compiler_simulator.c -o bin/compiler_simulator.exe -lkernel32

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] compiler_simulator compilation failed.
    exit /b %ERRORLEVEL%
)

echo [BUILD] Compiling workload 10 (rogue_worker_bomb.exe)...
clang -std=c11 -Wall -Wextra -mconsole -DUNICODE -D_UNICODE ^
    attacks/rogue_worker_bomb.c -o bin/rogue_worker_bomb.exe -lkernel32

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] rogue_worker_bomb compilation failed.
    exit /b %ERRORLEVEL%
)

echo [BUILD] Compiling workload 11 (allocation_acceleration.exe)...
clang -std=c11 -Wall -Wextra -mconsole -DUNICODE -D_UNICODE ^
    attacks/allocation_acceleration.c -o bin/allocation_acceleration.exe -lkernel32

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] allocation_acceleration compilation failed.
    exit /b %ERRORLEVEL%
)

echo [BUILD] Build successful! All binaries created in .\bin\
exit /b 0
