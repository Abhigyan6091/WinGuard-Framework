# WinGuard Step-by-Step Usage & Operational Guide

This guide walks you through building, configuring, running, and evaluating the **WinGuard** framework on Windows 10/11.

---

## Table of Contents
1. [Prerequisites & Environment](#1-prerequisites--environment)
2. [Step 1: Compiling the Entire Project](#step-1-compiling-the-entire-project)
3. [Step 2: Initializing the Sandbox Workspace](#step-2-initializing-the-sandbox-workspace)
4. [Step 3: Running Untrusted Workloads (`run`)](#step-3-running-untrusted-workloads-run)
5. [Step 4: Working with Security Policies](#step-4-working-with-security-policies)
6. [Step 5: Running Adversarial Stress Tests (`attack`)](#step-5-running-adversarial-stress-tests-attack)
7. [Step 6: Empirical Benchmarking & Experiments](#step-6-empirical-benchmarking--experiments)
8. [Step 7: Live Process Inspection & Monitoring](#step-7-live-process-inspection--monitoring)
9. [Step 8: Post-Mortem Forensics & Crash Dumps](#step-8-post-mortem-forensics--crash-dumps)
10. [Step 9: Automated Test Suites](#step-9-automated-test-suites)
11. [Troubleshooting & Exit Codes](#troubleshooting--exit-codes)

---

## 1. Prerequisites & Environment

WinGuard uses standard C (C11) with native Windows Unicode APIs (`...W`). It requires no third-party runtimes or external dependencies.

- **Operating System**: Windows 10 (version 1809+), Windows 11, or Windows Server (x86_64).
- **Compiler**: Clang (LLVM MinGW or LLVM for Windows) or Microsoft Visual C++ (MSVC).
- **Shell**: Command Prompt (`cmd.exe`) or Windows PowerShell.

Verify your compiler is present in your PATH:
```cmd
clang --version
```
*(If using the Martin Störsjö LLVM-MinGW toolchain included via winget, `build.bat` already has the standard path configured).*

---

## 2. Step 1: Compiling the Entire Project

Clone the repository and run the build script from the project root:

```cmd
git clone https://github.com/Abhigyan6091/WinGuard-Framework.git
cd WinGuard-Framework
build.bat
```

The script compiles:
- `bin\WinGuard.exe`: The primary framework engine, CLI supervisor, and monitor.
- `bin\dummy_workload.exe`: Safe target program for testing execution and telemetry.
- `bin\*.exe`: All 11 adversarial and validation workloads:
  - `process_stress.exe`, `memory_stress.exe`, `cpu_stress.exe`, `burst_cpu.exe`
  - `privilege_probe.exe`, `filesystem_probe.exe`, `adaptive_probe.exe`, `repeated_violation.exe`
  - `compiler_simulator.exe`, `rogue_worker_bomb.exe`, `allocation_acceleration.exe`

All binaries are placed inside `bin\`.

---

## 3. Step 2: Initializing the Sandbox Workspace

Before running workloads that perform file operations, initialize the sandbox directory structure and Mandatory Integrity SACLs:

```cmd
bin\WinGuard.exe fs init
```

This command creates:
- `sandbox\input\`: Read-only input files for untrusted processes.
- `sandbox\output\`: Writable destination for process outputs.
- `sandbox\temp\`: Scratchpad directory.

It attaches a Windows Low Mandatory Integrity SACL (`S:(ML;OICI;NW;;;LW)`) and DACL so Low Integrity processes can only write within `sandbox\output` and `sandbox\temp`, completely blocking unauthorized host writes.

To inspect the filesystem policy at any time:
```cmd
bin\WinGuard.exe fs policy
```

---

## 4. Step 3: Running Untrusted Workloads (`run`)

The `run` command launches any executable inside an isolated Windows Job Object with optional restricted tokens, Low Integrity labels, and high-frequency telemetry.

### A. Basic Run with Default Policy
```cmd
bin\WinGuard.exe run bin\dummy_workload.exe
```

### B. Running with an Adaptive Policy and Telemetry Monitoring
```cmd
bin\WinGuard.exe run bin\dummy_workload.exe --policy adaptive --monitor
```
When `--monitor` is specified:
- An independent background thread polls process and Job Object counters every 25ms (configurable via `--monitor-interval <ms>`).
- Live telemetry is saved to `results\telemetry_pid<PID>_<TIMESTAMP>.csv`.
- The adaptive finite state machine (LEVEL 0 &rarr; LEVEL 1 &rarr; LEVEL 2 &rarr; LEVEL 3) actively responds to anomalies.

### C. Running Heavy Compute / Build Tasks Without False Clamping
For compilers, code generators, or scientific simulations:
```cmd
bin\WinGuard.exe run bin\compiler_simulator.exe 3 --policy compute_workload --monitor
```
Under `compute_workload.policy`, WinGuard correlates CPU spikes with active disk I/O throughput and host CPU contention, allowing productive builds to burst freely without false-positive throttling.

### D. Overriding Hard Quotas Directly from the CLI
You can override policy settings directly on the command line:
```cmd
bin\WinGuard.exe run bin\dummy_workload.exe --cpu-limit 30 --memory-limit 128 --process-limit 4 --restricted --low-integrity
```
- `--cpu-limit <pct>`: Sets hard CPU cap (1–100%) via kernel scheduler.
- `--memory-limit <MB>`: Sets maximum virtual memory commitment quota.
- `--process-limit <N>`: Sets maximum concurrent active processes in the job tree.
- `--restricted`: Drops administrative privileges and injects `RESTRICTED_CODE` SID.
- `--low-integrity`: Demotes token to Low Mandatory Integrity Level (`S-1-16-4096`).
- `--csv-out <path>`: Exports telemetry to a custom CSV path.

---

## 5. Step 4: Working with Security Policies

Policy files are written in declarative INI-style syntax inside `policies\`:

| Policy File | Intended Use Case |
|:---|:---|
| `policies\adaptive.policy` | General workloads starting in LEVEL 0 with dynamic escalation & decay. |
| `policies\strict.policy` | High-security lockdown: hard caps, Low Integrity, restricted token. |
| `policies\permissive.policy` | Baseline observation policy for benchmarking and profiling. |
| `policies\compute_workload.policy` | Heavy compute, build pipelines, and simulations with elastic rate control. |

### Display a Compiled Policy
```cmd
bin\WinGuard.exe policy show adaptive
bin\WinGuard.exe policy show policies\compute_workload.policy
```

### Validate Syntax of a Custom Policy
```cmd
bin\WinGuard.exe policy compile policies\adaptive.policy
```

---

## 6. Step 5: Running Adversarial Stress Tests (`attack`)

WinGuard includes self-contained adversarial workloads designed to stress every isolation boundary:

```cmd
# 1. Process exhaustion (fork bomb) -> Blocked by ActiveProcessLimit (error 1816)
bin\WinGuard.exe attack process

# 2. Virtual memory exhaustion -> Blocked by JobMemoryLimit (error 1455)
bin\WinGuard.exe attack memory

# 3. Sustained CPU burn -> Clamped by kernel CPU rate caps
bin\WinGuard.exe attack cpu

# 4. Intermittent bursts and creeping duty cycle -> Caught by adaptive state machine
bin\WinGuard.exe attack burst

# 5. Token privilege escalation & handle theft -> Blocked by Restricted Token & Low MIC
bin\WinGuard.exe attack privilege

# 6. Host filesystem write probe -> Blocked by NTFS SACL / No-Write-Up
bin\WinGuard.exe attack filesystem

# 7. Adaptive multi-tier escalation & recovery -> Demonstrates bi-directional decay
bin\WinGuard.exe attack adaptive

# 8. Sustained multi-vector attacks -> Triggers LEVEL 3 Quarantine (0xC0000420)
bin\WinGuard.exe attack repeated

# 9. Heavy compute + disk I/O -> Demonstrates multi-signal correlation (no false clamping)
bin\WinGuard.exe attack compiler

# 10. Multi-process memory triage -> Selectively terminates rogue child (0xC000012D)
bin\WinGuard.exe attack triage

# 11. Allocation acceleration bomb (>150 MB/s) -> Caught by velocity detector
bin\WinGuard.exe attack acceleration
```

### Run the Full Security Matrix (8/8)
```cmd
bin\WinGuard.exe attack all
```
This runs the core attack vectors sequentially and prints an automated containment matrix.

---

## 7. Step 6: Empirical Benchmarking & Experiments

To measure performance overhead, containment efficacy, and memory reclamation across security modes:

### Run the Standard 3-Way Benchmark
```cmd
bin\WinGuard.exe benchmark
```
This executes identical burst workloads across:
1. `permissive.policy` (unconstrained baseline)
2. `strict.policy` (static hard limits)
3. `adaptive.policy` (dynamic FSM)

The output is printed to the console and saved to:
- `results\benchmark_report.md`
- `results\experiment_comparison.csv`

### Compare Any Custom Workload
You can benchmark any arbitrary executable or command line across all three paradigms:
```cmd
bin\WinGuard.exe experiment compare "bin\burst_cpu.exe burst 3"
```

---

## 8. Step 7: Live Process Inspection & Monitoring

### Attach Live Telemetry to an Existing Process
```cmd
bin\WinGuard.exe monitor <PID> --interval 50 --csv results\attached_telemetry.csv
```
Samples CPU utilization, memory, and thread counts live from the console. Press `Ctrl+C` to detach.

### Inspect Process Context
```cmd
bin\WinGuard.exe inspect <PID>
```
Displays security token properties, user SID, integrity level, privileges, and Job Object limits.

### Terminate a Process
```cmd
bin\WinGuard.exe kill <PID>
```

---

## 9. Step 8: Post-Mortem Forensics & Crash Dumps

When an untrusted workload reaches `LEVEL_3_QUARANTINED` due to severe policy violations or memory acceleration attacks:
1. WinGuard suspends all threads using `NtSuspendProcess` to freeze the memory state cleanly.
2. It captures a diagnostic user-mode crash dump (`MiniDumpWriteDump`) to `results\crash_dumps\`.
3. It terminates the Job Object (`0xC0000420`).

To inspect a generated crash dump:
- Open `results\crash_dumps\minidump_pid<PID>_<TIMESTAMP>.dmp` in **Visual Studio** (`File -> Open -> File...` then click *Debug with Native Only*).
- Or load it into **WinDbg**:
  ```cmd
  windbg -z results\crash_dumps\minidump_pid<PID>_<TIMESTAMP>.dmp
  ```
  Run `!analyze -v` to inspect stack traces, committed memory regions, and threads at the exact moment of quarantine.

---

## 10. Step 9: Automated Test Suites

To verify all core features, upgraded algorithms, and state machines automatically:

```powershell
powershell -ExecutionPolicy Bypass -File tests\test_v2_upgrades.ps1
```

This script verifies:
1. **Phase 1**: Heavy compute workload with active I/O finishes cleanly without false-positive clamping.
2. **Phase 2**: Multi-process memory triage selectively terminates only the rogue child process while protecting the coordinator.
3. **Phase 3**: Rapid allocation bursts (>150 MB/s) trigger `ALLOCATION_ACCELERATION_BOMB`.
4. **Phase 4**: LEVEL 3 quarantine freezes the target and writes a valid `.dmp` file to `results\crash_dumps\`.

---

## 11. Troubleshooting & Exit Codes

| Exit Code / Status | Meaning | Explanation |
|:---|:---|:---|
| `0 (0x00000000)` | Success | Target executed cleanly and exited normally. |
| `1816 (ERROR_NOT_ENOUGH_QUOTA)` | Quota Exceeded | Attempted to spawn more processes than allowed by `ActiveProcessLimit`. |
| `1455 (ERROR_COMMITMENT_LIMIT)` | Out of Memory Quota | Attempted to commit more virtual memory than allowed by `JobMemoryLimit`. |
| `0xC0000420` | Sandbox Quarantine Kill | Process exceeded violation thresholds and was terminated by WinGuard's adaptive state machine. |
| `0xC000012D` | Selective Child Triage | A specific rogue child worker was terminated by graduated memory triage to protect the parent process. |
| `5 (ERROR_ACCESS_DENIED)` | Access Denied | A Low Integrity or Restricted Token process attempted an unauthorized write or privilege escalation. |

### Common Issues:
- **`clang: command not found`**: Ensure your LLVM / MinGW `bin` directory is added to your Windows system `PATH`, or run from a developer command prompt.
- **`Access Denied` on `fs init`**: Run your terminal with standard permissions for local user sandboxes, or run as Administrator if configuring system-wide root paths.
- **Antivirus heuristic warnings**: Some third-party AV scanners flag intentional stress tests (like fork bombs in `process_stress.exe`). Add an exclusion folder for `bin/` if testing locally.
