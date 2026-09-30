# WinGuard: Adaptive OS-Level Process Isolation & Evaluation Framework

> **Important Disclaimer**: Windows already provides many of the underlying OS security primitives. WinGuard does not claim to replace Windows Sandbox or commercial endpoint security products. The project's contribution is an experimental framework for composing these primitives into adaptive policies and measuring their security and performance behavior under controlled adversarial workloads.

---

## 1. Project Vision & Research Question
Can adaptive composition of Windows OS security primitives provide stronger resistance to adversarial process behavior while avoiding the overhead of applying maximum restrictions to every process from the beginning?

WinGuard investigates:
- **Overhead**: Does dynamic escalation reduce CPU/memory latency for benign workloads?
- **Responsiveness**: How quickly do policy transitions respond to burst vs. slow attacks?
- **Trade-offs**: What security guarantees are retained or lost across isolation levels?

---

## 2. Adaptive Security State Machine
Every sandboxed process is governed by a state machine:

```
                         Process Starts
                               |
                               v
                       +----------------+
                       |   LEVEL 0      |  (Observe / Permissive)
                       +-------+--------+
                               | suspicious behavior
                               v
                       +----------------+
                       |   LEVEL 1      |  (Restricted)
                       +-------+--------+
                               | repeated violations
                               v
                       +----------------+
                       |   LEVEL 2      |  (Contained)
                       +-------+--------+
                               | critical violation
                               v
                       +----------------+
                       |   LEVEL 3      |  (Quarantined / Terminate)
                       +-------+--------+
```

---

## 3. Milestones Overview

### Milestone 1: Process Manager & Lifecycle Subsystem (Complete)
- **Win32 Process Creation**: Explicit invocation of [`CreateProcessW`](file:///include/process_manager.h) without leaking parent handles (`bInheritHandles = FALSE`).
- **Context Tracking**: Process ID (`PID`), Primary Thread ID (`TID`), process and thread handles, creation timestamps (`FILETIME` to `SYSTEMTIME`), security level, and policy binding.
- **Resource Monitoring**: Process CPU user/kernel execution time tracking via `GetProcessTimes`.
- **Handle Lifecycle Management**: Guaranteed handle cleanup (`CloseHandle`) upon termination to eliminate handle leakage.
- **CLI Commands**:
  - `WinGuard.exe run <target> [args...] [--policy <name>]`: Launch workload under tracking.
  - `WinGuard.exe inspect <pid>`: Query execution state, exit code, and timestamps of a live or finished PID.
  - `WinGuard.exe monitor <pid>`: Synchronize and wait for process exit.
  - `WinGuard.exe kill <pid>`: Terminate process by PID.

### Milestone 2: Windows Job Objects & Process Limit Enforcement (Complete)
- **Job Object Subsystem**: [`include/job_manager.h`](file:///include/job_manager.h) and [`src/job_manager.c`](file:///src/job_manager.c) implementing:
  - `CreateJobObjectW`
  - `AssignProcessToJobObject`
  - `SetInformationJobObject` (`JOBOBJECT_EXTENDED_LIMIT_INFORMATION`)
  - `QueryInformationJobObject` (`JobObjectBasicAccountingInformation`, `JobObjectExtendedLimitInformation`)
  - `TerminateJobObject`
- **Atomic Sandbox Assignment**: Launches target processes with `CREATE_SUSPENDED`, binds to Job Object, sets limits, and resumes thread (`ResumeThread`) to eliminate race windows.
- **Process Exhaustion Defense**: Dynamic enforcement of `ActiveProcessLimit` (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS`). Excess child process creation is blocked at the kernel boundary with `ERROR_NOT_ENOUGH_QUOTA (1816)`.
- **Job Accounting**: Live tracking of peak memory usage, active processes, and aggregated kernel/user CPU times across all processes in the job.
- **Adversarial Workload 1**: [`attacks/process_stress.c`](file:///attacks/process_stress.c) simulating rapid child process spawning to test and verify boundary enforcement.
- **CLI Attack Command**: `WinGuard.exe attack process` runs the automated process stress experiment against strict job boundaries.

### Milestone 3: CPU & Memory Limits Subsystem (Complete)
- **Committed Memory Controls**:
  - `JOB_OBJECT_LIMIT_PROCESS_MEMORY` & `JOB_OBJECT_LIMIT_JOB_MEMORY` applied via `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`.
  - Kernel-level enforcement intercepting `VirtualAlloc` commits. Excess memory requests fail with `ERROR_COMMITMENT_LIMIT (1455)`.
- **CPU Rate Controls (Throttling)**:
  - `JobObjectCpuRateControlInformation` with `JOB_OBJECT_CPU_RATE_CONTROL_ENABLE` and `JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP`.
  - Configures hard CPU rate caps (`CpuRate = percent * 100`) preventing sandboxed workloads from hogging host CPU cores.
- **Adversarial Workloads 2 & 3**:
  - [`attacks/memory_stress.c`](file:///attacks/memory_stress.c): Aggressive memory allocation and page-touch stress test.
  - [`attacks/cpu_stress.c`](file:///attacks/cpu_stress.c): Multi-threaded mathematical spin-loop benchmarking wall-clock vs consumed CPU time.
- **CLI Options & Attack Commands**:
  - `WinGuard.exe run ... --cpu-limit <pct> --memory-limit <MB> --process-limit <N>`
  - `WinGuard.exe attack memory`
  - `WinGuard.exe attack cpu`

### Milestone 4: Windows Access Tokens & Restricted Token Subsystem (Complete)
- **Token Inspection**: [`include/token_manager.h`](file:///include/token_manager.h) and [`src/token_manager.c`](file:///src/token_manager.c) querying `OpenProcessToken`, `GetTokenInformation` (`TokenUser`, `TokenIntegrityLevel`, `TokenRestrictedSids`, `TokenPrivileges`).
- **Dynamic Privilege Audit**: Maps LUIDs dynamically via `LookupPrivilegeNameW` without hardcoding privilege names.
- **Restricted Token Creation**: Generates restricted primary tokens using `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` with `SECURITY_RESTRICTED_CODE_RID` (`S-1-5-12`).
- **Mandatory Integrity Control (MIC)**: Lowers token integrity to Low (`S-1-16-4096`) via `SetTokenInformation(TokenIntegrityLevel)` with `SECURITY_MANDATORY_LOW_RID`.
- **Sandboxed Process Launching**: Dispatches restricted workloads using `CreateProcessAsUserW`.
- **Adversarial Workload 5**: [`attacks/privilege_probe.c`](file:///attacks/privilege_probe.c) auditing held privileges and verifying denial of privilege adjustment, cross-process access, and system file modification.
- **CLI Options & Attack Commands**:
  - `WinGuard.exe run ... --restricted --low-integrity`
  - `WinGuard.exe attack privilege`

### Milestone 5: Filesystem Policy & Workspace Isolation Subsystem (Complete)
- **Filesystem Hierarchy**: [`include/fs_manager.h`](file:///include/fs_manager.h) and [`src/fs_manager.c`](file:///src/fs_manager.c) establishing:
  - `sandbox/input/`  (Read-only DACL for Everyone & Restricted Code)
  - `sandbox/output/` (Read-Write DACL + Low Mandatory Integrity Level SACL)
  - `sandbox/temp/`   (Read-Write DACL + Low Mandatory Integrity Level SACL)
- **Windows Security Boundary**: Employs Windows Mandatory Integrity Control (MIC) `No-Write-Up` rule via `SetNamedSecurityInfoW` (`S:(ML;OICI;NW;;;LW)`). Low Integrity processes are permitted to write only to labeled Low Integrity directories and are strictly blocked by the Windows kernel from modifying input files or writing outside the sandbox workspace.
- **Adversarial Workload 4**: [`attacks/filesystem_probe.c`](file:///attacks/filesystem_probe.c) verifying:
  - Authorized input read -> `SUCCESS`
  - Unauthorized input tampering -> `ACCESS_DENIED (Win32 Error 5)`
  - Permitted output write -> `SUCCESS`
  - Permitted temp write -> `SUCCESS`
  - Unauthorized workspace escape -> `ACCESS_DENIED (Win32 Error 5)`
- **CLI Options & Commands**:
  - `WinGuard.exe fs policy`
  - `WinGuard.exe fs init`
  - `WinGuard.exe attack filesystem`

### Milestone 6: Logging & Behavior Monitoring Subsystem (Complete)
- **High-Frequency Background Monitoring Thread**: [`include/monitor.h`](file:///include/monitor.h) and [`src/monitor.c`](file:///src/monitor.c) run an asynchronous worker thread (`CreateThread`) sampling kernel accounting and memory state at high frequency (default 25-50ms).
- **Behavioral Metrics Sampled**:
  - Wall-clock elapsed duration and high-resolution timestamps.
  - Active and total process counts inside the Job Object (`JobObjectBasicAccountingInformation`).
  - Kernel CPU and User CPU time (in 100ns units converted to ms).
  - Instantaneous CPU utilization percentage (`%`) calculated via delta CPU time normalized against system core count.
  - Peak committed memory and working set memory via `JobObjectExtendedLimitInformation` and `GetProcessMemoryInfo`.
  - Real-time policy threshold violations (`VIOLATION_PROCESS_LIMIT`, `VIOLATION_MEMORY_LIMIT`, `THROTTLED_CPU_LIMIT`).
- **Telemetry Streaming & Time-Series CSV Export**:
  - Auto-creates `results/` directory.
  - Streams samples to CSV: `sample_id,timestamp_ms,elapsed_sec,active_processes,total_processes,cpu_percent,kernel_time_ms,user_time_ms,peak_memory_mb,status`.
  - Automatic stream flush ensures zero data loss upon crash or termination.
- **Telemetry Summary & Real-Time Attachment**:
  - Clean aggregated summary table printed upon workload termination (duration, sample count, peak/avg CPU %, peak memory, max concurrent processes, violations).
  - Live console monitor attachment to any running PID via `WinGuard.exe monitor <pid>`.
- **CLI Options & Verification**:
  - `WinGuard.exe run ... --monitor [--monitor-interval <ms>] [--csv-out <path>]`
  - `WinGuard.exe monitor <pid> [--interval <ms>] [--csv <path>]`
  - Test suite: [`tests/test_milestone6.ps1`](file:///tests/test_milestone6.ps1)

### Milestone 7: Policy Parser & Policy Compiler Subsystem (Complete)
- **Declarative Policy Specification Format (`.policy`)**: Clean INI-style specification defining `[metadata]`, `[security]`, `[limits]`, `[token]`, `[filesystem]`, and `[adaptive]` configuration blocks.
- **Standard Policy Profiles**:
  - [`policies/permissive.policy`](file:///policies/permissive.policy): Baseline observation tier (LEVEL 0, 90% CPU, 1024 MB RAM, 50 processes, Medium MIC).
  - [`policies/strict.policy`](file:///policies/strict.policy): High containment tier (LEVEL 2, 25% CPU cap, 128 MB RAM, 5 processes, Low MIC, stripped token).
  - [`policies/adaptive.policy`](file:///policies/adaptive.policy): Dynamic tier (LEVEL 0 baseline, 50% CPU, 256 MB RAM, 10 processes, escalation thresholds, decay intervals).
- **Policy Compiler & Semantic Validator**:
  - [`include/policy.h`](file:///include/policy.h) & [`src/policy.c`](file:///src/policy.c): Line-by-line lexical parser and AST/struct compiler (`policy_parse_file`, `policy_validate`, `policy_load`).
  - Diagnostic error reporting with line numbers for syntax errors, unknown levels, or out-of-range bounds.
- **Dynamic File Policy Execution**:
  - Pass any custom file to `--policy <path.policy>`: compiled on the fly and mapped into native Windows Job Object, Token, and Integrity primitives.
- **CLI Options & Verification**:
  - `WinGuard.exe policy compile <file.policy>`
  - `WinGuard.exe policy show [name|file.policy]`
### Milestone 8: Adaptive State Machine Engine (Complete)
- **Dynamic Security State Machine**: [`include/adaptive_engine.h`](file:///include/adaptive_engine.h) and [`src/adaptive_engine.c`](file:///src/adaptive_engine.c) implementing:
  - `LEVEL 0 (OBSERVE)`: Permissive observation, baseline Job quotas, normal priority.
  - `LEVEL 1 (RESTRICTED)`: First-tier containment, clamps CPU rate to 35% (HARD), limits process quota to 4, drops priority to `BELOW_NORMAL_PRIORITY_CLASS`.
  - `LEVEL 2 (CONTAINED)`: High containment, throttles CPU rate to 15% (HARD), limits process quota to 2, sets priority to `IDLE_PRIORITY_CLASS`, and invokes `EmptyWorkingSet()` to force working set memory eviction.
  - `LEVEL 3 (QUARANTINED)`: Maximum containment, throttles CPU to 5% (or terminates entire Job Object with `0xC0000420` if `auto_terminate_on_l3` is configured).
- **Bidirectional Dynamic Transitions**:
  - **Runtime Escalation**: Violation counters exceed configured `escalation_threshold` (e.g. CPU spikes, memory pressure, process quota exhaustion) -> dynamic escalation.
  - **Benign Time-Based Decay**: When a contained process behaves benignly without violations for `decay_interval_sec`, the engine demotes the security tier (e.g. `LEVEL 2 -> LEVEL 1 -> LEVEL 0`) and relaxes Job Object limits.
- **Decision Explainability & Full Audit Trail**:
  - Every state transition logged with timestamp, previous level, next level, trigger reason, and specific OS adjustments applied (`log_explain_decision`).
  - Aggregated audit trail printed upon workload exit.

### Milestone 9: Full Adversarial Workload Suite (Complete)
- **Comprehensive Adversarial Workload Suite (8 Self-Contained Test Workloads)**:
  1. [`attacks/process_stress.c`](file:///attacks/process_stress.c): Process exhaustion fork-bomb attack (contained by `ActiveProcessLimit`).
  2. [`attacks/memory_stress.c`](file:///attacks/memory_stress.c): Virtual memory commit exhaustion (contained by `JobMemoryLimit`).
  3. [`attacks/cpu_stress.c`](file:///attacks/cpu_stress.c): Multi-threaded continuous compute loop (throttled by `CpuRateControl`).
  4. [`attacks/burst_cpu.c`](file:///attacks/burst_cpu.c): Intermittent CPU burst & gradual creep duty-cycle patterns.
  5. [`attacks/privilege_probe.c`](file:///attacks/privilege_probe.c): Token privilege escalation and cross-process handle access probe (blocked by Restricted Token & Low MIC).
  6. [`attacks/filesystem_probe.c`](file:///attacks/filesystem_probe.c): Filesystem workspace isolation and sandbox escape probe (blocked by NTFS Low Mandatory SACL).
  7. [`attacks/adaptive_probe.c`](file:///attacks/adaptive_probe.c): Dynamic multi-phase escalation, containment, and benign decay probe.
  8. [`attacks/repeated_violation.c`](file:///attacks/repeated_violation.c): Sequential multi-vector stress probe challenging all sandbox vectors simultaneously.
- **Adversarial Security Evaluation Matrix**:
  - Automated suite runner `WinGuard.exe attack all` executes all 8 workloads sequentially, verifies kernel containment, and prints a structured evaluation matrix.
- **CLI Options & Verification**:
  - `WinGuard.exe attack <process|memory|cpu|burst|privilege|filesystem|adaptive|repeated|all>`
  - Test suite: [`tests/test_milestone9.ps1`](file:///tests/test_milestone9.ps1)

### Milestone 10 & 11: Comparative Experiments, Telemetry Analysis & Empirical Benchmark Subsystem (Complete)
- **3-Way Comparative Empirical Evaluator**: [`include/experiment.h`](file:///include/experiment.h) and [`src/experiment.c`](file:///src/experiment.c) execute identical workloads across:
  1. *Permissive Baseline*: Unconstrained execution baseline.
  2. *Static Strict Sandbox*: Rigid static isolation quotas.
  3. *Adaptive WinGuard Sandbox*: Multi-tier FSM with dynamic escalation and decay.
- **Automated Metric Instrumentation**:
  - Live wall-clock duration, total user and kernel CPU execution time (ms).
  - Peak and average CPU utilization (%).
  - Peak committed memory (MB) and physical working set reductions (`EmptyWorkingSet`).
  - Active process counts, logged policy violations, escalations, decay demotions.
  - Mean **Adaptation Latency** (ms) calculated from violation timestamp to kernel reconfiguration.
- **Dual Export Subsystem**:
  - **Structured CSV Export**: `results/experiment_comparison.csv` with machine-parseable schema.
  - **Comprehensive Markdown Export**: `results/benchmark_report.md` formatted with tables and empirical findings.
- **CLI Commands**:
  - `WinGuard.exe benchmark` (Automated 3-way evaluation with reports)
  - `WinGuard.exe experiment compare [workload] [--csv <path>] [--md <path>]`

### Milestone 12: Comprehensive Documentation & Viva Defense Guide (Complete)
- **Full Documentation Suite** in `docs/`:
  - [`docs/architecture.md`](file:///docs/architecture.md): System architecture, process lifecycle, race-condition immunity, and FSM transition matrix.
  - [`docs/windows_internals.md`](file:///docs/windows_internals.md): Deep-dive into Windows Job Objects (`EJOB`), Restricted Tokens, MIC (`S-1-16-4096`), SDDL, and Working Set paging.
  - [`docs/security_model.md`](file:///docs/security_model.md): Threat model, trust boundaries, adversary assumptions, and defense proofs.
  - [`docs/experiments.md`](file:///docs/experiments.md): Comprehensive empirical benchmark analysis, latency measurements, and static vs adaptive trade-offs.
  - [`docs/limitations.md`](file:///docs/limitations.md): User-mode supervisor boundaries, direct syscall evasion analysis, and kernel driver roadmap.
  - [`docs/viva.md`](file:///docs/viva.md): Complete Viva Voce technical examination defense guide with 13 in-depth questions and model answers.

---

## 4. Empirical Benchmark Results

Live results gathered directly by WinGuard on native Windows 11 (x86_64) running `WinGuard.exe benchmark`:

| Evaluation Metric | Permissive Baseline | Static Strict Sandbox | Adaptive WinGuard Sandbox |
|:---|:---:|:---:|:---:|
| **Applied Security Policy** | `policies\permissive.policy` | `policies\strict.policy` | `policies\adaptive_test.policy` |
| **Wall Clock Duration** | `2.11 s` | `2.11 s` | `2.09 s` |
| **Total User CPU Time** | `750 ms` | `765 ms` | `781 ms` |
| **Total Kernel CPU Time** | `78 ms` | `62 ms` | `31 ms` |
| **Peak CPU Utilization** | `14.44%` | `14.10%` | `15.31%` |
| **Average CPU Utilization** | `2.59%` | `2.48%` | `2.45%` |
| **Peak Committed Memory** | `50.63 MB` | `50.62 MB` | **`10.55 MB` (79.2% reduction)** |
| **Peak Concurrent Processes** | `1` | `1` | `1` |
| **Policy Violations Logged** | `0` | `0` | `5` |
| **Dynamic Escalations** | N/A (Static) | N/A (Static) | **`2`** |
| **Dynamic Decay Demotions** | N/A (Static) | N/A (Static) | **`1`** |
| **Mean Adaptation Latency** | N/A | N/A | **`281.0 ms`** |
| **Containment Enforcement** | `PERMITTED` | `CONTAINED [PASS]` | `ADAPTED [PASS]` |

---

## 5. Complete CLI Reference

```
Usage: WinGuard.exe <command> [options]

Commands:
  run <program> [args...] [--policy <name|file.policy>] [--process-limit <N>]
                          [--cpu-limit <pct>] [--memory-limit <MB>]
                          [--restricted] [--low-integrity]
                          [--monitor] [--monitor-interval <ms>] [--csv-out <path>]
                 Launch an untrusted target inside a sandboxed context.
                 Policies: permissive, strict, adaptive (or custom .policy file).

  experiment <subcmd> [workload] Comparative 3-way experiment (Permissive vs Strict vs Adaptive):
                 experiment compare [workload] [--csv <path>] [--md <path>]
                 Execute identical workload across all 3 security paradigms and compare.

  benchmark      Run automated empirical benchmarking suite with CSV & Markdown reports.

  policy <subcmd> Policy compiler & inspection:
                 policy show [name|file] - Display compiled policy specification
                 policy compile <file>   - Parse and validate .policy file syntax

  attack <name>  Execute controlled adversarial workloads against sandbox:
                 attack process    - Process exhaustion stress test
                 attack memory     - Memory exhaustion stress test
                 attack cpu        - CPU continuous exhaustion stress test
                 attack burst      - CPU burst and creep pattern probe
                 attack privilege  - Privilege & token boundary probe
                 attack filesystem - Filesystem workspace isolation probe
                 attack adaptive   - Dynamic state machine escalation & decay probe
                 attack repeated   - Multi-vector repeated boundary violation probe
                 attack all        - Execute complete test matrix across all workloads

  fs <subcmd>    Filesystem workspace utilities:
                 fs policy         - Display filesystem isolation policy
                 fs init           - Re-initialize sandbox/ directories & SACLs

  monitor <pid>  Attach live high-frequency telemetry monitor to running PID.
                 [--interval <ms>] [--csv <path>]

  inspect <pid>  Inspect a live or recently exited process context.

  kill <pid>     Terminate a process by its PID.

  help           Show usage and options guide.
```

---

## 6. Building and Running

### Build All Binaries
```cmd
.\build.bat
```

### Run Automated Verification Suites
```powershell
# Milestone 1: Process Lifecycle Tests
powershell -ExecutionPolicy Bypass -File tests\test_milestone1.ps1

# Milestone 2: Job Object & Process Limit Tests
powershell -ExecutionPolicy Bypass -File tests\test_milestone2.ps1

# Milestone 3: CPU & Memory Limits Tests
powershell -ExecutionPolicy Bypass -File tests\test_milestone3.ps1

# Milestone 4: Token & Privilege Probe Tests
powershell -ExecutionPolicy Bypass -File tests\test_milestone4.ps1

# Milestone 5: Filesystem Policy & Isolation Tests
powershell -ExecutionPolicy Bypass -File tests\test_milestone5.ps1

# Milestone 6: Behavior Monitoring & Telemetry Tests
powershell -ExecutionPolicy Bypass -File tests\test_milestone6.ps1

# Milestone 7: Policy Parser & Compiler Tests
powershell -ExecutionPolicy Bypass -File tests\test_milestone7.ps1

# Milestone 8: Adaptive State Machine & Decay Tests
powershell -ExecutionPolicy Bypass -File tests\test_milestone8.ps1

# Milestone 9: Complete Adversarial Workload Suite (8/8)
powershell -ExecutionPolicy Bypass -File tests\test_milestone9.ps1

# Milestones 10 & 11: Comparative Experiments & Benchmark Export Tests
powershell -ExecutionPolicy Bypass -File tests\test_milestone10.ps1
```

### Run Live Benchmarking & View Artifacts
```powershell
# Run 3-way empirical benchmark
.\bin\WinGuard.exe benchmark

# Inspect exported CSV and Markdown reports
Get-Content results\experiment_comparison.csv
Get-Content results\benchmark_report.md
```





