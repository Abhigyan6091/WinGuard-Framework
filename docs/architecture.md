# WinGuard System Architecture & Design Specification

## 1. Executive Summary

**WinGuard** is an adaptive, operating-system-level process isolation, behavior monitoring, and adversarial security evaluation framework designed natively for Microsoft Windows (x86_64, Windows 10/11/Server). Developed in standard C (C11) using the native Win32 Unicode API (`...W`), WinGuard translates declarative high-level security policies into kernel-enforced isolation primitives, continuously monitors runtime telemetry at high frequency, and dynamically adjusts security boundaries through a formal finite state machine (FSM).

Unlike static isolation containers or sandbox solutions that enforce invariant, rigid boundaries, WinGuard addresses the fundamental trade-off between **process capability** and **system safety**:
- Processes begin execution with proportional privileges and resource quotas.
- Real-time kernel telemetry detects resource spikes, fork bombs, and quota strains.
- An adaptive state engine escalates containment tiers dynamically, applying hard CPU clamps, priority demotions, and working-set trims.
- In the absence of malicious patterns, a time-based decay relaxation mechanism safely de-escalates containment.

---

## 2. Architectural Blueprint

```
+-----------------------------------------------------------------------------------+
|                                  USER / CLI                                       |
|               (WinGuard.exe run / attack / experiment / benchmark)                |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                               POLICY COMPILER                                     |
|    Parses declarative *.policy specifications into compiled PolicyConfig struct    |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                             PROCESS MANAGER (pm)                                  |
|  - CreateRestrictedToken() [Disable max privs, drop admin SIDs, add RESTRICTED]   |
|  - SetTokenInformation() [Assign Low Mandatory Integrity Label (S-1-16-4096)]    |
|  - CreateProcessAsUserW(..., CREATE_SUSPENDED)                                   |
|  - AssignProcessToJobObject() -> Prevent race window                             |
|  - ResumeThread()                                                                 |
+-----------------------------------------------------------------------------------+
             |                                                  |
             v                                                  v
+-------------------------------+             +-------------------------------------+
|      JOB MANAGER (jm)         |             |        FILESYSTEM MANAGER (fs)      |
| - Process Count Hard Limits   |             | - Sandbox Root Isolation (sandbox/) |
| - Hard CPU Rate Caps (1-100%) |             | - DACL: SYSTEM, Admins, Restricted  |
| - Commit & Process RAM Limits |             | - SACL: Low Integrity Mandatory NW  |
| - Kill-on-Job-Close Flag      |             +-------------------------------------+
+-------------------------------+
             ^
             | (Dynamic Reconfiguration)
+-----------------------------------------------------------------------------------+
|                            ADAPTIVE STATE ENGINE                                  |
|                                                                                   |
|    +-------------------+   Violation Threshold   +---------------------+          |
|    | LEVEL 0 (OBSERVE) | ----------------------> | LEVEL 1 (RESTRICTED)|          |
|    +-------------------+                         +---------------------+          |
|              ^                                              |                     |
|              | Decayed Quiescence                           | Violation Threshold |
|              | (Decay Timer Expired)                        v                     |
|    +-------------------+   Violation Threshold   +---------------------+          |
|    |      TERMINATE    | <---------------------- | LEVEL 2 (CONTAINED) |          |
|    |   (0xC0000420)    |                         +---------------------+          |
|    +-------------------+                                                          |
+-----------------------------------------------------------------------------------+
             ^
             | Telemetry Feed (Violations, CPU %, Working Set, Process Count)
+-----------------------------------------------------------------------------------+
|                           BEHAVIOR MONITOR (Thread)                               |
|  - High-frequency delta sampling (25-50ms)                                       |
|  - GetProcessTimes() & delta wall clock -> Live multi-core CPU %                 |
|  - GetProcessMemoryInfo() -> Private Commit & Working Set                        |
|  - QueryInformationJobObject() -> Active process count & kernel accounting       |
|  - CSV telemetry stream writer (`results/telemetry_pid<PID>_<TIME>.csv`)          |
+-----------------------------------------------------------------------------------+
```

---

## 3. Subsystem Breakdown

### 3.1 Policy Compiler (`src/policy.c`, `include/policy.h`)
- **Responsibility**: Parses declarative `.policy` plain-text configuration files or built-in templates (`permissive`, `strict`, `adaptive`).
- **Data Model**: Generates a strongly typed `PolicyConfig` struct storing:
  - Base quotas: `process_limit`, `memory_limit_bytes`, `cpu_limit_percent`, `cpu_hard_cap`.
  - Token flags: `use_restricted_token`, `integrity_level`.
  - State machine parameters: `initial_level`, `violation_threshold`, `decay_time_seconds`, `escalation_action`.
- **Validation**: Enforces syntactic and boundary validation (e.g., CPU limits must be between 1% and 100%, memory must not be zero).

### 3.2 Process Lifecycle Manager (`src/process_manager.c`, `include/process_manager.h`)
- **Race Condition Immunity**:
  1. The target binary is created using `CreateProcessAsUserW` (or `CreateProcessW`) with the `CREATE_SUSPENDED` creation flag.
  2. The process handle is assigned to the Windows Job Object *before* a single instruction of untrusted code executes:
     $$\text{CreateProcess(CREATE\_SUSPENDED)} \longrightarrow \text{AssignProcessToJobObject()} \longrightarrow \text{ResumeThread()}$$
  3. This completely prevents the classic "fork-race" where a target process forks malicious child processes before the supervisor can bind resource constraints.
- **Context Tracking**: Each isolated instance maintains a thread-safe `ProcessContext` holding handles, PIDs, policy parameters, and exit states.

### 3.3 Windows Job Object Manager (`src/job_manager.c`, `include/job_manager.h`)
- **Job Object Encapsulation**: A native Windows Job Object acts as a kernel-level resource boundary surrounding the process tree.
- **Limits Applied**:
  - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: Ensures that if the WinGuard supervisor exits or terminates unexpectedly, all child processes are immediately reaped by the kernel.
  - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`: Enforces a hard limit on concurrent running processes in the job.
  - `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`: Sets `ProcessMemoryLimit` and `JobMemoryLimit`.
  - `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION`: Sets `JOB_OBJECT_CPU_RATE_CONTROL_ENABLE` and `JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP` with `CpuRate` expressed in basis units ($1\% = 100$).

### 3.4 Access Token & Integrity Subsystem (`src/token_manager.c`, `include/token_manager.h`)
- **Restricted Access Token**: Uses `CreateRestrictedToken` with:
  - `DISABLE_MAX_PRIVILEGE`: Strips all administrative and dangerous privileges (e.g., `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, `SeBackupPrivilege`).
  - `Restricted SIDs`: Injects the `RESTRICTED_CODE` SID (`S-1-5-12`), causing standard ACL access checks to require both user membership and restricted SID membership.
- **Mandatory Integrity Control (MIC)**:
  - Constructs a `TOKEN_MANDATORY_LABEL` with SID `S-1-16-4096` (`SECURITY_MANDATORY_LOW_RID`).
  - Calls `SetTokenInformation(TokenIntegrityLevel)` to demote the token from Medium to Low integrity.
  - Under Windows MIC semantics, Low Integrity processes cannot write to Medium/High Integrity resources (No-Write-Up).

### 3.5 Isolated Filesystem Subsystem (`src/fs_manager.c`, `include/fs_manager.h`)
- **Workspace Layout**: Creates an isolated sandbox environment under `sandbox\`:
  - `sandbox\workspace\`: Target read/write scratchpad.
  - `sandbox\readonly\`: Target read-only reference data.
  - `sandbox\temp\`: Isolated scratch directory.
- **Security Descriptor Configuration**:
  - Injects a **Mandatory Label SACL**: `S:(ML;OICI;NW;;;LW)` (No-Write-Up for Low Integrity callers with container and object inheritance).
  - Configures an explicit **DACL**: Grants full control to `SYSTEM` and `Administrators`, and grants read/write permissions specifically to `Restricted Code` (`S-1-5-12`).

### 3.6 Behavior Monitoring & Telemetry Subsystem (`src/monitor.c`, `include/monitor.h`)
- **High-Frequency Background Thread**: Executes independently of the target process using `CreateThread`.
- **Delta CPU Computation**:
  $$\text{CPU \%} = \frac{\Delta \text{KernelTime} + \Delta \text{UserTime}}{\Delta \text{WallClockTime} \times \text{NumberOfProcessors}} \times 100\%$$
- **Telemetry Stream**: Outputs continuous real-time execution statistics to CSV:
  `timestamp_ms, elapsed_sec, cpu_percent, memory_bytes, memory_mb, active_processes, violation_flag`
- **Dynamic Dispatch**: Signals the Adaptive Engine whenever an active metric exceeds configured policy limits.

### 3.7 Adaptive State Machine Engine (`src/adaptive_engine.c`, `include/adaptive_engine.h`)
- **Finite State Machine (FSM)**:
  - **LEVEL 0 (OBSERVE)**: Baseline observation tier. Permissive quotas to prevent false-positive throttling on initialization bursts.
  - **LEVEL 1 (RESTRICTED)**: First-stage containment. CPU clamped to 35% hard cap, active process limit clamped to 4, priority dropped to `BELOW_NORMAL_PRIORITY_CLASS`.
  - **LEVEL 2 (CONTAINED)**: Severe containment. CPU clamped to 15% hard cap, active process limit clamped to 2, priority dropped to `IDLE_PRIORITY_CLASS`, working set flushed via `EmptyWorkingSet`.
  - **LEVEL 3 (TERMINATE / QUARANTINE)**: Immediate emergency kill via `TerminateJobObject(hJob, 0xC0000420)`.
- **Time-Based Decay Demotion**: Tracks quiescent elapsed time. If a process remains free of violations for `decay_time_seconds`, the engine steps the state down (`LEVEL 2 -> LEVEL 1 -> LEVEL 0`), restoring operational capacity.

---

## 4. Data Flow Matrix

| Event | Source Subsystem | Destination Subsystem | Mechanism |
|:---|:---|:---|:---|
| **Process Launch** | Process Manager | Kernel Executive | `CreateProcessAsUserW` (`CREATE_SUSPENDED`) |
| **Sandbox Enclosure** | Job Manager | Kernel Executive | `AssignProcessToJobObject` |
| **Telemetry Polling** | Behavior Monitor | Kernel Executive | `GetProcessTimes`, `GetProcessMemoryInfo`, `QueryInformationJobObject` |
| **Violation Event** | Behavior Monitor | Adaptive Engine | Callback / Direct Dispatch |
| **State Escalation** | Adaptive Engine | Job Manager / Process | `SetInformationJobObject`, `SetPriorityClass`, `EmptyWorkingSet` |
| **Emergency Kill** | Adaptive Engine | Kernel Executive | `TerminateJobObject(hJob, 0xC0000420)` |
| **Telemetry Export** | Behavior Monitor | Filesystem | Structured CSV Streaming (`results/`) |
| **Comparative Benchmark** | Experiment Runner | Console / Markdown / CSV | 3-way multi-paradigm test execution |
