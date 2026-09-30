# WinGuard: Adaptive OS-Level Process Isolation for Windows

Windows already provides solid low-level security primitives—Job Objects, Restricted Tokens, Low Mandatory Integrity labels, and NTFS ACLs. But traditional sandboxes treat isolation as an all-or-nothing switch: either a process runs with normal user permissions, or it's locked down with hard, static limits from the millisecond it starts.

Static sandboxes create a real dilemma. If you clamp limits too tight from the start, legitimate workloads (like compilers, installers, or video decoders) get choked during heavy startup bursts or fail altogether. If you loosen limits to make room for bursty behavior, an attacker has plenty of headroom to hog CPU cores, thrash memory, or spawn fork bombs.

**WinGuard** takes a different approach: **adaptive security**. It's a native Windows framework written in C (Win32 API) that translates declarative policies into kernel security mechanisms, continuously monitors process behavior at runtime, and dynamically tightens or relaxes isolation using a bidirectional state machine.

---

## How It Works

### 1. Race-Condition-Free Process Launching
When launching an untrusted binary, there is a classic race condition: if the process begins executing before the supervisor attaches limits, a fast fork bomb or network probe can escape containment in the first few milliseconds.

WinGuard eliminates this window completely:
1. The process is spawned with `CreateProcessAsUserW` (or `CreateProcessW`) using the `CREATE_SUSPENDED` flag.
2. The suspended process handle is immediately bound to a Windows Job Object with `AssignProcessToJobObject`.
3. Restricted token privileges and Low Integrity labels are applied.
4. Only after all kernel limits are active does WinGuard call `ResumeThread` on the primary thread.

### 2. Kernel-Enforced Isolation
WinGuard doesn't rely on fragile user-mode API hooking (which can be bypassed by direct `syscall` instructions). All containment is enforced directly inside the Windows NT kernel:
- **Windows Job Objects (`EJOB`)**: We configure `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` so that if the supervisor ever crashes or closes, the kernel instantly reaps all child processes (zero zombie processes). We enforce active process caps (excess forks are blocked by the kernel with error `1816`) and virtual memory commit caps (allocations exceeding quota fail at the `VirtualAlloc` boundary with error `1455`).
- **Hard CPU Rate Caps**: Using `JobObjectCpuRateControlInformation` with `JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP`, the kernel thread scheduler strictly caps CPU cycles to configured percentages—even when the rest of the system is completely idle.
- **Restricted Access Tokens**: Using `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)`, all administrative and sensitive privileges (like `SeDebugPrivilege` or `SeImpersonatePrivilege`) are permanently stripped. We also inject the `RESTRICTED_CODE` SID (`S-1-5-12`), which causes Windows access checks to require explicit grants to both the user and the restricted token.
- **Mandatory Integrity Control (MIC)**: We assign the process token a Low Integrity label (`S-1-16-4096`). Under the Windows Security Reference Monitor's `No-Write-Up` rule, the sandboxed process cannot write to user documents, system files, registry keys, or open handles to higher-integrity processes (preventing process injection or tampering with the supervisor).
- **Filesystem Workspace Isolation**: The sandbox filesystem environment (`sandbox/`) uses a custom SDDL security descriptor with a Low Integrity SACL (`S:(ML;OICI;NW;;;LW)`) and DACLs that grant write permissions only within designated scratchpad directories (`sandbox/output/`, `sandbox/temp/`).

### 3. High-Frequency Telemetry & Behavior Monitoring
An independent background thread samples process and job counters every 25ms:
- Combines `GetProcessTimes` kernel and user time deltas against high-resolution wall-clock ticks to calculate exact multi-core CPU utilization in real time.
- Queries committed memory and resident working set sizes via `GetProcessMemoryInfo` and Job Object accounting structures.
- Tracks concurrent active processes inside the job tree.
- Streams live telemetry to timestamped CSV files in `results/`.

### 4. The Adaptive State Machine (Escalation & Decay)
Processes begin in **LEVEL 0 (Observe)** with proportional quotas so benign initialization spikes aren't falsely throttled. If the behavior monitor detects anomalous spikes or repeated violations, the state machine steps up enforcement:

```
                  Untrusted Process Launch
                             │
                             ▼
                    ┌─────────────────┐
                    │     LEVEL 0     │  Baseline observation tier
                    │    (Observe)    │  Permissive quotas, startup headroom
                    └────────┬────────┘
                             │ Violation threshold reached (CPU spikes / fork attempts)
                             ▼
                    ┌─────────────────┐
                    │     LEVEL 1     │  First-tier containment
                    │  (Restricted)   │  CPU clamped to 35% hard cap, procs capped to 4,
                    └────────┬────────┘  priority dropped to BELOW_NORMAL
                             │ Repeated boundary pressure
                             ▼
                    ┌─────────────────┐
                    │     LEVEL 2     │  Severe containment
                    │   (Contained)   │  CPU clamped to 15% hard cap, procs capped to 2,
                    └────────┬────────┘  priority dropped to IDLE, EmptyWorkingSet() invoked
                             │ Critical / persistent violations
                             ▼
                    ┌─────────────────┐
                    │     LEVEL 3     │  Quarantine / Emergency Kill
                    │  (Terminated)   │  TerminateJobObject(0xC0000420)
                    └─────────────────┘
```

**Bi-directional Recovery (Time-Based Decay)**:  
Unlike static sandboxes that permanently lock down or abort, WinGuard can recover. If a process that was escalated to LEVEL 1 or 2 settles down and runs cleanly for a configured cooldown period (e.g., 1–5 seconds without violations), the engine demotes the isolation level (`LEVEL 2 -> LEVEL 1 -> LEVEL 0`) and expands its resource allocation again.

**Memory Eviction via `EmptyWorkingSet`**:  
When entering LEVEL 2, WinGuard invokes `K32EmptyWorkingSet()`. The Windows NT Memory Manager immediately flushes the process's resident physical pages back to pagefiles and standby lists. In our benchmarks, this instantly shrank physical RAM usage by **79.2%** (from ~50 MB to 10.5 MB) without terminating the process.

### 5. Policy Compiler & Adversarial Test Suite
- **Declarative Policies**: An INI-style parser compiles `.policy` files into strongly-typed C structures with semantic validation. Built-in profiles include `permissive.policy`, `strict.policy`, and `adaptive.policy`.
- **8 Targeted Adversarial Workloads**: We built self-contained attack binaries in `attacks/` to test every security boundary:
  1. `process_stress`: Recursive fork bomb (50x) &rarr; blocked by kernel active process quota (error 1816).
  2. `memory_stress`: 100+ MB virtual memory allocation &rarr; blocked by job memory commit limit (error 1455).
  3. `cpu_stress`: Multi-threaded infinite mathematical burn &rarr; throttled by job hard rate caps.
  4. `burst_cpu`: Intermittent bursts and creeping duty cycles &rarr; caught and clamped by adaptive FSM.
  5. `privilege_probe`: Privilege escalation & parent process handle opening &rarr; denied by stripped tokens and Low MIC.
  6. `filesystem_probe`: Unauthorized host writes & system directory tampering &rarr; denied by NTFS SACL / Low MIC.
  7. `adaptive_probe`: Multi-phase dynamic attack & cooldown &rarr; exercises multi-tier escalation and decay.
  8. `repeated_violation`: Multi-vector sustained pressure &rarr; triggers quarantine termination (`0xC0000420`).

Running `WinGuard.exe attack all` runs the complete suite sequentially and prints an automated containment matrix (100% containment across all 8 vectors).

---

## Empirical Benchmark Results

We evaluated identical dynamic workloads across three different security paradigms on native Windows 11 (x86_64, multi-core):

| Evaluation Metric | Permissive Baseline | Static Strict Sandbox | Adaptive WinGuard Sandbox |
|:---|:---:|:---:|:---:|
| **Applied Security Policy** | `policies\permissive.policy` | `policies\strict.policy` | `policies\adaptive_test.policy` |
| **Wall Clock Duration** | `2.11 s` | `2.11 s` | `2.09 s` |
| **Total User CPU Time** | `750 ms` | `765 ms` | `781 ms` |
| **Total Kernel CPU Time** | `78 ms` | `62 ms` | `31 ms` |
| **Peak CPU Utilization** | `14.44%` | `14.10%` | `15.31%` |
| **Average CPU Utilization** | `2.59%` | `2.48%` | `2.45%` |
| **Peak Committed Memory** | `50.63 MB` | `50.62 MB` | **`10.55 MB` (79.2% reduction)** |
| **Policy Violations Logged** | `0` | `0` | `5` |
| **Dynamic Escalations** | N/A (Static) | N/A (Static) | **`2`** |
| **Dynamic Decay Demotions** | N/A (Static) | N/A (Static) | **`1`** |
| **Mean Adaptation Latency** | N/A | N/A | **`281.0 ms`** |
| **Containment Enforcement** | `PERMITTED` | `CONTAINED [PASS]` | `ADAPTED [PASS]` |

**Key Takeaways:**
1. **Low Adaptation Latency**: From the onset of an unconstrained compute burst, the engine detected the anomaly and clamped the kernel scheduler rate within **281 ms**.
2. **Effective Memory Reclamation**: While static sandboxes allowed the process to keep 50 MB resident in RAM, WinGuard's working set trim stripped physical resident memory down to **10.55 MB** during containment.
3. **Graceful Decay**: After the attack phase subsided, the engine successfully demoted from LEVEL 2 to LEVEL 1, proving the state machine can recover rather than permanently hamstringing benign workloads.

---

## CLI Reference

```
Usage: WinGuard.exe <command> [options]

Commands:
  run <program> [args...] [--policy <name|file.policy>] [--process-limit <N>]
                          [--cpu-limit <pct>] [--memory-limit <MB>]
                          [--restricted] [--low-integrity]
                          [--monitor] [--monitor-interval <ms>] [--csv-out <path>]
                 Launch an untrusted target inside a sandboxed context.
                 Policies: permissive, strict, adaptive (or custom .policy file).

  benchmark      Run automated 3-way comparative benchmark (Permissive vs Strict vs Adaptive)
                 and export CSV & Markdown reports.

  experiment compare [workload] [--csv <path>] [--md <path>]
                 Run a comparative 3-way evaluation on any custom executable command.

  attack <name>  Execute controlled adversarial workloads against sandbox:
                 attack process    - Process exhaustion stress test (fork bomb)
                 attack memory     - Memory allocation stress test
                 attack cpu        - Multi-core continuous CPU burn
                 attack burst      - Intermittent CPU burst & creep pattern
                 attack privilege  - Privilege adjustment & process handle probe
                 attack filesystem - Host & sandbox filesystem boundary probe
                 attack adaptive   - Dynamic state escalation & decay probe
                 attack repeated   - Multi-vector repeated violation probe
                 attack all        - Run complete 8-vector evaluation matrix

  policy <subcmd> Policy compiler & inspection:
                 policy show [name|file] - Display compiled policy specification
                 policy compile <file>   - Parse and validate .policy file syntax

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

## Building & Running

### Requirements
- **OS**: Windows 10, Windows 11, or Windows Server (x86_64)
- **Compiler**: Clang (LLVM MinGW) or MSVC with C11 support
- **Libraries**: `kernel32`, `advapi32`, `psapi`

### Compile
Run the build script from the repository root:
```cmd
.\build.bat
```
This compiles `WinGuard.exe`, the test workloads, and all 8 adversarial binaries into `bin/`.

### Quick Start Examples

```cmd
# 1. Run the automated 3-way empirical benchmark suite
bin\WinGuard.exe benchmark

# 2. Run the complete adversarial security evaluation matrix
bin\WinGuard.exe attack all

# 3. Launch an untrusted program under adaptive isolation with live monitoring
bin\WinGuard.exe run bin\dummy_workload.exe --policy policies\adaptive.policy --monitor

# 4. Compare a custom workload across Permissive vs Strict vs Adaptive
bin\WinGuard.exe experiment compare "bin\burst_cpu.exe burst 2"

# 5. Inspect compiled security policy rules
bin\WinGuard.exe policy show policies\adaptive.policy
```

Generated benchmark reports and telemetry logs are written directly to `results/`:
- `results/benchmark_report.md`: Markdown comparison matrix and evaluation summary.
- `results/experiment_comparison.csv`: CSV comparison data across all tested paradigms.
- `results/telemetry_pid*.csv`: High-frequency delta telemetry streams.

---

## Detailed Technical Documentation

For deep technical details, kernel object breakdowns, threat models, and viva preparation, see the `docs/` directory:

- [**System Architecture & Subsystems** (`docs/architecture.md`)](docs/architecture.md): High-level architecture, component breakdown, process creation sequence, and FSM transition matrix.
- [**Windows Security Internals** (`docs/windows_internals.md`)](docs/windows_internals.md): Deep dive into `EJOB` structures, CPU rate hard caps, access tokens, `RESTRICTED_CODE`, Low MIC SACLs, SDDL, and `EmptyWorkingSet`.
- [**Security & Threat Model** (`docs/security_model.md`)](docs/security_model.md): Threat scope, adversary assumptions, trust boundaries, and attack vector defense matrix.
- [**Empirical Benchmarking & Performance Analysis** (`docs/experiments.md`)](docs/experiments.md): Evaluation methodology, metric breakdowns, adaptation latency, and trade-off analysis.
- [**Architectural Boundaries & Limitations** (`docs/limitations.md`)](docs/limitations.md): User-mode vs. kernel drivers, direct NT syscall evasion analysis, and future roadmap (ETW, Minifilter).
- [**Viva Voce Defense Guide & Q&A** (`docs/viva.md`)](docs/viva.md): 13 comprehensive questions and technical model answers for project presentation and defense.
