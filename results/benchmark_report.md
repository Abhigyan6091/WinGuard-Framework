# WinGuard Empirical Security & Performance Benchmark Report

**Evaluated Workload:** `bin\adaptive_probe.exe`  
**Evaluation Framework:** WinGuard Adaptive OS-Level Security Engine (C / Native Win32)  
**Sample Size:** N = 10 repeated benchmark trials per mode (Reported format: Mean +/- Standard Deviation)  

## 1. Comparative Performance & Security Matrix

| Evaluation Metric | Permissive Baseline (N=10) | Static Strict (N=10) | Adaptive WinGuard (N=10) |
|:---|:---:|:---:|:---:|
| **Policy Profile** | `policies\permissive.policy` | `policies\strict.policy` | `policies\adaptive_test.policy` |
| **Wall Clock Duration** | `2.16 +/- 0.01 s` | `0.90 +/- 0.05 s` | `2.14 +/- 0.02 s` |
| **User CPU Time** | `771 +/- 23.5 ms` | `734 +/- 40.2 ms` | `762 +/- 40.8 ms` |
| **Kernel CPU Time** | `65 +/- 23.1 ms` | `53 +/- 22.5 ms` | `46 +/- 26.5 ms` |
| **Peak CPU Utilization** | `15.54 +/- 1.55%` | `15.42 +/- 1.27%` | `14.77 +/- 1.00%` |
| **Average CPU Utilization** | `2.34 +/- 0.13%` | `7.87 +/- 0.45%` | `2.36 +/- 0.18%` |
| **Peak Committed Memory** | `50.62 +/- 0.00 MB` | `10.54 +/- 0.01 MB` | `10.54 +/- 0.00 MB` |
| **Concurrent Processes** | `1.0 +/- 0.0` | `1.0 +/- 0.0` | `1.0 +/- 0.0` |
| **Violations Logged** | `5.0 +/- 0.0` | `1.0 +/- 0.0` | `5.0 +/- 0.0` |
| **Dynamic Escalations** | N/A (Static) | N/A (Static) | `2.0 +/- 0.0` |
| **Dynamic Decay Demotions** | N/A (Static) | N/A (Static) | `1.0 +/- 0.0` |
| **Adaptation Latency** | N/A | N/A | `309.4 +/- 23.2 ms` |
| **Containment Status** | `PERMITTED` | `CONTAINED (QUARANTINED)` | `ADAPTED [PASS]` |

## 2. Key Empirical Findings & Analysis

1. **Static vs. Adaptive Trade-off**:
   - **Static Strict Sandbox**: Starts directly at LEVEL 2 (Contained) with Low MIC and stripped tokens. When the probe triggers an unconstrained CPU burst, the single-violation threshold (`escalation_threshold = 1`) immediately terminates the process at **0.90 s** via `TerminateJobObject(0xC0000420)`. While providing high containment, it forcibly terminates workloads that exhibit bursty initialization phases.
   - **Adaptive WinGuard Sandbox**: Starts in LEVEL 0 (Observe), allowing legitimate burst workloads to operate without artificial performance bottlenecks. Upon detecting anomalous patterns, it dynamically clamps Job Object rate limits and evicts working set memory within **309.4 ms** (mean adaptation latency) without terminating the process.
2. **Memory Containment & Working Set Eviction**:
   - Virtual memory commitment was constrained to **10.54 MB** by the Job Object commit quota (blocking the probe's attempt to commit 50 MB).
   - In LEVEL 2, `EmptyWorkingSet()` actively evicted the physical resident pages (Working Set) from physical RAM to pagefiles and standby lists.
3. **Bidirectional State Machine Recovery**:
   - Unlike static sandboxes which can never relax, WinGuard observed benign quiescent periods and executed **1.0 decay demotions**, restoring operational capacity.

## 3. Windows Kernel Primitives Utilized

- **Windows Job Objects**: `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION` (Hard rate caps), `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` (Process/Job memory limits), `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` (Fork containment).
- **Access Tokens & MIC**: `CreateRestrictedToken`, `SetTokenInformation` (Low Mandatory Integrity SACL).
- **NTFS Filesystem Isolation**: DACLs granting `Restricted Code` (`S-1-5-12`), Mandatory Label SACLs (`S:(ML;OICI;NW;;;LW)`).
- **Runtime Adaptation**: Dynamic calls to `SetInformationJobObject`, `SetPriorityClass`, and `EmptyWorkingSet`.

