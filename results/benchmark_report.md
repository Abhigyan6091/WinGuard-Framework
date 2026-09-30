# WinGuard Empirical Security & Performance Benchmark Report

**Evaluated Workload:** `bin\adaptive_probe.exe`  
**Evaluation Framework:** WinGuard Adaptive OS-Level Security Engine (C / Native Win32)  

## 1. Comparative Performance & Security Matrix

| Evaluation Metric | Permissive Baseline | Static Strict | Adaptive WinGuard |
|:---|:---:|:---:|:---:|
| **Policy Profile** | `policies\permissive.policy` | `policies\strict.policy` | `policies\adaptive_test.policy` |
| **Wall Clock Duration** | `2.11 s` | `2.11 s` | `2.09 s` |
| **User CPU Time** | `750 ms` | `765 ms` | `781 ms` |
| **Kernel CPU Time** | `78 ms` | `62 ms` | `31 ms` |
| **Peak CPU Utilization** | `14.44%` | `14.10%` | `15.31%` |
| **Average CPU Utilization** | `2.59%` | `2.48%` | `2.45%` |
| **Peak Committed Memory** | `50.63 MB` | `50.62 MB` | `10.55 MB` |
| **Concurrent Processes** | `1` | `1` | `1` |
| **Violations Logged** | `0` | `0` | `5` |
| **Dynamic Escalations** | N/A (Static) | N/A (Static) | `2` |
| **Dynamic Decay Demotions** | N/A (Static) | N/A (Static) | `1` |
| **Adaptation Latency** | N/A | N/A | `281.0 ms` |
| **Containment Status** | `PERMITTED` | `CONTAINED [PASS]` | `ADAPTED [PASS]` |

## 2. Key Empirical Findings & Analysis

1. **Static vs. Adaptive Trade-off**:
   - **Static Strict Sandbox**: Enforces immediate hard limits (Low MIC, stripped tokens, 25% CPU cap). While providing high security, it imposes constant overhead on benign phases.
   - **Adaptive WinGuard Sandbox**: Starts in LEVEL 0 (Observe), allowing legitimate burst workloads to operate without artificial performance bottlenecks. Upon detecting anomalous patterns, it dynamically clamps Job Object rate limits and evicts working set memory within **281.0 ms** (adaptation latency).
2. **Bidirectional State Machine Recovery**:
   - Unlike static sandboxes which can never relax, WinGuard observed benign quiescent periods and executed **1 decay demotion(s)**, restoring higher performance once the threat passed.

## 3. Windows Kernel Primitives Utilized

- **Windows Job Objects**: `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION` (Hard rate caps), `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` (Process/Job memory limits), `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` (Fork containment).
- **Access Tokens & MIC**: `CreateRestrictedToken`, `SetTokenInformation` (Low Mandatory Integrity SACL).
- **NTFS Filesystem Isolation**: DACLs granting `Restricted Code` (`S-1-5-12`), Mandatory Label SACLs (`S:(ML;OICI;NW;;;LW)`).
- **Runtime Adaptation**: Dynamic calls to `SetInformationJobObject`, `SetPriorityClass`, and `EmptyWorkingSet`.

