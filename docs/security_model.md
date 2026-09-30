# WinGuard Security & Threat Model

## 1. Scope & Adversary Assumptions

### 1.1 Target Threat
WinGuard isolates, confines, and evaluates **untrusted, hostile, or misbehaving user-mode executable binaries** executing on Microsoft Windows.

### 1.2 Adversary Capabilities
We assume an active adversary possessing arbitrary code execution within the isolated userland process. The adversary may attempt:
1. **Denial of Service (DoS) via Process Forking**: Rapidly spawning child processes (fork bomb) to exhaust kernel handle tables and thread dispatch tables.
2. **Resource Starvation via Memory Exhaustion**: Allocating gigabytes of virtual and physical RAM to induce paging thrash or out-of-memory crashes on the host.
3. **CPU Monopolization**: Spawning multi-threaded infinite compute loops or pulsing duty-cycle bursts to peg CPU cores at 100%.
4. **Privilege Escalation**: Attempting to acquire or activate privileged Windows rights (`SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, `SeAssignPrimaryTokenPrivilege`) to inspect, inject into, or manipulate other processes.
5. **Unauthorized Filesystem Modification**: Tampering with host files, user profiles, or system files (`C:\Windows\System32`, `C:\Users\...`) outside designated workspaces.
6. **Adaptive Boundary Evasion**: Timing attacks where malicious compute bursts are interspersed with quiescent periods to evade static monitors.

### 1.3 Out-of-Scope Threats (Explicit Boundaries)
- **Kernel-mode zero-day exploits**: Vulnerabilities in `ntoskrnl.exe` or third-party kernel drivers that allow ring-0 code execution.
- **Hardware-level microarchitectural attacks**: Meltdown, Spectre, or Rowhammer attacks exploiting physical hardware.
- **Physical host compromise**: Direct physical or DMA access to the target machine.

---

## 2. Trust Boundaries & Isolation Layers

```
+-----------------------------------------------------------------------------------+
|                            MEDIUM / HIGH INTEGRITY REALM                          |
|                                                                                   |
|   +---------------------------------------------------------------------------+   |
|   |                       WinGuard Supervisor Process                         |   |
|   |  - Full access to standard user/admin filesystem                          |   |
|   |  - Manages Windows Job Object handles                                     |   |
|   |  - Runs high-frequency behavior monitor and adaptive state engine          |   |
|   +---------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------+
                                         |
                       TRUST BOUNDARY (OS-Enforced Separation)
             - Process Isolation: Suspended initialization + Job enclosure
             - Token Isolation: DISABLE_MAX_PRIVILEGE + RESTRICTED_CODE SID
             - MIC Isolation: Low Integrity Label (S-1-16-4096)
             - Filesystem Isolation: Custom SDDL with Protected DACL + Low SACL
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                             LOW INTEGRITY SANDBOX REALM                           |
|                                                                                   |
|   +---------------------------------------------------------------------------+   |
|   |                        Target Untrusted Process                           |   |
|   |  - Stripped Access Token (Zero privileges)                                |   |
|   |  - Enclosed in Windows Job Object (Quota clamped)                         |   |
|   |  - Low Integrity SID (MIC blocks write access to Medium/High files)       |   |
|   |  - Can only write to sandbox\workspace\ and sandbox\temp\                 |   |
|   +---------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------+
```

---

## 3. Defense Mechanisms & Attack Vector Neutralization

| Attack Vector | Adversarial Workload | Exploitation Method | WinGuard Defensive Primitive | Outcome |
|:---|:---|:---|:---|:---|
| **Process Fork Exhaustion** | `bin\process_stress.exe` | Rapid recursive `CreateProcess` calls | `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` + Suspended job binding | **Contained**: `CreateProcess` returns error 1816 (`ERROR_NOT_ENOUGH_QUOTA`). |
| **Virtual Memory Exhaustion** | `bin\memory_stress.exe` | Allocating 100+ MB via `VirtualAlloc` | `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` (`ProcessMemoryLimit`) | **Contained**: `VirtualAlloc` fails with error 1455 (`ERROR_COMMITMENT_LIMIT`). |
| **Sustained CPU Exhaustion** | `bin\cpu_stress.exe` | Multi-threaded infinite mathematical burn | `JOBOBJECT_CPU_RATE_CONTROL_HARD_CAP` | **Throttled**: Kernel scheduler enforces hard CPU rate cap regardless of system idle time. |
| **Burst & Creep CPU** | `bin\burst_cpu.exe` | Oscillating CPU spikes | Adaptive FSM + Telemetry delta monitor | **Clamped**: Dynamic escalation clamps rate limits to 35% and 15%. |
| **Privilege Escalation** | `bin\privilege_probe.exe` | Calling `AdjustTokenPrivileges` for `SeDebugPrivilege` | `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` | **Denied**: Error 1300 (`ERROR_NOT_ALL_ASSIGNED`). Privileges are permanently removed. |
| **Inter-Process Tampering** | `bin\privilege_probe.exe` | Calling `OpenProcess(PROCESS_ALL_ACCESS)` on WinGuard | Low Integrity MIC + User Interface Privilege Isolation (UIPI) | **Denied**: Error 5 (`ERROR_ACCESS_DENIED`). Low integrity cannot open Medium integrity handle. |
| **Host Filesystem Write** | `bin\filesystem_probe.exe` | Writing to `C:\Windows\System32` or parent host files | Mandatory Label SACL (`S:(ML;OICI;NW;;;LW)`) + No-Write-Up | **Denied**: Error 5 (`ERROR_ACCESS_DENIED`). |
| **Sandbox Filesystem Write** | `bin\filesystem_probe.exe` | Writing to `sandbox\workspace\probe.txt` | Protected DACL granting `RESTRICTED_CODE` (`S-1-5-12`) | **Permitted**: Isolated workspace operations succeed cleanly. |
| **Repeated Multi-Vector Attacks** | `bin\repeated_violation.c` | Progressive memory allocations + CPU spikes | Multi-tier Adaptive State Machine | **Quarantined**: Escalates to LEVEL 1, then LEVEL 2, and terminates at LEVEL 3 via `TerminateJobObject(0xC0000420)`. |

---

## 4. Integrity Level Invariants

1. **No-Write-Up (`NW`) Guarantee**:
   Under Windows Security Reference Monitor rules, a process with a Low integrity token cannot open any object (file, registry key, process, desktop) for write or delete access if that object has an integrity level greater than Low, even if the DACL explicitly allows the user write permissions.
2. **Token Stripping Irreversibility**:
   In Windows NT security, privilege removal is **one-way**. Once privileges are removed via `CreateRestrictedToken`, no user-mode code can re-enable them. Only privileges that exist in the token in an *inactive* state can be enabled via `AdjustTokenPrivileges`. Stripped privileges do not exist in the token.
3. **Supervisor Tampering Immunity**:
   Because the WinGuard supervisor runs at Medium (or High) integrity and the child runs at Low integrity, the child cannot:
   - Call `OpenProcess` with `PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, or `PROCESS_SUSPEND_RESUME` on the supervisor.
   - Inject threads into the supervisor via `CreateRemoteThread`.
   - Send spoofed window messages (`SendMessage`, `PostMessage`) to the supervisor's message loop (UIPI).
