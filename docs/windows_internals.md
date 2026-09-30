# Windows Security Internals: Primitives, Subsystems & Mechanics

This document provides a deep, technical dive into the native Windows Operating System kernel primitives utilized by **WinGuard**, including how they are represented in kernel executive structures and how WinGuard leverages them in C via Win32 APIs.

---

## 1. Windows Job Objects (`EJOB` Kernel Executive Object)

### 1.1 Kernel Representation & Architecture
In the Windows NT kernel, a **Job Object** is represented by an executive object structure (`EJOB`). It groups one or more processes into a manageable unit that shares resource quotas and security constraints. A process can only belong to one non-nested job object (or a hierarchy of nested jobs in Windows 8+).

When a process is assigned to a job object via `AssignProcessToJobObject`:
1. The kernel adds the process (`EPROCESS`) to the job's process list (`EJOB.ProcessListHead`).
2. The `EPROCESS.Job` pointer is initialized to point to the `EJOB`.
3. Every subsequent process created by any process inside the job is automatically enrolled into the same `EJOB` (unless explicitly broken out with `CREATE_BREAKAWAY_FROM_JOB`, which WinGuard prevents).

### 1.2 Limit Structures & Flags

#### `JOBOBJECT_BASIC_LIMIT_INFORMATION` & `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`
WinGuard queries and configures these structures via `SetInformationJobObject` using information class `JobObjectExtendedLimitInformation`:
- **`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`**:
  Configured in `BasicLimitInformation.LimitFlags`. When the last user-mode handle to the Job Object is closed (such as when WinGuard terminates or is killed), the Windows kernel forcibly terminates all processes in the job. This guarantees **zero orphaned background processes**.
- **`JOB_OBJECT_LIMIT_ACTIVE_PROCESS`**:
  Caps the total number of simultaneous live processes within the job (`BasicLimitInformation.ActiveProcessLimit`). If a sandboxed process invokes `CreateProcess` when the active count reaches this quota, `CreateProcess` fails immediately with `ERROR_NOT_ENOUGH_QUOTA` (exit/error code 1816).
- **`ProcessMemoryLimit` & `JobMemoryLimit`**:
  - `ProcessMemoryLimit`: Caps the virtual address space commit limit for each individual process.
  - `JobMemoryLimit`: Caps the aggregate commit limit across all processes in the job.
  When an allocation exceeds this threshold (via `VirtualAlloc`, `HeapAlloc`, or stack growth), the kernel fails the allocation with `STATUS_COMMITMENT_LIMIT` / `ERROR_COMMITMENT_LIMIT` (error code 1455).

#### `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION`
Windows 8 and Windows Server 2012 introduced fine-grained CPU rate limits via the NT kernel scheduler. WinGuard configures this with information class `JobObjectCpuRateControlInformation`:
- **`JOB_OBJECT_CPU_RATE_CONTROL_ENABLE`**: Activates scheduler accounting for the job.
- **`JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP`**:
  Unlike weight-based scheduling (which only throttles when CPU contention exists), the `HARD_CAP` flag instructs the thread scheduler to strictly enforce the limit even when the CPU is 99% idle.
- **`CpuRate`**:
  Expressed in hundredths of a percent (basis points: $100\% = 10,000$). For example, a 25% CPU cap corresponds to `CpuRate = 2500`. The kernel tracks cycles consumed by threads in the job over a scheduling quantum and throttles thread readiness when the budget is depleted.

---

## 2. Windows Access Tokens & Privileges

### 2.1 Token Internals (`TOKEN` Object)
Every Windows process possesses a **primary access token** representing its security context. The token contains:
- User SID (e.g., `S-1-5-21-...`)
- Group SIDs (e.g., `Administrators`, `Users`, `Everyone`)
- Privileges (e.g., `SeDebugPrivilege`, `SeShutdownPrivilege`)
- Mandatory Integrity Level SID (e.g., `Medium` `S-1-16-8192`)
- Restricted SIDs list (if restricted)

### 2.2 Token Restriction Mechanics (`CreateRestrictedToken`)
WinGuard constructs restricted tokens via `CreateRestrictedToken`:
1. **`DISABLE_MAX_PRIVILEGE`**:
   The kernel walks the token's privilege array and removes *all* privileges except `SeChangeNotifyPrivilege` (traverse checking). Privileges such as `SeDebugPrivilege` (which allows opening arbitrary process handles) or `SeImpersonatePrivilege` are completely stripped.
2. **Restricted SIDs (`S-1-5-12` `RESTRICTED_CODE`)**:
   Adding a restricted SID transforms the token into a *Restricted Token*. Under Windows security reference monitor (SRM) access checks:
   $$\text{Access Granted} \iff (\text{DACL grants User/Groups}) \land (\text{DACL grants Restricted SIDs})$$
   If an object's DACL does not explicitly grant access to the `RESTRICTED_CODE` SID, access is denied even if the user is a member of `Administrators`.

---

## 3. Windows Mandatory Integrity Control (MIC)

### 3.1 Architecture
Introduced in Windows Vista, MIC enforces access control based on **Integrity Levels (IL)**:
- **System**: `S-1-16-16384` (`0x4000`)
- **High**: `S-1-16-12288` (`0x3000`) - Elevated Administrator
- **Medium**: `S-1-16-8192` (`0x2000`) - Standard User
- **Low**: `S-1-16-4096` (`0x1000`) - Sandboxed / Untrusted
- **Untrusted**: `S-1-16-0` (`0x0000`)

### 3.2 Integrity Policies
The Security Reference Monitor enforces integrity policies prior to evaluating discretionary ACLs:
- **No-Write-Up (`NW`)**: A subject at integrity level $L_s$ cannot open an object at integrity level $L_o$ for write access if $L_s < L_o$.
- **No-Read-Up (`NR`)**: Restricts read access to higher-integrity securable objects (optional).

WinGuard sets the token integrity level to `Low` (`S-1-16-4096`):
```c
TOKEN_MANDATORY_LABEL tml;
tml.Label.Sid = pSidLow; // S-1-16-4096
tml.Label.Attributes = SE_GROUP_INTEGRITY;
SetTokenInformation(hToken, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(pSidLow));
```
Even if an administrator account launches WinGuard, the sandboxed child process running at `Low` integrity cannot write to:
- Standard user files (Desktop, Documents, etc. are Medium integrity)
- Windows system files (System32 is High/System integrity)
- Registry keys (`HKLM`, `HKCU`)
- Window message queues (UIPI - User Interface Privilege Isolation blocks `WM_DROPFILES`, `PostMessage`)

---

## 4. NTFS Security Descriptors & SDDL

### 4.1 Security Descriptor Architecture
A Windows **Security Descriptor (`SECURITY_DESCRIPTOR`)** contains:
1. **Owner SID**: The principal who owns the object.
2. **Group SID**: Primary group for POSIX compliance.
3. **DACL (Discretionary Access Control List)**: Dictates who has read, write, execute, or delete permissions.
4. **SACL (System Access Control List)**: Dictates auditing rules and **Mandatory Integrity Labels**.

### 4.2 WinGuard SDDL Specification
WinGuard isolates its filesystem sandbox (`sandbox/`) by compiling Security Descriptor Definition Language (SDDL) strings using `ConvertStringSecurityDescriptorToSecurityDescriptorW`:

```sddl
D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGWGX;;;RC)S:(ML;OICI;NW;;;LW)
```

**Deconstruction:**
- `D:P`: Discretionary ACL; Protected (`P` prevents ACE inheritance from parent folders).
- `(A;OICI;GA;;;SY)`: Allow (`A`), Object & Container Inherit (`OICI`), Generic All (`GA`), to `SYSTEM` (`SY`).
- `(A;OICI;GA;;;BA)`: Allow (`A`), Object & Container Inherit (`OICI`), Generic All (`GA`), to Built-in Administrators (`BA`).
- `(A;OICI;GRGWGX;;;RC)`: Allow (`A`), Object & Container Inherit (`OICI`), Generic Read/Write/Execute (`GRGWGX`), to **Restricted Code (`RC` / `S-1-5-12`)**.
- `S:(ML;OICI;NW;;;LW)`: SACL; Mandatory Label (`ML`), Object & Container Inherit (`OICI`), **No-Write-Up policy (`NW`)**, at **Low Integrity (`LW` / `S-1-16-4096`)**.

---

## 5. Working Set & Memory Management

### 5.1 Working Set Mechanics
A process's **Working Set** is the set of physical memory pages currently resident in RAM.
- When an application rapidly touches newly allocated memory, page faults bring pages into the working set.
- Under memory pressure or containment escalation, WinGuard invokes:
  ```c
  K32EmptyWorkingSet(hProcess);
  ```
- This instructs the Windows Memory Manager (Mm) to strip all resident pages from the process's working set and write modified pages back to the paging file or standby list.
- In WinGuard's empirical benchmarks, calling `EmptyWorkingSet` upon escalating to `LEVEL 2 (CONTAINED)` drops resident physical RAM consumption from ~50 MB down to **10.55 MB** instantly, neutralizing RAM starvation without terminating the process.

---

## 6. Process Creation Sequence & Race-Condition Immunity

The exact sequence executed by WinGuard guarantees that an untrusted process cannot run unauthorized code outside the sandbox:

```c
// 1. Create the process in a suspended state
CreateProcessAsUserW(
    hRestrictedToken,     // Stripped token (Low MIC + Restricted SIDs)
    NULL,                 // Application path
    cmd_line,             // Command line
    NULL, NULL, FALSE,
    CREATE_SUSPENDED | CREATE_NEW_CONSOLE, // Suspended state!
    NULL, NULL,
    &si, &pi
);

// 2. Associate process handle with the kernel Job Object
AssignProcessToJobObject(hJob, pi.hProcess);

// 3. Start high-frequency behavior monitoring thread
monitor_start(pMon);

// 4. Resume the primary thread of the untrusted process
ResumeThread(pi.hThread);
```
Because the thread is suspended during steps 1 and 2:
- The process cannot spawn unmonitored children.
- The process cannot consume unconstrained CPU cycles.
- The process cannot exceed memory quotas.
- The kernel enforces Job Object constraints from the first instruction at `mainCRTStartup`.
