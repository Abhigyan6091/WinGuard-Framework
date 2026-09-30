# WinGuard: Comprehensive Viva Voce Defense Guide & Technical Q&A

This guide prepares the author for in-depth academic and technical examinations regarding the **WinGuard** framework. Questions are categorized by domain, ranging from core Operating System internals to security models and empirical evaluation.

---

## 1. Core Operating Systems & Architecture

### Q1: Why did you build WinGuard in standard C (Win32 API) instead of high-level languages like C# (.NET) or Python?
> **Model Answer:**  
> Systems-level process isolation and security frameworks require deterministic memory management, zero runtime overhead (no garbage collection pauses or runtime JIT compilation), direct access to kernel executive objects, and precise control over Win32 structure alignments. High-level runtimes inject heavy runtime dependencies, abstract away vital security flags, and cannot safely manipulate suspended process contexts or raw Security Descriptor Definition Language (SDDL) tokens without complex P/Invoke marshalling overhead. Writing native C with Unicode (`...W`) Win32 APIs guarantees direct, high-performance interactions with the Windows NT kernel.

### Q2: How does a Windows Job Object differ fundamentally from a Linux cgroup?
> **Model Answer:**  
> While both serve as OS-level hierarchical resource container primitives, their kernel implementations differ:
> 1. **Job Objects (`EJOB`)** are native Windows executive objects. They provide atomic lifecycle controls such as `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, which forces the kernel to reap all descendant processes immediately when the job handle closes, eliminating zombie processes.
> 2. **cgroups** in Linux separate resource controllers (`cpu`, `memory`, `pids`) into individual pseudo-filesystem hierarchies (`/sys/fs/cgroup/`).
> 3. Job Objects natively integrate with Windows token-based security and User Interface Privilege Isolation (UIPI), whereas cgroups rely on Linux namespaces (`pid`, `net`, `mnt`) and seccomp-BPF for complete isolation.

### Q3: Why is creating the process with `CREATE_SUSPENDED` critical to sandbox integrity?
> **Model Answer:**  
> In process management, there is an inherent race condition if a process is allowed to run before being assigned to its isolation container. If a target is launched without `CREATE_SUSPENDED`, its primary thread begins executing at its entry point immediately. In that brief window (often milliseconds), an adversarial binary could invoke `CreateProcess` to fork unmonitored child processes or initiate network connections before the supervisor calls `AssignProcessToJobObject`. By launching suspended, WinGuard assigns the process to the Job Object *before* a single instruction of userland code executes, closing this race window completely.

---

## 2. Windows Security Primitives & Internals

### Q4: What is a Restricted Token and how does it prevent privilege escalation?
> **Model Answer:**  
> A Restricted Token is created via `CreateRestrictedToken`. It modifies an existing access token in three ways:
> 1. It permanently strips privileges (via `DISABLE_MAX_PRIVILEGE`), deleting rights like `SeDebugPrivilege` or `SeImpersonatePrivilege`.
> 2. It converts administrative group SIDs to `USE_FOR_DENY_ONLY`, meaning they can only be used to deny access in ACLs, never to grant access.
> 3. It adds a list of **Restricted SIDs** (such as `RESTRICTED_CODE`, `S-1-5-12`). Under Windows Security Reference Monitor rules, access to an object is granted only if the user/group passes the DACL check **AND** the restricted SIDs also pass the DACL check. Unless an object's DACL explicitly grants access to `Restricted Code`, access is denied.

### Q5: How does Windows Mandatory Integrity Control (MIC) enforce isolation even if the user is an Administrator?
> **Model Answer:**  
> Windows Vista introduced MIC, which places an Integrity Level (IL) label in the token's SACL. The Security Reference Monitor enforces the **No-Write-Up (`NW`)** integrity policy *before* evaluating the Discretionary Access Control List (DACL).
> Even if a file's DACL grants `Everyone: Full Control` or `Administrators: Full Control`, if the requesting process has a **Low Integrity** label (`S-1-16-4096`) and the file has a **Medium Integrity** label (standard user files) or **High Integrity** label (system directories), the kernel immediately rejects write, modify, or delete requests with `ERROR_ACCESS_DENIED`.

### Q6: How does WinGuard isolate the filesystem without relying on virtualization?
> **Model Answer:**  
> WinGuard establishes a custom-tailored filesystem boundary rooted at `sandbox\`. It compiles an SDDL security descriptor:
> `D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGWGX;;;RC)S:(ML;OICI;NW;;;LW)`
> 1. The **SACL** sets a Low Integrity Mandatory Label with `NW` (No-Write-Up). Any attempts by the Low Integrity sandboxed process to write outside this folder are blocked by the OS.
> 2. The **DACL** grants full control to `SYSTEM` and `Administrators`, and explicitly grants `Generic Read/Write/Execute` (`GRGWGX`) to the `Restricted Code` SID (`RC` / `S-1-5-12`).
> Thus, the sandboxed process is granted full read/write scratchpad access within `sandbox\workspace\`, while all host writes are denied by the kernel.

---

## 3. Behavior Monitoring & State Machine Dynamics

### Q7: How does WinGuard compute multi-core CPU percentage in real time without relying on heavy WMI or performance counters?
> **Model Answer:**  
> WinGuard's behavior monitor runs on an independent thread, calling `GetProcessTimes` at high frequency (every 25 ms). `GetProcessTimes` queries the kernel thread accounting structures, returning 64-bit integer values in 100-nanosecond intervals for `KernelTime` and `UserTime`.
> By tracking the delta in combined kernel + user time over the delta in high-resolution wall-clock time (`QueryPerformanceCounter` / `GetTickCount64`) and normalizing across the system's logical processor count (`SYSTEM_INFO.dwNumberOfProcessors`), WinGuard computes exact, multi-core CPU utilization with negligible overhead (<0.1% CPU).

### Q8: What is "Adaptation Latency" and how is it measured?
> **Model Answer:**  
> Adaptation latency is the total wall-clock duration elapsed from the onset of a policy-violating behavioral event (such as a CPU burst or memory allocation wave) to the moment the Adaptive State Machine reconfigures kernel containment parameters. In WinGuard's empirical benchmarks, this is measured using monotonic millisecond timestamps (`transitions[0].timestamp_ms - start_tick`) and was measured at **281.0 ms**.

### Q9: How does WinGuard prevent state "flapping" or oscillation between escalation and decay?
> **Model Answer:**  
> Flapping occurs when a system oscillates erratically between high and low enforcement states. WinGuard prevents this through two mechanisms:
> 1. **Violation Thresholds with Hysteresis**: Escalation requires $N$ consecutive violation sampling ticks ($N \ge 2$), filtering out transient, benign noise.
> 2. **Extended Quiescent Decay Timers**: De-escalation (demotion) requires an uninterrupted period of benign behavior (e.g., 1000–5000 ms). Any single violation tick during this interval instantly resets the decay countdown to zero.

### Q10: What does `EmptyWorkingSet` actually do when WinGuard escalates to LEVEL 2?
> **Model Answer:**  
> Calling `K32EmptyWorkingSet(hProcess)` invokes the Windows NT Memory Manager to remove all resident physical pages from the target process's working set. The modified pages are written back to the pagefile or mapped files, and the page frames are returned to the standby/free lists. This immediately reduces the process's physical memory footprint (in our benchmarks, dropping from ~50 MB to 10.55 MB), relieving host memory pressure without aborting the process.

---

## 4. Threat Model, Adversarial Suite & Limitations

### Q11: If an adversarial process attempts to terminate or inject code into WinGuard, what prevents it?
> **Model Answer:**  
> Two independent OS barriers protect the supervisor:
> 1. **User Interface Privilege Isolation (UIPI)**: Low integrity processes cannot send Windows messages (`WM_COMMAND`, `WM_DROPFILES`) to Medium/High integrity windows.
> 2. **Kernel Process Object Security**: To terminate or inject code, the adversary must call `OpenProcess` requesting `PROCESS_TERMINATE` or `PROCESS_VM_WRITE`. The Windows Security Reference Monitor checks the caller's integrity level against the target's integrity level. Because Low cannot write or modify Medium/High, the call fails immediately with `ERROR_ACCESS_DENIED` (error code 5).

### Q12: What happens if an adversary tries to run a fork bomb inside the sandbox?
> **Model Answer:**  
> In `process_stress.exe`, the adversary spawns 50 recursive child processes. Because the process is assigned to a Job Object with `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` set to a strict quota (e.g., 2 to 5), the Windows kernel tracks the active process count in the `EJOB`. When the limit is reached, any subsequent `CreateProcess` call returns `FALSE` and `GetLastError()` yields `ERROR_NOT_ENOUGH_QUOTA` (error code 1816). All child processes are also automatically bound to the same job, preventing breakout.

### Q13: What are the theoretical limitations of a user-mode sandbox like WinGuard compared to a hypervisor?
> **Model Answer:**  
> WinGuard relies on the integrity of the underlying Windows NT kernel (`ntoskrnl.exe`). If an attacker exploits a ring-0 kernel driver vulnerability (such as a Bring Your Own Vulnerable Driver attack) or a kernel privilege escalation exploit, they can compromise the host OS. A Type-1 or Type-2 hypervisor (like Hyper-V or KVM) creates a hardware-isolated Virtual Machine boundary with separate virtual memory and guest kernel, offering stronger isolation at the expense of significant memory footprint, startup latency, and virtualization overhead.
