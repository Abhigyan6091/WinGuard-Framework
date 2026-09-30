# WinGuard Architectural Boundaries, Limitations & Future Roadmap

In the interest of rigorous academic and engineering honesty, this document articulates the explicit boundaries of user-mode process isolation on Windows, identifies theoretical and practical evasion vectors, and charts the future architectural evolution toward kernel-assisted sandboxing.

---

## 1. User-Mode Supervisor Architecture: Inherent Constraints

WinGuard operates as a **user-mode security supervisor** utilizing native Windows executive objects (Job Objects, Access Tokens, Security Descriptors). While this provides significant portability, zero driver signing requirements, and high runtime stability, user-mode isolation has inherent theoretical boundaries compared to ring-0 (kernel) hypervisors.

### 1.1 Direct NT System Calls (`syscall` / SSN)
- **Mechanism**: Modern evasion frameworks (e.g., Hell's Gate, SysWhispers) bypass Win32 user-mode DLL hooks (`ntdll.dll`, `kernel32.dll`) by executing direct assembly `syscall` instructions with dynamic System Service Numbers (SSNs).
- **WinGuard Posture**: WinGuard does **not** rely on user-mode API hooking (such as Detours or inline trampolines). WinGuard's security boundaries (Job Object quotas, Low Integrity tokens, NTFS DACLs/SACLs) are enforced inside the Windows Kernel (`ntoskrnl.exe`, Security Reference Monitor). Even if an adversary executes direct syscalls (e.g., `NtCreateProcessEx` or `NtAllocateVirtualMemory`), the kernel executive still evaluates the calling thread's token and enclosing job quotas.

### 1.2 Path-Based Filesystem Virtualization vs. Access Control
- **Limitation**: WinGuard uses NTFS Discretionary and Mandatory SACL access control to restrict file write operations. However, WinGuard does not implement copy-on-write filesystem virtualization (such as Docker overlay filesystems or Windows Sandbox VHD mounts).
- **Consequence**: If an application requires writing to a path outside `sandbox/` (e.g., `%APPDATA%\Vendor\config.ini`), the write operation simply fails with `ERROR_ACCESS_DENIED`. It is not transparently redirected to an isolated sandbox overlay unless a kernel minifilter driver is deployed.

### 1.3 Asynchronous Telemetry Sampling Gap
- **Limitation**: WinGuard's behavior monitor operates via periodic polling (every 25 ms).
- **Consequence**: An adversarial process can execute a micro-burst lasting less than 25 ms before being throttled. While the kernel Job Object's hard caps (`JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP`) enforce hardware-level thread scheduler limits instantaneously, dynamic state transitions (`LEVEL 0 -> LEVEL 1`) incur an adaptation latency of ~100–300 ms.

### 1.4 Denial of Service Against Global Resources
- **Limitation**: Certain OS resources are global and not fully accounted for by Windows Job Objects:
  - User and GDI object tables (`USER32` window handles, device contexts).
  - High-frequency named pipe or local socket connection storms.
- **Mitigation**: Low Integrity processes are blocked from accessing Medium/High Integrity desktop window queues via User Interface Privilege Isolation (UIPI).

---

## 2. Theoretical Evasion Vectors & Attack Surface

| Evasion Vector | Technique | Feasibility Against WinGuard | Countermeasure / Limitation |
|:---|:---|:---|:---|
| **Direct Syscall Forking** | Issuing `NtCreateProcessEx` directly to bypass `CreateProcessW` | Blocked by Kernel | The process is inside an `EJOB` object; the kernel rejects the fork if `ActiveProcessLimit` is reached. |
| **Token Theft / Impersonation** | Opening winlogon/lsass token via `OpenProcessToken` | Blocked by SRM | Low Integrity token cannot open Medium/High processes; privileges are stripped via `DISABLE_MAX_PRIVILEGE`. |
| **Paging Thrash Attack** | Rapidly touching pages to induce physical RAM thrash | Mitigated by FSM | Adaptive Engine invokes `K32EmptyWorkingSet`, evicting working set pages to disk cache. |
| **Kernel Driver Exploit (BYOVD)** | Dropping a vulnerable signed driver to gain ring-0 execution | Blocked by Token | Low integrity token cannot obtain `SeLoadDriverPrivilege` or write to `\SystemRoot\System32\drivers`. |
| **Microarchitectural Timing Attack**| Modulating CPU execution to leak data across cores | Out of Scope | Hardware/CPU architecture limitation; requires hypervisor-level core pinning. |

---

## 3. Future Architectural Roadmap

To evolve WinGuard from a native user-mode isolation framework into an enterprise-grade defense solution, the following enhancements are envisioned:

### 3.1 Kernel Minifilter Driver Integration (`FLTMGR.SYS`)
- Deploy an accompanying ring-0 Filesystem Minifilter Driver.
- Implement **transparent Copy-On-Write (COW) path redirection**: any write to host filesystem paths (`C:\Program Files`, `C:\Users`) is invisibly redirected to `sandbox\shadow\`, enabling seamless legacy application compatibility with zero host contamination.

### 3.2 Event Tracing for Windows (ETW) & eBPF for Windows
- Replace timer-based polling (`GetProcessTimes`) with a real-time ETW event consumer session:
  - Subscribing to `Microsoft-Windows-Kernel-Process` and `Microsoft-Windows-Kernel-Memory`.
  - Enables **zero-latency, event-driven violation triggers** (adaptation latency drops from ~200 ms to < 5 ms).
- Explore integration with Microsoft's emerging **eBPF for Windows** project to run verifiable bytecode within the Windows network stack and kernel tracepoints.

### 3.3 Dynamic Binary Instrumentation (DBI)
- Integrate a lightweight userland instrumentation engine (e.g., Frida or DynamoRIO) for optional in-depth system call tracing and argument inspection during exploratory behavioral profiling.
