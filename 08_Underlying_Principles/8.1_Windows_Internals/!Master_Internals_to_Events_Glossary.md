# !Master_Internals_to_Events_Glossary

> **Purpose**: This glossary bridges the gap between abstract Windows Internal concepts and concrete forensic artifacts. It serves as a rapid-mapping guide for Detection Engineering and Threat Hunting by linking core principles to the documentation in this repository.

## 1. Core Identity & Access Control

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **Access Token** | A kernel object describing the security context (SIDs and Privileges) of a user or process. | **4624** (Logon), **4672** (Privileged Logon) | `8.1.02_Access_Tokens.md` |
| **SID** | Security Identifier; a unique value used to identify a trustee (User/Group). | **4624**, **4634** (Logoff) | `8.1.02_Access_Tokens.md` |
| **SACL** | System Access Control List; determines which access attempts generate audit records. | **4663** (Object Access), **4907** (Audit Change) | `8.1.01_Object_Security_SACL.md` |
| **Privileges** | Specific administrative rights granted to an account (e.g., `SeDebugPrivilege`). | **4672** (Special privileges assigned) | `8.1.02_Access_Tokens.md` |
| **Handle** | An audited abstract "Voucher" issued by the Kernel allowing a process to access a resource. | **4663** (Object Access) | `8.1.07_Security_Context_Tokens_Handles_and_Pointers.md` |
| **Pointer** | A direct physical/virtual memory address, bypassing kernel audit during use. | N/A (Memory Forensics) | `8.1.07_Security_Context_Tokens_Handles_and_Pointers.md` |
| **Logon Session (LUID)** | A kernel-level authentication context keyed by a locally unique identifier, linking 4624 to all subsequent process/object access events. | **4624**, **4688** (SubjectLogonId), **4663** | `8.1.11_LSA_Logon_Session_Chain_and_Logon_Types.md` |

## 2. Component Object Model (COM) & Registry

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **CLSID** | Class ID; a unique GUID identifying a specific COM functional component. | **4657** (Registry Value Change) | `8.1.06_COM_Architecture_and_Registry_Ledger.md` |
| **AppID** | Application ID; defines the security policy and Token context for a COM object. | **4657** (Registry Value Change) | `8.1.06_COM_Architecture_and_Registry_Ledger.md` |
| **RPCSS** | The COM System Scheduler; the "Foreman" that consults the Registry and activates COM objects. | **4688** (Process Creation: `dllhost.exe`) | `8.1.06_COM_Architecture_and_Registry_Ledger.md` |
| **Surrogate** | `dllhost.exe`; a process hosting COM objects outside the client process to provide isolated execution. | **4688** (Parent: `svchost.exe`) | `8.1.06_COM_Architecture_and_Registry_Ledger.md` |
| **Transaction Logs** | `.LOG` files recording pending registry modifications before they are flushed to the primary hive, essential for catching ephemeral persistence. | N/A (Registry Analysis) | `8.1.22_Registry_Transactions_and_Dirty_Hives.md` |
| **Dirty Hive** | A registry state where the primary disk hive lacks the latest uncommitted changes stored in active memory or transaction logs. | N/A (Registry Analysis) | `8.1.22_Registry_Transactions_and_Dirty_Hives.md` |

## 3. Execution & Memory Management

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **Syscall** | The assembly instruction used to cross from User Mode (Ring 3) to Kernel Mode (Ring 0). | **Sysmon ID 25** (Process Tampering) | `8.1.05_The_User_Mode_Ecosystem_and_Call_Stack.md`; `8.1.29_EDR_Hooking_and_Unhooking_Mechanics.md` (direct/indirect syscall evasion) |
| **IOCTL / IRP** | The communication mechanism between user-mode applications and kernel drivers. IRPs are the "packets" the I/O Manager routes through driver Dispatch Tables; abused by rootkits via IRP Hooking to intercept and filter kernel operations. | N/A (Kernel Analysis) | `8.1.05_The_User_Mode_Ecosystem_and_Call_Stack.md` (Section 5) |
| **PEB / TEB** | Process/Thread Environment Block; user-mode structures holding metadata like loaded modules and stack boundaries. | N/A (Memory Forensics) | `8.1.09_PEB_and_TEB_Structures.md` |
| **VAS** | Virtual Address Space; the private, isolated memory space provided to each process. | N/A (Memory Forensics) | `8.1.16_Virtual_Address_Space_Architecture.md` |
| **Pagefile / Swapfile** | OS-managed disk backing stores for RAM. `pagefile.sys` pages out individual 4KB memory blocks (including fileless malware's private allocations); `swapfile.sys` suspends entire UWP app working sets. Both are forensic goldmines for recovering decrypted payloads and cleartext strings post-termination. | N/A (Disk Forensics) | `8.1.24_Pagefile_and_Swapfile_Mechanics.md` |
| **PE Format** | Portable Executable; the standard data structure dictating how a binary is mapped into memory. | N/A (Static Analysis) | `8.1.15_Portable_Executable_Architecture.md` |
| **Rundll32** | A legitimate Windows host process used as a proxy to execute code within DLLs. | **4688**, **Sysmon ID 7** | `8.1.12_Rundll32.exe_Execution_Logic_and_Dynamic_Link_Library_(DLL)_Loading.md` |
| **Manual Map** | Evasion technique where malware acts as its own loader to stay "fileless" in unbacked memory. | **Sysmon ID 7** (Missing Image Load) | `8.1.10_Manual_Mapping_and_IAT_Reconstruction.md` |
| **EPROCESS** | The master operational structure residing in kernel memory that represents an active process and its metadata. | N/A (Memory Forensics: `pslist`/`psscan`) | `8.1.17_EPROCESS_and_DKOM_Mechanics.md` |
| **DKOM** | Direct Kernel Object Manipulation; a rootkit stealth technique that hides a malicious process by unlinking its `EPROCESS` block from the `ActiveProcessLinks` chain. | N/A (Memory Forensics) | `8.1.17_EPROCESS_and_DKOM_Mechanics.md` |
| **PsLoadedModuleList** | The kernel's authoritative doubly-linked list tracking all loaded driver (`.sys`) modules. The Ring 0 equivalent of `ActiveProcessLinks` — rootkits unlink their `_KLDR_DATA_TABLE_ENTRY` node to vanish from AV/EDR driver enumeration. Detected via `modscan` vs `modules` discrepancy in Volatility. | N/A (Memory Forensics: `modules`/`modscan`) | `8.1.25_PsLoadedModuleList_and_Kernel_Module_DKOM_Mechanics.md` |
| **Heap** | User-mode dynamic memory allocator managed by `_HEAP` (NT Heap) or `_SEGMENT_HEAP` structures; where decrypted configurations, staged shellcode, and most runtime-assembled malware data reside. | N/A (Memory Forensics) | `8.1.26_Windows_Heap_Internals_and_Memory_Allocator.md` |
| **Heap Segment** | A `VirtualAlloc`-backed memory region owned by a heap; each segment is a `VadPrivate` node in the process's VAD tree. | N/A (Memory Forensics) | `8.1.26_Windows_Heap_Internals_and_Memory_Allocator.md` |
| **LFH (Low Fragmentation Heap)** | Front-end allocator that manages small, frequently-allocated chunks in size-class buckets; where C2 command buffers and short decrypted strings typically live. | N/A (Memory Forensics) | `8.1.26_Windows_Heap_Internals_and_Memory_Allocator.md` |
| **TLS Callback** | Pre-entry-point callback registered in the PE's TLS Directory; executed by the loader before `main()`. Standard vehicle for pre-breakpoint debugger detection. | N/A (Static / Dynamic Analysis) | `8.1.27_Exception_Handling_and_TLS_Callbacks.md` |
| **SEH (Structured Exception Handling)** | Per-function exception dispatch mechanism; stack-based linked list on x86 (rooted at `TEB.NtTib.ExceptionList`), table-based via `.pdata` on x64. | N/A (Static / Dynamic Analysis) | `8.1.27_Exception_Handling_and_TLS_Callbacks.md` |
| **VEH (Vectored Exception Handling)** | Process-global exception handler registered via `AddVectoredExceptionHandler`; runs before SEH; primary vehicle for hardware-breakpoint-based stealth hooking. | N/A (Runtime API) | `8.1.27_Exception_Handling_and_TLS_Callbacks.md` |
| **APC (Asynchronous Procedure Call)** | Per-thread function-pointer queue delivered when the thread enters an alertable wait state; abused via `QueueUserAPC` for injection without thread creation. | **Sysmon ID 8 (absence)**, ETW-TI `KiUserApcDispatcher` | `8.1.17_EPROCESS_and_DKOM_Mechanics.md` (§8) |
| **Alertable Wait State** | Thread condition (entered via `SleepEx(ms, TRUE)`, `WaitForSingleObjectEx(..., TRUE)`, etc.) that triggers delivery of queued user-mode APCs; architectural constraint that makes APC injection reliable against some targets and unreliable against others. | N/A (Runtime State) | `8.1.17_EPROCESS_and_DKOM_Mechanics.md` (§8) |
| **PPID Spoofing** | Falsification of `_EPROCESS.InheritedFromUniqueProcessId` via `UpdateProcThreadAttribute` + `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`; deceives Sysmon Event 1 / Security 4688 but NOT the kernel `Microsoft-Windows-Kernel-Process` ETW provider. | **Sysmon ID 1** (deceived), **Kernel-Process ETW** (truthful) | `8.1.17_EPROCESS_and_DKOM_Mechanics.md` (§9) |
| **API Hashing** | Runtime Win32 API resolution technique: walks the PEB `Ldr` list to locate a module, parses its Export Directory, and matches export-name hashes against precomputed constants. Evades static analysis by eliminating API name strings from the binary. | N/A (Static Analysis) | `8.1.10_Manual_Mapping_and_IAT_Reconstruction.md` (§4) |
| **Hell's Gate / Halo's Gate** | API-hashing-adjacent technique that harvests the `mov eax, <imm32>` syscall number directly from `ntdll.dll` stubs, enabling direct syscall execution without invoking the hooked function prologue. | ETW-TI thread stack walks | `8.1.10_Manual_Mapping_and_IAT_Reconstruction.md` (§4.3), `8.1.29_EDR_Hooking_and_Unhooking_Mechanics.md` (§3.1) |

## 4. Service Orchestration & Inter-Process Communication

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **SCM** | Service Control Manager (`services.exe`); the RPC server orchestrating the lifecycle and security context of services. | **7045**, **Sysmon ID 13** | `8.1.14_SCM_Architecture_and_Service_Security_Deep_Dive.md` |
| **Named Pipes** | A conduit for one-way or duplex inter-process communication, frequently abused over SMB. | **Sysmon ID 17**, **Sysmon ID 18** | `8.1.13_ Windows_Service_Control_Manager_Named_Pipes_Communication.md` |
| **MSRPC** | Microsoft RPC; the protocol utilized to communicate with SCM (e.g., via `\pipe\svcctl`). | **Sysmon ID 18** (Pipe Connected) | `8.1.14_SCM_Architecture_and_Service_Security_Deep_Dive.md` |
| **WMI** | Windows Management Instrumentation; the core OS management engine heavily abused for remote lateral movement and stealthy execution. | **Sysmon IDs 19, 20, 21**, **5861** | `8.1.23_WMI_and_CIM_Repository_Architecture.md` |
| **CIM Repository** | The central database (`OBJECTS.DATA`) storing WMI class definitions and persistent payloads. | N/A (Fileless Persistence Analysis) | `8.1.23_WMI_and_CIM_Repository_Architecture.md` |
| **WMI Eventing** | The autonomous execution mechanism consisting of Event Filters, Consumers, and Bindings. | **5861** (WMI Activity) | `8.1.23_WMI_and_CIM_Repository_Architecture.md` |

## 5. Key Security Boundaries, Trust & Telemetry

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **ETW** | Event Tracing for Windows; the core high-performance telemetry backbone capturing pre-execution data. | **Various ETW Providers** | `8.1.04_ETW_Architecture_and_Telemetry_Orchestration.md` |
| **ETW-TI** | Threat Intelligence Provider; supplies advanced EDRs with restricted telemetry on process injection. | **Sysmon ID 8** (CreateRemoteThread) | `8.1.04_ETW_Architecture_and_Telemetry_Orchestration.md` |
| **Authenticode** | Digital signatures providing Integrity and Origin validation, but not context safety. | **CodeIntegrity 3004 / 3089**, **Sysmon ID 7** | `8.1.03_Authenticode_Certificate_Chain_Verification.md` |
| **Time-stamping** | Counter-signatures ensuring a signature remains valid even after the original certificate expires. | **Sysmon ID 7** (BYOVD Analysis) | `8.1.03_Authenticode_Certificate_Chain_Verification.md` |
| **Memory Probing** | Kernel safety checks (`ProbeForRead`/`Write`) ensuring applications don't tamper with Kernel Space. | N/A (Blue Screen / Crash Dump) | `8.1.08_Kernel_Guardrails_and_Verification_Logic.md` |
| **AMSI (Antimalware Scan Interface)** | OS-level interface (`amsi.dll`) that lets scripting hosts submit deobfuscated buffers to a registered antimalware provider for inspection before execution. The primary detection surface for PowerShell, WSH, .NET reflection, and Office macros. | `Microsoft-Windows-Antimalware-Scan-Interface` ETW provider; **Defender EID 1116/1117** | `8.1.28_AMSI_and_Script_Scanning_Architecture.md` |
| **AMSI Provider** | COM in-process server (e.g., `MpOav.dll` for Defender) registered under `HKLM\SOFTWARE\Microsoft\AMSI\Providers`; receives buffers from `amsi.dll` and forwards to the scanning engine. | **Sysmon ID 13 / Security 4657** (registry tampering); **Defender EID 5007** (provider state changes) | `8.1.28_AMSI_and_Script_Scanning_Architecture.md` |
| **EDR User-Mode Hook** | Inline patch placed by an EDR's injected DLL on `ntdll.dll` / `kernelbase.dll` function prologues, redirecting API calls through EDR inspection logic before the syscall executes. | ETW-TI (hook detection of `.text` modification on `ntdll.dll`) | `8.1.29_EDR_Hooking_and_Unhooking_Mechanics.md` |
| **Direct Syscall** | Evasion technique: malware emits its own `mov r10, rcx; mov eax, <syscall#>; syscall` sequence, bypassing the hooked `ntdll.dll` function prologue entirely. | ETW-TI thread stack walks (syscall returning to unbacked memory) | `8.1.29_EDR_Hooking_and_Unhooking_Mechanics.md` (§3.1) |
| **Indirect Syscall** | Refinement of direct syscall: jumps to the `syscall; ret` gadget *inside* `ntdll.dll` to keep the return address within a legitimately-backed module, defeating simple stack-walk heuristics. | Correlation of behavior vs. absence of hook telemetry | `8.1.29_EDR_Hooking_and_Unhooking_Mechanics.md` (§3.2) |
| **Unhooking** | Restoration of hooked function prologues by reading the original bytes from a fresh mapping of `ntdll.dll` (via `NtOpenFile`/`NtReadFile` or `NtMapViewOfSection`) and overwriting the in-memory hooks. | ETW-TI `ProtectVirtualMemory` events targeting `ntdll.dll` range | `8.1.29_EDR_Hooking_and_Unhooking_Mechanics.md` (§3.3) |

## 6. File System, Forensics & Shell Artifacts

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **MFT** | Master File Table; the core NTFS structure managing file metadata, timestamps, and resident data limits. | N/A (Disk Forensics) | `8.1.18_NTFS_and_File_System_Internals.md` |
| **Timestomping** | The manipulation of the `$STANDARD_INFORMATION` attribute to forge file creation dates, detectable by cross-referencing the kernel-managed `$FILE_NAME`. | N/A (MFT Analysis) | `8.1.18_NTFS_and_File_System_Internals.md` |
| **USN Journal ($J)** | The Update Sequence Number journal providing event-based tracking for file creations, modifications, and deletions. | N/A (Disk Forensics) | `8.1.18_NTFS_and_File_System_Internals.md` |
| **ShimCache** | Also known as `AppCompatCache`; logs executable paths and their evaluation Last Modified time to ensure legacy compatibility. | N/A (Registry Analysis) | `8.1.19_Application_Compatibility_Subsystem.md` |
| **Amcache** | An application inventory cache storing deep binary metadata, notably retrieving the SHA1 hash of executables even after deletion. | **4656 / 4663** (Deletion Attempts) | `8.1.19_Application_Compatibility_Subsystem.md` |
| **Prefetch (.pf)** | Files generated by the SysMain service serving as definitive proof of program execution, execution frequency, and modules loaded within the first 10 seconds. | N/A (File Analysis) | `8.1.20_Windows_Prefetch_and_SysMain_Service.md` |
| **LNK Files** | OS-generated shortcut files capturing detailed access history, including MAC times, volume serial numbers, and network share routing. | N/A (Shell Artifacts) | `8.1.21_Windows_Shell_Namespace_and_User_Tracking.md` |
| **JumpLists** | Artifacts tracking "Recent Items" accessed via specific applications, proving direct user interaction with target files. | N/A (Shell Artifacts) | `8.1.21_Windows_Shell_Namespace_and_User_Tracking.md` |
| **ShellBags** | Registry entries recording UI preferences that prove directory traversal, persisting even if the target folder is subsequently deleted. | N/A (Registry Analysis) | `8.1.21_Windows_Shell_Namespace_and_User_Tracking.md` |