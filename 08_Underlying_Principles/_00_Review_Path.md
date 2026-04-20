# The Underlying Principles: Reading Paths
 
This document is a narrative textbook designed for weekly review. It stitches fragmented knowledge into a cohesive story of system internals and adversarial movement.
 
**Structure Note:**
- **Path 1** covers the complete lifecycle of Windows Internals.
- **Path 2** covers the progression of an Active Directory compromise.
- **Cross-Protocol Integration:** After finishing both, read the dedicated section on Cross-Protocol Authentication to see where standard models fail.
- **Script-Layer Side Chapter:** A standalone narrative covering interpreted code — scripts, macros, and in-memory .NET — which sits upstream of PE analysis and follows its own architecture rather than the compiled-binary lifecycle.
- **Isolated Foundations:** Document [8.3.01 - 802.11 Fundamentals](8.3_Network_Foundataion/8.3.01_802.11_Fundamentals.md) is kept separate as it serves as a standalone hardware foundation not directly tied to the OS narrative.
---
 
## Path 1: Windows Internals — The Orchestrated Lifecycle
 
**Protagonist:** A process trying to run, survive, and interact within the complex ecosystem of the Windows OS.
 
### Act 0: The Stage
Before the protagonist is born, the stage must be understood. The mental model for Windows is a strictly divided realm: the outer courtyard of Ring 3 (User Mode) where applications live, and the inner sanctum of Ring 0 (Kernel Mode) where the OS core operates. A process in Ring 3 cannot directly touch hardware or allocate physical memory. The *only* legitimate bridge between these two worlds is the Syscall.
 
Equally important: every security decision in this story ultimately reduces to one comparison — the Subject's Token (who I am) against the Object's Security Descriptor (who is allowed). Everything from privilege escalation to defense evasion is a variation on manipulating one side of this comparison.
 
### Act I: Conception and Validation
Every execution begins as a dormant PE file on the disk. Before it can draw its first breath in memory, the OS must locate its physical footprint and consult tracking mechanisms like Prefetch to optimize its launch. The system evaluates compatibility needs and dissects the PE structure to understand the code it is about to host. Windows does not trust blindly; it scrutinizes cryptographic signatures through Authenticode to ensure the protagonist is exactly who they claim to be before granting entry. But scrutiny has limits — the protagonist can lie about its own lineage at birth, falsifying the `InheritedFromUniqueProcessId` field via a documented attribute-list API so that all downstream user-mode telemetry sees a fabricated parent.
→ Deep dive: [NTFS Internals](8.1_Windows_Internals/8.1.18_NTFS_and_File_System_Internals.md), [Prefetch & SysMain](8.1_Windows_Internals/8.1.20_Windows_Prefetch_and_SysMain_Service.md), [Application Compatibility](8.1_Windows_Internals/8.1.19_Application_Compatibility_Subsystem.md), [PE Architecture](8.1_Windows_Internals/8.1.15_Portable_Executable_Architecture.md), [Authenticode Verification](8.1_Windows_Internals/8.1.03_Authenticode_Certificate_Chain_Verification.md), [PPID Spoofing (§9 of 8.1.17)](8.1_Windows_Internals/8.1.17_EPROCESS_and_DKOM_Mechanics.md)
 
* **Self-Test:**
  1. If an Authenticode signature is valid but the timestamp is post-expiration, how does Windows handle it and why?
  2. Why does a Prefetch file prove a program was *executed*, while ShimCache only proves it *existed* or was checked for compatibility?
  3. Why does PPID Spoofing deceive Sysmon Event 1 but not the `Microsoft-Windows-Kernel-Process` ETW provider? What does this tell you about where user-mode telemetry sources their "parent process" field?
* **Detection Takeaway:** Intent vs. Action: Sysmon EID 11 (File Create) indicates intent; EID 4688/Sysmon EID 1 (Process Create) confirms execution. Lineage Truth: Kernel-Process ETW records real parent PID; divergence from Sysmon EID 1's `ParentImage` is definitive PPID Spoofing evidence.
### Act II: The Inheritance of Identity
Before allocating a single byte of memory, the OS must first decide who this process belongs to. Its identity is predetermined. It is born into a "Logon Session" created by the Local Security Authority (LSA) at the moment a user or service authenticated to the system. This session is the protagonist's lineage, providing the source for its primary Access Token. The process does not create its own rights; it inherits them from this session chain, which dictates its fundamental relationship to the interactive world or the network.
→ Deep dive: [LSA Logon Session Chain](8.1_Windows_Internals/8.1.11_LSA_Logon_Session_Chain_and_Logon_Types.md), [Access Tokens](8.1_Windows_Internals/8.1.02_Access_Tokens.md)
 
* **Self-Test:**
  1. What is the difference between a Primary Token and an Impersonation Token regarding how a process uses them?
  2. When a user double-clicks an executable, how does the new process physically acquire the token from the explorer.exe session?
* **Detection Takeaway:** Origin Tracing: EID 4624 LogonType is downstream evidence. True source requires correlating back to the upstream Type 3 logon via `TargetUserName` + time window.
### Act III: The Breath of Life
Validated and identified, the process is granted its virtual reality: the Virtual Address Space (VAS). It believes it owns a private, continuous memory world, but the kernel is the ultimate landlord, swapping physical RAM pages to the Pagefile on disk when resources are tight. To manage this lifecycle, the kernel constructs the fundamental EPROCESS structure as the authoritative ledger of the process's existence, while user-mode blocks (PEB/TEB) are carved out to store its internal configuration. Within this address space, the protagonist carves further structure — a heap allocator that subdivides large committed regions into small chunks on demand, creating the working surface where every decrypted payload, every C2 command buffer, every cleartext secret the protagonist holds will ultimately sit.
→ Deep dive: [Virtual Address Space](8.1_Windows_Internals/8.1.16_Virtual_Address_Space_Architecture.md), [Pagefile & Swapfile](8.1_Windows_Internals/8.1.24_Pagefile_and_Swapfile_Mechanics.md), [EPROCESS Structures](8.1_Windows_Internals/8.1.17_EPROCESS_and_DKOM_Mechanics.md), [PEB and TEB](8.1_Windows_Internals/8.1.09_PEB_and_TEB_Structures.md), [Heap Internals and Memory Allocator](8.1_Windows_Internals/8.1.26_Windows_Heap_Internals_and_Memory_Allocator.md)
 
* **Self-Test:**
  1. If memory pages are marked `PAGE_EXECUTE_READWRITE` (RWX), why is this highly suspicious in user-mode VAS?
  2. What vital execution information is stored in the PEB that an analyst would want to read during live memory analysis?
  3. In a process running on Windows 10+, how would you determine whether it is using NT Heap or Segment Heap, and why does the distinction matter for applying the correct Volatility plugin to a memory dump?
* **Detection Takeaway:** Injection Heuristic: Sysmon EID 8 (CreateRemoteThread) + abnormal cross-process memory allocation = Active VAS manipulation. Heap-Aware Forensics: Extracting decrypted C2 configurations, cleartext credentials, and staged payloads requires parsing the correct heap allocator — wrong allocator choice produces silent garbage, not clear errors.
### Act IV: Interaction and Flow
The protagonist must now reach out to survive. It loads standard DLL libraries to gain functionality and requests handles to interact with files or registry hives. Every time it reaches for an object, the Security Reference Monitor checks its token against the object's SACL. Beneath each of these legitimate interactions lies a call stack that ultimately descends to a Syscall — demonstrating the authorized path from Ring 3 to Ring 0. But the protagonist may decline the standard path entirely. A sophisticated implementation can walk the PEB's loaded-module lists, parse export directories by hand, and match export-name hashes against precomputed constants — acquiring API addresses without leaving a single function name in its own binary. Its threads can be summoned to execute arbitrary code through the APC queue whenever they enter an alertable wait, and its control flow can be diverted through deliberate exceptions and vectored handlers that never appear in the decompiler's reconstructed graph.
→ Deep dive: [DLL Loading](8.1_Windows_Internals/8.1.12_Rundll32.exe_Execution_Logic_and_Dynamic_Link_Library_(DLL)_Loading.md), [Tokens & Handles](8.1_Windows_Internals/8.1.07_Security_Context_Tokens_Handles_and_Pointers.md), [Object Security (SACL)](8.1_Windows_Internals/8.1.01_Object_Security_SACL.md), [The Call Stack & Syscalls](8.1_Windows_Internals/8.1.05_The_User_Mode_Ecosystem_and_Call_Stack.md), [Named Pipes](8.1_Windows_Internals/8.1.13_Windows_Service_Control_Manager_Named_Pipes_Communication.md), [Manual API Resolution (§4 of 8.1.10)](8.1_Windows_Internals/8.1.10_Manual_Mapping_and_IAT_Reconstruction.md), [APC Queue Mechanics (§8 of 8.1.17)](8.1_Windows_Internals/8.1.17_EPROCESS_and_DKOM_Mechanics.md), [Exception Handling and TLS Callbacks](8.1_Windows_Internals/8.1.27_Exception_Handling_and_TLS_Callbacks.md)
 
* **Self-Test:**
  1. In the standard DLL Search Order, which specific directory check is most commonly exploited for Side-loading, and why?
  2. Why do threat actors prefer using Named Pipes over standard TCP/UDP ports for lateral movement within an environment?
  3. Why does APC injection (via `QueueUserAPC`) evade Sysmon Event 8 entirely, while producing nearly identical execution results to `CreateRemoteThread`? What does this tell you about the detection gap between kernel-callback-based telemetry and ETW-TI?
  4. In a sample that hijacks control flow via a VEH handler + hardware breakpoints on `AmsiScanBuffer`, which memory-integrity signals fail to trigger, and why? What detection layer remains viable?
* **Detection Takeaway:** The Call Stack is the Truth: Legitimate API calls are backed by `ntdll.dll`/`kernel32.dll` frames; unbacked frames equate to direct Syscall evasion. Queue-Based Injection: Absence of Sysmon EID 8 in the presence of `VirtualAllocEx`/`WriteProcessMemory` against a remote process is itself signal — look for `QueueUserAPC` or APC-dispatch ETW-TI events. Exception-Based Evasion: VEH + hardware breakpoints modify nothing in memory — detection depends on thread DR-register inspection, not integrity scans.
### Act V: The Orchestrated Existence
Not all processes are started by a user's click; many are orchestrated by system-level foremen. The Service Control Manager (SCM) acts as the foreman for background services, managing their state through a dedicated architecture. Meanwhile, the WMI repository serves as an autonomous engine for system management. This orchestrated layer allows processes to be triggered remotely or persistently, often through complex COM interactions and registry transactions that leave subtle logs even when successful.
→ Deep dive: [SCM Architecture](8.1_Windows_Internals/8.1.14_SCM_Architecture_and_Service_Security_Deep_Dive.md), [WMI/CIM Repository](8.1_Windows_Internals/8.1.23_WMI_and_CIM_Repository_Architecture.md), [COM Architecture](8.1_Windows_Internals/8.1.06_COM_Architecture_and_Registry_Ledger.md), [Registry Transactions](8.1_Windows_Internals/8.1.22_Registry_Transactions_and_Dirty_Hives.md)
 
* **Self-Test:**
  1. When a service is installed, what registry key is modified, and which process actually creates the service executable in memory?
  2. How can WMI be abused to establish persistence without writing an executable to disk?
* **Detection Takeaway:** Orchestration Tripwires: EID 7045 (Service Creation) or Sysmon EID 19/20/21 (WMI Activity) = Indicators of autonomous, orchestrated execution.
### Act VI: The Watchers
The journey of the process is recorded by real-time sentinels. ETW captures the protagonist's live actions, while kernel guardrails ensure it doesn't cross into the forbidden kernel space. Adversary evasion fundamentally aims to blind these watchers. At the user-mode level, Manual Mapping bypasses the loader entirely to avoid DLL load telemetry. At the kernel-mode level, adversaries attack the ledgers that underpin enumeration itself — and here EPROCESS DKOM (hiding processes from Ring 3 enumeration) and PsLoadedModuleList DKOM (hiding drivers from Ring 0 enumeration) are classical mirror images of each other.
 
User-mode monitors layer alongside the kernel sentinels. The Antimalware Scan Interface hooks into every major scripting host — PowerShell, WSH, .NET reflection, Office macros — scanning deobfuscated buffers after unwrapping but before execution. EDR products inject monitoring DLLs that rewrite `ntdll.dll` function prologues, forcing every sensitive API call to pass through inspection logic before the syscall fires. These monitors live inside the protagonist's own address space, and this is their fundamental weakness: the protagonist can overwrite AMSI's scan function to return clean, restore the original `ntdll.dll` bytes to remove hooks, or — more subtly — use hardware breakpoints and exception handlers to neutralize hooks without modifying any memory at all, leaving integrity checks with nothing to report. Direct and indirect syscall techniques cut the call chain at the boundary, executing the kernel transition from code that `ntdll.dll` has never seen.
→ Deep dive: [ETW Architecture](8.1_Windows_Internals/8.1.04_ETW_Architecture_and_Telemetry_Orchestration.md), [Kernel Guardrails](8.1_Windows_Internals/8.1.08_Kernel_Guardrails_and_Verification_Logic.md), [Manual Mapping](8.1_Windows_Internals/8.1.10_Manual_Mapping_and_IAT_Reconstruction.md), [Kernel Module DKOM](8.1_Windows_Internals/8.1.25_PsLoadedModuleList_and%20Kernel_Module_DKOM_Mechanics.md), [EPROCESS DKOM](8.1_Windows_Internals/8.1.17_EPROCESS_and_DKOM_Mechanics.md), [AMSI Architecture](8.1_Windows_Internals/8.1.28_AMSI_and_Script_Scanning_Architecture.md), [EDR Hooking and Unhooking](8.1_Windows_Internals/8.1.29_EDR_Hooking_and_Unhooking_Mechanics.md)
 
* **Self-Test:**
  1. Why is Manual Mapping inherently invisible to standard DLL load ETW providers (like `Microsoft-Windows-Kernel-Process`)?
  2. If a process removes itself from the `ActiveProcessLinks` doubly linked list, how can memory forensics still identify it?
  3. Why does AMSI's architectural design — co-residing in the same process as the content it scans — make every AMSI bypass structurally viable even against future patches? What is the equivalent "co-residency problem" for EDR user-mode hooks?
  4. If a sample produces no ETW-TI `ProtectVirtualMemory` event targeting `ntdll.dll`, and `ntdll.dll` `.text` section in memory matches the on-disk hash, can you conclude the sample is not evading user-mode hooks? Why or why not?
* **Detection Takeaway:** Ledger Tampering: Active I/O without a corresponding process listing, or abrupt termination of ETW providers = Ring 0/Ring 3 evasion underway. Script-Host Bypass: AMSI provider unregistration (Defender EID 5007) or `amsiInitFailed`-pattern strings in PS 4104 logs = bypass in progress. Hook Removal: ETW-TI `ProtectVirtualMemory` events against `ntdll.dll` or `amsi.dll` address ranges, paired with subsequent sensitive API calls from the same process, are the canonical correlation.
### Act VII: The Archives
Long after the process has died, its echoes remain in the disk's "archives." Shell artifacts like LNK files, JumpLists, and ShellBags track where the process has been and what the user has touched. These form a permanent forensic ledger. For an investigator, these archives represent the static reality of what truly happened, providing a timeline that real-time telemetry might have missed or that an attacker failed to wipe completely.
→ Deep dive: [Shell Namespace & User Tracking](8.1_Windows_Internals/8.1.21_Windows_Shell_Namespace_and_User_Tracking.md), [Registry Transactions](8.1_Windows_Internals/8.1.22_Registry_Transactions_and_Dirty_Hives.md)
 
* **Self-Test:**
  1. What specific piece of evidence does a ShellBag provide that a LNK file does not?
  2. If an attacker deletes a registry key to hide their tracks, how might the `.LOG` transaction files still expose the historical value?
* **Detection Takeaway:** Timestamp Stomping: LNK internal embedded MAC times misaligned with File system MAC times = Manufactured history.
---
 
## Path 2: Active Directory — The Ascent of an Adversary
 
**Protagonist:** An attacker attempting to navigate from a compromised standard user to Domain Admin.
 
### Act I: Surveying the Invisible Kingdom
The adversary lands on a single endpoint, assuming the identity of a standard user. To move forward, they must first comprehend the invisible web that binds the organization together. They map the hierarchy of domains and the complex trust relationships that act as bridges between disparate territories. They query the schema to understand the blueprint of every object in the realm, constantly aware of the overarching governance and protection mechanisms that watch for unauthorized reconnaissance.
→ Deep dive: [Identity and Principals](8.2_Active_Directory/8.2.01_Identity_and_Security_Principals.md), [Hierarchy and Trust](8.2_Active_Directory/8.2.02_Hierarchy_and_Trust_Architecture.md), [Schema and Templates](8.2_Active_Directory/8.2.03_Schema_and_Object_Templates.md), [Governance Mechanisms](8.2_Active_Directory/8.2.04_Governance_and_Protection_Mechanisms.md)
 
* **Self-Test:**
  1. Why does the mere existence of a Foreign Security Principal (FSP) object serve as cryptographic proof of a trust relationship?
  2. What role does the Global Catalog play when resolving group memberships for a user authenticating across different domains in the same forest?
* **Detection Takeaway:** Reconnaissance Signature: High-volume LDAP queries (EID 4662) targeting root naming context or schema attributes from a single non-admin host.
### Act II: The Currency of Trust
Lateral movement requires speaking the local dialects of authentication. The adversary observes the legacy chatter of NTLM, understanding its weaknesses and challenge-response mechanics. However, true power lies in mastering the primary currency: Kerberos. By studying the precise cryptography of TGTs and service tickets, and understanding how services are permitted to delegate authentication on behalf of others, the attacker learns how to imperceptibly flow across the network.
→ Deep dive: [NTLM Mechanism](8.2_Active_Directory/8.2.09_NTLM_Authentication_Mechanism.md), [Kerberos Protocol](8.2_Active_Directory/8.2.06_Kerberos_Protocol_and_Encryption.md), [Kerberos Delegation](8.2_Active_Directory/8.2.12_Kerberos_Delegation_Mechanics.md)
 
* **Self-Test:**
  1. What distinct replay or cracking problems do the NTLMv2 client challenge (nonce) and server challenge individually solve?
  2. Why is Unconstrained Delegation fundamentally more dangerous than Constrained Delegation regarding the TGT?
* **Detection Takeaway:** Legacy Abuse: EID 4769 (Service Ticket Requested) + RC4 encryption (0x17) = Potential Kerberoasting or protocol downgrade attack.
### Act III: The Static Misconfigurations
Before attempting complex protocol abuse, the adversary exploits the sins of the past: historical misconfigurations left dormant. They hunt for hardcoded passwords in old group policies or exploit poorly delegated permissions. The attacker is not breaking the system; they are simply reading what is exposed and modifying what poorly structured Access Control Lists (ACLs) permit them to touch. This is a phase of passive exploitation based on administrative oversight.
→ Deep dive: [GPP Vulnerability](8.2_Active_Directory/8.2.07_GPP_cpassword_Vulnerability.md), [GPO Abuse](8.2_Active_Directory/8.2.08_GPO_Delegation_and_Abuse_Logic.md), [ACL Principles](8.2_Active_Directory/8.2.14_Active_Directory_ACL_Principles.md)
 
* **Self-Test:**
  1. If an attacker has `GenericWrite` over a user object, name two distinct ways they can leverage this to compromise the account.
  2. Why did Microsoft ultimately deprecate the GPP cpassword feature, and why are old environments still vulnerable?
* **Detection Takeaway:** Static Abuse: EID 5136 (Directory Service Object Modified) + target is `msDS-AllowedToDelegateTo` or core GPO attributes.
### Act IV: The Protocol Coercions
When static flaws are exhausted, the adversary turns to active provocation. They coerce legitimate, highly privileged services (like Domain Controllers or Exchange servers) into authenticating back to them. By capturing and relaying these forced credentials, or by weaponizing misconfigured AD CS (Active Directory Certificate Services) templates via ESC1, the attacker forces the system to hand over powerful identities. This is active exploitation of the protocol's trust logic.
→ Deep dive: [Authentication Coercion](8.2_Active_Directory/8.2.13_Authentication_Coercion_Mechanics.md), [AD CS ESC1](8.2_Active_Directory/8.2.15_AD_CS_ESC1_and_Vulnerability_Mechanics.md)
 
* **Self-Test:**
  1. What is the role of the RPC interface `MS-RPRN` in standard authentication coercion attacks (like PetitPotam/PrinterBug)?
  2. In an ESC1 attack, what specific template misconfiguration allows an attacker to request a certificate on behalf of a Domain Admin?
* **Detection Takeaway:** Coercion Signature: EID 5145 (Network Share Checked) + IPC$ + specific RPC pipes (`spoolss`, `lsarpc`) originating from non-admin subnets.
### Act V: The Ultimate Mimicry
The final ascent requires bypassing standard authentication entirely. Reaching the apex, the adversary abuses the very mechanisms domain controllers use to replicate physical storage data. By impersonating a domain controller (DCSync), they request the most guarded cryptographic secrets of the kingdom (the KRBTGT hash). With these master keys, they mint their own Golden Tickets, achieving total persistence and transforming from an intruder into a permanent fixture.
→ Deep dive: [Physical Storage](8.2_Active_Directory/8.2.05_Physical_Storage_and_Lifecycle.md), [DCSync Logic](8.2_Active_Directory/8.2.10_DCSync_Attack_Logic.md), [Golden Ticket Mechanics](8.2_Active_Directory/8.2.11_Kerberos_Golden_Ticket_Mechanics.md)
 
* **Self-Test:**
  1. Why doesn't a DCSync attack require code execution on the Domain Controller itself?
  2. How does a Golden Ticket bypass the standard TGT lifespan constraints enforced by Group Policy?
* **Detection Takeaway:** DCSync Signature: EID 4662 + `DS-Replication-Get-Changes` / `-All` extended rights + Source IP is not a known DC.
---
 
## Integration View: Beyond the LSA
 
**The Missing Narrative:** Path 1 assumes the Local Security Authority (LSA) sits at the center of process identity. Path 2 assumes AD (Kerberos/NTLM) sits at the center of network identity. But modern environments break these assumptions. Many protocols do not pass through the LSA at all. SQL authentication handles its own identity; OAuth relies on external token issuers; anonymous RPC calls bypass traditional principal validation entirely.
 
When you have mastered the standard lifecycle of Windows and the standard escalation of AD, you must read the **Cross-Protocol Authentication Visibility Matrix**. This document acts as the bridge, illustrating where the standard OS telemetry goes blind because the application layer is handling its own security context.
 
→ Read the Integration: [Cross-Protocol Authentication Visibility Matrix](8.4_Authentication_and_Identity/8.4.01_Cross_Protocol_Authentication_Visibility_Matrix.md)
 
---
 
## Side Chapter: The Script Layer — When the Executable Is Text
 
**Protagonist:** A script — PowerShell, VBScript/JScript, VBA macro, or .NET assembly delivered as bytes — trying to execute malicious behavior while evading the defensive stack Microsoft has built specifically to inspect it.
 
**Why this is a side chapter, not an Act in Path 1:** The script layer doesn't follow the compiled-binary lifecycle. A script is never loaded by the OS image loader, never signed by Authenticode, never mapped to a VAD with a file-backed `ImageMap`. It arrives as text, is parsed and interpreted inside a host process, and leaves behind a forensic trail dominated by the **host's** artifacts rather than its own. Path 1's framework still applies — once the script's host process does something, we're back in familiar territory — but the script's own architecture is distinct enough to warrant separate treatment.
 
### Chapter I: The Interpreter's Architectural Necessity
Every scripting language, regardless of surface syntax, executes code through the same four-stage pipeline: source text → tokenizer → parser → AST → interpreter. Obfuscation operates on the source text layer. The interpreter operates on the AST layer. **The gap between these two layers is the unavoidable deobfuscation point** — the interpreter cannot execute what it cannot parse, and it cannot parse what it has not already deobfuscated. This architectural necessity is the foundation of sink substitution, of PowerShell's Event 4104 "free deobfuscation," and of AMSI's effectiveness against obfuscated scripts.
→ Deep dive: [Interpreter Architecture and Deobfuscation Primitives](8.1_Windows_Internals/8.1.34_Interpreter_Architecture_and_Deobfuscation_Primitives.md), [Text Encoding and Character Set Foundations](8.1_Windows_Internals/8.1.36_Text_Encoding_and_Character_Set_Foundations.md)
 
* **Self-Test:**
  1. Why is sink substitution (replacing `IEX` / `eval` / `Execute` with a logging operation) an architectural necessity rather than a clever trick? What property of interpreter design guarantees its effectiveness?
  2. Under what conditions does sink substitution *fail*? Give two structural categories of obfuscation that sink substitution cannot defeat.
  3. PowerShell's `-EncodedCommand` flag uses UTF-16LE. If you decode the Base64 blob and interpret it as UTF-8, what is the characteristic symptom? Why does this specifically happen?
* **Detection Takeaway:** The Parser Is the Choke Point: Any content-inspection telemetry placed at or just before parser input (PowerShell Event 4104, AMSI) sees deobfuscated content by architectural necessity. Obfuscation-resistant detection always lives at or below this layer.
### Chapter II: The Hosts and Their Instrumentation
Scripts do not execute in a vacuum — they run inside host processes (PowerShell engine, Windows Script Host, Office, MSHTA) that Microsoft has instrumented to varying degrees. PowerShell is deeply instrumented: AMSI integration at the ScriptBlock level, Event 4104 with full deobfuscated content, CLR-level assembly scanning. VBScript and JScript have partial AMSI integration only since Windows 10 1709. Office 365 VBA has AMSI integration per-procedure; legacy Office does not. Batch/CMD has **no AMSI integration at all** — not an oversight, but an architectural reality inherited from DOS. This uneven coverage dictates which detection strategies work for which language.
→ Deep dive: [AMSI Architecture](8.1_Windows_Internals/8.1.28_AMSI_and_Script_Scanning_Architecture.md), [Script Telemetry Surface Comparison](8.1_Windows_Internals/8.1.35_Script_Telemetry_Surface_Comparison.md)
 
* **Self-Test:**
  1. Rank PowerShell, legacy Office VBA, and CMD batch from most-instrumented to least-instrumented for content inspection. What are the architectural reasons for this ranking?
  2. Why does a multi-layer kill chain (email → VBA → CMD → PowerShell → .NET payload) require per-stage detection rather than forward-tracing from any single stage?
  3. An AMSI provider returns `AMSI_RESULT_CLEAN` (< 0x8000) for a PowerShell script. What are four architectural reasons this could be a false negative rather than a genuinely clean script?
* **Detection Takeaway:** Instrumentation Gradient: PowerShell 4104 + AMSI is high-ROI; CMD content inspection is architecturally impossible. Build detection at the most-instrumented layer available for each segment of a multi-stage chain, and use process-creation events (EID 4688 / Sysmon EID 1) as the universal fallback for uninstrumented layers.
### Chapter III: The COM Bridge to the OS
Scripts never call Windows APIs directly. They reach the OS through **COM Automation** — a late-binding dispatch mechanism built on the `IDispatch` interface. Every `CreateObject("Scripting.FileSystemObject")`, every `CreateObject("ADODB.Stream")`, every `GetObject("winmgmts:...")` is a COM Automation call. The string `"CreateTextFile"` cannot be obfuscated — it travels through `IDispatch::GetIDsOfNames` as plaintext. The corresponding DLL (`scrrun.dll` for FSO, `msado15.dll` for ADODB.Stream) must load into the script host process. These are **architectural invariants** — detection at the COM layer survives script-level obfuscation because the script cannot hide its COM invocations without ceasing to function.
→ Deep dive: [COM Automation and the IDispatch Interface](8.1_Windows_Internals/8.1.30_COM_Automation_and_IDispatch_Interface.md), [COM Architecture and Registry Ledger](8.1_Windows_Internals/8.1.06_COM_Architecture_and_Registry_Ledger.md)
 
* **Self-Test:**
  1. Why does VBScript require the `Set` keyword for object assignments but not for primitive assignments? What underlying COM type system feature forces this distinction?
  2. An obfuscated VBScript dynamically concatenates `"ADOD" & "B.Stream"` to evade string-matching detection. What two telemetry signals still fire despite this obfuscation, and why are they architecturally unevadable?
  3. What is the OS design property that allows a standard (non-admin) user to hijack any ProgID's resolution for their own processes? How is this exploited in COM Hijacking persistence?
* **Detection Takeaway:** COM Invariants: DLL-load fingerprinting (Sysmon EID 7 for `msado15.dll` into a script host = high-fidelity binary-dropper signal) and registry-tampering monitoring (`HKCU\Software\Classes\CLSID\*\InprocServer32` writes = hijacking attempt) both survive arbitrary script-level obfuscation.
### Chapter IV: The CLR as an Alternative Interpreter
When a script or loader needs to execute .NET code, it invokes the Common Language Runtime (CLR) — a user-mode virtual machine that can load and execute an entire assembly from a byte array in memory via `System.Reflection.Assembly.Load(byte[])`. This is the architectural foundation of "fileless" .NET execution: Cobalt Strike's `execute-assembly`, PowerShell reflective loading, and most modern C2 post-exploitation toolkits. Since .NET 4.8, the CLR's byte-array load path integrates with AMSI, providing content inspection before verification. The `Microsoft-Windows-DotNETRuntime` ETW provider independently logs every assembly load regardless of AMSI status. These two layers together form the defensive answer to in-memory .NET execution.
→ Deep dive: [CLR and In-Memory Assembly Loading](8.1_Windows_Internals/8.1.31_CLR_and_In_Memory_Assembly_Loading.md)
 
* **Self-Test:**
  1. Why does `Assembly.Load(byte[])` produce no Sysmon Event 7 for the loaded payload, even though the payload is a fully-formed PE? What OS load path is being bypassed?
  2. In Cobalt Strike's `execute-assembly` technique, the sacrificial process is typically `rundll32.exe`. What specific DLL load into `rundll32.exe` is the highest-fidelity indicator of this technique, and why?
  3. AMSI-for-CLR scans `Assembly.Load(byte[])` calls. What four structural bypass paths allow this scan to be defeated?
* **Detection Takeaway:** CLR Hosting Anomaly: `clr.dll` loading into a process with no .NET reason to host it (e.g., `notepad.exe`, `rundll32.exe` in suspicious contexts) is a high-fidelity .NET injection signal. Pair with DotNETRuntime ETW assembly-load events for full coverage.
### Chapter V: The Container Formats
Some scripts arrive packaged in document containers that must be unwrapped before analysis. Legacy Office documents use the **OLE Compound File Binary Format (CFBF)** — a hierarchical FAT-like filesystem inside a single file, where VBA code lives as a combination of `CompressedSource` (what analysts extract) and `PerformanceCache` (what the runtime actually executes). The two can be made to disagree, producing **VBA stomping** — the plaintext an analyst sees does not match the code the interpreter runs. Modern `.docm` / `.xlsm` files are ZIP archives containing a legacy CFBF (`vbaProject.bin`), so the same architecture — and the same stomping technique — applies to modern documents too.
→ Deep dive: [OLE Compound File and VBA Project Structure](8.1_Windows_Internals/8.1.32_OLE_Compound_File_and_VBA_Project_Structure.md)
 
* **Self-Test:**
  1. Why does VBA stomping depend on matching the attacker's Office version to the victim's? What would happen if the versions differ, and how does this affect the reliability of the technique?
  2. An `.xlsm` file (modern Excel) is extracted and `olevba` reports only benign-looking macros. What structural check must be performed before concluding the document is safe?
  3. Why does the VBA compression algorithm (MS-OVBA) require specialized tooling rather than standard gunzip/zlib decompression? What practical consequence does this have for analysts lacking proper tooling?
* **Detection Takeaway:** Structural Divergence: Comparing `CompressedSource` size/hash against `PerformanceCache` (via `pcodedmp` or similar) detects stomping when source analysis alone is insufficient. Document-level detection supplements content-level detection in legacy-Office environments with no VBA AMSI.
### Chapter VI: The Policy Barrier
PowerShell has a defensive feature that most organizations never deploy: **Constrained Language Mode (CLM)**. When WDAC or AppLocker is enforcing application control, PowerShell automatically activates CLM for all non-allowlisted scripts, restricting them to a minimal subset of language features. CLM specifically blocks `Add-Type`, `Invoke-Expression`, COM object creation, and .NET reflection — the exact capabilities offensive PowerShell tooling depends on. On a CLM-enforced host, attempted attacks still log fully in Event 4104 (intent captured) but fail at execution (outcome neutralized). This is the asymmetric defensive position every PowerShell-involved environment should aspire to. Four documented bypass paths exist — PowerShell v2 downgrade, runspace escape, signed-script trust abuse, and COM-layer escape — each with its own detection and remediation.
→ Deep dive: [PowerShell Language Modes and Policy Enforcement](8.1_Windows_Internals/8.1.33_PowerShell_Language_Modes_and_Policy_Enforcement.md)
 
* **Self-Test:**
  1. What is the one-line PowerShell query that tells an IR responder what language mode the current session is operating in? Why is this triage check valuable early in any PowerShell-involved incident?
  2. CLM is enabled on a host. An attacker gains code execution via an unpatched browser exploit and attempts `Add-Type -TypeDefinition`. Describe precisely what happens at each layer: what logs fire, what errors are produced, what does not execute.
  3. Name the four documented CLM bypass paths. For each, describe a specific detection signal that would indicate the bypass is being attempted.
* **Detection Takeaway:** Enforcement Drift Signal: A host that previously reported `ConstrainedLanguage` now reporting `FullLanguage` indicates WDAC/AppLocker policy failure or tampering — itself a high-value indicator independent of any specific attack. Also hunt for `-Version 2` in PowerShell command lines as the simplest CLM bypass path.
---
 
**Side-Chapter Integration Note:** Nothing in this side chapter replaces Path 1. The script layer is *upstream* of Path 1 — a script eventually spawns processes, loads DLLs, writes files, and makes network connections, at which point Path 1's framework applies. Think of this chapter as "how the executable gets to exist," and Path 1 as "what happens once it does." The two together form the full picture for any script-originated incident.