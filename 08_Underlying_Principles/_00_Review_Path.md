# The Underlying Principles: Reading Paths

This document is a narrative textbook designed for weekly review. It stitches fragmented knowledge into a cohesive story of system internals and adversarial movement. 

**Structure Note:**
- **Path 1** covers the complete lifecycle of Windows Internals.
- **Path 2** covers the progression of an Active Directory compromise.
- **Cross-Protocol Integration:** After finishing both, read the dedicated section on Cross-Protocol Authentication to see where standard models fail.
- **Isolated Foundations:** Document [8.3.01 - 802.11 Fundamentals](8.3_Network_Foundataion/8.3.01_802.11_Fundamentals.md) is kept separate as it serves as a standalone hardware foundation not directly tied to the OS narrative.

---

## Path 1: Windows Internals — The Orchestrated Lifecycle

**Protagonist:** A process trying to run, survive, and interact within the complex ecosystem of the Windows OS.

### Act 0: The Stage
Before the protagonist is born, the stage must be understood. The mental model for Windows is a strictly divided realm: the outer courtyard of Ring 3 (User Mode) where applications live, and the inner sanctum of Ring 0 (Kernel Mode) where the OS core operates. A process in Ring 3 cannot directly touch hardware or allocate physical memory. The *only* legitimate bridge between these two worlds is the Syscall. Every subsequent act in this path is ultimately a story of who is standing in which Ring, and how they interact across this boundary.

### Act I: Conception and Validation
Every execution begins as a dormant PE file on the disk. Before it can draw its first breath in memory, the OS must locate its physical footprint and consult tracking mechanisms like Prefetch to optimize its launch. The system evaluates compatibility needs and dissects the PE structure to understand the code it is about to host. Windows does not trust blindly; it scrutinizes cryptographic signatures through Authenticode to ensure the protagonist is exactly who they claim to be before granting entry.
→ Deep dive: [NTFS Internals](8.1_Windows_Internals/8.1.18_NTFS_and_File_System_Internals.md), [Prefetch & SysMain](8.1_Windows_Internals/8.1.20_Windows_Prefetch_and_SysMain_Service.md), [Application Compatibility](8.1_Windows_Internals/8.1.19_Application_Compatibility_Subsystem.md), [PE Architecture](8.1_Windows_Internals/8.1.15_Portable_Executable_Architecture.md), [Authenticode Verification](8.1_Windows_Internals/8.1.03_Authenticode_Certificate_Chain_Verification.md)

* **Self-Test:**
  1. If an Authenticode signature is valid but the timestamp is post-expiration, how does Windows handle it and why?
  2. Why does a Prefetch file prove a program was *executed*, while ShimCache only proves it *existed* or was checked for compatibility?
* **Detection Takeaway:** File creation (Sysmon EID 11) is intent; Process creation (EID 4688/Sysmon EID 1) is action. Telemetry must differentiate the dormant file from the executing PE.

### Act II: The Inheritance of Identity
Before allocating a single byte of memory, the OS must first decide who this process belongs to. Its identity is predetermined. It is born into a "Logon Session" created by the Local Security Authority (LSA) at the moment a user or service authenticated to the system. This session is the protagonist’s lineage, providing the source for its primary Access Token. The process does not create its own rights; it inherits them from this session chain, which dictates its fundamental relationship to the interactive world or the network.
→ Deep dive: [LSA Logon Session Chain](8.1_Windows_Internals/8.1.11_LSA_Logon_Session_Chain_and_Logon_Types.md), [Access Tokens](8.1_Windows_Internals/8.1.02_Access_Tokens.md)

* **Self-Test:**
  1. What is the difference between a Primary Token and an Impersonation Token regarding how a process uses them?
  2. When a user double-clicks an executable, how does the new process physically acquire the token from the explorer.exe session?
* **Detection Takeaway:** EID 4624 LogonType is downstream evidence; the true source IP often resides in the upstream Type 3 logon. Link Type 3 to Type 10 via TargetUserName + time window, not just the LUID.

### Act III: The Breath of Life
Validated and identified, the process is granted its virtual reality: the Virtual Address Space (VAS). It believes it owns a private, continuous memory world, but the kernel is the ultimate landlord, swapping physical RAM pages to the Pagefile on disk when resources are tight. To manage this lifecycle, the kernel constructs the fundamental EPROCESS structure as the authoritative ledger of the process's existence, while user-mode blocks (PEB/TEB) are carved out to store its internal configuration.
→ Deep dive: [Virtual Address Space](8.1_Windows_Internals/8.1.16_Virtual_Address_Space_Architecture.md), [Pagefile & Swapfile](8.1_Windows_Internals/8.1.24_Pagefile_and_Swapfile_Mechanics.md), [EPROCESS Structures](8.1_Windows_Internals/8.1.17_EPROCESS_and_DKOM_Mechanics.md), [PEB and TEB](8.1_Windows_Internals/8.1.09_PEB_and_TEB_Structures.md)

* **Self-Test:**
  1. If memory pages are marked `PAGE_EXECUTE_READWRITE` (RWX), why is this highly suspicious in user-mode VAS?
  2. What vital execution information is stored in the PEB that an analyst would want to read during live memory analysis?
* **Detection Takeaway:** Process injection often reveals itself as abnormal cross-process memory allocations (Sysmon EID 8), where a process opens a handle to another specifically to manipulate its VAS.

### Act IV: Interaction and Flow
The protagonist must now reach out to survive. It loads standard DLL libraries to gain functionality and requests handles to interact with files or registry hives. Every time it reaches for an object, the Security Reference Monitor checks its token against the object's SACL. Beneath each of these legitimate interactions lies a call stack that ultimately descends to a Syscall — demonstrating the authorized path from Ring 3 to Ring 0. 
→ Deep dive: [DLL Loading](8.1_Windows_Internals/8.1.12_Rundll32.exe_Execution_Logic_and_Dynamic_Link_Library_(DLL)_Loading.md), [Tokens & Handles](8.1_Windows_Internals/8.1.07_Security_Context_Tokens_Handles_and_Pointers.md), [Object Security (SACL)](8.1_Windows_Internals/8.1.01_Object_Security_SACL.md), [The Call Stack & Syscalls](8.1_Windows_Internals/8.1.05_The_User_Mode_Ecosystem_and_Call_Stack.md), [Named Pipes](8.1_Windows_Internals/8.1.13_Windows_Service_Control_Manager_Named_Pipes_Communication.md)

* **Self-Test:**
  1. How does Windows resolve the location of a DLL if the application doesn't provide an absolute path?
  2. Why do threat actors prefer using Named Pipes over standard TCP/UDP ports for lateral movement within an environment?
* **Detection Takeaway:** The Call Stack is the truth teller; a handle requested via legitimate API will have `ntdll.dll` and `kernel32.dll` in the stack, while unbacked or spoofed frames indicate evasion.

### Act V: The Orchestrated Existence
Not all processes are started by a user’s click; many are orchestrated by system-level foremen. The Service Control Manager (SCM) acts as the foreman for background services, managing their state through a dedicated architecture. Meanwhile, the WMI repository serves as an autonomous engine for system management. This orchestrated layer allows processes to be triggered remotely or persistently, often through complex COM interactions and registry transactions that leave subtle logs even when successful.
→ Deep dive: [SCM Architecture](8.1_Windows_Internals/8.1.14_SCM_Architecture_and_Service_Security_Deep_Dive.md), [WMI/CIM Repository](8.1_Windows_Internals/8.1.23_WMI_and_CIM_Repository_Architecture.md), [COM Architecture](8.1_Windows_Internals/8.1.06_COM_Architecture_and_Registry_Ledger.md), [Registry Transactions](8.1_Windows_Internals/8.1.22_Registry_Transactions_and_Dirty_Hives.md)

* **Self-Test:**
  1. When a service is installed, what registry key is modified, and which process actually creates the service executable in memory?
  2. How can WMI be abused to establish persistence without writing an executable to disk?
* **Detection Takeaway:** EID 7045 (Service Creation) and Sysmon EID 19/20/21 (WMI Activity) are the primary tripwires for identifying malicious orchestration and persistent autonomous execution.

### Act VI: The Watchers
The journey of the process is recorded by real-time sentinels. ETW captures the protagonist's live actions, while kernel guardrails ensure it doesn't cross into the forbidden kernel space. Adversary evasion fundamentally aims to blind these watchers. They bypass the standard OS loaders entirely via Manual Mapping, or they attack the very ledgers that underpin enumeration — the EPROCESS ActiveProcessLinks (Ring 3) and the PsLoadedModuleList (Ring 0) DKOM techniques being classical mirror images of evasion.
→ Deep dive: [ETW Architecture](8.1_Windows_Internals/8.1.04_ETW_Architecture_and_Telemetry_Orchestration.md), [Kernel Guardrails](8.1_Windows_Internals/8.1.08_Kernel_Guardrails_and_Verification_Logic.md), [Manual Mapping](8.1_Windows_Internals/8.1.10_Manual_Mapping_and_IAT_Reconstruction.md), [Kernel Module DKOM](8.1_Windows_Internals/8.1.25_PsLoadedModuleList_and Kernel_Module_DKOM_Mechanics.md), [EPROCESS DKOM](8.1_Windows_Internals/8.1.17_EPROCESS_and_DKOM_Mechanics.md)

* **Self-Test:**
  1. Why is Manual Mapping inherently invisible to standard DLL load ETW providers (like `Microsoft-Windows-Kernel-Process`)?
  2. If a process removes itself from the `ActiveProcessLinks` doubly linked list, how can memory forensics still identify it?
* **Detection Takeaway:** A process executing network or disk I/O but missing from the active process list, or an ETW provider suddenly stopping reporting without a system reboot, are hard indicators of ledger tampering.

### Act VII: The Archives
Long after the process has died, its echoes remain in the disk's "archives." Shell artifacts like LNK files, JumpLists, and ShellBags track where the process has been and what the user has touched. These form a permanent forensic ledger. For an investigator, these archives represent the static reality of what truly happened, providing a timeline that real-time telemetry might have missed or that an attacker failed to wipe completely.
→ Deep dive: [Shell Namespace & User Tracking](8.1_Windows_Internals/8.1.21_Windows_Shell_Namespace_and_User_Tracking.md), [Registry Transactions](8.1_Windows_Internals/8.1.22_Registry_Transactions_and_Dirty_Hives.md)

* **Self-Test:**
  1. What specific piece of evidence does a ShellBag provide that a LNK file does not?
  2. If an attacker deletes a registry key to hide their tracks, how might the `.LOG` transaction files still expose the historical value?
* **Detection Takeaway:** Time discrepancy is key; if a LNK file's internal embedded MAC times do not align logically with the file system MAC times, timestamp stomping has likely occurred.

---

## Path 2: Active Directory — The Ascent of an Adversary

**Protagonist:** An attacker attempting to navigate from a compromised standard user to Domain Admin.

### Act I: Surveying the Invisible Kingdom
The adversary lands on a single endpoint, assuming the identity of a standard user. To move forward, they must first comprehend the invisible web that binds the organization together. They map the hierarchy of domains and the complex trust relationships that act as bridges between disparate territories. They query the schema to understand the blueprint of every object in the realm, constantly aware of the overarching governance and protection mechanisms that watch for unauthorized reconnaissance.
→ Deep dive: [Identity and Principals](8.2_Active_Directory/8.2.01_Identity_and_Security_Principals.md), [Hierarchy and Trust](8.2_Active_Directory/8.2.02_Hierarchy_and_Trust_Architecture.md), [Schema and Templates](8.2_Active_Directory/8.2.03_Schema_and_Object_Templates.md), [Governance Mechanisms](8.2_Active_Directory/8.2.04_Governance_and_Protection_Mechanisms.md)

* **Self-Test:**
  1. How does a Foreign Security Principal differ from a standard Domain User in terms of how it is queried by BloodHound?
  2. What is the fundamental difference between an External Trust and a Forest Trust regarding transitivity?
* **Detection Takeaway:** High volumes of LDAP queries targeting the root naming context or specific schema attributes (EID 4662) from a single endpoint indicate active reconnaissance.

### Act II: The Currency of Trust
Lateral movement requires speaking the local dialects of authentication. The adversary observes the legacy chatter of NTLM, understanding its weaknesses and predictable challenge-response mechanics. However, true power lies in mastering the primary currency: Kerberos. By studying the precise cryptography of TGTs and service tickets, and understanding how services are permitted to delegate authentication on behalf of others, the attacker learns how to imperceptibly flow across the network.
→ Deep dive: [NTLM Mechanism](8.2_Active_Directory/8.2.09_NTLM_Authentication_Mechanism.md), [Kerberos Protocol](8.2_Active_Directory/8.2.06_Kerberos_Protocol_and_Encryption.md), [Kerberos Delegation](8.2_Active_Directory/8.2.12_Kerberos_Delegation_Mechanics.md)

* **Self-Test:**
  1. In NTLMv2, what part of the challenge-response prevents basic pass-the-hash attacks if the hashes aren't cached locally?
  2. Why is Unconstrained Delegation fundamentally more dangerous than Constrained Delegation regarding the TGT?
* **Detection Takeaway:** EID 4769 (Service Ticket Requested) utilizing RC4 encryption (0x17) instead of AES (0x12) is a strong indicator of legacy protocol abuse or Kerberoasting.

### Act III: The Static Misconfigurations
Before attempting complex protocol abuse, the adversary exploits the sins of the past: historical misconfigurations left dormant. They hunt for hardcoded passwords in old group policies or exploit poorly delegated permissions. The attacker is not breaking the system; they are simply reading what is exposed and modifying what poorly structured Access Control Lists (ACLs) permit them to touch. This is a phase of passive exploitation based on administrative oversight.
→ Deep dive: [GPP Vulnerability](8.2_Active_Directory/8.2.07_GPP_cpassword_Vulnerability.md), [GPO Abuse](8.2_Active_Directory/8.2.08_GPO_Delegation_and_Abuse_Logic.md), [ACL Principles](8.2_Active_Directory/8.2.14_Active_Directory_ACL_Principles.md)

* **Self-Test:**
  1. If an attacker has `GenericWrite` over a user object, name two distinct ways they can leverage this to compromise the account.
  2. Why did Microsoft ultimately deprecate the GPP cpassword feature, and why are old environments still vulnerable?
* **Detection Takeaway:** EID 5136 (Directory Service Object Modified) focusing on changes to the `msDS-AllowedToDelegateTo` attribute or unauthorized GPO edits highlights static configuration abuse.

### Act IV: The Protocol Coercions
When static flaws are exhausted, the adversary turns to active provocation. They coerce legitimate, highly privileged services (like Domain Controllers or Exchange servers) into authenticating back to them. By capturing and relaying these forced credentials, or by weaponizing misconfigured AD CS (Active Directory Certificate Services) templates via ESC1, the attacker forces the system to hand over powerful identities. This is active exploitation of the protocol's trust logic.
→ Deep dive: [Authentication Coercion](8.2_Active_Directory/8.2.13_Authentication_Coercion_Mechanics.md), [AD CS ESC1](8.2_Active_Directory/8.2.15_AD_CS_ESC1_and_Vulnerability_Mechanics.md)

* **Self-Test:**
  1. What is the role of the RPC interface `MS-RPRN` in standard authentication coercion attacks (like PetitPotam/PrinterBug)?
  2. In an ESC1 attack, what specific template misconfiguration allows an attacker to request a certificate on behalf of a Domain Admin?
* **Detection Takeaway:** Look for anomalous EID 5145 (Network Share Object Checked) involving IPC$ and specific RPC pipes (e.g., `spoolss`, `lsarpc`) originating from non-administrative subnets.

### Act V: The Ultimate Mimicry
The final ascent requires bypassing standard authentication entirely. Reaching the apex, the adversary abuses the very mechanisms domain controllers use to replicate physical storage data. By impersonating a domain controller (DCSync), they request the most guarded cryptographic secrets of the kingdom (the KRBTGT hash). With these master keys, they mint their own Golden Tickets, achieving total persistence and transforming from an intruder into a permanent fixture.
→ Deep dive: [Physical Storage](8.2_Active_Directory/8.2.05_Physical_Storage_and_Lifecycle.md), [DCSync Logic](8.2_Active_Directory/8.2.10_DCSync_Attack_Logic.md), [Golden Ticket Mechanics](8.2_Active_Directory/8.2.11_Kerberos_Golden_Ticket_Mechanics.md)

* **Self-Test:**
  1. Why doesn't a DCSync attack require code execution on the Domain Controller itself?
  2. How does a Golden Ticket bypass the standard TGT lifespan constraints enforced by Group Policy?
* **Detection Takeaway:** EID 4662 indicating the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` extended rights originating from an IP address that does not belong to a known Domain Controller is the definitive DCSync signature.

---

## Integration View: Beyond the LSA

**The Missing Narrative:** Path 1 assumes the Local Security Authority (LSA) sits at the center of process identity. Path 2 assumes AD (Kerberos/NTLM) sits at the center of network identity. But modern environments break these assumptions. Many protocols do not pass through the LSA at all. SQL authentication handles its own identity; OAuth relies on external token issuers; anonymous RPC calls bypass traditional principal validation entirely. 

When you have mastered the standard lifecycle of Windows and the standard escalation of AD, you must read the **Cross-Protocol Authentication Visibility Matrix**. This document acts as the bridge, illustrating where the standard OS telemetry goes blind because the application layer is handling its own security context.

→ Read the Integration: [Cross-Protocol Authentication Visibility Matrix](8.4_Authentication_and_Identity/8.4.01_Cross_Protocol_Authentication_Visibility_Matrix.md)