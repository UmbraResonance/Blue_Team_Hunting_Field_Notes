# The Underlying Principles: Reading Paths

This document is a narrative textbook designed for weekly review. It stitches fragmented knowledge into a cohesive story of system internals and adversarial movement. 

**Structure Note:**
- **Path 1** covers the complete lifecycle of Windows Internals.
- **Path 2** covers the progression of an Active Directory compromise.
- **Cross-Protocol Integration:** After finishing both, read [8.4.01 - Cross-Protocol Authentication Visibility Matrix](8.4_Authentication_and_Identity/8.4.01_Cross_Protocol_Authentication_Visibility_Matrix.md) to see how these worlds collide.
- **Isolated Foundations:** Document [8.3.01 - 802.11 Fundamentals](8.3_Network_Foundataion/8.3.01_802.11_Fundamentals.md) is kept separate as it serves as a standalone hardware foundation not directly tied to the OS narrative.

---

## Path 1: Windows Internals — The Orchestrated Lifecycle

**Protagonist:** A process trying to run, survive, and interact within the complex ecosystem of the Windows OS.

### Act I: Conception and Validation
Every execution begins as a dormant PE file on the disk. Before it can draw its first breath in memory, the OS must locate its physical footprint and consult tracking mechanisms like Prefetch to optimize its launch. The system evaluates compatibility needs and dissects the PE structure to understand the code it is about to host. Windows does not trust blindly; it scrutinizes cryptographic signatures through Authenticode to ensure the protagonist is exactly who they claim to be before granting entry.
→ Deep dive: [NTFS Internals](8.1_Windows_Internals/8.1.18_NTFS_and_File_System_Internals.md), [Prefetch & SysMain](8.1_Windows_Internals/8.1.20_Windows_Prefetch_and_SysMain_Service.md), [Application Compatibility](8.1_Windows_Internals/8.1.19_Application_Compatibility_Subsystem.md), [PE Architecture](8.1_Windows_Internals/8.1.15_Portable_Executable_Architecture.md), [Authenticode Verification](8.1_Windows_Internals/8.1.03_Authenticode_Certificate_Chain_Verification.md)

### Act II: The Inheritance of Identity
Before the process exists, its identity is already predetermined. It is born into a "Logon Session" created by the Local Security Authority (LSA) at the moment a user or service authenticated to the system. This session is the protagonist’s lineage, providing the source for its primary Access Token. The process does not create its own rights; it inherits them from this session chain, which dictates its relationship to the interactive world or the network.
→ Deep dive: [LSA Logon Session Chain](8.1_Windows_Internals/8.1.11_LSA_Logon_Session_Chain_and_Logon_Types.md), [Access Tokens](8.1_Windows_Internals/8.1.02_Access_Tokens.md)

### Act III: The Breath of Life
Validated and identified, the process is granted its virtual reality: the Virtual Address Space (VAS). It believes it owns a private, continuous memory world, but the kernel is the ultimate landlord, swapping physical RAM pages to the Pagefile on disk when resources are tight. To manage this lifecycle, the kernel constructs the fundamental EPROCESS structure as the authoritative ledger of the process's existence, while user-mode blocks (PEB/TEB) are carved out to store its internal configuration.
→ Deep dive: [Virtual Address Space](8.1_Windows_Internals/8.1.16_Virtual_Address_Space_Architecture.md), [Pagefile & Swapfile](8.1_Windows_Internals/8.1.24_Pagefile_and_Swapfile_Mechanics.md), [EPROCESS Structures](8.1_Windows_Internals/8.1.17_EPROCESS_and_DKOM_Mechanics.md), [PEB and TEB](8.1_Windows_Internals/8.1.09_PEB_and_TEB_Structures.md)

### Act IV: Interaction and Flow
The protagonist must now reach out to survive. It loads DLL libraries to gain functionality and requests handles to interact with files or registry hives. Every time it reaches for an object, the Security Reference Monitor checks its token against the object's SACL. Beneath each of these reaches lies a call stack that ultimately descends to a Syscall — the only legitimate passage from Ring 3 to Ring 0 — which is why analysts watching the call stack can tell apart legitimate API use from direct Syscall evasion.
→ Deep dive: [DLL Loading](8.1_Windows_Internals/8.1.12_Rundll32.exe_Execution_Logic_and_Dynamic_Link_Library_(DLL)_Loading.md), [Tokens & Handles](8.1_Windows_Internals/8.1.07_Security_Context_Tokens_Handles_and_Pointers.md), [Object Security (SACL)](8.1_Windows_Internals/8.1.01_Object_Security_SACL.md), [The Call Stack & Syscalls](8.1_Windows_Internals/8.1.05_The_User_Mode_Ecosystem_and_Call_Stack.md), [Named Pipes](8.1_Windows_Internals/8.1.13_Windows_Service_Control_Manager_Named_Pipes_Communication.md), [Manual Mapping](8.1_Windows_Internals/8.1.10_Manual_Mapping_and_IAT_Reconstruction.md)

### Act V: The Orchestrated Existence
Not all processes are started by a user’s click; many are orchestrated by system-level foremen. The Service Control Manager (SCM) acts as the foreman for background services, managing their state through a dedicated architecture. Meanwhile, the WMI repository serves as an autonomous engine for system management. This orchestrated layer allows processes to be triggered remotely or persistently, often through complex COM interactions and registry transactions that leave subtle logs even when successful.
→ Deep dive: [SCM Architecture](8.1_Windows_Internals/8.1.14_SCM_Architecture_and_Service_Security_Deep_Dive.md), [WMI/CIM Repository](8.1_Windows_Internals/8.1.23_WMI_and_CIM_Repository_Architecture.md), [COM Architecture](8.1_Windows_Internals/8.1.06_COM_Architecture_and_Registry_Ledger.md), [Registry Transactions](8.1_Windows_Internals/8.1.22_Registry_Transactions_and_Dirty_Hives.md)

### Act VI: The Watchers
The journey of the process is recorded by real-time sentinels. ETW captures the protagonist's live actions, while kernel guardrails ensure it doesn't cross into the forbidden kernel space. Rootkits that attempt to vanish from these watchers do so by attacking the very ledgers that underpin enumeration — the EPROCESS ActiveProcessLinks (Ring 3) and the PsLoadedModuleList (Ring 0) DKOM techniques being the classical mirror images of each other.
→ Deep dive: [ETW Architecture](8.1_Windows_Internals/8.1.04_ETW_Architecture_and_Telemetry_Orchestration.md), [Kernel Guardrails](8.1_Windows_Internals/8.1.08_Kernel_Guardrails_and_Verification_Logic.md), [Kernel Module DKOM](8.1_Windows_Internals/8.1.25_PsLoadedModuleList_and Kernel_Module_DKOM_Mechanics.md), [EPROCESS DKOM](8.1_Windows_Internals/8.1.17_EPROCESS_and_DKOM_Mechanics.md)

### Act VII: The Archives
Long after the process has died, its echoes remain in the disk's "archives." Shell artifacts like LNK files, JumpLists, and ShellBags track where the process has been and what the user has touched. These, combined with the forensic remnants in Registry .LOG transaction files, form a permanent forensic ledger. For an investigator, these archives represent the static reality of what truly happened, providing a timeline that real-time telemetry might have missed.
→ Deep dive: [Shell Namespace & User Tracking](8.1_Windows_Internals/8.1.21_Windows_Shell_Namespace_and_User_Tracking.md), [Registry Transactions](8.1_Windows_Internals/8.1.22_Registry_Transactions_and_Dirty_Hives.md)

---

## Path 2: Active Directory — The Ascent of an Adversary

**Protagonist:** An attacker attempting to navigate from a compromised standard user to Domain Admin.

### Act I: Surveying the Invisible Kingdom
The adversary lands on a single endpoint, assuming the identity of a standard user. To move forward, they must first comprehend the invisible web that binds the organization together. They map the hierarchy of domains and the complex trust relationships that act as bridges between disparate territories. They query the schema to understand the blueprint of every object in the realm, constantly aware of the overarching governance and protection mechanisms that watch for unauthorized reconnaissance.
→ Deep dive: [Identity and Principals](8.2_Active_Directory/8.2.01_Identity_and_Security_Principals.md), [Hierarchy and Trust](8.2_Active_Directory/8.2.02_Hierarchy_and_Trust_Architecture.md), [Schema and Templates](8.2_Active_Directory/8.2.03_Schema_and_Object_Templates.md), [Governance Mechanisms](8.2_Active_Directory/8.2.04_Governance_and_Protection_Mechanisms.md)

### Act II: The Currency of Trust
Lateral movement requires speaking the local dialects of authentication. The adversary observes the legacy chatter of NTLM, understanding its weaknesses and predictable challenge-response mechanics. However, true power lies in mastering the primary currency: Kerberos. By studying the precise cryptography of ticket-granting tickets and service tickets, and understanding how services are permitted to delegate authentication on behalf of others, the attacker learns how to impersonate identities across the network smoothly.
→ Deep dive: [NTLM Mechanism](8.2_Active_Directory/8.2.09_NTLM_Authentication_Mechanism.md), [Kerberos Protocol](8.2_Active_Directory/8.2.06_Kerberos_Protocol_and_Encryption.md), [Kerberos Delegation](8.2_Active_Directory/8.2.12_Kerberos_Delegation_Mechanics.md)

### Act III: Exploiting the Fabric
With the map in hand and the currency understood, the adversary begins to manipulate the domain's fabric. They hunt for historical misconfigurations, such as hardcoded passwords left in group policies, or exploit poorly delegated permissions that allow them to modify critical objects. When direct access is denied, they coerce legitimate services into authenticating back to them, capturing and relaying credentials. Furthermore, they abuse misconfigured certificate templates, turning a seemingly benign feature into an instant escalation path. Everything relies on finding the tiniest flaws in the access control lists.
→ Deep dive: [GPP Vulnerability](8.2_Active_Directory/8.2.07_GPP_cpassword_Vulnerability.md), [GPO Abuse](8.2_Active_Directory/8.2.08_GPO_Delegation_and_Abuse_Logic.md), [Authentication Coercion](8.2_Active_Directory/8.2.13_Authentication_Coercion_Mechanics.md), [AD CS ESC1](8.2_Active_Directory/8.2.15_AD_CS_ESC1_and_Vulnerability_Mechanics.md), [ACL Principles](8.2_Active_Directory/8.2.14_Active_Directory_ACL_Principles.md)

### Act IV: The Ultimate Mimicry
The final ascent requires bypassing standard authentication entirely. Reaching the apex, the adversary abuses the very mechanisms domain controllers use to replicate physical storage data among themselves. By impersonating a domain controller, they request the most guarded cryptographic secrets of the kingdom. With these master keys, they mint their own golden tickets, achieving total persistence and transforming from an intruder into a permanent fixture of the domain's reality.
→ Deep dive: [Physical Storage](8.2_Active_Directory/8.2.05_Physical_Storage_and_Lifecycle.md), [DCSync Logic](8.2_Active_Directory/8.2.10_DCSync_Attack_Logic.md), [Golden Ticket Mechanics](8.2_Active_Directory/8.2.11_Kerberos_Golden_Ticket_Mechanics.md)