# The Underlying Principles: Reading Paths

This document is not a reference manual; it is a storybook. It is designed for weekly review to stitch the fragmented knowledge of incident response and detection engineering back into a cohesive narrative. 

When reviewing, read the prose first to understand the "why" and the "flow". Only follow the `→ Deep dive` links if you find your memory failing on the technical specifics. Do not fall into the rabbit hole of clicking every link.

---

## Path 1: Windows Internals — The Life of a Process

**Protagonist:** A process trying to run, survive, and interact within the operating system.

### Act I: Conception and Validation
Every execution begins with a dormant file resting on the disk. Before a process can draw its first breath in memory, the operating system must locate its physical footprint and consult tracking mechanisms designed to optimize its launch. Simultaneously, the system evaluates the application's compatibility needs and meticulously dissects its internal structure. Windows does not trust blindly; it scrutinizes cryptographic signatures to ensure the code hasn't been tampered with before granting it entry into the execution environment.
→ Deep dive: [NTFS Internals](8.1_Windows_Internals/8.1.18_NTFS_and_File_System_Internals.md), [Prefetch & SysMain](8.1_Windows_Internals/8.1.20_Windows_Prefetch_and_SysMain_Service.md), [Application Compatibility](8.1_Windows_Internals/8.1.19_Application_Compatibility_Subsystem.md), [PE Architecture](8.1_Windows_Internals/8.1.15_Portable_Executable_Architecture.md), [Authenticode Verification](8.1_Windows_Internals/8.1.03_Authenticode_Certificate_Chain_Verification.md)

### Act II: The Breath of Life
Once validated, the operating system carves out an isolated, blank canvas for the protagonist. This is the virtual address space, a private reality where the process believes it owns everything. To ground this illusion in reality, the kernel constructs fundamental tracking structures to manage the process's lifecycle, while user-mode environment blocks are created so the process knows who it is. Crucially, the process is handed its access token—a cryptographic badge of identity that dictates exactly what it is permitted to see and touch in the world.
→ Deep dive: [Virtual Address Space](8.1_Windows_Internals/8.1.16_Virtual_Address_Space_Architecture.md), [EPROCESS Mechanics](8.1_Windows_Internals/8.1.17_EPROCESS_and_DKOM_Mechanics.md), [PEB and TEB](8.1_Windows_Internals/8.1.09_PEB_and_TEB_Structures.md), [Access Tokens](8.1_Windows_Internals/8.1.02_Access_Tokens.md)

### Act III: Interaction and Survival
A process cannot exist in absolute isolation; it must reach out. It dynamically loads external libraries to gain capabilities and requests handles to interact with files, registry keys, and other objects. Every single time our protagonist reaches for an object, the kernel's security reference monitor intercepts the request, comparing the process's token against the object's security descriptor. If the process attempts complex operations, like establishing communication through COM or named pipes, or if malicious actors attempt to forcefully map unauthorized code into its memory, the call stack becomes the ultimate ledger of its execution history. 
→ Deep dive: [DLL Loading](8.1_Windows_Internals/8.1.12_Rundll32.exe_Execution_Logic_and_Dynamic_Link_Library_(DLL)_Loading.md), [COM Architecture](8.1_Windows_Internals/8.1.06_COM_Architecture_and_Registry_Ledger.md), [Tokens, Handles, and Pointers](8.1_Windows_Internals/8.1.07_Security_Context_Tokens_Handles_and_Pointers.md), [Object Security (SACL)](8.1_Windows_Internals/8.1.01_Object_Security_SACL.md), [The Call Stack](8.1_Windows_Internals/8.1.05_The_User_Mode_Ecosystem_and_Call_Stack.md), [Manual Mapping](8.1_Windows_Internals/8.1.10_Manual_Mapping_and_IAT_Reconstruction.md)

### Act IV: The Watchers in the Dark
The journey of the process is never truly private. From the moment it is created to its termination, kernel guardrails enforce strict boundaries, ensuring it doesn't corrupt the core of the system. More importantly, every significant action, memory allocation, and network connection generates a ripple. The operating system's telemetry orchestration engine captures these ripples, broadcasting the protagonist's every move to defensive sensors waiting in the dark. 
→ Deep dive: [Kernel Guardrails](8.1_Windows_Internals/8.1.08_Kernel_Guardrails_and_Verification_Logic.md), [ETW Architecture](8.1_Windows_Internals/8.1.04_ETW_Architecture_and_Telemetry_Orchestration.md)

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