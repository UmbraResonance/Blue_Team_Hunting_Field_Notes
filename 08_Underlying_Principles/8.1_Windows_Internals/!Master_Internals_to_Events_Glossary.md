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

## 2. Component Object Model (COM) & Registry

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **CLSID** | Class ID; a unique GUID identifying a specific COM functional component. | **4657** (Registry Value Change) | `8.1.06_COM_Architecture_and_Registry_Ledger.md` |
| **AppID** | Application ID; defines the security policy and Token context for a COM object. | **4657** (Registry Value Change) | `8.1.06_COM_Architecture_and_Registry_Ledger.md` |
| **RPCSS** | The COM System Scheduler; the "Foreman" that consults the Registry and activates COM objects. | **4688** (Process Creation: `dllhost.exe`) | `8.1.06_COM_Architecture_and_Registry_Ledger.md` |
| **Surrogate** | `dllhost.exe`; a process hosting COM objects outside the client process to provide isolated execution. | **4688** (Parent: `svchost.exe`) | `8.1.11_RPCSS_and_COM_Surrogate_Orchestration.md` |

## 3. Execution & Memory Management

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **Syscall** | The assembly instruction used to cross from User Mode (Ring 3) to Kernel Mode (Ring 0). | **Sysmon ID 25** (Process Tampering) | `8.1.05_The_User_Mode_Ecosystem_and_Call_Stack.md` |
| **Direct Syscall** | An evasion technique where malware issues the Syscall directly, bypassing User-Land EDR hooks. | N/A (Thread Call Stack Analysis) | `8.1.05_The_User_Mode_Ecosystem_and_Call_Stack.md` |
| **SSDT** | System Service Descriptor Table; the navigation board routing Syscalls to physical kernel functions. | N/A (Kernel Architecture) | `8.1.08_Kernel_Guardrails_and_Verification_Logic.md` |
| **Subsystem DLLs** | Components like `kernel32.dll` translating Win32 APIs into internal native system calls. | **Sysmon ID 7** (Image Loaded) | `8.1.05_The_User_Mode_Ecosystem_and_Call_Stack.md` |
| **Manual Map** | Evasion technique where malware acts as its own loader to stay "fileless". | **Sysmon ID 7** (Missing Image Load) | `8.1.10_Manual_Mapping_and_IAT_Reconstruction.md` |

## 4. Key Security Boundaries, Trust & Telemetry

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **ETW** | Event Tracing for Windows; the core high-performance telemetry backbone capturing pre-execution data. | **Various ETW Providers** | `8.1.04_ETW_Architecture_and_Telemetry_Orchestration.md.md` |
| **ETW-TI** | Threat Intelligence Provider; supplies advanced EDRs with restricted telemetry on process injection. | **Sysmon ID 8** (CreateRemoteThread) | `8.1.04_ETW_Architecture_and_Telemetry_Orchestration.md.md` |
| **Authenticode** | Digital signatures providing Integrity and Origin validation, but not context safety. | **CodeIntegrity 3004 / 3089**, **Sysmon ID 7** | `8.1.03_Authenticode_Certificate_Chain_Verification.md` |
| **Time-stamping** | Counter-signatures ensuring a signature remains valid even after the original certificate expires. | **Sysmon ID 7** (BYOVD Analysis) | `8.1.03_Authenticode_Certificate_Chain_Verification.md` |
| **Memory Probing** | Kernel safety checks (`ProbeForRead`/`Write`) ensuring applications don't tamper with Kernel Space. | N/A (Blue Screen / Crash Dump) | `8.1.08_Kernel_Guardrails_and_Verification_Logic.md` |