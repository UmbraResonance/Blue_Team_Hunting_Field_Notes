# !Master_Internals_to_Events_Glossary

> **Purpose**: This glossary bridges the gap between abstract Windows Internal concepts and concrete forensic artifacts. It serves as a rapid-mapping guide for Detection Engineering and Threat Hunting by linking core principles to the documentation in this repository.

## 1. Core Identity & Access Control

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **Access Token** | A kernel object describing the security context of a user; your "Digital ID Badge". | **4624** (Logon), **4672** (Privileged Logon) | `8.1.2_Access_Tokens.md` |
| **SID** | Security Identifier; a unique value used to identify a trustee (User/Group). | **4624**, **4634** (Logoff) | `8.1.2_Access_Tokens.md` |
| **SACL** | System Access Control List; determines which access attempts generate audit records. | **4663** (Object Access) | `8.1.1_Object_Security_SACL.md` |
| **Handle** | An abstract "Voucher" issued by the Kernel to allow a process to access a specific resource. | **4663** (Object Access) | `8.1.7_Security_Context_Tokens_Handles_and_Pointers.md` |
| **Rundll32** | A trusted Windows utility used to execute code within DLLs; a high-frequency execution proxy. | **4688**, **Sysmon ID 1**, **Sysmon ID 7** | `8.1.12_Rundll32_Execution_and_DLL_Loading.md` |

## 2. Component Object Model (COM) & Registry

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **CLSID** | Class ID; a unique GUID that identifies a specific COM functional component. | **4657** (Registry Value Change) | `8.1.6_COM_Architecture_and_Registry_Ledger.md` |
| **RPCSS** | The COM Service Control Manager; the "Foreman" that activates COM objects. | **4688** (Process Creation: `dllhost.exe`) | `8.1.11_RPCSS_and_COM_Surrogate_Orchestration.md` |
| **Surrogate** | `dllhost.exe`; a process that hosts COM objects outside the client process. | **4688** (Parent: `svchost.exe`) | `8.1.11_RPCSS_and_COM_Surrogate_Orchestration.md` |

## 3. Execution & Memory Management

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **Syscall** | Instruction used to cross from User Mode (Ring 3) to Kernel Mode (Ring 0). | **Sysmon ID 25** (Process Tampering) | `8.1.8_Kernel_Guardrails_and_Verification_Logic.md` |
| **PEB** | Process Environment Block; a user-mode structure containing process metadata. | N/A (Memory Forensics) | `8.1.9_PEB_and_TEB_Structures.md` |
| **Manual Map** | Evasion technique where malware acts as its own loader to stay "fileless". | **Sysmon ID 7** (Missing Image Load) | `8.1.10_Manual_Mapping_and_IAT_Reconstruction.md` |
| **IAT** | Import Address Table; a table of function pointers resolved at runtime. | N/A (Memory Analysis) | `8.1.10_Manual_Mapping_and_IAT_Reconstruction.md` |

## 4. Key Security Boundaries & Telemetry

* **Ring 3 vs Ring 0**: The fundamental split between unprivileged apps and the privileged Kernel.
* **ETW (Event Tracing for Windows)**: The telemetry backbone used by EDRs to subscribe to provider data.
* **AMSI (Antimalware Service Interface)**: The in-memory buffer scanner, often bypassed by Native/Manual Mapping techniques.
* **DLL Search Order:** The specific sequence Windows follows to resolve and load libraries; manipulated during DLL Side-loading attacks to hijack execution.
