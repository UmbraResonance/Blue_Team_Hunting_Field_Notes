# Master Internals-to-Events Glossary

> **Purpose**: This glossary bridges the gap between abstract Windows Internal concepts and concrete forensic artifacts. It serves as a rapid-mapping guide for Detection Engineering and Threat Hunting.

## 1. Core Identity & Access Control

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **Access Token** | A kernel object describing the security context of a user; your "Digital ID Badge". | **4624** (Logon), **4672** (Privileged Logon) | `8.1.2_Access_Tokens.md` |
| **SID** | Security Identifier; a unique value of variable length used to identify a trustee (User/Group). | **4624**, **4634** (Logoff) | `8.1.2_Access_Tokens.md` |
| **SACL** | System Access Control List; determines which access attempts generate audit records. | **4663** (Object Access) | `8.1.1_Object_Security_SACL.md` |
| **Handle** | An abstract "Voucher" issued by the Kernel to allow a process to access a specific resource. | **4663** (Object Access) | `8.1.7_Security_Context_Tokens_Handles_and_Pointers.md` |

## 2. Component Object Model (COM) & Registry

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **CLSID** | Class ID; a unique GUID that identifies a specific COM functional component. | **4657** (Registry Value Change) | `8.1.6_COM_Architecture_and_Registry_Ledger.md` |
| **AppID** | Application ID; defines the security settings (permissions/identity) for one or more CLSIDs. | **4657** (Registry Change) | `8.1.6_COM_Architecture_and_Registry_Ledger.md` |
| **RPCSS** | The COM Service Control Manager; the "Foreman" that activates COM objects. | **4688** (Process Creation: `dllhost.exe`) | `8.1.6_COM_Architecture_and_Registry_Ledger.md` |

## 3. Execution & Memory Management

| Internals Term | Plain English Definition | Primary Event IDs | Related Internal Docs |
| :--- | :--- | :--- | :--- |
| **Syscall** | The assembly-level instruction used to cross from User Mode (Ring 3) to Kernel Mode (Ring 0). | **Sysmon ID 25** (Process Tampering) | `8.1.5_The_User_Mode_Ecosystem_and_Call_Stack.md` |
| **ntdll.dll** | The final User Mode library; the gateway that exports the Native API and initiates Syscalls. | **4688** (Image Load) | `8.1.5_The_User_Mode_Ecosystem_and_Call_Stack.md` |
| **PEB** | Process Environment Block; a user-mode data structure containing process-specific metadata. | N/A (Detected via Memory Analysis) | `8.1.7_In_Memory_Execution_and_AMSI_Bypass.md` |
| **SSDT** | System Service Descriptor Table; the Kernel's "Service Menu" used to map Syscall IDs to functions. | N/A (Kernel-level monitoring) | `8.1.8_Kernel_Guardrails_and_Verification_Logic.md` |

## 4. Key Security Boundaries

* **Ring 3 (User Mode)**: Where your browser and .NET apps live. Heavily monitored but easily "blinded" by advanced evasion.
* **Ring 0 (Kernel Mode)**: The "Safe" zone where the CPU executes privileged instructions and the **Final Access Check** occurs.
* **AMSI (Antimalware Service Interface)**: The "In-memory Guard" for scripts and managed code; often bypassed by Native code execution.

---

### 💡 Hunting Implementation Tip:

When performing **Threat Hunting**, follow this workflow:
1.  **Observe**: See high volumes of **Event 4663** (Object Access Attempted) in your SIEM.
2.  **Map**: Consult this glossary; Event 4663 maps to **Handle** and **SACL**.
3.  **Analyze**: Reference `8.1.7`; recall that advanced adversaries create handles even when bypassing APIs.
4.  **Verify**: Check the **Thread Stack** for addresses outside of `ntdll.dll` memory space to confirm a **Direct Syscall** attack.