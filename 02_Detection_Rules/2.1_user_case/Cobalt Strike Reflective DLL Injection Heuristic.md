# Use Case: Cobalt Strike Reflective DLL Injection Heuristic

## Metadata & Governance
**Name:** Cobalt Strike Reflective DLL Injection Heuristic
**Severity:** High
**Status:** Experimental
**ATT&CK Tags:** - T1620 - Reflective Code Loading

## Threat Context
**Description:** Detects potential Reflective DLL Injection (RDI) by identifying processes that spawn and trigger Remote Thread Creation (Event ID 8) without any corresponding Image Load (Event ID 7). This heuristic approach targets the core behavior of memory-only payloads (like Cobalt Strike Beacons) that bypass traditional disk-based detection by loading code directly into a process's address space.

## Detection Logic (Layered Detection)
### Layer 1: Heuristic Correlation (Phase 2)
* **Goal:** Detect the specific execution sequence of RDI.
* **Logic:** Use Sigma Correlation to associate three specific events within a 5-minute window, grouped by `ProcessGuid`:
    1. **Process Creation** (Sysmon EID 1).
    2. **Remote Thread Creation** (Sysmon EID 8).
    3. **Missing Image Load** (Sysmon EID 7).
* **Filter:** Exclude known noise from JIT compilers (e.g., .NET, Java) and internal browser process management.
* **Alert:** Trigger a high-priority alert if a remote thread is created but no associated DLL image is registered as loaded.

## Engineering Requirements (Data Sources)
* **Log Source:** Windows Sysmon
* **Sysmon Event ID 1 (Process Creation):** `ProcessGuid`, `Image`, `ParentImage`, `CommandLine`
* **Sysmon Event ID 8 (CreateRemoteThread):** `ProcessGuid`, `RemoteThreadId`, `TargetImage`
* **Sysmon Event ID 7 (Image Loaded):** `ProcessGuid`, `ImageLoaded`

## Validation (Phase 4)
* **Manual Testing:**
    * **Atomic Test:** Execute a reflective loader (e.g., via Cobalt Strike or open-source RDI tools) targeting `notepad.exe`.
    * **Edge Case:** Verify that legitimate DLL loads (standard software updates) do not trigger the correlation.
* **Success Criteria:**
    * **Alert Fidelity:** SIEM successfully joins the events via `ProcessGuid` within 5 minutes.
    * **Field Accuracy:** The `TargetImage` and `RemoteThreadId` fields are correctly populated.