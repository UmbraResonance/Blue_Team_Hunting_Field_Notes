# Reporting & Documentation Standards

Standardized templates for incident documentation, chain of custody, and intelligence analysis.

## Template Usage & Workflow

### 1. [Timeline_Tracker.csv](./7.1_Timeline_Tracker.csv)
**Phase: Triage & Response**
* **Purpose:** The central narrative. Records "Events" (What happened?) and "Actions" (What did we do?).
* **Key Rule:** Mandatory use of `Timestamp_UTC` for correlation. Link to evidence using `EV-XX` IDs.

### 2. [Evidence_Artifact_Log.csv](./7.2_Evidence_Artifact_Log.csv)
**Phase: Collection & Preservation**
* **Purpose:** Chain of Custody (CoC). Records "Objects" (Files, Logs, Memory).
* **Key Rule:** Calculate SHA256 immediately upon acquisition.
* **Exam Mode:** Use as a text scratchpad for recording Flags, IP addresses, and Log queries.

### 3. [Malware_Analysis_Report.md](./7.3_Malware_Analysis_Report.md)
**Phase: Deep Dive Analysis**
* **Purpose:** Technical dissection of specific malicious binaries found during the incident.
* **Input:** Malware samples extracted and logged in `7.2`.
* **Output:** Capabilities, Configs, and Indicators (IOCs) that feed into the CTI Workbench.

### 4. [DFIR_to_CTI_Workbench.md](./7.4_DFIR_to_CTI_Workbench.md)
**Phase: Attribution & Intelligence**
* **Purpose:** Bridge between raw artifacts and strategic context.
* **Features:**
    * **Diamond Model:** Map the Campaign (Adversary + Infrastructure + Capability + Victim).
    * **Analytical QA:** Use the integrated "Gap Analysis" section to validate your findings.
    * **Activity Threads:** Link multiple diamonds to reconstruct complex attack chains.

### 5. [Final_Incident_Report_Template.md](./7.5_Final_Incident_Report_Template.md)
**Phase: Deliverable**
* **Purpose:** The official output for Management (Executive Summary) and Engineering (Technical Analysis).
* **Synthesis:** Aggregates the Timeline (7.1), Evidence (7.2), and Analysis findings (7.3 & 7.4) into one document.

---

## ⚡ Operational SOP

### 1. Timeline vs. Evidence Log
* **Timeline Tracker (7.1)** = **Actions & Events (Red & Blue)**.
    * *Attacker Actions:* "Admin executed malicious script."
    * *Defender Actions:* "Analyst isolated host via EDR." (**CRITICAL:** Record all containment/remediation steps here to calculate MTTR).
    * *Format:* "10:00 UTC - Admin executed malicious script."
    * *Do not:* Do not clutter this with full file hashes or raw log dumps. Use the Reference ID (`EV-01`).
* **Evidence Log (7.2)** = **Objects & Assets**.
    * *Format:* "EV-01 | script.ps1 | SHA256: a1b2..."
    * *Rule:* If you extracted it, exported it, or isolated it, it goes here.

### 2. Timezone Discipline
* **Mandatory UTC:** The `Timestamp_UTC` column in the Timeline is the **only** source of truth for sorting.
* **Source Offset:** Always record the `Timezone_Offset` (e.g., UTC+8) of the source system.
    * *Reason:* To correctly reconstruct the user's local context (e.g., "Was it midnight or 9 AM for the user?").

### 3. Naming & Linking
* **Evidence ID:** Use sequential `EV-01`, `EV-02` format.
* **Cross-Referencing:**
    * `7.1 Timeline` points to `EV-01`.
    * `7.3 Malware Report` analyzes `EV-01`.
    * `7.5 Final Report` cites `EV-01` as IoC.

### 4. Campaign Analysis (Activity Threads)
* **Multi-Stage Attacks:** Do not create multiple CTI files.
* **Structure:** Duplicate **"Section 3: Diamond Model"** within `7.4_DFIR_to_CTI_Workbench.md` for each stage.
* **Linkage:** Explicitly define the `Previous Event` (Cause) and `Next Event` (Effect) to visualize the attack chain (e.g., *Phishing Diamond* → *C2 Diamond*).