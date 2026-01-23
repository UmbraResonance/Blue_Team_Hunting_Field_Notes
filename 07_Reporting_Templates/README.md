# Reporting & Documentation Standards

Standardized templates for incident documentation, chain of custody, and intelligence analysis.

## Template Usage

### 1. [Timeline_Tracker.csv](https://github.com/UmbraResonance/Blue_Team_Knowledge_Base/blob/main/07_Reporting_Templates/7.1_Timeline_Tracker.csv))

**Purpose:** The central operational narrative. Records "Events" and "Actions".

* **Primary Key:** `Timestamp_UTC`. All cross-system correlation must use UTC.
* **Usage:**
  * Log key findings immediately during triage.
  * Use `Timestamp_Local` only for reconstructing user context (e.g., business hours vs. after hours).
  * Link to physical files using the `Evidence_Ref` column (e.g., `EV-01`).

### 2. [Evidence_Artifact_Log.csv](https://github.com/UmbraResonance/Blue_Team_Knowledge_Base/blob/main/07_Reporting_Templates/7.1_Timeline_Tracker.csv)

**Purpose:** Chain of Custody (CoC). Records "Objects" and "Assets".

* **Scope:** Extracted malware samples, memory dumps, disk images, and **exported** log files (CSV/JSON).
* **Standards:**
  * **Hash:** Calculate SHA256 immediately upon acquisition to ensure integrity.
  * **Storage:** Note the physical location (e.g., "Encrypted Cold Storage", "Malware Sandbox").
  * **SIEM Logs:** Do not log simple queries here. Only log **exported files** that serve as tangible evidence.

---

## ⚡ Operational SOP

### 1. Timeline vs. Evidence Log

* **Timeline Tracker:** Records **Actions**.
* *Example:* "10:00 UTC - Admin executed malicious script."

* **Evidence Log:** Records **Objects**.
* *Example:* "EV-01 - `script.ps1` (SHA256: `a1b2...`) extracted from host."

### 2. Timezone Discipline

* **Mandatory UTC:** All logs (Firewall, Cloud, Server) must be normalized to UTC in the tracker.
* **Offset:** Always record the `Timezone_Offset` of the source system to prevent analysis errors.

### 3. Naming Convention

* **Evidence ID:** Use sequential `EV-XX` format.
* **Reference:** The `Evidence_Ref` in the Timeline must match the `Evidence_ID` in the Artifact Log.
