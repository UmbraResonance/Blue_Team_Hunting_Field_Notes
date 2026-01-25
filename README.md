# 🛡️ Blue Team Threat Hunting Field Notes

> **My personal arsenal of detection logic, query syntax, and artifact analysis.**
> *Curated for operational utility, rapid deployment, and high-pressure environments.*

---

## 📖 About This Field Manual

This repository is **not a textbook**; it is my **personal combat notebook**.

It serves as a centralized, living collection of tradecraft and detection strategies that I have researched, tested, and curated for my own use as a Security Analyst. The content here reflects my personal methodology in dissecting TTPs and translating them into actionable defense mechanisms.

The goal is to bridge the gap between abstract threat intelligence and the specific, often messy reality of log analysis in the field.

---

## 🧠 Design Philosophy

I built this repository to solve specific challenges I encounter in daily operations:
1.  **Zero Friction Retrieval:** When an alert fires, I need the exact Wireshark filter or Volatility command *now*.
2.  **Detection-as-Code:** Moving from manual hunting queries to automated detection rules to prevent recurrence.
3.  **Strict SOPs:** Standardized templates to ensure findings are recorded with legal and forensic precision (Chain of Custody).

---

## 📂 The Arsenal (Architecture)

| Directory | Purpose | Key Use Case |
| :--- | :--- | :--- |
| **[`01_Hunting_Cheatsheets`](./01_Hunting_Cheatsheets/)** | **Log & Artifact Reference** | "Eyes-on-glass" hunting. Rapid lookup for Event IDs, Process Genealogy, and Artifact paths. |
| **[`02_Detection_Rules`](./02_Detection_Rules/)** | **Detection Logic \(Sigma/YARA\)** | Heuristic rules (YAML/Sigma) for SIEM/EDR engineering. |
| **[`03_DFIR_Playbooks`](./03_DFIR_Playbooks/)** | **Incident Response SOPs** | SOPs for specific incident types (e.g., Phishing). |
| **[`04_Malware_Analysis`](./04_Malware_Analysis_Cheatsheets/)** WIP| **Reverse Engineering Guides** | Reverse engineering checklists and lab command references. |
| **[`05_Threat_Intel`](./05_Threat_Intelligence_Library/)** WIP| **Adversary Knowledge Base** | Adversary profiles (APTs) and Diamond Model strategies. |
| **[`06_Tool_Vault`](./06_Tool_Command_Vault/)** | **Command Syntax Library** | Pure command reference (KAPE, Volatility, Zimmerman Tools). |
| **[`07_Reporting`](./07_Reporting_Templates/)** | **Documentation & Evidence** | **Operational Core.** Timeline trackers, Evidence logs, and Final Reports. |

---

## ⚡ Operational Workflow (Incident Lifecycle)

How to utilize this repository during a live incident:

### Phase 1: Triage & Detection
* **Trigger:** Alert received or anomaly detected.
* **Action:** Consult **`01_Hunting`** to interpret raw logs (Windows/Network).
* **Documentation:** Open **`7.1_Timeline_Tracker.csv`** immediately to start logging the narrative (Red & Blue actions).

### Phase 2: Investigation & Analysis
* **Action:** Use **`06_Tool_Vault`** to execute precise forensic collection.
* **Action:** Log all extracted files into **`7.2_Evidence_Artifact_Log.csv`** (Chain of Custody).
* **Deep Dive:** If malware is recovered, analyze using **`04_Malware`** and produce **`7.3_Malware_Analysis_Report.md`**.

### Phase 3: Containment & Intelligence
* **Action:** Execute containment steps from **`03_Playbooks`** and log them in the Timeline.
* **Attribution:** Pivot from artifacts to attribution using **`7.4_DFIR_to_CTI_Workbench.md`** (Diamond Model).

### Phase 4: Deliverable
* **Action:** Synthesize all findings into **`77.5_Final_Incident_Report_Template.md`**.
* **Feedback:** Create new rules in **`02_Detection`** to close the gap.

---

## 🛑 Standard Operation Procedure (SOP)

1.  **Write it Down:** If it's not in the *Timeline Tracker*, it didn't happen.
2.  **UTC is King:** All logs must be converted to UTC for correlation.
3.  **Hash Everything:** Never extract a file without calculating its SHA256 immediately.
4.  **Pivot:** Don't stop at the alert. Use the *CTI Workbench* to find the infrastructure behind the attack.

---

## ⚠️ Disclaimer

* **For Defense Only:** The techniques described here are for defensive security analysis, incident response, and educational purposes.
* **Context Matters:** Every environment is different. Validate logic before production deployment.

---

*Maintained by Juana | Cyber Security Analyst*
*Last Updated: January 2026*