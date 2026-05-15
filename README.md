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
4.  **Engineering-First Approach:** Detections are not just "queries"; they follow a strict Detection Development Lifecycle (DDLC) to ensure quality, vendor-neutrality, and verifiable results.
5.  **First-Principles Thinking:** Operational commands (01, 06) are backed by deep OS internals knowledge (08). We don't just run queries; we understand how the OS generates the artifacts (e.g., how EPROCESS/VAD structures expose DKOM evasion, or why Kerberos delegation misconfigurations enable RBCD attacks).
6.  **Layered Cross-Reference:** Malware TTPs (04) are explicitly anchored to OS internals (08) — e.g., Process Hollowing references VAD tree mechanics, and COM Hijacking references RPCSS architecture.
7.  **Force Multiplication:** Codifying manual tradecraft and research (01-08) into automated, reusable modules (09) to ensure defense operates at machine speed.

---

## 📂 The Arsenal (Architecture)

| Directory | Purpose | Key Use Case |
| :--- | :--- | :--- |
| **[`01_Hunting_Cheatsheets`](./01_Hunting_Cheatsheets/)** | **Log & Artifact Reference** | "Eyes-on-glass" hunting reference. Covers MITRE-mapped hunting matrix, Event ID deep-dive with cross-protocol failure code tables, process genealogy, network protocol filters (Wireshark/BPF), forensic artifact map, and memory analysis commands. |
| **[`02_Detection_Rules`](./02_Detection_Rules/)** | **Detection Logic (Sigma rules + YARA notes)** | Heuristic rules driven by the [DDLC Framework](./02_Detection_Rules/!DDLC_Workflow.md). Includes use-case design (2.1) and engineering-focused implementation notes. |
| **[`03_DFIR_Playbooks`](./03_DFIR_Playbooks/)** | **Incident Response SOPs** | Standardized response workflows organized into two tracks: **`3.1_Playbooks`** (phishing analysis, network forensics) and **`3.2_Investigation_Workflows`** (memory forensics — phase-driven Volatility 3 + MemProcFS workflow). |
| **[`04_Malware_Analysis`](./04_Malware_Analysis_Cheatsheets/)**| **Malware Analysis Playbooks** | TTP-to-API behavior reference, static triage (PE/x64 asm/Windows API), and dynamic debugging workflows. |
| **[`05_Threat_Intel`](./05_Threat_Intelligence_Library/)** WIP| **Adversary Knowledge Base** | Adversary profiles (APTs) and Diamond Model strategies. |
| **[`06_Tool_Vault`](./06_Tool_Command_Vault/)** | **Query & Command Vault** | Operator-grade command reference. Covers DFIR tooling (KAPE, EZ Tools), cross-platform live response (Windows/Linux), SIEM query languages (Splunk SPL, Elastic Elastic KQL/EQL/ESQL), network analysis & detection (tshark/Zeek, Snort 3/Suricata), and agentic DFIR (Velociraptor VQL). |
| **[`07_Reporting`](./07_Reporting_Templates/)** | **Documentation & Evidence** | **Operational Core.** Timeline trackers, evidence logs (chain of custody), malware analysis reports, CTI attribution workbench (Diamond Model), and final incident reports. |
| **[`08_Underlying_Principles`](./08_Underlying_Principles/)** | **OS Internals & Security Architecture** | Windows Internals (Ring 0/3, DKOM, NTFS), Active Directory (Kerberos, AD CS, Delegation), and Cross-Protocol Authentication. Includes a narrative review path stitching the fragments into a coherent adversary lifecycle story. |
| **[`09_Automation_Vault`](./09_Automation_Vault/)** | **Security Automation Hub** | **Scaling Defense.** Modular scripts for Identity & AD auditing, DFIR triage, and CTI collection pipelines. |
| **[`10_Case_Studies`](./10_Case_Studies/)** | **End-to-End Investigations** | End-to-End investigation teardowns spanning purple teaming, DFIR, and malware analysis — bridging offensive mechanics with defensive detection. |

---

## ⚡ Operational Workflow (Incident Lifecycle)

How to utilize this repository during a live incident:

### Phase 1: Triage & Detection
* **Trigger:** Alert received or anomaly detected.
* **Action:** Consult **`01_Hunting`** to interpret raw logs (Windows/Network).
* **Documentation:** Open **`7.1_Timeline_Tracker.csv`** immediately to start logging the narrative.

### Phase 2: Investigation & Analysis
* **Action:** Use **`06_Tool_Vault`** to execute precise forensic collection and SIEM querying (SPL/KQL).
* **Action:** Log all extracted artifacts into **`7.2_Evidence_Artifact_Log.csv`** (Chain of Custody).
* **Deep Dive:** If malware is recovered, analyze using **`04_Malware`** and produce **`7.3_Malware_Analysis_Report.md`**.

### Phase 3: Containment & Intelligence
* **Action:** Execute containment steps from **`03_Playbooks`**.
* **Attribution:** Pivot from artifacts to attribution using **`7.4_DFIR_to_CTI_Workbench.md`** (Diamond Model).

### Phase 4: Deliverable
* **Action:** Synthesize all findings into **`7.5_Final_Incident_Report_Template.md`**.
* **Continuous Improvement:** Feed lessons learned back into the [DDLC Workflow](./02_Detection_Rules/!DDLC_Workflow.md) to develop new, verified detection rules.

### Continuous Improvement (The Loop):
* **Gap Analysis:** If a detection was missed, verify existing logic in `01_Hunting`.
* **Deep Dive:** Consult `08_Underlying_Principles` to understand the theoretical mechanism before writing new rules.
* **Structured Review:** Utilize the `_00_Review_Path.md` to conduct systematic study sessions, connecting isolated artifacts and techniques into a cohesive narrative of the adversary lifecycle.
* **Engineering:** Codify verified hunting and response logic into `09_Automation_Vault` to automate repetitive tasks (e.g., AD auditing, CTI collection).
* **Pressure Testing:** Use the teardowns and simulations in `10_Case_Studies` to continuously validate and refine the entire arsenal.

---

## 🛑 Standard Operating Procedures (SOPs)

Recognizing that reactive incident response and proactive security engineering require different operational mindsets, this repository strictly adheres to a dual-track SOP structure.

### Track A: Incident Response & DFIR (Reactive)
*Core Objective: Maintain Chain of Custody, ensure rapid containment, and preserve forensic integrity during live incidents.*
1.  **Write it Down:** If it is not documented in the *Timeline Tracker*, it did not happen.
2.  **UTC is King:** All extracted logs and timeline entries must be strictly converted to UTC for accurate correlation.
3.  **Hash Everything:** Never extract or handle a file from a compromised host without calculating and logging its SHA256 immediately.
4.  **Pivot Relentlessly:** An alert is merely a starting point. Use the *CTI Workbench* to pivot from localized artifacts to the adversary's broader infrastructure.

### Track B: Purple Teaming & Detection Engineering (Proactive)
*Core Objective: Deepen TTP understanding, validate telemetry generation, and expand detection coverage through safe emulation.*
1.  **Execution Context Over Hashes:** File hashes are brittle; behaviors are not. Prioritize documenting exact payload generation commands, CLI arguments, and obfuscation routines over static file hashes.
2.  **ATT&CK Mapping:** Every emulated adversary action must be explicitly linked to a MITRE ATT&CK sub-technique to measure and visualize defensive coverage.
3.  **Telemetry Validation:** The goal is not simply to "execute the exploit," but to scientifically verify if the underlying OS telemetry (e.g., Sysmon, ETW, EID 4104) successfully captured the targeted behavior.
4.  **Close the Loop:** Every emulation exercise must result in either the validation of an existing detection rule or the creation of a new Sigma/YARA draft routed into the DDLC pipeline.

---

## ⚠️ Disclaimer

* **For Defense Only:** The techniques described here are for defensive security analysis, incident response, and educational purposes.
* **Context Matters:** Every environment is different. Validate logic before production deployment.

---

*Maintained by Juana | Cyber Security Analyst* *Last Updated: May 2026*
