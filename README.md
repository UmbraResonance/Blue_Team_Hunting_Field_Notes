# Blue Team Threat Hunting Field Notes

> **My personal arsenal of detection logic, query syntax, and artifact analysis.**
>
> *Curated for operational utility, rapid deployment, and high-pressure environments.*

---

## 📖 About This Field Manual

This repository is **not a textbook**; it is my **personal combat notebook**.

It serves as a centralized, living collection of tradecraft and detection strategies that I have researched, tested, and curated for my own use as a Security Analyst. The content here reflects my personal methodology in dissecting TTPs and translating them into actionable defense mechanisms.

The goal is to bridge the gap between abstract threat intelligence and the specific, often messy reality of log analysis in the field.

## 🧠 Design Philosophy (Why This Exists)

I built this repository to solve specific challenges I encounter in daily operations:

1.  **Zero Friction Retrieval:** When an alert fires, I don't want to browse documentation. I need the exact Wireshark filter or Volatility command *now*.
2.  **Goal-Oriented Structure:** Artifacts are organized by **Investigation Goal** (e.g., "Find Hidden Processes"), not just by tool name.
3.  **Detection-as-Code:** Moving from manual hunting queries to automated detection rules (YAML/Sigma) to prevent recurrence.
4.  **Standardized Output:** Templates to ensure that findings are recorded with legal and forensic precision.

---

## 📂 The Arsenal (Directory Structure)

This repository is organized to follow the lifecycle of a security incident: **Hunt -> Detect -> Respond -> Analyze -> Report**.

### [`01_Hunting_Cheatsheets`](./01_Hunting_Cheatsheets/)
**The "Map" (Discovery Phase).**
High-density CSV tables designed for "eyes-on-glass" hunting. Used to spot anomalies in raw data.
* **`1.1_Master_Hunting_Matrix`**: Central index of hunting hypotheses.
* **`1.2_Windows_Process_Genealogy`**: Reference for normal vs. malicious parent-child process relationships.
* **`1.3_Network_Protocol_Filters`**: Wireshark filters for C2, Recon, and Exfil patterns.
* **`1.4_Forensics_Artifacts_Map`**: Disk artifact mapping (Amcache, ShimCache, ShellBags) organized by investigation goal.
* **`1.5_Memory_Analysis_Volatility`**: Volatility 3 command reference for finding rootkits and injection.

### [`02_Detection_Rules`](./02_Detection_Rules/)
**The "Code" (Engineering Phase).**
Where hunting logic is solidified into automated rules.
* Contains heuristic rules (YAML/Sigma) for SIEM/EDR.
* *Example:* `Cobalt Strike Reflective DLL Injection Heuristic.yaml`

### [`03_DFIR_Playbooks`](./03_DFIR_Playbooks/)
**The "Script" (Response Phase).**
Standard Operating Procedures (SOPs) for specific incident types.
* Step-by-step guides for Phishing, Ransomware, and Account Compromise.
* Ensures consistent triage and containment processes.

### [`04_Malware_Analysis_Cheatsheets`](./04_Malware_Analysis_Cheatsheets/)
**The "Deep Dive" (Analysis Phase).**
Reference checklists for dissecting malicious binaries.
* **Static Analysis:** PE header anomalies, suspicious imports, and packing indicators.
* **Dynamic Analysis:** Sandbox monitoring points and anti-evasion checks.
* **Deobfuscation:** CyberChef recipes for decoding payloads.
* **Assembly:** x86/x64 basics for identifying key logic flows.

### [`05_Threat_Intelligence_Library`](./05_Threat_Intelligence_Library/)
**The "Context" (Attribution Phase).**
Knowledge base on Threat Actors and TTPs.
* Adversary profiles (APT groups, Ransomware gangs).
* MITRE ATT&CK mapping and Campaign tracking logs.

### [`06_Tool_Command_Vault`](./06_Tool_Command_Vault/)
**The "Dictionary" (Reference).**
Pure syntax reference for tools.
* "How-to" guides for Nmap, PowerShell, KAPE, etc.
* Used when I know *what* I want to do, but forget the specific flags.

### [`07_Reporting_Templates`](./07_Reporting_Templates/)
**The "Deliverable" (Communication Phase).**
Templates for documenting findings and producing final reports.
* **Timeline Tracker:** For unifying timestamps across UTC and Local timezones.
* **Evidence Log:** Chain of custody tracking for extracted artifacts.
* **DFIR_to_CTI_Workbench:** Framework for converting raw artifacts into intelligence and TTP mapping.

---

## ⚡ Operational Workflow

My typical workflow using this repository:

1.  **Triage:** Use **`01_Hunting`** to filter noise and identify the smoking gun (e.g., suspicious PCAP or Prefetch).
2.  **Record:** Log findings immediately into **`07_Reporting`** (Timeline Tracker).
3.  **Analyze:** If malware is recovered, use **`04_Malware`** checklists to extract IOCs.
4.  **Contain:** Follow **`03_Playbooks`** to isolate and remediate.
5.  **Engineer:** Take the findings and write a new rule in **`02_Detection`** to catch it next time.

---

## ⚠️ Disclaimer

* **For Defense Only:** The techniques described here are for defensive security analysis, incident response, and educational purposes.
* **Context Matters:** Every environment is different. "Tuning" logic provided here should be validated against your own baseline before deployment in production.

---

*Maintained by Juana | Cyber Security Analyst*
*Last Updated: January 2026*
