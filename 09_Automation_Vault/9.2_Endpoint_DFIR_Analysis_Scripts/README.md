# 9.2 Endpoint DFIR Analysis [Dehydrated]

This module provides **"Panic Button"** scripts for rapid volatile data collection and high-performance log hunting during live incidents.

## 📂 Script Inventory

| Script | Platform | Function | Use Case |
| :--- | :--- | :--- | :--- |
| `Get-EndpointTriage.ps1` | Windows | **The Panic Button.** Collects processes, network connections, DNS cache, and services. | Phase 1: Rapid Triage |
| `Search-SecurityEvents.ps1` | Windows | High-performance hunter using `FilterHashtable` for rapid Security log analysis. | Phase 2: Targeted Investigation |
| `triage.sh` | Linux | Native bash script to collect persistence (Cron/Systemd), network, and auth logs. | Phase 1: Linux Live Response |

## 🚀 Usage Notice

> **Note:** To protect the intellectual property of the detection logic and prevent potential misuse, the core functional code has been removed from this public repository. 
> 
> These scripts demonstrate **forensic collection standards** and **automation workflows**. If you are a recruiter or a security professional interested in the full implementation for legitimate purposes, please contact the author.