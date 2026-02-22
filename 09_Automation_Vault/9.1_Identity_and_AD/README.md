# 9.1 Identity & AD Automation

This module focuses on the **proactive auditing and hardening** of Active Directory environments. The scripts here are designed to identify common misconfigurations and "Shadow Admin" pathways that lead to domain-wide compromise.

## 📂 Script Inventory

| Script | Purpose | Underlying Principle |
| :--- | :--- | :--- |
| `Audit-ADAdminPersistence.ps1` | Detects stale accounts with `adminCount=1` that are no longer in protected groups. | [8.2.04 Governance] |
| `Audit-ADKerberoasting.ps1` | Audits SPNs allowing weak RC4 encryption and identifies non-gMSA service accounts. | [8.2.06 Kerberos Logic] |
| `Audit-ADKerberosDelegation.ps1` | Audits risky Kerberos delegation setups (Unconstrained, KCD, RBCD) and checks Machine Account Quota (MAQ). | [8.2.06 Kerberos Logic] |
| `Audit-ADRootTrustAndDCSync.ps1` | Combined audit for krbtgt account health (Golden Ticket risk) and DCSync permissions. | [8.2.10 DCSync Logic] |
| `Audit-ADSidHistory.ps1` | Scans for the `sIDHistory` attribute to identify potential SID Injection backdoors. | [8.2.01 Identity Principals] |
| `Audit-LAPSSafetyCheck.ps1` | Verifies AD Schema confidentiality and audits OU delegation for LAPS passwords. | [8.2.04 Governance] |
| `Find-ADUserClearText.ps1` | Greps AD user attributes (Description, Notes) for clear-text passwords. | N/A (Standard Audit) |
| `Audit-ESC1AttackSurface.ps1` | Audits Certificate Templates for SAN impersonation (ESC1) and evaluates ACL exposure. | [8.2.15 AD CS ESC1 Logic] |
| `Audit-CoercedAuthAttackSurface.ps1` | Audits attack surfaces for coerced authentication (MS-RPRN, MS-EFSR, MS-FSRVP) and AD CS Web Enrollment (ESC8). | [8.2.13 Coercion & ESC8 Logic] |

## 🚀 Usage

> **Notice:** The full functional code for these scripts has been removed from the public repository to prevent unauthorized abuse in production environments. 
> 
> These versions serve as a demonstration of **Detection Engineering** logic and **PowerShell tool development** standards. If you are a cybersecurity professional and wish to discuss the underlying logic or obtain the full implementation for legitimate research/auditing purposes, please contact the author via LinkedIn or GitHub DM.