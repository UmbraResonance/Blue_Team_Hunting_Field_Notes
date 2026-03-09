# Use Case: Non-ASCII Characters in Identity Directory Events

## Metadata & Governance
**Name:** Non-ASCII Characters in Identity Directory Events
**Severity:** Medium
**Status:** Experimental
**ATT&CK Tags:** - T1036 - Masquerading
- Defense Evasion

## Threat Context
**Description:** Detects potential obfuscation or directory anomalies by identifying the presence of non-ASCII characters (unicode codepoints > 127) in account-related fields (UPN and SAM account names). Attackers often use homoglyph/homograph attacks (e.g., replacing a Latin 'a' with a Cyrillic 'а') to create accounts that look legitimate to human administrators but are distinct in system logs, facilitating masquerading and evasion.

## Detection Logic (Layered Detection)
### Layer 1: Pattern Identification (Phase 2)
* **Goal:** Identify characters outside the standard ASCII range (0-127).
* **Logic:** Apply regex `[^\x00-\x7F]` to key identity directory fields:
    * `TargetUserName`
    * `UserPrincipalName`
    * `SamAccountName`
    * `DisplayName`
* **Filter:** Legitimate international characters in multi-national organizations or service accounts with localized naming conventions.
* **Alert:** Trigger alert when an identity object is created or modified with suspicious non-ASCII characters.

## Engineering Requirements (Data Sources)
* **Log Source:** M365 (identity_directory_events)
* **Fields Required:** `TargetAccountUpn`, `AccountUpn`, `AccountName`, `DisplayName`

## Validation (Phase 4)
* **Manual Testing:**
    * **Basic:** Create a test user in Entra ID/AD with a Cyrillic character in the display name.
    * **Scripted:** Use PowerShell to generate a bulk creation of accounts using various non-standard Unicode characters.
* **Success Criteria:**
    * **Regex Fidelity:** The regex correctly flags characters such as `ñ`, `а`, or `é`.
    * **Zero Misses:** All four targeted fields are successfully monitored.