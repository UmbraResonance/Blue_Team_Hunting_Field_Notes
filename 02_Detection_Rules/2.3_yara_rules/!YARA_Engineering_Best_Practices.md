# YARA Engineering & Deep Static Analysis Field Notes

## 1. OPSEC & Deployment Strategy
* **Passive Nature:** YARA is a pattern-matching engine, not an active mitigation tool. In modern SOC architectures, YARA serves as the detection logic (the "eyes") deployed via EDR platforms, which then handle the active blocking (the "hands").
* **OPSEC Constraints:** Avoid uploading targeted, unverified suspicious binaries to public cloud sandboxes (e.g., VirusTotal, Any.Run) during active incidents. Threat actors actively monitor these platforms for their payload hashes. 
* **Localized Hunting:** Prioritize localized static analysis and the development of internal YARA/Sigma rules. Deploying these rules through internal EDR/SIEM keeps the detection mechanisms strictly confidential and invisible to the adversary.

## 2. String Modifiers & Extraction Techniques
### 2.1 Essential String Modifiers
Applying appropriate modifiers is critical to reducing false positives and catching evasion techniques:
* `wide`: Mandatory for matching UTF-16LE encoded strings, which are standard for Windows APIs and internal OS structures.
* `ascii wide`: Best practice to simultaneously capture both single-byte and double-byte encodings of the same string.
* `fullword`: Prevents partial matches by ensuring the string is bounded by non-alphanumeric characters (e.g., matching `cmd` without triggering on `macmd5`).
* `nocase`: Essential for neutralizing script-based case randomization evasion (e.g., `pOwErShElL.exe`).

### 2.2 Advanced String Extraction
When conducting triage in a headless Linux environment without access to advanced dynamic tools:

**Headless Static Extraction (Bash One-Liner):**
Extracts both ASCII and Wide strings, prepends their decimal offsets, and sorts them by physical location to reconstruct the contextual order of strings within the binary:
    ```bash
    ( strings -a -td "$@" | sed 's/^\(\s*[0-9][0-9]*\) \(.*\)$/\1 A \2/' ; strings -a -td -el "$@" | sed 's/^\(\s*[0-9][0-9]*\) \(.*\)$/\1 W \2/' ) | sort -n
    ```

*Note: For comprehensive extraction, especially involving stack strings or encoded payloads, default to Mandiant FLOSS in the analysis pipeline.*

## 3. PE Structure Validation
Relying solely on file extensions or the `MZ` magic byte is insufficient, as adversaries frequently spoof these indicators.

### 3.1 The Golden Standard PE Check
Implement a two-step validation to definitively confirm a valid Windows Portable Executable structure. This checks the DOS header and dynamically traverses the `e_lfanew` pointer to verify the NT Header.

* **Navigation Pointer Chain:** `DOS Header (0x00)` -> `e_lfanew (0x3c)` -> `PE Header` -> `Optional Header` -> `Data Directory 15` -> `CLI Header` -> `MetaData Root` -> `BSJB Signature`.

    ```yara
    import "pe"

    rule Is_Valid_PE {
        condition:
            // 1. Check MZ (0x5A4D) at offset 0
            // 2. Read 32-bit pointer at 0x3c, jump to that offset, and check for PE (0x4550)
            uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550
    }
    ```

---

## 4. Heuristic & Structural Anomaly Detection
Transitioning from static string matching to behavioral and structural profiling is required for advanced threats (e.g., packed payloads, wipers).

### 4.1 Information Entropy
* **Metric:** Shannon Entropy evaluates data randomness on a scale of `0.0` to `8.0`.
* **Indicator of Compromise (IOC):** Sections (particularly `.rsrc` or unusually named sections) with an entropy value strictly greater than `7.5` strongly indicate compression, packing, or encryption.

### 4.2 Bounded Searching & Funnel Logic
Use structural counters as the first layer of the "detection funnel" to minimize CPU-intensive operations (like entropy calculations) before iterating through resources.

* **Heuristic Thresholds:**
    * `pe.number_of_sections > 4`: Identifies unusual section counts typical of packers or injectors.
    * `pe.number_of_signatures == 0`: High suspicion if combined with malicious behavior (legitimate commercial software is usually signed).
    * `pe.number_of_resources > 1 and pe.number_of_resources < 15`: Typical resource count for standalone malware droppers; filters out complex legitimate software.

**Example: Refined Hunting for Encrypted Resource Payloads**

    ```yara
    import "pe"
    import "math"

    rule Detect_Advanced_Obfuscated_Payload {
        condition:
            // Level 1: Fast Structural Triage
            filesize < 1MB and 
            pe.number_of_signatures == 0 and
            pe.number_of_sections > 4 and
            
            // Level 2: Precision Resource Iteration
            for any i in (0..pe.number_of_resources - 1): (
                pe.resources[i].id == 101 and          // Specific CTI-linked Resource ID
                pe.resources[i].language == 0 and      // Language Neutral (0)
                pe.resources[i].length > 20KB and      // Minimum payload size threshold
                math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.8 and
                not ( "This program cannot be run in DOS mode." in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length) )
            )
    }
    ```