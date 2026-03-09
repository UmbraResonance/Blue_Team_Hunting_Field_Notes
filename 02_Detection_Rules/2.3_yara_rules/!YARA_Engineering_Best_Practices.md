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
* `fullword`: Prevents partial matches by ensuring the string is bounded by non-alphanumeric characters.
* `nocase`: Essential for neutralizing script-based case randomization evasion (e.g., `pOwErShElL.exe`).

### 2.2 Advanced String Extraction

**Headless Static Extraction (Bash One-Liner):**
Extracts both ASCII and Wide strings, prepended with their decimal offsets, and sorted by physical location:

    ```bash
    ( strings -a -td "$@" | sed 's/^\(\s*[0-9][0-9]*\) \(.*\)$/\1 A \2/' ; strings -a -td -el "$@" | sed 's/^\(\s*[0-9][0-9]*\) \(.*\)$/\1 W \2/' ) | sort -n
    ```
## 3. PE Structure Validation

Relying solely on file extensions or the `MZ` magic byte is insufficient for advanced threat hunting.

### 3.1 Standard Windows PE Validation (Generic)

Implement a two-step validation to confirm a valid PE structure by dynamically traversing the `e_lfanew` pointer. This ensures the file is a legitimate executable and not a truncated or spoofed binary.

    ```yara
    import "pe"

    rule Is_Valid_PE {
        condition:
            // 1. Verify MZ (0x5A4D) at offset 0
            // 2. Read 32-bit pointer at 0x3c, jump to that offset, and check for PE (0x4550)
            uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550
    }
    ```

### 3.2 .NET Metadata & Assembly Identification (Specific)

Unlike native binaries, .NET executables contain a secondary header structure (CLI Header) typically located within the `.text` section.

* **Navigation Pointer Chain:** `DOS Header (0x00)` -> `e_lfanew (0x3c)` -> `PE Header` -> `Optional Header` -> `Data Directory 15` -> `CLI Header` -> `MetaData Root` -> `BSJB Signature`.

    import "pe"
    import "dotnet"

    rule Is_DotNet_Executable {
        condition:
            // Verify via the COM Descriptor Directory (Entry 15) or the dotnet module
            dotnet.is_dotnet or pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].size > 0
    }

## 4. Heuristic & Structural Anomaly Detection

### 4.1 Information Entropy

* **Metric:** Shannon Entropy (0.0 to 8.0).
* **Indicator:** Values > 7.5 in non-code sections (e.g., `.rsrc`) strongly indicate compressed, packed, or encrypted payloads.

### 4.2 Bounded Searching & Funnel Logic (Detection Optimization)

Use structural counters as the first layer of the "detection funnel" to minimize CPU-intensive operations before iterating through resources.

* **Heuristic Thresholds:**
    * `pe.number_of_sections > 4`: Detects unusual section counts common in custom packers or multi-stage injectors.
    * `pe.number_of_signatures == 0`: High-risk indicator for unsigned binaries in enterprise environments.
    * `pe.number_of_resources`: Typically 1-15 for standalone malware droppers; legitimate commercial software often exceeds 50.

**Universal Template: Hunting Obfuscated Resource Payloads**

```yara
    import "pe"
    import "math"

    rule Detect_Heuristic_Resource_Payload {
        condition:
            // Level 1: Initial Funnel (Fast structural checks)
            pe.number_of_signatures == 0 and
            pe.number_of_sections > 4 and
            pe.number_of_resources < 15 and
            
            // Level 2: Targeted Iteration (Deep content checks)
            for any i in (0..pe.number_of_resources - 1): (
                pe.resources[i].length > 20KB and
                math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.5 and
                
                // Bounded search: Ensure the block is not a plaintext PE file
                not ( "This program cannot be run in DOS mode." in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length) )
                
                // Optional: Match specific CTI-derived Resource IDs or Languages
                // pe.resources[i].id == <TARGET_ID> or pe.resources[i].language == 0
            )
    }
```    