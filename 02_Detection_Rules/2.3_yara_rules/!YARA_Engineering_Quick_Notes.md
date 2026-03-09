# YARA Engineering Quick Notes

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

```yara
    import "pe"
    import "dotnet"

    rule Is_DotNet_Executable {
        condition:
            // Verify via the COM Descriptor Directory (Entry 15) or the dotnet module
            dotnet.is_dotnet or pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].size > 0
    }
```

## 4. Heuristic & Structural Anomaly Detection

### 4.1 Information Entropy

* **Metric:** Shannon Entropy (0.0 to 8.0).
* **Indicator:** Values > 7.5 in non-code sections (e.g., `.rsrc`) strongly indicate compressed, packed, or encrypted payloads.

### 4.2 Bounded Searching & Funnel Logic (Detection Optimization)

When hunting for hidden payloads, decouple the **core structural match** from **contextual heuristics**.

**Core Structural Logic (The "What"):**
Identifies the presence of high-entropy resource blocks which suggest encrypted or packed content.

```yara
    for any i in (0..pe.number_of_resources - 1): (
        math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.5 and
        pe.resources[i].length > 10KB
    )
```

**Heuristic Enhancement Filters (The "Context"):**
Optional constraints to be added based on the specific environment and target threat profile.

* **Binary Type Filters:**
    * `pe.number_of_signatures == 0`: Use if the target environment enforces signed binaries.
    * `pe.number_of_sections > 4`: Use to catch custom packers or multi-stage loaders.
    * `pe.number_of_resources < 20`: Use to filter out complex commercial applications.
    * `pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].size == 0`: [Anti-Forensics/OpSec Indicator] Identifies PE files where the Debug Directory is missing or zeroed out. This indicates a deliberate effort by the author to strip PDB paths and conceal build environment metadata, perfectly aligning with the profile of advanced actors practicing strict operational security. Pair this with the signature absence for high-fidelity hunting.

* **Deep Content Filters:**
    * `not ( "This program cannot be run in DOS mode." in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length) )`: Ensures the resource itself is not just another plain PE file.
    * `pe.resources[i].language == 0`: Targets "Language Neutral" resources, common in malicious payloads.
    * `pe.resources[i].id == <TARGET_ID>`: Use when hunting for a specific threat actor known to hardcode resource IDs.

## 5. Signature Engineering Best Practices & Limitations

### 5.1 String Definition Optimization (Hex vs. Text)

Confusing the use cases for text and hexadecimal strings leads to unmaintainable rule repositories and poor scanning performance. Never blindly convert readable ASCII/Wide strings into hex bytes just to utilize the hex engine.

* **Text Strings:** Prioritize explicit text definitions (`"string" ascii wide nocase`) for human-readable artifacts such as file paths, Mutex names, PDB paths, and hardcoded C2 domains. This preserves rule readability and significantly lowers maintenance overhead for other analysts.
* **Hexadecimal Strings:** Strictly reserve hex strings (`{ 01 A2 ?? FF }`) for matching machine code (Assembly Opcodes), magic bytes, or specific binary payload signatures (e.g., injected shellcode). 
* **Dynamic Hex Matching:** Utilize wildcards (`?`) or jumps (`[1-4]`) within hex strings to account for variable bytes in opcodes caused by different compilers, registers, or minor obfuscation techniques.
    ```yara
    // BAD Practice: Converting a readable PDB path to Hex (Unmaintainable)
    $pdb_bad = { 43 3A 5C 63 72 79 73 69 73 5C 52 65 6C 65 61 73 65 }
    
    // GOOD Practice: Clear, readable text definition
    $pdb_good = "C:\\crysis\\Release" ascii nocase
    
    // CORRECT Hex Usage: Hunting for Shellcode (Opcodes) in Memory
    // 648b ??30 corresponds to 'mov edx, fs:[???+0x30]' (PEB parsing technique)
    $shellcode_mov = { 64 8b ?? 30 } 
    ```

### 5.2 Scope Limitations: YARA vs. Structured Telemetry

* **The Anti-Pattern:** Applying YARA's flat string matching against highly structured, JSON-like telemetry (e.g., ETW streams, Windows Event Logs) is computationally expensive and fragile in a production SOC environment. For example, a YARA rule looking for `$s = "Write-Host"` will completely fail if the adversary uses basic tick obfuscation (e.g., ``W`r`i`t`e`-`H`o`s`t``).
* **The Pivot to SIEM/Sigma:** YARA is inherently designed for contiguous blocks of memory or flat files on disk. For structured log data, the engineering best practice is to forward the events to a SIEM (via agents like Sysmon) and utilize structured detection logic such as Sigma. This allows for evaluating specific key-value pairs (e.g., mapping `EventID: 4104` to parsed `ScriptBlockText` fields), creating robust detection mechanisms that are immune to simple flat-string evasion.