# Sigma Rules Engineering Quick Reference

> **Focus:** Core syntax definitions, operator behaviors, and detection engineering templates.
> **Use Case:** Cheat sheet for developing, troubleshooting, and converting Sigma rules.

## 1. Rule Skeleton Template & Metadata

The core structure of a Sigma rule. Metadata fields are crucial for SOC alert triaging and MITRE ATT&CK coverage mapping.

```yaml
    title: <Rule_Name_Summary>
    id: <UUIDv4>
    status: <experimental|test|stable|unsupported> # Use 'unsupported' if using advanced aggregations not universally supported by backends
    description: <Detailed_description_of_the_threat>
    tags:
        - attack.<tactic_name>     # e.g., attack.credential_access
        - attack.t<XXXX>.<XXX>     # e.g., attack.t1003.001
    logsource:
        category: <process_creation|process_access|network_connection|...>
        product: windows
    detection:
        selection:
            <Field_Name>: '<Value>'
        condition: selection
    falsepositives:
        - <Known_benign_behavior_1>
        - <Known_benign_behavior_2>
    level: <low|medium|high|critical>
```

## 2. Logical Operations: Lists vs. Maps

The most common point of failure in rule logic is confusing list and map behaviors.

* **Lists (Array format `-`):** Evaluated as **OR**.
* **Maps (Key-Value format):** Evaluated as **AND**.

    ```yaml
    # [OR Logic] Matches if <Field_A> equals <Value_1> OR <Value_2>
    selection:
        <Field_A>:
            - '<Value_1>'
            - '<Value_2>'

    # [AND Logic] Matches if <Field_A> equals <Value_1> AND <Field_B> equals <Value_2>
    selection:
        <Field_A>: '<Value_1>'
        <Field_B>: '<Value_2>'

    # [Combined Logic] Matches if (<Field_A> equals <Value_1>) AND (<Field_B> equals <Value_2> OR <Value_3>)
    selection:
        <Field_A>: '<Value_1>'
        <Field_B>:
            - '<Value_2>'
            - '<Value_3>'
    ```

## 3. Value Modifiers

Modifiers are appended to the field name using a pipe `|` and apply to the value.

| Modifier | Behavior | Syntax Example |
| :--- | :--- | :--- |
| `\|contains` | Wraps value in wildcards `*` | `CommandLine\|contains: 'mimikatz'` |
| `\|startswith` | Adds wildcard `*` to the end | `Image\|startswith: 'C:\Windows\Temp\'` |
| `\|endswith` | Adds wildcard `*` to the beginning | `TargetImage\|endswith: '\lsass.exe'` |
| `\|all` | Forces **AND** logic on a list | `CommandLine\|contains\|all: ['-nop', '-hidden']` |
| `\|base64offset`| Matches values despite Base64 padding shifts | `CommandLine\|contains\|base64offset: 'Invoke-ReflectivePEInjection'` |
| `\|re` | Regular Expression evaluation | `CommandLine\|re: '.{1000,}'` |

> **Performance Warning:** Avoid `|re` unless absolutely necessary. Regex drastically increases search execution time when converted to SIEM backends like Splunk or ELK.

## 4. Advanced Aggregations (Thresholding)

Used for temporal statistical detections (e.g., Brute Force, Password Spray, Exfiltration).

*Template:*
`condition: <selection> | count(<Field_To_Count>) by <Grouping_Field> > <Threshold>`

```yaml
    detection:
        selection:
            EventID: <Target_Event_ID>
            <Field_To_Count>: '*' # Required: Asserts field existence for SIEM parser
            <Grouping_Field>: '*'
        condition: selection | count(<Field_To_Count>) by <Grouping_Field> > <Threshold_Integer>
```

## 5. False Positive Management (Robust Condition Pattern)

Do not mix malicious indicators and whitelist exclusions in the same block. Use the `1 of filter_*` condition pattern for modular exception management.

```yaml
    detection:
        selection_core:
            <Target_Field_A>|endswith: '\<Malicious_Pattern>'
            <Target_Field_B>: '<Suspicious_Value>'
        filter_known_benign_1:
            <Source_Field_A>: '<Known_Safe_Value>'
        filter_known_benign_2:
            <Source_Field_B>|startswith: '<Approved_Path_Pattern>\'
        # Modular condition logic allows easy scaling of exclusions
        condition: selection_core and not 1 of filter_known_benign_*
```

## 6. Pipeline Conversion Constraints

* **Splunk (sigmac / pySigma):** Raw conversion generates global searches (performance killer). Always append environment-specific config files during conversion to inject `index` and `sourcetype`.
    *Command:* `python sigmac -t splunk <RULE.yml> -c splunk-windows.yml`

* **Microsoft Sentinel (pySigma):** Default field mapping assumes ECS normalization. Always apply the `microsoft365defender` or `windows` pipeline during conversion to correctly resolve fields like `NewProcessName` → `InitiatingProcessFileName`. Inject the `workspace` parameter via backend config to avoid global table scans.
    *Command:* `sigma convert -t microsoft365defender -p microsoft365defender <RULE.yml>`
    *Watch for:* KQL does not support all Sigma aggregation conditions natively (e.g., `near`). Mark affected rules `status: unsupported`.

* **Elastic (pySigma):** Field names follow ECS (Elastic Common Schema). Native Sigma fields (e.g., `CommandLine`) must map to ECS equivalents (e.g., `process.command_line`) via the `windows` pipeline. Verify mappings before deploying, as unmapped fields silently return zero results.
    *Command:* `sigma convert -t lucene -p ecs_windows <RULE.yml>`
    *Watch for:* Lucene does not support regex (`|re`) natively in all contexts — prefer EQL or ES|QL backends for regex-heavy rules.

* **Chainsaw (Offline DFIR):**
    If valid rules return 0 hits, the mapping is broken. Chainsaw requires strict XML-path mapping definitions (`--mapping`) to translate generic Sigma fields (e.g., `NewProcessName`) into EVTX-specific structures.