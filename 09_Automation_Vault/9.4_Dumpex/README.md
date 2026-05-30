# dumpex

A Windows Minidump (`.DMP`) analysis tool for DFIR and CTF use cases. Extracts memory regions, detects common injection techniques, generates triage reports anchored to EDR alerts, and diffs two dumps to isolate changes over time.

---

## Installation

**Requirements:** Python 3.8+, Windows or Linux.

```bash
pip install minidump
```

No other dependencies. Download `dumpex.py` and run it directly.

```bash
python dumpex.py --help
```

---

## Quick Start

```bash
# 1. Get your bearings — what process, what OS, what user
python dumpex.py suspicious.DMP --sysinfo

# 2. Run all TTP detectors at once
python dumpex.py suspicious.DMP --hunt all

# 3. Deep-dive on an EDR alert
python dumpex.py suspicious.DMP --report --report-tid 0x3a8
```

---

## Command Reference

### Recon

| Command | Description |
|---|---|
| `--sysinfo` | OS version, hostname, username, PID, process start time, CPU |
| `--peb` | Process Environment Block: image path, command line, working dir, environment variables |
| `--modules` | All loaded modules with base address, size, and full path |
| `--threads` | All threads with start address and module backing |
| `--list` | All memory regions with protection flags and type |
| `--list --filter PAGE_EXECUTE` | Filter regions by protection string |

---

### TTP Hunting

```bash
python dumpex.py target.DMP --hunt <ttp>
```

| TTP | What it detects |
|---|---|
| `injection` | RWX memory × hidden PE headers × unbacked threads — cross-correlated |
| `hollowing` | MEM_PRIVATE at image base, missing MZ header, PEB path mismatch |
| `stomping` | MEM_IMAGE regions with RWX or IOC strings in non-whitelisted module memory |
| `all` | All three playbooks + summary card |

Add `--verbose` to expand individual addresses and matched strings.

```bash
python dumpex.py target.DMP --hunt all --verbose
```

**Note on false positives:** `--hunt stomping` automatically skips known network DLLs
(`wininet.dll`, `winhttp.dll`, `ws2_32.dll`, and others) that legitimately contain
URL and socket strings. If one of these appears in the output as skipped, that is
expected behaviour, not a missed detection.

---

### Triage Report

Anchors a full investigation to a single indicator from an EDR alert, threat
intelligence feed, or network traffic. Correlates thread, memory, and string
evidence and produces a MECE-scored verdict.

```bash
# From an EDR alert — thread ID
python dumpex.py target.DMP --report --report-tid 0x3a8

# From an EDR alert — memory address
python dumpex.py target.DMP --report --report-addr 0xb120870000

# From threat intelligence — C2 IP or domain
python dumpex.py target.DMP --report --report-string "192.168.1.100"

# Combine anchors
python dumpex.py target.DMP --report --report-tid 0x3a8 --report-addr 0xb120870000

# Extract the suspicious region while reporting
python dumpex.py target.DMP --report --report-tid 0x3a8 -o region.bin
```

**MECE verdict dimensions** — each scored at most once regardless of how many
raw signals contributed to it:

| Dimension | What triggers it |
|---|---|
| `unbacked_thread` | Thread start address falls outside all known modules |
| `rwx_private` | Region is PAGE_EXECUTE_READWRITE + MEM_PRIVATE |
| `injected_pe` | MZ header in unregistered private memory |
| `ioc_strings` | IOC pattern matched in region strings |

Score → verdict mapping: 1 = Suspicious, 2 = Likely Malicious, 3+ = High Confidence Malicious.

---

### Diff (Two Dumps)

Compares a before and after dump. Left argument is the earlier (baseline) dump;
right argument is the later (suspicious) dump. Added = new in the right dump.

```bash
python dumpex.py before.DMP --diff after.DMP
python dumpex.py before.DMP --diff after.DMP --diff-mode modules
python dumpex.py before.DMP --diff after.DMP --diff-mode threads
python dumpex.py before.DMP --diff after.DMP --diff-mode memory
python dumpex.py before.DMP --diff after.DMP --diff-mode all --verbose
```

By default `--diff` shows only actionable changes — RWX regions, executable
regions, and module changes. Use `--verbose` to include all routine regions
(PAGE_READONLY, PAGE_NOACCESS) added by newly loaded DLLs.

---

### Extraction

```bash
# Extract raw bytes — --size is optional, auto-resolved from the memory region table
python dumpex.py target.DMP --extract 0xb120870000 -o payload.bin
python dumpex.py target.DMP --extract 0x3a0000 --size 0x4e000 -o payload.bin

# Extract strings — --size is optional for the same reason
python dumpex.py target.DMP --strings 0xb120870000
python dumpex.py target.DMP --strings 0x3a0000 --size 0x4e000

# Filter strings with a regex
python dumpex.py target.DMP --strings 0x3a0000 --grep "http|cmd|pipe"

# Unicode only, shorter minimum length
python dumpex.py target.DMP --strings 0x3a0000 --encoding unicode --min-len 4
```

`--size` is optional for both `--extract` and `--strings`. When omitted, the tool
looks up the memory region containing the address and uses its actual size. If the
address is not found in the region table, it falls back to `0x10000`. Addresses and
sizes accept both hex (`0x3a0000`) and decimal.

---

## Recommended Triage Workflow

### Phase 1 — Context

Establish what you are looking at before running any detectors.

```bash
python dumpex.py target.DMP --sysinfo   # OS, hostname, PID, process start time
python dumpex.py target.DMP --peb       # image path, command line, working dir
python dumpex.py target.DMP --modules   # loaded DLLs — look for unexpected names or paths
```

Red flags at this stage: executable running from `Downloads`, `AppData\Temp`, or
with a randomly generated name; `BeingDebugged: 1`; `StandardOutput` handle
value that is not 1 or 2 (may indicate redirected output to a pipe or socket).

### Phase 2 — Automated TTP Detection

```bash
python dumpex.py target.DMP --hunt all
```

Evaluate the summary card:

- **Injection HIGH CONFIDENCE** → note the RWX region addresses and unbacked TIDs,
  proceed to Phase 3 with those as anchors.
- **Hollowing detected** → the primary executable image is compromised; extract
  the image base region and send to a disassembler.
- **Stomping detected** → note the specific DLL flagged; the legitimate module has
  been partially overwritten. Extract that region and compare to a clean copy.
- **All CLEAN** → the dump may predate the injection, or the attacker used
  RW→RX allocation to avoid RWX regions (see Known Limitations). Proceed to
  Phase 3 with any IOC you have from other sources.

### Phase 3 — Targeted Correlation

Anchor the investigation to a specific indicator.

```bash
# From EDR alert
python dumpex.py target.DMP --report --report-tid <TID>
python dumpex.py target.DMP --report --report-addr <ADDR>

# From threat intelligence or network traffic
python dumpex.py target.DMP --report --report-string "<C2 IP or domain>"

# If you have a clean baseline dump
python dumpex.py clean.DMP --diff target.DMP --diff-mode all
```

The report produces a structured verdict with up to four MECE dimensions.
Network-protocol IOC hits (URLs, IPs) automatically print a ±128-byte hex
context dump around the match so adjacent C2 configuration values (port
numbers, headers, keys) are visible even if they are shorter than the minimum
string length.

### Phase 4 — Extraction and Handoff

```bash
# Pull the suspicious region
python dumpex.py target.DMP --extract <ADDR> --size <SIZE> -o payload.bin

# Scan strings in the region before extracting
python dumpex.py target.DMP --strings <ADDR> --size <SIZE> --grep "http|pipe|cmd"
```

Hand `payload.bin` to your disassembler (IDA, Ghidra, x64dbg) or sandbox for
dynamic analysis.

---

## Known Limitations

### Header Wiping

`--hunt injection` and `--hunt hollowing` both look for the `MZ` magic bytes
(`0x4D 0x5A`) to identify PE files in memory. Malware that zeroes its headers
after loading (header wiping) will not be caught by MZ-based checks. The
unbacked-thread check (`--hunt injection`) and the `MEM_PRIVATE` type check
(`--hunt hollowing`) are not affected, so partial detection is still possible.

**Mitigation:** If injection is suspected but no MZ is found, run
`--strings <ADDR> --size <SIZE>` on the RWX region. A shellcode loader without
a PE header will still leave API name strings, import hints, or C2 configuration
in the region.

### RW→RX Allocation Pattern

The primary RWX detector flags `PAGE_EXECUTE_READWRITE`. Attackers who allocate
memory as `PAGE_READWRITE`, write the payload, then call `VirtualProtect` to
switch to `PAGE_EXECUTE_READ` will not trigger Check 1 of `--hunt injection`.
The unbacked-thread check is unaffected and will still fire if the thread is
running in private memory with no module backing.

### Kernel-Level Manipulation

This tool operates exclusively on user-mode minidumps. Kernel rootkits that use
DKOM (Direct Kernel Object Manipulation) to unlink threads from the thread list
or hide memory regions from the VAD tree will not be visible. A full physical
memory image analysed with Volatility is required for kernel-level detection.

### Stomping False Positives

Module Stomping detection scans executable MEM_IMAGE regions for IOC strings.
Network-heavy DLLs (`wininet.dll`, `winhttp.dll`, `ws2_32.dll`, `urlmon.dll`,
and others) are whitelisted because they legitimately contain URL prefixes,
socket API names, and HTTP header strings. If these DLLs appear in
`[·] Whitelisted network DLLs skipped`, that is expected, not a missed detection.
Truly anomalous strings (shellcode markers, C2 beacons) inside whitelisted DLLs
still trigger an alert because a separate, stricter IOC pattern is applied to
them.

### Minidump Coverage

A minidump only captures pages that were committed and accessible at the moment
the dump was taken. Pages that were already freed, guard pages, and kernel pages
are absent. If a thread or region appears missing, it may have been released
before the dump was created.

---

## Input Sources for `--report`

The report command accepts anchors from multiple sources:

| Source | Command |
|---|---|
| EDR alert (TID) | `--report-tid 0x3a8` |
| EDR alert (address) | `--report-addr 0xb120870000` |
| Sysmon Event ID 8 `StartAddress` field | `--report-addr <StartAddress>` |
| WinDbg / x64dbg output address | `--report-addr <addr>` |
| Threat intelligence (C2 IP/domain) | `--report-string "192.168.1.100"` |
| PCAP correlation (observed IP) | `--report-string "10.0.0.5"` |
| dumpex `--hunt` output (RWX address) | `--report-addr <addr from hunt>` |

`--report-string` searches all committed memory regions for the string (ASCII
and UTF-16LE), then automatically runs the full triage on each region where it
is found.

---

## What dumpex Does Not Do

| Need | Recommended tool |
|---|---|
| Disassemble / reverse engineer extracted code | IDA Pro, Ghidra, x64dbg |
| Decrypt or deobfuscate payloads | CyberChef, manual analysis |
| Full physical memory analysis (kernel structures) | Volatility 3 |
| Dynamic behaviour observation | Sandbox, x64dbg attached |
| Network traffic correlation | Wireshark + PCAP |
| Acquire the dump from a live machine | WinPmem, ProcDump, Task Manager |

dumpex is a triage tool. Its job is to narrow the investigation down to a
specific region or thread, extract the payload, and hand off to the right
specialist tool.
