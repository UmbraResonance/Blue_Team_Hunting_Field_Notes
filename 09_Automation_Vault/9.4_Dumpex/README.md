# dumpex

**dumpex** is a command-line DFIR/CTF triage tool for analyzing Windows minidump (`.DMP`) files. It parses minidump structures to surface system information, memory layout, loaded modules, and thread state — and includes a TTP detection engine to hunt for signs of process injection, module stomping, C2 named pipes, and Cobalt Strike beacons.

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

## Standalone Open Source Projects
As operational scripts mature into full-fledged DFIR engines, they are spun off into their own dedicated repositories to support proper version control, releases, and CI/CD pipelines.

* **[dumpex](https://github.com/bitbug0x55AA/dumpex/tree/main)**