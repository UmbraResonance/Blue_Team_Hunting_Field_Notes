#!/usr/bin/env python3
"""
dumpex — Minidump Memory Extractor & Analyzer
DFIR/CTF triage tool for Windows .DMP files.

RECON:
  python dumpex.py dump.DMP --sysinfo
  python dumpex.py dump.DMP --peb
  python dumpex.py dump.DMP --modules
  python dumpex.py dump.DMP --threads
  python dumpex.py dump.DMP --list [--filter PAGE_EXECUTE]

HUNT (TTP detection):
  python dumpex.py dump.DMP --hunt injection
  python dumpex.py dump.DMP --hunt hollowing
  python dumpex.py dump.DMP --hunt stomping
  python dumpex.py dump.DMP --hunt all [--verbose]

REPORT (alert triage):
  python dumpex.py dump.DMP --report --report-tid 0x3a8
  python dumpex.py dump.DMP --report --report-addr 0xb120870000
  python dumpex.py dump.DMP --report --report-string "192.168.1.1"

DIFF (two dumps):
  python dumpex.py before.DMP --diff after.DMP
  python dumpex.py before.DMP --diff after.DMP --diff-mode modules|threads|memory|all

EXTRACTION:
  python dumpex.py dump.DMP --extract 0x3a0000 --size 0x4e000 -o out.bin
  python dumpex.py dump.DMP --strings 0x3a0000 --size 0x4e000 --grep "http|cmd"
  python dumpex.py dump.DMP --strings 0x3a0000 --encoding unicode --min-len 4
"""

import argparse
import re
import sys
import os
from pathlib import Path

try:
    from minidump.minidumpfile import MinidumpFile
except ImportError:
    print("[!] minidump not installed. Run: pip install minidump")
    sys.exit(1)


# ── ANSI colors (auto-disabled if not a TTY) ──────────────────────────────────
USE_COLOR = sys.stdout.isatty()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def RED(t):    return _c("91", t)
def GREEN(t):  return _c("92", t)
def YELLOW(t): return _c("93", t)
def CYAN(t):   return _c("96", t)
def BOLD(t):   return _c("1",  t)
def DIM(t):    return _c("2",  t)


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_hex_or_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)

def prot_str(protect) -> str:
    try:    return protect.name
    except: return str(protect)

def open_dump(path: str) -> MinidumpFile:
    if not os.path.exists(path):
        print(RED(f"[!] File not found: {path}"))
        sys.exit(1)
    return MinidumpFile.parse(path)

def read_region(mf: MinidumpFile, addr: int, size: int) -> bytes:
    reader = mf.get_reader().get_buffered_reader()
    reader.move(addr)
    return reader.read(size)

def get_modules(mf: MinidumpFile) -> list:
    if mf.modules and mf.modules.modules:
        return mf.modules.modules
    return []

def get_thread_infos(mf: MinidumpFile) -> list:
    if mf.thread_info and mf.thread_info.infos:
        return mf.thread_info.infos
    return []

def get_memory_regions(mf: MinidumpFile) -> list:
    if mf.memory_info and mf.memory_info.infos:
        return mf.memory_info.infos
    return []

def module_name_only(full_path: str) -> str:
    """Extract just the filename from a full module path."""
    return os.path.basename(full_path).lower() if full_path else ""

def addr_to_module(addr: int, modules: list):
    """Return module if address falls within it, else None."""
    for m in modules:
        if m.baseaddress <= addr < m.endaddress:
            return m
    return None

SUSPICIOUS_PROTS = {"PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY"}


def _resolve_size(mf: MinidumpFile, addr: int, requested_size: int | None) -> int:
    """
    If the user didn't specify --size, look up the memory region that contains
    addr and return its actual size (capped at the region boundary).
    Falls back to 0x10000 if the region cannot be found.
    """
    if requested_size is not None:
        return requested_size
    for r in get_memory_regions(mf):
        if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
            actual = r.RegionSize - (addr - r.BaseAddress)
            return actual
    return 0x10000  # fallback if region not in memory info
SYSTEM_RANGE     = 0x7FF000000000  # below this = user/non-system range on x64


# ── Single-dump commands ──────────────────────────────────────────────────────

def cmd_list(mf, filter_prot=None):
    regions = get_memory_regions(mf)
    print(f"\n{BOLD('Address'):<24} {BOLD('Size'):<14} {BOLD('State'):<14} {BOLD('Protection'):<32} {BOLD('Type')}")
    print("─" * 100)
    count = 0
    for r in regions:
        p = prot_str(r.Protect)
        if filter_prot and filter_prot.upper() not in p.upper():
            continue
        color = RED if any(s in p for s in SUSPICIOUS_PROTS) else (lambda x: x)
        print(color(f"0x{r.BaseAddress:<22x} 0x{r.RegionSize:<12x} {prot_str(r.State):<14} {p:<32} {prot_str(r.Type)}"))
        count += 1
    print(f"\n{GREEN(f'[+] {count} region(s) shown.')}")


def cmd_modules(mf):
    mods = get_modules(mf)
    print(f"\n{BOLD('Base'):<20} {BOLD('End'):<20} {BOLD('Size'):<12} {BOLD('Module')}")
    print("─" * 80)
    for m in sorted(mods, key=lambda x: x.baseaddress):
        print(f"0x{m.baseaddress:<18x} 0x{m.endaddress:<18x} 0x{m.size:<10x} {m.name}")
    print(f"\n{GREEN(f'[+] {len(mods)} module(s).')}")


def cmd_threads(mf):
    threads  = {t.ThreadId: t for t in (mf.threads.threads if mf.threads else [])}
    infos    = get_thread_infos(mf)
    modules  = get_modules(mf)

    print(f"\n{BOLD('TID'):<10} {BOLD('StartAddress'):<20} {BOLD('KernelTime'):<12} {BOLD('UserTime'):<12} {BOLD('Backed By')}")
    print("─" * 90)
    for ti in infos:
        sa  = ti.StartAddress or 0
        mod = addr_to_module(sa, modules)
        backed = DIM(os.path.basename(mod.name)) if mod else RED("⚠  NOT IN ANY MODULE")
        print(f"0x{ti.ThreadId:<8x} 0x{sa:<18x} {ti.KernelTime:<12} {ti.UserTime:<12} {backed}")
    print(f"\n{GREEN(f'[+] {len(infos)} thread(s).')}")


def _hunt_rwx(mf: MinidumpFile) -> list:
    """Return list of RWX regions. Internal — used by --hunt injection."""
    regions = get_memory_regions(mf)
    hits = []
    for r in regions:
        p = prot_str(r.Protect)
        if any(s in p for s in SUSPICIOUS_PROTS):
            hits.append(r)
    return hits


def _hunt_hidden_pe(mf: MinidumpFile) -> list:
    """Return list of (region, in_module_list) for MZ headers. Internal."""
    modules    = get_modules(mf)
    known_bases = {m.baseaddress for m in modules}
    hits = []
    for r in get_memory_regions(mf):
        if prot_str(r.State) != "MEM_COMMIT":
            continue
        try:
            data = read_region(mf, r.BaseAddress, min(2, r.RegionSize))
        except Exception:
            continue
        if data[:2] == b'MZ':
            hits.append((r, r.BaseAddress in known_bases))
    return hits


def _hunt_unbacked_threads(mf: MinidumpFile) -> list:
    """Return list of ThreadInfo with no module backing. Internal."""
    modules = get_modules(mf)
    infos   = get_thread_infos(mf)
    return [ti for ti in infos
            if not addr_to_module(ti.StartAddress or 0, modules)]


def cmd_extract(mf, addr, size, output, auto_size=False):
    auto_note = DIM(" (auto from region)") if auto_size else ""
    print(f"[*] Reading 0x{size:x}{auto_note} bytes from 0x{addr:x} ...")
    try:
        data = read_region(mf, addr, size)
    except Exception as e:
        print(RED(f"[!] Read failed: {e}")); sys.exit(1)

    if data[:2] == b'MZ':
        print(YELLOW("[!] MZ header detected — this looks like an injected PE!"))

    out = output or f"region_0x{addr:x}.bin"
    Path(out).write_bytes(data)
    print(GREEN(f"[+] Saved {len(data)} bytes → {out}"))


def cmd_strings(mf, addr, size, min_len, grep, encoding, auto_size=False):
    auto_note = DIM(" (auto from region)") if auto_size else ""
    print(f"[*] Extracting strings from 0x{addr:x} (size=0x{size:x}{auto_note}, min={min_len}, enc={encoding})")
    try:
        data = read_region(mf, addr, size)
    except Exception as e:
        print(RED(f"[!] Read failed: {e}")); sys.exit(1)

    results = []
    if encoding in ("ascii", "both"):
        pat = rb'[ -~]{' + str(min_len).encode() + rb',}'
        results += [(m.start(), "ASCII", m.group().decode("ascii", errors="replace"))
                    for m in re.finditer(pat, data)]
    if encoding in ("unicode", "both"):
        pat = rb'(?:[ -~]\x00){' + str(min_len).encode() + rb',}'
        results += [(m.start(), "UTF16", m.group().decode("utf-16-le", errors="replace"))
                    for m in re.finditer(pat, data)]

    results.sort(key=lambda x: x[0])
    grep_re = re.compile(grep, re.IGNORECASE) if grep else None

    print(f"\n{BOLD('Offset'):<14} {BOLD('Enc'):<7} {BOLD('String')}")
    print("─" * 70)
    shown = 0
    for offset, enc, s in results:
        if grep_re and not grep_re.search(s):
            continue
        line = f"0x{addr + offset:<12x} {enc:<7} {s}"
        print(YELLOW(line) if grep_re else line)
        shown += 1
    print(f"\n{GREEN(f'[+] {shown} string(s) shown.')}")


def cmd_peb(mf: MinidumpFile):
    peb = mf.peb
    if not peb:
        print("[!] PEB could not be parsed (missing sysinfo or thread list in dump)")
        return

    print(f"\n{BOLD('═══ PEB ═══')}")
    print(f"  {'PEB Address':<24} 0x{peb.address:x}")
    print(f"  {'BeingDebugged':<24} {peb.being_debugged}")
    print(f"  {'ImageBaseAddress':<24} 0x{peb.image_base_address:x}")
    print(f"  {'ImagePath':<24} {peb.image_path or '(none)'}")
    print(f"  {'CommandLine':<24} {peb.command_line or '(none)'}")
    print(f"  {'WindowTitle':<24} {peb.window_title or '(none)'}")
    print(f"  {'DllPath':<24} {peb.dll_path or '(none)'}")
    print(f"  {'CurrentDirectory':<24} {peb.current_directory or '(none)'}")
    print(f"  {'StandardInput':<24} {peb.standard_input}")
    print(f"  {'StandardOutput':<24} {peb.standard_output}")
    print(f"  {'StandardError':<24} {peb.standard_error}")

    if peb.environment_variables:
        print(f"\n  {BOLD('Environment Variables:')}")
        for env in peb.environment_variables:
            k = env.get("name", "") if isinstance(env, dict) else env[0]
            v = env.get("value", "") if isinstance(env, dict) else env[1]
            print(f"    {k}={v}")




def cmd_sysinfo(mf: MinidumpFile):
    import datetime

    si  = mf.sysinfo
    mi  = mf.misc_info
    peb = mf.peb

    # Hostname from environment variables
    hostname = "(unknown)"
    username = "(unknown)"
    if peb and peb.environment_variables:
        for env in peb.environment_variables:
            name = env.get("name", "") if isinstance(env, dict) else env[0]
            val  = env.get("value", "") if isinstance(env, dict) else env[1]
            if name.upper() == "COMPUTERNAME":
                hostname = val
            if name.upper() == "USERNAME":
                username = val

    print(f"\n{BOLD('═══ SYSTEM INFO ═══')}")

    # ── OS ──────────────────────────────────────────────────────────────
    print(f"\n  {BOLD('Operating System')}")
    if si:
        os_name = si.OperatingSystem or "Windows (unknown version)"
        build   = si.BuildNumber if si.BuildNumber is not None else "?"
        major   = si.MajorVersion if si.MajorVersion is not None else "?"
        minor   = si.MinorVersion if si.MinorVersion is not None else "?"
        csd     = f" {si.CSDVersion}" if si.CSDVersion else ""
        arch    = si.ProcessorArchitecture.name if si.ProcessorArchitecture else "?"
        ptype   = si.ProductType.name if si.ProductType else "?"
        print(f"    {'OS':<22} {os_name}{csd}")
        print(f"    {'Version':<22} {major}.{minor}.{build}")
        print(f"    {'Architecture':<22} {arch}")
        print(f"    {'Product Type':<22} {ptype}")
    else:
        print(f"    {DIM('(sysinfo stream not available)')}")

    # ── Host ────────────────────────────────────────────────────────────
    print(f"\n  {BOLD('Host')}")
    print(f"    {'Hostname':<22} {hostname}")
    print(f"    {'Username':<22} {username}")

    # ── Process ─────────────────────────────────────────────────────────
    print(f"\n  {BOLD('Process')}")
    if mi and mi.ProcessId:
        print(f"    {'PID':<22} {mi.ProcessId} (0x{mi.ProcessId:x})")
    if mi and mi.ProcessCreateTime:
        try:
            ts = datetime.datetime.fromtimestamp(mi.ProcessCreateTime, tz=datetime.timezone.utc)
            print(f"    {'Process Start (UTC)':<22} {ts.strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception:
            print(f"    {'Process Start':<22} {mi.ProcessCreateTime}")
    if mi and mi.ProcessUserTime is not None:
        print(f"    {'CPU User Time':<22} {mi.ProcessUserTime}s")
    if mi and mi.ProcessKernelTime is not None:
        print(f"    {'CPU Kernel Time':<22} {mi.ProcessKernelTime}s")
    if peb:
        print(f"    {'Image Path':<22} {peb.image_path or '(none)'}")
        print(f"    {'Command Line':<22} {peb.command_line or '(none)'}")
        print(f"    {'Working Dir':<22} {peb.current_directory or '(none)'}")
        print(f"    {'BeingDebugged':<22} {peb.being_debugged}")

    # ── CPU ─────────────────────────────────────────────────────────────
    if si:
        print(f"\n  {BOLD('CPU')}")
        print(f"    {'Processors':<22} {si.NumberOfProcessors}")
        if si.VendorId:
            try:
                vendor = bytes(si.VendorId).decode("ascii", errors="replace").rstrip("\x00")
                print(f"    {'Vendor':<22} {vendor}")
            except Exception:
                pass
        if mi and mi.ProcessorCurrentMhz:
            print(f"    {'Current MHz':<22} {mi.ProcessorCurrentMhz}")
        if mi and mi.ProcessorMaxMhz:
            print(f"    {'Max MHz':<22} {mi.ProcessorMaxMhz}")

    # ── Dump metadata ────────────────────────────────────────────────────
    print(f"\n  {BOLD('Dump File')}")
    print(f"    {'File':<22} {os.path.basename(mf.filename)}")
    if mf.threads:
        print(f"    {'Threads in dump':<22} {len(mf.threads.threads)}")
    if mf.modules:
        print(f"    {'Modules in dump':<22} {len(mf.modules.modules)}")
    print()


def _get_region_at(addr: int, regions: list):
    """Find the memory region containing addr."""
    for r in regions:
        if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
            return r
    return None


def _extract_strings_from_data(data: bytes, min_len: int = 6) -> list:
    """\n    Extract ASCII and UTF-16LE strings.\n    Returns list of (offset, enc, string).\n    UTF-16LE covers Windows API names, registry paths, and wide-char C2\n    configs that pure ASCII scans miss entirely.\n    """
    results = []
    pat_ascii = rb'[ -~]{' + str(min_len).encode() + rb',}'
    results += [(m.start(), "ASCII", m.group().decode("ascii", errors="replace"))
                for m in re.finditer(pat_ascii, data)]
    pat_uni = rb'(?:[ -~]\x00){' + str(min_len).encode() + rb',}'
    results += [(m.start(), "UTF16", m.group().decode("utf-16-le", errors="replace"))
                for m in re.finditer(pat_uni, data)]
    results.sort(key=lambda x: x[0])
    return results


def _hexdump_context(data: bytes, offset: int, region_base: int,
                     before: int = 128, after: int = 128) -> str:
    """\n    Hex+ASCII mixed dump of bytes surrounding offset within data.\n    Used for context-aware IOC display (e.g. UA string near C2 IP/port).\n    """
    start     = max(0, offset - before)
    end       = min(len(data), offset + after)
    chunk     = data[start:end]
    hit_rel   = offset - start

    lines = []
    for i in range(0, len(chunk), 16):
        row     = chunk[i:i+16]
        addr    = region_base + start + i
        hex_col = " ".join(f"{b:02x}" for b in row).ljust(48)
        asc_col = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        if i <= hit_rel < i + 16:
            lines.append(f"    {YELLOW(f'0x{addr:016x}')}  {YELLOW(hex_col)}  {YELLOW(asc_col)}")
        else:
            lines.append(f"    {DIM(f'0x{addr:016x}')}  {hex_col}  {DIM(asc_col)}")
    return "\n".join(lines)


# MECE indicator dimensions — each scored at most once.
# Prevents double-counting correlated observations (e.g. thread unbacked
# and "thread in same region" are the same phenomenon, not two signals).
INDICATOR_DIMS = {
    "unbacked_thread": "Unbacked thread execution (start addr outside all known modules)",
    "rwx_private":     "Anomalous memory protection (RWX + MEM_PRIVATE)",
    "injected_pe":     "Injected PE (MZ header in unregistered private memory)",
    "ioc_strings":     "IOC string pattern(s) matched in region",
}

def _verdict(dims: dict) -> str:
    score = len(dims)
    if score == 0:
        return GREEN("CLEAN — no suspicious indicators found")
    if score == 1:
        return YELLOW("SUSPICIOUS — 1 independent indicator")
    if score == 2:
        return YELLOW("LIKELY MALICIOUS — 2 independent indicators")
    return RED(f"HIGH CONFIDENCE MALICIOUS — {score} independent indicators")


def _search_string_in_memory(mf: MinidumpFile, needle: str) -> list:
    """\n    Search all committed memory regions for needle (ASCII and UTF-16LE).\n    Returns list of (region, offset, encoding) tuples, one per hit region\n    (deduplicated by region base so we report each region once).\n    """
    regions  = get_memory_regions(mf)
    hits     = []
    seen     = set()
    needle_b = needle.encode("ascii", errors="replace")
    needle_w = needle.encode("utf-16-le")

    for r in regions:
        if prot_str(r.State) != "MEM_COMMIT":
            continue
        if r.BaseAddress in seen:
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            continue

        off_a = data.find(needle_b)
        if off_a != -1:
            hits.append((r, off_a, "ASCII"))
            seen.add(r.BaseAddress)
            continue

        off_w = data.find(needle_w)
        if off_w != -1:
            hits.append((r, off_w, "UTF16"))
            seen.add(r.BaseAddress)

    return hits


def cmd_report(mf: MinidumpFile, report_tid: str = None, report_addr: str = None,
              report_string: str = None, extract_to: str = None, min_len: int = 6):
    """\n    Alert triage card: given a TID, address, or string from an EDR alert / TI feed,\n    correlate thread, memory, and string evidence into a structured verdict.\n    Verdict uses MECE dimensions — each dimension scored at most once.\n\n    --report-string: search all memory for the string, then run triage on each\n                    matching region. Useful when the anchor is a C2 IP, domain,\n                    or known malware string from threat intelligence.\n    """
    # ── String search mode: find regions, then triage each one ───────
    if report_string and not report_addr:
        print(f"\n{BOLD('Searching memory for:')} {CYAN(repr(report_string))}")
        print("─" * 55)
        hits = _search_string_in_memory(mf, report_string)
        if not hits:
            print(RED(f"  [!] String not found in any committed memory region."))
            print(DIM("      Try --strings with a broader address range to verify."))
            return
        print(GREEN(f"  [+] Found in {len(hits)} region(s):"))
        for r, off, enc in hits:
            abs_addr = r.BaseAddress + off
            p        = prot_str(r.Protect)
            t        = prot_str(r.Type)
            rwx_tag  = RED(" ◄ RWX") if any(s in p for s in SUSPICIOUS_PROTS) else ""
            print(f"    0x{r.BaseAddress:016x}  hit@0x{abs_addr:x}  [{enc}]  {p}  {t}{rwx_tag}")
        print()

        # Run full triage on each hit region
        for i, (r, off, enc) in enumerate(hits, 1):
            if len(hits) > 1:
                print(BOLD(f"{'═'*55}"))
                print(BOLD(f"  Triaging hit {i}/{len(hits)} — region 0x{r.BaseAddress:x}"))
                print(BOLD(f"{'═'*55}"))
            cmd_report(mf,
                      report_tid=report_tid,
                      report_addr=hex(r.BaseAddress),
                      report_string=None,   # prevent recursion
                      extract_to=extract_to,
                      min_len=min_len)
        return

    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    infos   = get_thread_infos(mf)
    tid_map = {ti.ThreadId: ti for ti in infos}

    tid_int  = parse_hex_or_int(report_tid)  if report_tid  else None
    addr_int = parse_hex_or_int(report_addr) if report_addr else None

    dims: dict  = {}          # MECE verdict dimensions
    target_addr = addr_int
    region      = None        # resolved in section 2, reused throughout

    IOC_PATTERNS = re.compile(
        r'https?://|cmd\.exe|powershell|CreateRemoteThread'
        r'|VirtualAlloc|WriteProcessMemory|WinExec|\\pipe\\'
        r'|base64|decode|payload|shellcode|beacon|cobalt'
        r'|LoadLibrary|GetProcAddress|InternetOpen|WSASocket',
        re.IGNORECASE
    )
    NET_PATTERNS = re.compile(
        r'https?://|User-Agent|Content-Type|Host:|Accept:|POST |GET '
        r'|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'|:\d{2,5}$',
        re.IGNORECASE
    )

    print(f"\n{BOLD('══════════════════════════════════════════')}")
    print(f"{BOLD('  dumpex TRIAGE REPORT')}")
    print(f"{BOLD('══════════════════════════════════════════')}")
    print(f"  File : {os.path.basename(mf.filename)}")
    if report_tid:  print(f"  TID  : {report_tid}")
    if report_addr: print(f"  Addr : {report_addr}")
    print()

    # ── 1. Thread analysis ────────────────────────────────────────────
    if tid_int is not None:
        print(BOLD("[ 1 ] THREAD ANALYSIS"))
        print("─" * 50)
        thread_info = tid_map.get(tid_int)
        if not thread_info:
            print(RED(f"  [!] TID 0x{tid_int:x} not found in dump."))
            print(DIM("      Thread may have exited before dump was taken."))
        else:
            sa  = thread_info.StartAddress or 0
            mod = addr_to_module(sa, modules)
            print(f"  {'TID':<22} 0x{thread_info.ThreadId:x}")
            print(f"  {'Start Address':<22} 0x{sa:x}")
            print(f"  {'Kernel Time':<22} {thread_info.KernelTime}")
            print(f"  {'User Time':<22} {thread_info.UserTime}")
            if mod:
                print(f"  {'Backed By':<22} {GREEN(mod.name)}")
                print(f"  {'Module Range':<22} 0x{mod.baseaddress:x} — 0x{mod.endaddress:x}")
            else:
                print(f"  {'Backed By':<22} {RED('NOT IN ANY MODULE ⚠')}")
                dims['unbacked_thread'] = (
                    f"TID 0x{thread_info.ThreadId:x} start addr 0x{sa:x} "
                    f"has no module backing"
                )
            if target_addr is None:
                target_addr = sa
        print()

    # ── 2. Memory region ─────────────────────────────────────────────
    if target_addr is not None:
        print(BOLD("[ 2 ] MEMORY REGION AT TARGET ADDRESS"))
        print("─" * 50)
        region = _get_region_at(target_addr, regions)
        if not region:
            print(RED(f"  [!] No committed region found at 0x{target_addr:x}"))
            print(DIM("      Address may not be in a page captured by this dump."))
        else:
            p          = prot_str(region.Protect)
            mtype      = prot_str(region.Type)
            rmod       = addr_to_module(region.BaseAddress, modules)
            is_rwx     = any(s in p for s in SUSPICIOUS_PROTS)
            is_private = "MEM_PRIVATE" in mtype

            print(f"  {'Region Base':<22} 0x{region.BaseAddress:x}")
            print(f"  {'Region Size':<22} 0x{region.RegionSize:x}  ({region.RegionSize // 1024} KB)")
            print(f"  {'Protection':<22} {RED(p) if is_rwx else p}")
            print(f"  {'Type':<22} {mtype}")
            print(f"  {'Module Owner':<22} "
                  f"{DIM(rmod.name) if rmod else RED('none — unregistered private memory')}")

            if is_rwx and is_private:
                print(f"\n  {RED('[!] RWX + MEM_PRIVATE — classic shellcode/injection marker')}")
                dims['rwx_private'] = (
                    f"Region 0x{region.BaseAddress:x} is "
                    f"PAGE_EXECUTE_READWRITE + MEM_PRIVATE"
                )
            elif is_rwx:
                print(f"\n  {YELLOW('[~] PAGE_EXECUTE_READWRITE (module-backed — notable but less suspicious)')}")

            try:
                header = read_region(mf, region.BaseAddress, min(64, region.RegionSize))
                if header[:2] == b'MZ' and not rmod:
                    print(f"  {RED('[!] MZ header — injected PE in unregistered private memory')}")
                    dims['injected_pe'] = (
                        f"MZ header at 0x{region.BaseAddress:x} in unregistered private memory"
                    )
                elif header[:2] == b'MZ':
                    print(f"  {DIM('[·] MZ header (known module — expected)')}")
            except Exception:
                pass
        print()

    # ── 3. Other threads in same region ──────────────────────────────
    if region is not None:
        sharing = [ti for ti in infos
                   if region.BaseAddress <= (ti.StartAddress or 0)
                   < region.BaseAddress + region.RegionSize]
        if sharing:
            print(BOLD("[ 3 ] THREADS EXECUTING IN THIS REGION"))
            print("─" * 50)
            for ti in sharing:
                mod    = addr_to_module(ti.StartAddress or 0, modules)
                backed = DIM(os.path.basename(mod.name)) if mod else RED("NOT IN ANY MODULE ⚠")
                tag    = DIM(" ← report TID") if ti.ThreadId == tid_int else ""
                print(f"  TID=0x{ti.ThreadId:<8x}  "
                      f"StartAddr=0x{ti.StartAddress or 0:x}  {backed}{tag}")
                # Merge into unbacked_thread dimension — same phenomenon
                if not mod and 'unbacked_thread' not in dims:
                    dims['unbacked_thread'] = (
                        f"TID 0x{ti.ThreadId:x} in region 0x{region.BaseAddress:x} "
                        f"has no module backing"
                    )
            print()

    # ── 4. Strings + context-aware IOC display ────────────────────────
    if region is not None:
        print(BOLD("[ 4 ] STRINGS IN REGION"))
        print("─" * 50)
        print(DIM(f"  Scanning {region.RegionSize // 1024} KB  "
                  f"(ASCII + UTF-16LE, min_len={min_len})"))
        print()
        try:
            data    = read_region(mf, region.BaseAddress, region.RegionSize)
            strings = _extract_strings_from_data(data, min_len=min_len)

            ioc_hits = [(off, enc, s) for off, enc, s in strings
                        if IOC_PATTERNS.search(s)]
            net_offs = {off for off, enc, s in ioc_hits if NET_PATTERNS.search(s)}
            notable  = [(off, enc, s) for off, enc, s in strings
                        if not IOC_PATTERNS.search(s) and len(s) > 20][:20]

            if ioc_hits:
                print(f"  {RED(f'[!] {len(ioc_hits)} IOC match(es):')}")
                for off, enc, s in ioc_hits:
                    abs_addr = region.BaseAddress + off
                    print(RED(f"    0x{abs_addr:x}  {CYAN(f'[{enc}]'):<14}  {s}"))
                    if off in net_offs:
                        print(YELLOW("    ↳ Network pattern — ±128 byte context:"))
                        print(_hexdump_context(data, off, region.BaseAddress))
                        print()
                dims['ioc_strings'] = (
                    f"{len(ioc_hits)} IOC pattern(s) matched "
                    f"({len(net_offs)} network-protocol hit(s))"
                )
            else:
                print(f"  {DIM('[·] No IOC patterns matched.')}")

            if notable:
                print(f"\n  {BOLD('Other notable strings (len > 20, top 20):')}")
                for off, enc, s in notable:
                    print(f"    0x{region.BaseAddress + off:x}  "
                          f"{CYAN(f'[{enc}]'):<14}  {s}")

            n_ascii = sum(1 for _, e, _ in strings if e == 'ASCII')
            n_utf16 = sum(1 for _, e, _ in strings if e == 'UTF16')
            print(DIM(f"\n  Total: {len(strings)} strings  "
                      f"(ASCII: {n_ascii}  UTF-16LE: {n_utf16})"))
        except Exception as e:
            print(RED(f"  [!] Could not read region: {e}"))
        print()

    # ── Verdict (MECE) ────────────────────────────────────────────────
    print(BOLD("[ VERDICT ]"))
    print("─" * 50)
    print(f"  {_verdict(dims)}\n")
    if dims:
        for key, detail in dims.items():
            label = INDICATOR_DIMS.get(key, key)
            print(f"  {BOLD('►')} {YELLOW(label)}")
            print(f"    {DIM(detail)}")

    # ── Optional extract ──────────────────────────────────────────────
    if extract_to and region is not None:
        print()
        try:
            data = read_region(mf, region.BaseAddress, region.RegionSize)
            Path(extract_to).write_bytes(data)
            print(GREEN(f"[+] Region extracted → {extract_to}  ({len(data)} bytes)"))
        except Exception as e:
            print(RED(f"[!] Extract failed: {e}"))
    print()


# ── Hunt playbooks ────────────────────────────────────────────────────────────

def _print_hunt_header(title: str):
    print(f"\n{BOLD('══════════════════════════════════════════')}")
    print(f"{BOLD(f'  HUNT: {title}')}")
    print(f"{BOLD('══════════════════════════════════════════')}\n")

def _print_check(label: str, status: str, detail: str = ""):
    icon = RED("[!]") if "SUSPICIOUS" in status or "ANOMAL" in status else (
           YELLOW("[~]") if "NOTABLE" in status else GREEN("[✓]"))
    print(f"  {icon} {BOLD(label)}")
    print(f"      Status : {status}")
    if detail:
        print(f"      Detail : {detail}")
    print()


def _hunt_injection(mf: MinidumpFile, verbose: bool = False) -> dict:
    """\n    Detect classic process injection via cross-correlation of three signals.\n    Each signal alone can be noise; overlap between them raises confidence.\n    Returns dict of findings for use in --hunt all summary.\n    """
    modules = get_modules(mf)
    rwx     = _hunt_rwx(mf)
    pe_hits = _hunt_hidden_pe(mf)
    threads = _hunt_unbacked_threads(mf)

    injected_pe_regions = {r.BaseAddress for r, known in pe_hits if not known}
    rwx_bases           = {r.BaseAddress for r in rwx}

    # Cross-correlate: regions that are BOTH RWX and contain a hidden PE
    rwx_and_pe = rwx_bases & injected_pe_regions

    # Threads whose start addr falls inside a RWX region
    def in_rwx(addr):
        for r in rwx:
            if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
                return r
        return None

    threads_in_rwx = [(ti, in_rwx(ti.StartAddress or 0)) for ti in threads
                      if in_rwx(ti.StartAddress or 0)]

    # Score (independent signals)
    score = 0
    if rwx:            score += 1
    if injected_pe_regions: score += 1
    if threads:        score += 1

    findings = {
        "rwx":        rwx,
        "hidden_pe":  [(r, k) for r, k in pe_hits if not k],
        "threads":    threads,
        "rwx_and_pe": rwx_and_pe,
        "threads_in_rwx": threads_in_rwx,
        "score":      score,
    }

    # ── Output ────────────────────────────────────────────────────────
    _print_hunt_header("Process Injection")

    # Check 1: RWX memory
    if rwx:
        detail = f"{len(rwx)} region(s)"
        if verbose:
            for r in rwx:
                p = prot_str(r.Protect)
                t = prot_str(r.Type)
                detail += f"\n          0x{r.BaseAddress:x}  size=0x{r.RegionSize:x}  {p}  {t}"
        _print_check("RWX memory regions", RED("SUSPICIOUS"), detail)
    else:
        _print_check("RWX memory regions", GREEN("CLEAN — none found"))

    # Check 2: Hidden PE headers
    hidden = [(r, k) for r, k in pe_hits if not k]
    if hidden:
        detail = f"{len(hidden)} unregistered PE(s)"
        if verbose:
            for r, _ in hidden:
                detail += f"\n          0x{r.BaseAddress:x}  {prot_str(r.Protect)}"
        _print_check("Hidden PE headers (MZ not in module list)", RED("SUSPICIOUS"), detail)
    else:
        _print_check("Hidden PE headers", GREEN("CLEAN — all MZ headers in module list"))

    # Check 3: Unbacked threads
    if threads:
        detail = f"{len(threads)} thread(s) with no module backing"
        if verbose:
            for ti in threads:
                detail += f"\n          TID=0x{ti.ThreadId:x}  StartAddr=0x{ti.StartAddress or 0:x}"
        _print_check("Unbacked threads", RED("SUSPICIOUS"), detail)
    else:
        _print_check("Unbacked threads", GREEN("CLEAN — all threads backed by known modules"))

    # Check 4: Correlation bonus
    if rwx_and_pe:
        addrs = ", ".join(f"0x{a:x}" for a in rwx_and_pe)
        _print_check("RWX + hidden PE overlap", RED("SUSPICIOUS — high confidence injection"),
                     f"Regions with both signals: {addrs}")
    if threads_in_rwx:
        for ti, r in threads_in_rwx:
            _print_check("Thread executing inside RWX region",
                         RED("SUSPICIOUS — active shellcode execution"),
                         f"TID=0x{ti.ThreadId:x} in region 0x{r.BaseAddress:x}")

    # Verdict
    verdict = (RED("HIGH CONFIDENCE INJECTION") if score >= 3 else
               YELLOW("LIKELY INJECTION") if score == 2 else
               YELLOW("POSSIBLE INJECTION") if score == 1 else
               GREEN("CLEAN"))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/3 independent signals)\n")

    if not verbose and (rwx or hidden or threads):
        print(DIM("  Use --verbose to list individual addresses.\n"))

    return findings


def _hunt_hollowing(mf: MinidumpFile, verbose: bool = False) -> dict:
    """\n    Detect Process Hollowing by comparing PEB image path against\n    the actual memory backing of the main module base address.\n\n    Process Hollowing fingerprint:\n      1. Main module memory type is MEM_PRIVATE instead of MEM_IMAGE\n      2. MZ header at image base is missing or zeroed\n      3. Image base memory is RWX (needed to write replacement code)\n    """
    peb     = mf.peb
    modules = get_modules(mf)
    regions = get_memory_regions(mf)

    findings = {"checks": [], "score": 0}

    _print_hunt_header("Process Hollowing")

    if not peb:
        print(RED("  [!] PEB not available — cannot run hollowing check.\n"))
        return findings

    image_base = peb.image_base_address
    image_path = peb.image_path or "(unknown)"

    print(f"  {DIM('PEB ImagePath  :')} {image_path}")
    print(f"  {DIM('ImageBaseAddr  :')} 0x{image_base:x}\n")

    # ── Check 1: Memory type at image base ────────────────────────────
    base_region = None
    for r in regions:
        if r.BaseAddress <= image_base < r.BaseAddress + r.RegionSize:
            base_region = r
            break

    if not base_region:
        _print_check("Memory type at image base",
                     YELLOW("NOTABLE — region not found in dump"),
                     "Image base page may not have been captured")
    else:
        mtype = prot_str(base_region.Type)
        p     = prot_str(base_region.Protect)
        if "MEM_IMAGE" in mtype:
            _print_check("Memory type at image base",
                         GREEN("CLEAN — MEM_IMAGE (mapped from disk)"),
                         f"0x{base_region.BaseAddress:x}  {mtype}  {p}")
        else:
            _print_check("Memory type at image base",
                         RED("SUSPICIOUS — MEM_PRIVATE (not mapped from disk)"),
                         f"0x{base_region.BaseAddress:x}  {mtype}  {p}")
            findings["score"] += 1

    # ── Check 2: MZ header at image base ──────────────────────────────
    try:
        header = read_region(mf, image_base, min(64, 0x1000))
        if header[:2] == b'MZ':
            _print_check("MZ header at image base",
                         GREEN("CLEAN — MZ present"),
                         f"Header bytes: {header[:8].hex()}")
        elif header[:2] == b'':
            _print_check("MZ header at image base",
                         RED("SUSPICIOUS — MZ zeroed out (header wiping)"),
                         f"First bytes: {header[:8].hex()}")
            findings["score"] += 1
        else:
            _print_check("MZ header at image base",
                         YELLOW("NOTABLE — unexpected bytes where MZ should be"),
                         f"First bytes: {header[:8].hex()}")
            findings["score"] += 1
    except Exception as e:
        _print_check("MZ header at image base",
                     YELLOW("NOTABLE — could not read"),
                     str(e))

    # ── Check 3: RWX at image base ────────────────────────────────────
    if base_region:
        p = prot_str(base_region.Protect)
        if any(s in p for s in SUSPICIOUS_PROTS):
            _print_check("Protection at image base",
                         RED("SUSPICIOUS — RWX (write needed to hollow)"),
                         f"{p}")
            findings["score"] += 1
        else:
            _print_check("Protection at image base",
                         GREEN(f"CLEAN — {p}"))

    # ── Check 4: Module list sanity ───────────────────────────────────
    main_mod = addr_to_module(image_base, modules)
    if main_mod:
        mod_name = os.path.basename(main_mod.name).lower()
        peb_name = os.path.basename(image_path).lower()
        if mod_name == peb_name:
            _print_check("PEB image name vs module list",
                         GREEN(f"CLEAN — both report '{mod_name}'"))
        else:
            _print_check("PEB image name vs module list",
                         RED("SUSPICIOUS — name mismatch"),
                         f"PEB says '{peb_name}', module list says '{mod_name}'")
            findings["score"] += 1
    else:
        _print_check("PEB image name vs module list",
                     YELLOW("NOTABLE — image base not in any module"),
                     "Main executable may have been unmapped")
        findings["score"] += 1

    # Verdict
    score = findings["score"]
    verdict = (RED("HIGH CONFIDENCE HOLLOWING") if score >= 3 else
               YELLOW("LIKELY HOLLOWING") if score == 2 else
               YELLOW("POSSIBLE HOLLOWING") if score == 1 else
               GREEN("CLEAN — no hollowing indicators"))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/4 checks flagged)\n")
    return findings


def _extract_ioc_strings(data: bytes, base_addr: int) -> list:
    """
    Extract IOC-relevant strings with full length preservation.
    Uses two strategies:
      1. Standard printable-ASCII regex (catches most strings)
      2. Anchor-and-extend for known prefixes (https://, http://) that may
         be followed by bytes that break the printable-ASCII run — this
         prevents truncation of URLs stored with mixed-case or encoded chars.
    Returns list of (offset, enc, string).
    """
    results = []
    seen_offsets = set()

    # Strategy 1: standard printable ASCII, min 8 chars
    pat = rb'[ -~]{8,}'
    for m in re.finditer(pat, data):
        results.append((m.start(), "ASCII", m.group().decode("ascii", errors="replace")))
        seen_offsets.add(m.start())

    # Strategy 2: anchor-and-extend for URL prefixes
    # Read forward from the prefix until we hit a null or non-printable run > 1
    URL_ANCHORS = [b'https://', b'http://']
    for anchor in URL_ANCHORS:
        pos = 0
        while True:
            idx = data.find(anchor, pos)
            if idx == -1:
                break
            if idx not in seen_offsets:
                # Extend forward: accept printable ASCII + common URL chars
                end = idx
                while end < len(data) and (32 <= data[end] < 127):
                    end += 1
                s = data[idx:end].decode("ascii", errors="replace")
                if len(s) >= 8:
                    results.append((idx, "ASCII-URL", s))
                    seen_offsets.add(idx)
            pos = idx + 1

    # UTF-16LE
    pat_uni = rb'(?:[ -~]\x00){8,}'
    for m in re.finditer(pat_uni, data):
        if m.start() not in seen_offsets:
            results.append((m.start(), "UTF16",
                            m.group().decode("utf-16-le", errors="replace")))

    results.sort(key=lambda x: x[0])
    return results


# Modules whose code sections legitimately contain network/API strings.
# Hits inside these are almost always false positives for stomping detection.
STOMPING_WHITELIST = {
    "wininet.dll", "winhttp.dll", "urlmon.dll", "mshtml.dll",
    "ieframe.dll", "cryptsp.dll", "crypt32.dll", "ncrypt.dll",
    "schannel.dll", "secur32.dll", "ws2_32.dll", "dnsapi.dll",
    "dhcpcsvc.dll", "iphlpapi.dll", "mswsock.dll", "cryptdll.dll",
    "rasapi32.dll", "rasman.dll",
}

# IOC patterns for stomping — deliberately excludes https?:// and InternetOpen
# because those appear in whitelisted DLLs. They are caught separately with
# a whitelist check so we can still flag them in non-whitelisted modules.
STOMPING_IOC = re.compile(
    r'cmd\.exe|powershell|CreateRemoteThread|VirtualAlloc'
    r'|WriteProcessMemory|shellcode|beacon|cobalt'
    r'|base64|WSASocket|meterpreter|mimikatz',
    re.IGNORECASE
)

# Patterns that are suspicious ONLY outside whitelisted network DLLs
STOMPING_NET_IOC = re.compile(
    r'https?://[^\s]{6,}'          # full URL, not just prefix
    r'|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{2,5})?'  # IP:port
    r'|InternetOpen|LoadLibrary[AW]?\s*\('
    r'|GetProcAddress',
    re.IGNORECASE
)


def _hunt_stomping(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Detect Module Stomping: malicious code written into a legitimate
    loaded DLL's memory, which retains its MEM_IMAGE type and stays
    in the module list — invisible to thread/RWX checks.

    Fingerprints:
      1. MEM_IMAGE region with RWX protection (write needed to stomp)
      2. Executable MEM_IMAGE region containing IOC strings
         — whitelisted network DLLs (wininet, winhttp etc.) are excluded
           to suppress systematic false positives
    """
    modules = get_modules(mf)
    regions = get_memory_regions(mf)

    findings = {"rwx_image": [], "ioc_image": [], "score": 0}

    _print_hunt_header("Module Stomping")

    # ── Check 1: MEM_IMAGE regions with RWX ───────────────────────────
    rwx_image = []
    for r in regions:
        p     = prot_str(r.Protect)
        mtype = prot_str(r.Type)
        if "MEM_IMAGE" in mtype and any(s in p for s in SUSPICIOUS_PROTS):
            mod = addr_to_module(r.BaseAddress, modules)
            rwx_image.append((r, mod))

    if rwx_image:
        detail = f"{len(rwx_image)} MEM_IMAGE region(s) with RWX"
        if verbose:
            for r, mod in rwx_image:
                name = os.path.basename(mod.name) if mod else "(unknown module)"
                detail += f"\n          0x{r.BaseAddress:x}  {name}  {prot_str(r.Protect)}"
        _print_check("MEM_IMAGE regions with RWX protection",
                     RED("SUSPICIOUS — write access to mapped module memory"),
                     detail)
        findings["rwx_image"] = rwx_image
        findings["score"] += 1
    else:
        _print_check("MEM_IMAGE regions with RWX protection",
                     GREEN("CLEAN — no mapped module regions are writable+executable"))

    # ── Check 2: IOC strings in executable MEM_IMAGE regions ─────────
    print(f"  {DIM('[*] Scanning executable MEM_IMAGE regions for IOC strings...')}\n")
    ioc_hits    = []
    skipped_wl  = []

    for r in regions:
        mtype = prot_str(r.Type)
        p     = prot_str(r.Protect)
        state = prot_str(r.State)
        if "MEM_IMAGE" not in mtype or state != "MEM_COMMIT":
            continue
        if "EXECUTE" not in p:
            continue
        if r.RegionSize > 0x500000:
            continue

        mod      = addr_to_module(r.BaseAddress, modules)
        mod_name = os.path.basename(mod.name).lower() if mod else ""
        is_wl    = mod_name in STOMPING_WHITELIST

        try:
            data    = read_region(mf, r.BaseAddress, r.RegionSize)
            strings = _extract_ioc_strings(data, r.BaseAddress)

            # Apply appropriate pattern based on whitelist status
            if is_wl:
                # Whitelisted: only flag the truly unusual IOCs, not network strings
                hits = [(off, enc, s) for off, enc, s in strings
                        if STOMPING_IOC.search(s)]
                if hits:
                    ioc_hits.append((r, mod, hits, False))
                else:
                    skipped_wl.append(mod_name)
            else:
                # Non-whitelisted: flag both general IOCs and network patterns
                hits = [(off, enc, s) for off, enc, s in strings
                        if STOMPING_IOC.search(s) or STOMPING_NET_IOC.search(s)]
                if hits:
                    ioc_hits.append((r, mod, hits, True))
        except Exception:
            continue

    if skipped_wl:
        unique_wl = sorted(set(skipped_wl))
        print(f"  {DIM(f'[·] Whitelisted network DLLs skipped (network strings expected): {chr(44).join(unique_wl)}')}")
        print()

    if ioc_hits:
        total = sum(len(h) for _, _, h, _ in ioc_hits)
        detail = f"{total} IOC string(s) across {len(ioc_hits)} module region(s)"
        _print_check("IOC strings in module code regions",
                     RED("SUSPICIOUS — malicious strings inside legitimate module memory"),
                     detail)
        if verbose:
            for r, mod, hits, _ in ioc_hits:
                name = os.path.basename(mod.name) if mod else "(unknown)"
                print(f"    {YELLOW(f'Region 0x{r.BaseAddress:x}  [{name}]')}")
                for off, enc, s in hits[:10]:
                    print(f"      0x{r.BaseAddress+off:x}  [{enc}]  {s}")
                if len(hits) > 10:
                    print(DIM(f"      ... and {len(hits)-10} more"))
                print()
        findings["ioc_image"] = ioc_hits
        findings["score"] += 1
    else:
        _print_check("IOC strings in module code regions",
                     GREEN("CLEAN — no IOC patterns in executable module memory"))

    score = findings["score"]
    verdict = (RED("HIGH CONFIDENCE STOMPING") if score >= 2 else
               YELLOW("POSSIBLE STOMPING") if score == 1 else
               GREEN("CLEAN — no stomping indicators"))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/2 checks flagged)\n")

    if not verbose and ioc_hits:
        print(DIM("  Use --verbose to list matched strings per region.\n"))

    return findings


def cmd_hunt(mf: MinidumpFile, ttp: str, verbose: bool = False):
    """Run TTP-specific detection playbooks."""
    valid = {"injection", "hollowing", "stomping", "all"}
    if ttp not in valid:
        print(RED(f"[!] Unknown TTP '{ttp}'. Choose from: {', '.join(sorted(valid))}"))
        sys.exit(1)

    run_injection = ttp in ("injection", "all")
    run_hollowing = ttp in ("hollowing", "all")
    run_stomping  = ttp in ("stomping",  "all")

    results = {}

    if run_injection:
        results["injection"] = _hunt_injection(mf, verbose=verbose)
    if run_hollowing:
        results["hollowing"] = _hunt_hollowing(mf, verbose=verbose)
    if run_stomping:
        results["stomping"]  = _hunt_stomping(mf,  verbose=verbose)

    # Summary card for --hunt all
    if ttp == "all":
        print(BOLD("══════════════════════════════════════════"))
        print(BOLD("  HUNT SUMMARY"))
        print(BOLD("══════════════════════════════════════════"))
        labels = {
            "injection": ("Process Injection", results["injection"]["score"], 3),
            "hollowing": ("Process Hollowing", results["hollowing"]["score"], 4),
            "stomping":  ("Module Stomping",   results["stomping"]["score"],  2),
        }
        any_hit = False
        for key, (name, score, max_score) in labels.items():
            if score == 0:
                verdict = GREEN("CLEAN")
            elif score >= max_score - 1:
                verdict = RED("HIGH CONFIDENCE")
                any_hit = True
            else:
                verdict = YELLOW("POSSIBLE")
                any_hit = True
            print(f"  {name:<25} {verdict}  ({score}/{max_score})")
        print()
        if not any_hit:
            print(GREEN("  Overall: No TTP indicators found in this dump."))
        else:
            print(YELLOW("  Overall: One or more TTPs detected. Run --report for deep-dive."))
        print()

# ── Diff engine ───────────────────────────────────────────────────────────────

def diff_modules(mf_a, mf_b, label_a, label_b):
    mods_a = {module_name_only(m.name): m for m in get_modules(mf_a)}
    mods_b = {module_name_only(m.name): m for m in get_modules(mf_b)}

    added   = set(mods_b) - set(mods_a)
    removed = set(mods_a) - set(mods_b)
    both    = set(mods_a) & set(mods_b)

    print(f"\n{BOLD('═══ MODULE DIFF ═══')}")
    print(f"  {DIM(label_a)}: {len(mods_a)} modules")
    print(f"  {DIM(label_b)}: {len(mods_b)} modules\n")

    if added:
        print(GREEN(f"  [+] Added in {label_b} ({len(added)}):"))
        for name in sorted(added):
            m = mods_b[name]
            print(GREEN(f"      0x{m.baseaddress:016x}  {m.name}"))
    else:
        print(DIM("  [+] No new modules."))

    if removed:
        print(RED(f"\n  [-] Removed from {label_a} ({len(removed)}):"))
        for name in sorted(removed):
            m = mods_a[name]
            print(RED(f"      0x{m.baseaddress:016x}  {m.name}"))
    else:
        print(DIM("\n  [-] No removed modules."))

    # Rebased modules (same name, different base)
    rebased = [(n, mods_a[n], mods_b[n]) for n in both
               if mods_a[n].baseaddress != mods_b[n].baseaddress]
    if rebased:
        print(YELLOW(f"\n  [~] Rebased ({len(rebased)}):"))
        for name, ma, mb in sorted(rebased):
            print(YELLOW(f"      {name}: 0x{ma.baseaddress:x} → 0x{mb.baseaddress:x}"))


def diff_threads(mf_a, mf_b, label_a, label_b):
    def tid_map(mf):
        return {ti.ThreadId: ti for ti in get_thread_infos(mf)}

    ta = tid_map(mf_a)
    tb = tid_map(mf_b)
    modules_b = get_modules(mf_b)

    added   = set(tb) - set(ta)
    removed = set(ta) - set(tb)

    print(f"\n{BOLD('═══ THREAD DIFF ═══')}")
    print(f"  {DIM(label_a)}: {len(ta)} threads")
    print(f"  {DIM(label_b)}: {len(tb)} threads\n")

    if added:
        print(GREEN(f"  [+] New threads in {label_b} ({len(added)}):"))
        for tid in sorted(added):
            ti = tb[tid]
            sa = ti.StartAddress or 0
            mod = addr_to_module(sa, modules_b)
            backed = os.path.basename(mod.name) if mod else RED("NOT IN ANY MODULE ⚠")
            print(GREEN(f"      TID=0x{tid:x}  StartAddr=0x{sa:x}  Backed by: {backed}"))
    else:
        print(DIM("  [+] No new threads."))

    if removed:
        print(RED(f"\n  [-] Threads gone from {label_b} ({len(removed)}):"))
        for tid in sorted(removed):
            ti = ta[tid]
            print(RED(f"      TID=0x{tid:x}  StartAddr=0x{ti.StartAddress or 0:x}"))
    else:
        print(DIM("\n  [-] No removed threads."))


def diff_memory(mf_a, mf_b, label_a, label_b, verbose=False):
    # Protection flags worth reporting
    NOTABLE_PROTS = {
        "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY",  # RWX — always report
        "PAGE_EXECUTE_READ", "PAGE_EXECUTE",                  # executable — report
        "PAGE_READWRITE",                                     # writable — report if private
    }
    EXEC_PROTS = {"PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY",
                  "PAGE_EXECUTE_READ", "PAGE_EXECUTE"}

    def region_map(mf):
        return {r.BaseAddress: r for r in get_memory_regions(mf)}

    def is_notable(r):
        p = prot_str(r.Protect)
        return any(n in p for n in NOTABLE_PROTS)

    def region_label(r):
        p = prot_str(r.Protect)
        t = prot_str(r.Type)
        rwx  = RED(" ◄ RWX!")        if any(s in p for s in SUSPICIOUS_PROTS) else ""
        priv = YELLOW(" [PRIVATE]")  if "MEM_PRIVATE" in t else ""
        exec_ = YELLOW(" [EXEC]")    if any(e in p for e in EXEC_PROTS) and not rwx else ""
        return f"0x{r.BaseAddress:016x}  size=0x{r.RegionSize:<8x}  {p:<32}{rwx}{priv}{exec_}"

    ra = region_map(mf_a)
    rb = region_map(mf_b)

    added   = set(rb) - set(ra)
    removed = set(ra) - set(rb)
    changed = {addr for addr in set(ra) & set(rb)
               if prot_str(ra[addr].Protect) != prot_str(rb[addr].Protect)}

    # Categorize added regions
    added_rwx      = [a for a in added if any(s in prot_str(rb[a].Protect) for s in SUSPICIOUS_PROTS)]
    added_exec     = [a for a in added if any(e in prot_str(rb[a].Protect) for e in EXEC_PROTS)
                      and a not in added_rwx]
    added_notable  = [a for a in added if is_notable(rb[a])
                      and a not in added_rwx and a not in added_exec]
    added_noise    = [a for a in added if a not in added_rwx
                      and a not in added_exec and a not in added_notable]

    # Removed: only show executable ones (likely code that disappeared)
    removed_exec   = [r for r in removed if any(e in prot_str(ra[r].Protect) for e in EXEC_PROTS)]
    removed_other  = [r for r in removed if r not in removed_exec]

    print(f"\n{BOLD('═══ MEMORY REGION DIFF ═══')}")
    print(f"  {DIM(label_a)}: {len(ra)} regions")
    print(f"  {DIM(label_b)}: {len(rb)} regions")
    print(f"  {DIM('Delta')}: +{len(added)} / -{len(removed)} regions\n")

    # ── Added: RWX (always show) ──
    if added_rwx:
        print(RED(f"  [!] RWX regions in {label_b} ({len(added_rwx)}) — HIGH SUSPICION:"))
        for addr in sorted(added_rwx):
            print(RED(f"      {region_label(rb[addr])}"))
    else:
        print(DIM("  [!] No RWX regions added."))

    # ── Added: other executable ──
    if added_exec:
        print(YELLOW(f"\n  [+] New executable regions in {label_b} ({len(added_exec)}):"))
        for addr in sorted(added_exec):
            print(YELLOW(f"      {region_label(rb[addr])}"))

    # ── Added: notable (writable etc) ──
    if added_notable and verbose:
        print(f"\n  [+] Other notable new regions ({len(added_notable)}):") 
        for addr in sorted(added_notable):
            print(f"      {region_label(rb[addr])}")

    # ── Noise summary (not shown unless --verbose) ──
    if added_noise:
        if verbose:
            print(f"\n  [+] Routine new regions ({len(added_noise)}) — likely from new DLLs:")
            for addr in sorted(added_noise):
                r = rb[addr]
                print(DIM(f"      0x{addr:016x}  size=0x{r.RegionSize:<8x}  {prot_str(r.Protect)}"))
        else:
            print(DIM(f"\n  [·] {len(added_noise)} routine regions hidden (PAGE_READONLY/NOACCESS from new DLLs)."))
            print(DIM( "      Use --verbose to show all."))

    # ── Removed: executable (most interesting) ──
    if removed_exec:
        print(RED(f"\n  [-] Executable regions gone from {label_b} ({len(removed_exec)}):"))
        for addr in sorted(removed_exec):
            print(RED(f"      {region_label(ra[addr])}"))

    if removed_other and verbose:
        print(f"\n  [-] Other removed regions ({len(removed_other)}):")
        for addr in sorted(removed_other):
            r = ra[addr]
            print(DIM(f"      0x{addr:016x}  size=0x{r.RegionSize:<8x}  {prot_str(r.Protect)}"))
    elif removed_other:
        print(DIM(f"\n  [·] {len(removed_other)} removed non-exec regions hidden. Use --verbose to show all."))

    # ── Protection changes ──
    if changed:
        print(YELLOW(f"\n  [~] Protection changed ({len(changed)}):"))
        for addr in sorted(changed):
            old_p = prot_str(ra[addr].Protect)
            new_p = prot_str(rb[addr].Protect)
            flag  = RED(" ← now RWX!") if any(s in new_p for s in SUSPICIOUS_PROTS) else ""
            print(YELLOW(f"      0x{addr:016x}  {old_p} → {new_p}{flag}"))
    else:
        print(DIM("\n  [~] No protection changes."))


def cmd_diff(mf_a, path_b, mode, verbose=False):
    mf_b   = open_dump(path_b)
    label_a = os.path.basename(mf_a.filename)
    label_b = os.path.basename(path_b)

    print(f"\n{BOLD('dumpex diff')}: {CYAN(label_a)} vs {CYAN(label_b)}")
    print("─" * 60)

    if mode in ("modules", "all"):
        diff_modules(mf_a, mf_b, label_a, label_b)
    if mode in ("threads", "all"):
        diff_threads(mf_a, mf_b, label_a, label_b)
    if mode in ("memory", "all"):
        diff_memory(mf_a, mf_b, label_a, label_b, verbose=verbose)

    print()


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="dumpex",
        description=BOLD("dumpex — Minidump Memory Extractor & Analyzer"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='\n'.join(__doc__.strip().splitlines()[3:]) if __doc__ else None
    )

    parser.add_argument("dumpfile", help="Primary .DMP file")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list",         action="store_true", help="List all memory regions")
    mode.add_argument("--modules",      action="store_true", help="List loaded modules")
    mode.add_argument("--threads",      action="store_true", help="List threads with analysis")
    mode.add_argument("--extract",      metavar="ADDR",      help="Extract raw bytes at address")
    mode.add_argument("--strings",      metavar="ADDR",      help="Extract strings at address")
    mode.add_argument("--peb",          action="store_true", help="Show PEB info")
    mode.add_argument("--sysinfo",      action="store_true", help="Show OS, host, process and CPU summary")
    mode.add_argument("--diff",         metavar="DUMP2",     help="Diff against a second .DMP file")
    mode.add_argument("--report",        action="store_true", help="Generate triage report anchored to a TID, address, or string")
    mode.add_argument("--hunt",          metavar="TTP",       help="TTP detection: injection | hollowing | stomping | all")

    # Shared
    parser.add_argument("-s", "--size",      metavar="SIZE",   help="Region size in hex")
    parser.add_argument("-o", "--output",    metavar="FILE",   help="Output file for --extract")
    parser.add_argument("--filter",          metavar="PROT",   help="Filter --list by protection name")
    parser.add_argument("--grep",            metavar="REGEX",  help="Regex filter for --strings")
    parser.add_argument("--min-len",         metavar="N", type=int, default=6,
                        help="Minimum string length (default: 6)")
    parser.add_argument("--encoding",        choices=["ascii", "unicode", "both"], default="both",
                        help="String encoding to scan (default: both)")
    parser.add_argument("--diff-mode",       choices=["modules", "threads", "memory", "all"],
                        default="all", help="What to diff (default: all)")

    parser.add_argument('--verbose',    action='store_true', help='Show all regions including routine ones')
    parser.add_argument('--report-tid',  metavar='TID',  help='Anchor report to this Thread ID (hex or decimal)')
    parser.add_argument('--report-addr',   metavar='ADDR',   help='Anchor report to this memory address (hex)')
    parser.add_argument('--report-string', metavar='STRING', help='Search all memory for string, report on each hit region')
    args = parser.parse_args()
    mf   = open_dump(args.dumpfile)

    if   args.list:         cmd_list(mf, args.filter)
    elif args.modules:      cmd_modules(mf)
    elif args.threads:      cmd_threads(mf)
    elif args.peb:          cmd_peb(mf)
    elif args.sysinfo:      cmd_sysinfo(mf)
    elif args.report:
        if not args.report_tid and not args.report_addr and not args.report_string:
            print(RED("[!] --report requires at least one of: --report-tid, --report-addr, --report-string"))
            sys.exit(1)
        cmd_report(mf,
                  report_tid=args.report_tid,
                  report_addr=args.report_addr,
                  report_string=args.report_string,
                  extract_to=args.output,
                  min_len=args.min_len)
    elif args.hunt:         cmd_hunt(mf, args.hunt, verbose=args.verbose)
    elif args.diff:         cmd_diff(mf, args.diff, args.diff_mode, verbose=args.verbose)

    elif args.extract:
        addr = parse_hex_or_int(args.extract)
        _req = parse_hex_or_int(args.size) if args.size else None
        size = _resolve_size(mf, addr, _req)
        cmd_extract(mf, addr, size, args.output, auto_size=_req is None)

    elif args.strings:
        addr = parse_hex_or_int(args.strings)
        _req = parse_hex_or_int(args.size) if args.size else None
        size = _resolve_size(mf, addr, _req)
        cmd_strings(mf, addr, size, args.min_len, args.grep, args.encoding, auto_size=_req is None)


if __name__ == "__main__":
    main()