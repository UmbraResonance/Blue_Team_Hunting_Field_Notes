#!/usr/bin/env python3
"""
dumpex — Minidump Memory Extractor & Analyzer
DFIR/CTF triage tool for Windows .DMP files.

RECON:
  python dumpex.py dump.DMP --sysinfo
  python dumpex.py dump.DMP --pid
  python dumpex.py dump.DMP --peb
  python dumpex.py dump.DMP --modules
  python dumpex.py dump.DMP --threads
  python dumpex.py dump.DMP --list [--filter PAGE_EXECUTE]

HUNT (TTP detection):
  python dumpex.py dump.DMP --hunt injection
  python dumpex.py dump.DMP --hunt hollowing
  python dumpex.py dump.DMP --hunt stomping
  python dumpex.py dump.DMP --hunt pipe
  python dumpex.py dump.DMP --hunt cs-beacon [--verbose]
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
import struct
import binascii
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


def va_to_file_offset(mf: MinidumpFile, va: int):
    """
    Translate a Virtual Address (in the target process) to its byte offset
    inside the .dmp file, using the memory segment table.

    Returns None if the VA is not covered by any segment in the dump.

    Address types in a minidump
    ───────────────────────────
      Virtual Address (VA)
          The address as seen by the target process at the time of the dump.
          Every field named BaseAddress / StartAddress / baseaddress /
          StartOfMemoryRange carries a VA. It is NOT a physical RAM address.

      File offset  (dump-file offset)
          Byte position inside the .dmp file where that memory was written.
          Formula: segment.start_file_address + (va - segment.start_virtual_address)
          This is the closest thing to a "physical" locator that a minidump
          exposes, but it refers to the file, not to RAM.

      Physical address (RAM)
          The real hardware address. Minidumps do NOT record this; it is
          only available in kernel / full memory dumps with PFN tables.
    """
    if not va:
        return None
    segs = []
    if mf.memory_segments_64 and mf.memory_segments_64.memory_segments:
        segs = mf.memory_segments_64.memory_segments
    elif mf.memory_segments and mf.memory_segments.memory_segments:
        segs = mf.memory_segments.memory_segments
    for seg in segs:
        if seg.start_virtual_address <= va < seg.end_virtual_address:
            return seg.start_file_address + (va - seg.start_virtual_address)
    return None


def addr_label(mf: MinidumpFile, va: int, region_base=None, indent: int = 2) -> str:
    """
    Return a consistent multi-line annotation for any VA returned by hunt/report.

      VA (process)   0x<va>          — address in the target process
      File offset    0x<offset>      — byte position inside the .dmp file
      Region base    0x<base>        — start of the enclosing memory region
                                       (omitted when same as va or not given)

    Physical Address (RAM) is not available in minidumps.
    """
    pad = " " * indent
    lines = [f"{pad}{'VA (process)':<16} 0x{va:016x}"]

    fo = va_to_file_offset(mf, va)
    if fo is not None:
        lines.append(f"{pad}{'File offset (.dmp)':<20} 0x{fo:016x}")
    else:
        lines.append(f"{pad}{'File offset (.dmp)':<20} {DIM('(VA not captured in dump)')}")

    if region_base is not None and region_base != va:
        lines.append(f"{pad}{'Region base (VA)':<20} 0x{region_base:016x}")

    return "\n".join(lines)


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


def _pe_timestamp_to_str(ts: int) -> str:
    """
    Convert a PE TimeDateStamp (Unix epoch, 32-bit) to a UTC string.
    Returns a dimmed note for zero / sentinel values.
    """
    import datetime
    if not ts:
        return DIM("(not set)")
    if ts == 0xFFFFFFFF:
        return DIM("(reproducible build — timestamp suppressed)")
    try:
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        if dt.year < 1980 or dt.year > 2040:
            return f"0x{ts:08x}  {YELLOW('(suspicious value)')}"
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError, ValueError):
        return f"0x{ts:08x}  {YELLOW('(out of range)')}"


def _version_str(vi) -> str:
    """
    Format VS_FIXEDFILEINFO into 'major.minor.patch.build' strings.
    Returns None if the block is absent or entirely zero.
    """
    if vi is None:
        return None
    try:
        fv_ms = vi.dwFileVersionMS
        fv_ls = vi.dwFileVersionLS
        pv_ms = vi.dwProductVersionMS
        pv_ls = vi.dwProductVersionLS
        if fv_ms == 0 and fv_ls == 0 and pv_ms == 0 and pv_ls == 0:
            return None
        file_ver    = f"{fv_ms >> 16}.{fv_ms & 0xFFFF}.{fv_ls >> 16}.{fv_ls & 0xFFFF}"
        product_ver = f"{pv_ms >> 16}.{pv_ms & 0xFFFF}.{pv_ls >> 16}.{pv_ls & 0xFFFF}"
        if file_ver == product_ver:
            return file_ver
        return f"{file_ver}  (product: {product_ver})"
    except Exception:
        return None


def cmd_modules(mf):
    mods = get_modules(mf)

    for m in sorted(mods, key=lambda x: x.baseaddress):
        name     = m.name or "(unnamed)"
        basename = os.path.basename(name)

        ts_raw  = getattr(m, "timestamp", 0) or 0
        ts_str  = _pe_timestamp_to_str(ts_raw)
        ver_str = _version_str(getattr(m, "versioninfo", None))
        checksum = getattr(m, "checksum", 0) or 0

        # Anomaly flags
        flags = []
        if not m.name:
            flags.append(RED("[NO NAME]"))
        if ts_raw and ts_raw < 315532800:   # before 1980-01-01
            flags.append(YELLOW("[OLD TIMESTAMP]"))
        flag_str = "  " + " ".join(flags) if flags else ""

        print(f"\n  {BOLD(basename)}{flag_str}")
        print(f"  {'Full path':<18} {DIM(name)}")
        print(f"  {'Base → End':<18} 0x{m.baseaddress:016x} → 0x{m.endaddress:016x}  (size 0x{m.size:x})")
        print(f"  {'Compiled (UTC)':<18} {ts_str}")
        if ver_str:
            print(f"  {'File version':<18} {ver_str}")
        if checksum:
            print(f"  {'Checksum':<18} 0x{checksum:08x}")

    print(f"\n{GREEN(f'[+] {len(mods)} module(s).')}")


def _filetime_to_str(ft: int) -> str:
    """
    Convert a Windows FILETIME (100-ns intervals since 1601-01-01) to a
    human-readable UTC string.  Returns "(none)" for zero / unset values.
    """
    import datetime
    if not ft:
        return "(none)"
    try:
        # FILETIME epoch offset to Unix epoch in microseconds
        EPOCH_DIFF_US = 11644473600 * 1_000_000
        us = ft // 10 - EPOCH_DIFF_US
        dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"0x{ft:x}"


def _dumpflags_str(flags) -> str:
    """Return a compact label for MINIDUMP_THREAD_INFO DumpFlags."""
    if flags is None:
        return ""
    name = flags.name if hasattr(flags, "name") else str(flags)
    # Map verbose enum names to short tags
    TAG = {
        "MINIDUMP_THREAD_INFO_EXITED_THREAD":   "[EXITED]",
        "MINIDUMP_THREAD_INFO_WRITING_THREAD":  "[DUMPER]",
        "MINIDUMP_THREAD_INFO_ERROR_THREAD":    "[ERROR]",
        "MINIDUMP_THREAD_INFO_INVALID_CONTEXT": "[NO_CTX]",
        "MINIDUMP_THREAD_INFO_INVALID_INFO":    "[NO_INFO]",
        "MINIDUMP_THREAD_INFO_INVALID_TEB":     "[NO_TEB]",
    }
    return TAG.get(name, f"[{name}]") if name else ""


def cmd_threads(mf):
    import datetime

    threads  = {t.ThreadId: t for t in (mf.threads.threads if mf.threads else [])}
    infos    = get_thread_infos(mf)
    modules  = get_modules(mf)

    # Determine whether timing data is available (CreateTime != 0 for any thread)
    has_times = any(getattr(ti, "CreateTime", 0) for ti in infos)

    for ti in infos:
        sa     = ti.StartAddress or 0
        mod    = addr_to_module(sa, modules)
        backed = DIM(os.path.basename(mod.name)) if mod else RED("⚠  NOT IN ANY MODULE")

        # ── Flags / status ────────────────────────────────────────────────
        flag_tag    = _dumpflags_str(getattr(ti, "DumpFlags", None))
        exit_status = getattr(ti, "ExitStatus", None)
        exited      = flag_tag == "[EXITED]"

        # ── Times ─────────────────────────────────────────────────────────
        create_time = _filetime_to_str(getattr(ti, "CreateTime", 0))
        exit_time   = _filetime_to_str(getattr(ti, "ExitTime",   0))
        kernel_time = getattr(ti, "KernelTime", 0)
        user_time   = getattr(ti, "UserTime",   0)

        # ── Render ────────────────────────────────────────────────────────
        tid_str = f"0x{ti.ThreadId:x}"
        if flag_tag == "[DUMPER]":
            tid_str = CYAN(tid_str) + f" {CYAN(flag_tag)}"
        elif exited:
            tid_str = DIM(tid_str) + f" {DIM(flag_tag)}"
        elif flag_tag:
            tid_str = YELLOW(tid_str) + f" {YELLOW(flag_tag)}"

        print(f"\n  {BOLD('TID')}              {tid_str}")
        print(f"  {'StartAddress':<16} 0x{sa:x}  ← {backed}")
        if has_times:
            print(f"  {'Created':<16} {create_time}")
            if exited:
                print(f"  {'Exited':<16} {YELLOW(exit_time)}")
                if exit_status is not None:
                    code_str = f"0x{exit_status:x}"
                    label    = YELLOW(code_str) if exit_status else DIM(code_str + " (clean)")
                    print(f"  {'ExitStatus':<16} {label}")
            else:
                print(f"  {'Exited':<16} {DIM('(still running)')}")
        print(f"  {'KernelTime':<16} {kernel_time}")
        print(f"  {'UserTime':<16} {user_time}")

    if not has_times:
        print(f"\n  {DIM('[~] CreateTime/ExitTime not available — dump was produced without ThreadInfoList stream.')}")

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


def cmd_pid(mf: MinidumpFile):
    """
    Report the Process ID recorded in the minidump.

    Tries multiple streams in priority order so the result is as reliable
    as possible even when a dump was produced by a non-standard tool:

      1. MINIDUMP_MISC_INFO  – most authoritative; written by MiniDumpWriteDump
      2. Thread list         – all threads share the same owning PID on Windows;
                               reported as a cross-check when MiscInfo is absent
      3. Exception stream    – contains ThreadId; used purely as a last resort
         (gives TID, not PID, so it is labelled accordingly)
    """
    pid      = None
    source   = None
    warnings = []

    # ── 1. MiscInfo (most reliable) ──────────────────────────────────────
    mi = mf.misc_info
    if mi and getattr(mi, "ProcessId", None):
        pid    = mi.ProcessId
        source = "MINIDUMP_MISC_INFO (ProcessId field)"

    # ── 2. Thread list cross-check / fallback ────────────────────────────
    #    minidump-python exposes thread.ThreadId but NOT thread.ProcessId
    #    directly; however, we can cross-check that MiscInfo PID is plausible
    #    by confirming threads exist.  When MiscInfo is missing we report the
    #    thread count as evidence and surface any TID that might help.
    threads = mf.threads.threads if mf.threads else []
    if threads and pid is None:
        tids = [t.ThreadId for t in threads]
        warnings.append(
            f"MiscInfo stream absent — PID not directly recoverable from thread list.\n"
            f"    {len(tids)} thread(s) found: "
            + ", ".join(f"0x{t:x}" for t in tids[:8])
            + (" …" if len(tids) > 8 else "")
        )

    # ── 3. Exception stream – last resort (gives TID, not PID) ───────────
    exc = getattr(mf, "exception", None)
    exc_tid = None
    if exc and pid is None:
        try:
            exc_tid = exc.ThreadId
        except AttributeError:
            pass
        if exc_tid:
            warnings.append(
                f"Exception stream present: faulting TID = 0x{exc_tid:x} "
                f"(this is a Thread ID, not a Process ID)"
            )

    # ── Output ────────────────────────────────────────────────────────────
    print(f"\n{BOLD('═══ PROCESS ID ═══')}")

    if pid is not None:
        print(f"  {'PID (decimal)':<26} {GREEN(str(pid))}")
        print(f"  {'PID (hex)':<26} {GREEN(f'0x{pid:x}')}")
        print(f"  {'Source':<26} {DIM(source)}")
        if threads:
            print(f"  {'Threads in dump':<26} {len(threads)}")
    else:
        print(f"  {YELLOW('[!] ProcessId not found in MiscInfo stream.')}")

    for w in warnings:
        print(f"\n  {YELLOW('[~]')} {w}")

    if pid is None and not warnings:
        print(f"  {RED('[!] Could not determine PID — dump may lack MiscInfo, thread list, and exception stream.')}")

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
        modules_list = get_modules(mf)

        print(f"\n{BOLD('Searching memory for:')} {CYAN(repr(report_string))}")
        print("─" * 55)
        hits = _search_string_in_memory(mf, report_string)
        if not hits:
            print(RED(f"  [!] String not found in any committed memory region."))
            print(DIM("      Try --strings with a broader address range to verify."))
            return

        # Split into actionable (MEM_PRIVATE / no module) vs noise (MEM_IMAGE in known module)
        private_hits = []
        image_hits   = []
        for r, off, enc in hits:
            mtype  = prot_str(r.Type)
            mod    = addr_to_module(r.BaseAddress, modules_list)
            if "MEM_IMAGE" in mtype and mod:
                image_hits.append((r, off, enc, mod))
            else:
                private_hits.append((r, off, enc))

        # Summary line
        print(GREEN(f"  [+] Found in {len(hits)} region(s):"))
        for r, off, enc in private_hits:
            abs_addr = r.BaseAddress + off
            fo_abs   = va_to_file_offset(mf, abs_addr)
            fo_str   = f"0x{fo_abs:x}" if fo_abs is not None else "(not captured)"
            p        = prot_str(r.Protect)
            t        = prot_str(r.Type)
            rwx_tag  = RED(" ◄ RWX") if any(s in p for s in SUSPICIOUS_PROTS) else ""
            print(f"    {RED('►')} [{enc}]  {p}  {t}{rwx_tag}")
            print(f"      VA  = region base 0x{r.BaseAddress:016x}  +  offset 0x{off:x}  =  0x{abs_addr:016x}")
            print(f"      DMP = file offset {fo_str}")
        if image_hits:
            mod_names = sorted({os.path.basename(m.name) for _, _, _, m in image_hits})
            print(DIM(f"    [·] {len(image_hits)} hit(s) in known MEM_IMAGE modules "
                      f"({', '.join(mod_names)}) — skipped (expected content)"))
        print()

        if not private_hits:
            print(DIM("  [·] All hits are in known system modules — no actionable regions to triage."))
            return

        # Run full triage only on private/unregistered hits
        for i, (r, off, enc) in enumerate(private_hits, 1):
            if len(private_hits) > 1:
                print(BOLD(f"{'═'*55}"))
                print(BOLD(f"  Triaging hit {i}/{len(private_hits)} — region 0x{r.BaseAddress:x}"))
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

            fo_reg = va_to_file_offset(mf, region.BaseAddress)
            fo_reg_str = f"0x{fo_reg:x}" if fo_reg is not None else "(not captured in dump)"
            print(f"  {'Region base (VA)':<24} 0x{region.BaseAddress:016x}  {DIM('← process virtual address')}")
            print(f"  {'Region base (file offset)':<24} {fo_reg_str}  {DIM('← byte offset inside .dmp')}")
            print(f"  {'Physical addr (RAM)':<24} {DIM('not recorded in minidumps')}")
            print(f"  {'IOC addr = base + offset':<24} {DIM('see formula per string below')}")
            print(f"  {'Region Size':<24} 0x{region.RegionSize:x}  ({region.RegionSize // 1024} KB)")
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
                    abs_addr   = region.BaseAddress + off
                    fo_abs     = va_to_file_offset(mf, abs_addr)
                    fo_abs_str = f"0x{fo_abs:x}" if fo_abs is not None else "(not captured)"
                    print(RED(f"    {CYAN(f'[{enc}]'):<14} {s}"))
                    print(RED(f"      VA  = region base 0x{region.BaseAddress:016x}  +  offset 0x{off:x}  =  0x{abs_addr:016x}"))
                    print(RED(f"      DMP = file offset {fo_abs_str}"))
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
                    abs_addr   = region.BaseAddress + off
                    fo_abs     = va_to_file_offset(mf, abs_addr)
                    fo_abs_str = f"0x{fo_abs:x}" if fo_abs is not None else "?"
                    print(f"    {CYAN(f'[{enc}]'):<14} {s}")
                    print(DIM(f"      VA  = 0x{region.BaseAddress:016x} + 0x{off:x} = 0x{abs_addr:016x}  DMP = {fo_abs_str}"))

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
                fo = va_to_file_offset(mf, r.BaseAddress)
                fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
                detail += (f"\n          VA (process)      0x{r.BaseAddress:016x}"
                           f"  size=0x{r.RegionSize:x}"
                           f"\n          File offset       {fo_str}"
                           f"\n          Region base (VA)  0x{r.BaseAddress:016x}"
                           f"\n          {p}  {t}")
        _print_check("RWX memory regions", RED("SUSPICIOUS"), detail)
    else:
        _print_check("RWX memory regions", GREEN("CLEAN — none found"))

    # Check 2: Hidden PE headers
    hidden = [(r, k) for r, k in pe_hits if not k]
    if hidden:
        detail = f"{len(hidden)} unregistered PE(s)"
        if verbose:
            for r, _ in hidden:
                p = prot_str(r.Protect)
                fo = va_to_file_offset(mf, r.BaseAddress)
                fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
                detail += (f"\n          VA (process)      0x{r.BaseAddress:016x}"
                           f"\n          File offset       {fo_str}"
                           f"\n          Region base (VA)  0x{r.BaseAddress:016x}"
                           f"\n          {p}")
        _print_check("Hidden PE headers (MZ not in module list)", RED("SUSPICIOUS"), detail)
    else:
        _print_check("Hidden PE headers", GREEN("CLEAN — all MZ headers in module list"))

    # Check 3: Unbacked threads
    if threads:
        detail = f"{len(threads)} thread(s) with no module backing"
        if verbose:
            for ti in threads:
                sa = ti.StartAddress or 0
                fo = va_to_file_offset(mf, sa)
                fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
                detail += (f"\n          TID=0x{ti.ThreadId:x}"
                           f"\n          VA (process)   0x{sa:016x}"
                           f"\n          File offset    {fo_str}"
                           f"\n          Region base (VA) — see StartAddr above")
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

    fo_base = va_to_file_offset(mf, image_base)
    fo_base_str = f"0x{fo_base:x}" if fo_base is not None else "(not captured)"
    print(f"  {DIM('PEB ImagePath     :')} {image_path}")
    print(f"  {DIM('ImageBase VA      :')} 0x{image_base:016x}  {DIM('(process virtual address)')}")
    print(f"  {DIM('ImageBase offset  :')} {fo_base_str}          {DIM('(byte offset in .dmp file)')}")
    print()

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
            fo_reg = va_to_file_offset(mf, base_region.BaseAddress)
            fo_reg_str = f"0x{fo_reg:x}" if fo_reg is not None else "(not captured)"
            _print_check("Memory type at image base",
                         GREEN("CLEAN — MEM_IMAGE (mapped from disk)"),
                         f"VA (process) 0x{base_region.BaseAddress:016x}  File offset {fo_reg_str}  {mtype}  {p}")
        else:
            fo_reg = va_to_file_offset(mf, base_region.BaseAddress)
            fo_reg_str = f"0x{fo_reg:x}" if fo_reg is not None else "(not captured)"
            _print_check("Memory type at image base",
                         RED("SUSPICIOUS — MEM_PRIVATE (not mapped from disk)"),
                         f"VA (process) 0x{base_region.BaseAddress:016x}  File offset {fo_reg_str}  {mtype}  {p}")
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



def _hunt_pipe(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Detect Named Pipe C2 / Lateral Movement channels.

    Strategy: structural, not signature-based.
      Check 1 — Pipe names in MEM_PRIVATE memory
                 (system DLLs legitimately reference pipes; private memory does not)
      Check 2 — C2 artifacts near private pipe names
                 (IP:port, HTTP URLs in same region = strong signal)
      Check 3 — Known framework pipe naming patterns (bonus score only)
      Check 4 — Unbacked thread executing in same region as pipe name
    """
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    infos   = get_thread_infos(mf)

    # Pipe name patterns
    # Match pipe names in both ASCII and UTF-16LE.
    # UTF-16LE pattern built at runtime to avoid null bytes in source.
    PIPE_PAT_ASCII = re.compile(
        rb'(?:\\[?]{0,2}\\pipe\\|\\pipe\\|\\.\\pipe\\)',
        re.IGNORECASE
    )
    _utf16_pipe = '\\pipe\\'.encode('utf-16-le')
    PIPE_PAT_UTF16 = re.compile(re.escape(_utf16_pipe), re.IGNORECASE)
    # Known C2 framework pipe name patterns with specific attribution.
    # Each entry: (compiled_regex, framework, technique, reference)
    KNOWN_FRAMEWORK_PIPES = [
        (re.compile(r'postex_', re.I),
         "Cobalt Strike", "Post-Exploitation (postex) pipe — default name for CS post-ex jobs",
         "T1559.001"),
        (re.compile(r'msagent_', re.I),
         "Cobalt Strike", "SMB Beacon peer-to-peer pipe — default msagent pipe name",
         "T1090.001"),
        (re.compile(r'status_[0-9a-f]+', re.I),
         "Cobalt Strike", "Beacon status pipe — used for internal Beacon comms",
         "T1559.001"),
        (re.compile(r'MSSE-[0-9a-f]+-server', re.I),
         "Metasploit", "Meterpreter named pipe transport — default MSSE pipe",
         "T1559.001"),
        (re.compile(r'mojo\.\d+\.\d+', re.I),
         "Chrome / Chromium IPC (possible abuse)", "Mojo IPC pipe — legitimate but abused by some loaders",
         "T1559.001"),
        (re.compile(r'DserNamePipe', re.I),
         "Various", "PrintNightmare / Spooler exploit pipe name",
         "T1068"),
        (re.compile(r'583da750', re.I),
         "Cobalt Strike", "Hardcoded CS pipe name fragment seen in older versions",
         "T1559.001"),
        (re.compile(r'psexesvc', re.I),
         "PsExec / Impacket", "PSExec service pipe — used for lateral movement via SMB",
         "T1021.002"),
        (re.compile(r'paexec', re.I),
         "PAExec", "PAExec lateral movement pipe",
         "T1021.002"),
        (re.compile(r'remcom', re.I),
         "RemCom", "RemCom lateral movement tool pipe",
         "T1021.002"),
        (re.compile(r'svcctl', re.I),
         "SCM / Lateral Movement", "Service Control Manager pipe — abused by SCM-based lateral movement",
         "T1021.002"),
    ]
    # C2 context patterns for neighbourhood scan
    C2_PAT = re.compile(
        r'https?://|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{2,5})?'
        r'|submit\.php|/ca$|/w2p',
        re.IGNORECASE
    )

    findings = {
        "private_pipes":   [],   # (region, offset, name)
        "c2_context":      [],   # (region, pipe_name, c2_strings)
        "framework_pipes": [],   # (region, pipe_name, pattern)
        "unbacked_in_rgn": [],   # (thread_info, region)
        "score": 0,
    }

    _print_hunt_header("Named Pipe C2 / Lateral Movement")

    # ── Collect all pipe name occurrences ────────────────────────────
    private_pipes = []   # (region, offset, decoded_name)
    image_pipes   = []   # (region, mod_name, decoded_name)

    for r in regions:
        if prot_str(r.State) != "MEM_COMMIT":
            continue
        mtype = prot_str(r.Type)
        mod   = addr_to_module(r.BaseAddress, modules)

        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            continue

        def _extract_pipe_name(data, m, is_utf16):
            end = m.end()
            if is_utf16:
                # Read UTF-16LE chars until double-null or end
                while end + 1 < len(data):
                    ch = data[end]
                    hi = data[end + 1]
                    if hi == 0 and 32 <= ch < 127:
                        end += 2
                    else:
                        break
                raw = data[m.start():end]
                try:
                    return raw.decode("utf-16-le", errors="replace")
                except Exception:
                    return repr(raw)
            else:
                while end < len(data) and 32 <= data[end] < 127:
                    end += 1
                raw = data[m.start():end]
                try:
                    return raw.decode("ascii", errors="replace")
                except Exception:
                    return repr(raw)

        # Classify: only Microsoft system DLLs under System32/SysWOW64 are
        # treated as "expected".  Any other image-backed region — including
        # executables like update.exe, or DLLs outside the system directories
        # — is flagged the same as private memory so it cannot hide pipe refs.
        def _is_system_dll(module) -> bool:
            if module is None:
                return False
            path = (module.name or "").replace("\\", "/").lower()
            return (
                "/windows/system32/"  in path or
                "/windows/syswow64/" in path or
                "/windows/winsxs/"   in path
            )

        for m in PIPE_PAT_ASCII.finditer(data):
            name = _extract_pipe_name(data, m, is_utf16=False)
            if "MEM_IMAGE" in mtype and _is_system_dll(mod):
                image_pipes.append((r, os.path.basename(mod.name), name))
            else:
                private_pipes.append((r, m.start(), name))

        for m in PIPE_PAT_UTF16.finditer(data):
            name = _extract_pipe_name(data, m, is_utf16=True)
            if "MEM_IMAGE" in mtype and _is_system_dll(mod):
                image_pipes.append((r, os.path.basename(mod.name), name))
            else:
                private_pipes.append((r, m.start(), name))

    # Deduplicate private pipes by (region_base, name)
    seen_private = set()
    deduped = []
    for r, off, name in private_pipes:
        key = (r.BaseAddress, name.strip())
        if key not in seen_private:
            seen_private.add(key)
            deduped.append((r, off, name))
    private_pipes = deduped

    # ── Check 1: Pipe names outside trusted system DLLs ──────────────
    if private_pipes:
        detail = f"{len(private_pipes)} pipe name(s) in non-system memory"
        if verbose:
            for r, off, name in private_pipes:
                p    = prot_str(r.Protect)
                mtype_r = prot_str(r.Type)
                mod_r   = addr_to_module(r.BaseAddress, modules)
                rwx  = RED(" [RWX]") if any(s in p for s in SUSPICIOUS_PROTS) else ""
                abs_va = r.BaseAddress + off
                fo_abs = va_to_file_offset(mf, abs_va)
                fo_str = f"0x{fo_abs:x}" if fo_abs is not None else "(not captured)"
                if mod_r and "MEM_IMAGE" in mtype_r:
                    backer = YELLOW(f" [image: {os.path.basename(mod_r.name)}]")
                else:
                    backer = DIM(" [private/unregistered]")
                detail += (f"\n          VA (process)   0x{abs_va:016x}{rwx}{backer}"
                           f"\n          File offset    {fo_str}"
                           f"\n          Region base    0x{r.BaseAddress:016x}"
                           f"\n          Pipe name: {name.strip()}")
        _print_check("Pipe names outside trusted system DLLs",
                     RED("SUSPICIOUS — pipe name found in non-system memory"),
                     detail)
        findings["private_pipes"] = private_pipes
        findings["score"] += 1
    else:
        _print_check("Pipe names outside trusted system DLLs",
                     GREEN("CLEAN — all pipe name references are in known system modules"))

    if image_pipes and verbose:
        mod_names = sorted({n for _, n, _ in image_pipes})
        print(DIM(f"  [·] {len(image_pipes)} pipe reference(s) in system DLLs "
                  f"({', '.join(mod_names)}) — expected, skipped\n"))

    # ── Check 2: C2 artifacts near private pipe names ─────────────────
    c2_hits = []
    for r, off, pipe_name in private_pipes:
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            continue
        # Scan strings in the whole region for C2 patterns
        strings = _extract_strings_from_data(data, min_len=6)
        c2_strings = [s for _, _, s in strings if C2_PAT.search(s)]
        if c2_strings:
            c2_hits.append((r, pipe_name.strip(), c2_strings))

    if c2_hits:
        detail = f"{len(c2_hits)} region(s) with pipe name + C2 artifacts"
        if verbose:
            for r, pipe_name, c2s in c2_hits:
                detail += f"\n          Region 0x{r.BaseAddress:x}  pipe: {pipe_name}"
                for s in c2s[:3]:
                    detail += f"\n            C2: {s}"
                if len(c2s) > 3:
                    detail += f"\n            ... and {len(c2s)-3} more"
        _print_check("C2 artifacts co-located with pipe name",
                     RED("SUSPICIOUS — C2 IP/URL in same region as private pipe name"),
                     detail)
        findings["c2_context"] = c2_hits
        findings["score"] += 1
    else:
        _print_check("C2 artifacts near pipe names",
                     GREEN("CLEAN — no C2 patterns found near private pipe names"))

    # ── Check 3: Known framework patterns with attribution ───────────
    framework_hits = []  # (region, full_pipe_name, framework, technique, mitre_id)
    for r, off, name in private_pipes:
        clean = name.strip()
        for pat, framework, technique, mitre in KNOWN_FRAMEWORK_PIPES:
            if pat.search(clean):
                framework_hits.append((r, clean, framework, technique, mitre))
                break  # one attribution per pipe name

    if framework_hits:
        detail = f"{len(framework_hits)} match(es) — framework attribution:"
        for r, pipe_name, framework, technique, mitre in framework_hits:
            detail += f"\n          Pipe     : {pipe_name}"
            detail += f"\n          Framework: {framework}"
            detail += f"\n          Technique: {technique}"
            detail += f"\n          MITRE    : {mitre}"
        _print_check("Known C2 framework pipe naming pattern",
                     RED(f"SUSPICIOUS — {framework_hits[0][2]} pipe pattern identified"),
                     detail)
        findings["framework_pipes"] = framework_hits
        findings["score"] += 1
    else:
        _print_check("Known C2 framework pipe naming pattern",
                     DIM("CLEAN — no known framework patterns (note: custom names evade this check)"))

    # ── Check 4: Unbacked threads in same region as pipe name ─────────
    pipe_regions = {r.BaseAddress for r, _, _ in private_pipes}
    unbacked_in_pipe_rgn = []
    for ti in infos:
        sa = ti.StartAddress or 0
        for r in regions:
            if r.BaseAddress in pipe_regions:
                if r.BaseAddress <= sa < r.BaseAddress + r.RegionSize:
                    if not addr_to_module(sa, modules):
                        unbacked_in_pipe_rgn.append((ti, r))

    if unbacked_in_pipe_rgn:
        detail = f"{len(unbacked_in_pipe_rgn)} unbacked thread(s) executing in pipe-name region"
        if verbose:
            for ti, r in unbacked_in_pipe_rgn:
                detail += (f"\n          TID=0x{ti.ThreadId:x}  "
                           f"StartAddr=0x{ti.StartAddress:x}  "
                           f"Region=0x{r.BaseAddress:x}")
        _print_check("Unbacked thread in same region as pipe name",
                     RED("SUSPICIOUS — active execution at pipe name location"),
                     detail)
        findings["unbacked_in_rgn"] = unbacked_in_pipe_rgn
        findings["score"] += 1
    else:
        _print_check("Unbacked threads in pipe-name region",
                     GREEN("CLEAN — no unbacked threads in regions containing pipe names"))

    # ── Verdict ───────────────────────────────────────────────────────
    score = findings["score"]
    verdict = (RED("HIGH CONFIDENCE C2 PIPE / LATERAL MOVEMENT") if score >= 3 else
               YELLOW("LIKELY C2 PIPE")                           if score == 2 else
               YELLOW("POSSIBLE C2 PIPE")                         if score == 1 else
               GREEN("CLEAN — no named pipe C2 indicators"))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/4 checks flagged)\n")

    if not verbose and private_pipes:
        print(DIM("  Use --verbose to expand pipe names, C2 strings, and thread details.\n"))

    return findings

# ── Cobalt Strike Beacon Detection ───────────────────────────────────────────
# Decoding logic adapted from 1768.py by Didier Stevens (public domain)
# https://blog.didierstevens.com/programs/cobalt-strike-tools/
#
# Locates the XOR-obfuscated TLV config table written by MiniDumpWriteDump and
# extracted during beacon reflective loading.  Two XOR keys are tried:
#   0x69  ('i') — CS3-era beacons
#   0x2E  ('.') — CS4-era beacons

CS_BEACON_SIGNATURE  = b'\x00\x01\x00\x01\x00\x02'   # plaintext TLV start
CS_SIG_XOR69         = b'ihihik'                       # above ^ 0x69
CS_SIG_XOR2E         = b'././.,'                       # above ^ 0x2e
CS_MAX_SEG_SCAN      = 50 * 1024 * 1024               # skip segments > 50 MB

# Field IDs from 1768.py dConfigIdentifiers
CS_FIELD_NAMES = {
    0x0001: 'BeaconType',
    0x0002: 'Port',
    0x0003: 'SleepTime',
    0x0004: 'MaxGetSize',
    0x0005: 'Jitter',
    0x0006: 'MaxDNS',
    0x0007: 'PublicKey',
    0x0008: 'C2Server',
    0x0009: 'UserAgent',
    0x000a: 'HTTP_PostURI',
    0x000b: 'MalleableC2',
    0x000c: 'HTTP_GetHeader',
    0x000d: 'HTTP_PostHeader',
    0x000e: 'SpawnTo',
    0x000f: 'PipeName',
    0x0010: 'KillDate_Year',
    0x0011: 'KillDate_Month',
    0x0012: 'KillDate_Day',
    0x0013: 'DNS_Idle',
    0x0014: 'DNS_Sleep',
    0x0015: 'SSH_Host',
    0x0016: 'SSH_Port',
    0x0017: 'SSH_Username',
    0x0018: 'SSH_Password',
    0x0019: 'SSH_PubKey',
    0x001a: 'HTTP_GetVerb',
    0x001b: 'HTTP_PostVerb',
    0x001c: 'HttpPostChunk',
    0x001d: 'SpawnTo_x86',
    0x001e: 'SpawnTo_x64',
    0x001f: 'CryptoScheme',
    0x0020: 'Proxy',
    0x0021: 'Proxy_Username',
    0x0022: 'Proxy_Password',
    0x0023: 'Proxy_Type',
    0x0025: 'LicenseID',
    0x0026: 'bStageCleanup',
    0x0027: 'bCFGCaution',
    0x0028: 'KillDate',
    0x002b: 'ProcInject_StartRWX',
    0x002c: 'ProcInject_UseRWX',
    0x002d: 'ProcInject_MinAlloc',
    0x002e: 'ProcInject_Transform_x86',
    0x002f: 'ProcInject_Transform_x64',
    0x0031: 'BindHost',
    0x0032: 'UsesCookies',
    0x0033: 'ProcInject_Execute',
    0x0034: 'ProcInject_AllocMethod',
    0x0035: 'ProcInject_Stub',
    0x0036: 'HostHeader',
    0x0037: 'EXIT_FUNK',
    0x0038: 'SSH_Banner',
    0x0039: 'SMB_FrameHeader',
    0x003a: 'TCP_FrameHeader',
    0x003b: 'HeadersToRemove',
    0x003c: 'DNS_Beacon',
    0x003d: 'DNS_A',
    0x003e: 'DNS_AAAA',
    0x003f: 'DNS_TXT',
    0x0040: 'DNS_Metadata',
    0x0041: 'DNS_Output',
    0x0042: 'DNS_Resolver',
    0x0043: 'DNS_Strategy',
    0x0044: 'DNS_StrategyRotateSecs',
    0x0045: 'DNS_StrategyFailX',
    0x0046: 'DNS_StrategyFailSecs',
    0x0047: 'MaxRetry_Attempts',
    0x0048: 'MaxRetry_Increase',
    0x0049: 'MaxRetry_Duration',
}

# From 1768.py LookupConfigValue
CS_BEACON_TYPES = {
    0:  'HTTP',
    1:  'DNS',
    2:  'SMB (bind pipe)',
    4:  'TCP (reverse)',
    8:  'HTTPS',
    16: 'TCP (bind)',
}
CS_PROXY_TYPES = {
    1: 'no proxy',
    2: 'IE settings',
    4: 'hardcoded proxy',
}
CS_INJECT_PERMS = {
    0x01: 'PAGE_NOACCESS',      0x02: 'PAGE_READONLY',
    0x04: 'PAGE_READWRITE',     0x08: 'PAGE_WRITECOPY',
    0x10: 'PAGE_EXECUTE',       0x20: 'PAGE_EXECUTE_READ',
    0x40: 'PAGE_EXECUTE_READWRITE',
    0x80: 'PAGE_EXECUTE_WRITECOPY',
}


def _cs_xor_bytes(data: bytes, key: int) -> bytes:
    """Single-byte XOR decode. Mirrors 1768.py Xor() for single-byte keys."""
    kb = key & 0xff
    return bytes(b ^ kb for b in data)


def _cs_scan_segment(data: bytes, seg_va: int, seg_fo: int) -> list:
    """
    Search one memory segment for CS beacon config signatures.

    Strategy (from 1768.py AnalyzeEmbeddedPEFileSub):
      For each XOR key (0x69, 0x2e), search for the pre-XOR'd marker.
      On hit: XOR-decode from that offset, verify the plaintext signature.

    Returns list of (xor_key, hit_va, hit_file_offset, decoded_config_bytes).
    """
    results = []
    for key, marker in ((0x69, CS_SIG_XOR69), (0x2e, CS_SIG_XOR2E)):
        start = 0
        while True:
            idx = data.find(marker, start)
            if idx == -1:
                break
            chunk = _cs_xor_bytes(data[idx: idx + 0x10000], key)
            if chunk.startswith(CS_BEACON_SIGNATURE):
                results.append((key, seg_va + idx, seg_fo + idx, chunk))
            start = idx + 1
    return results


def _cs_parse_tlv(data: bytes) -> dict:
    """
    Parse a CS TLV config block (adapted from 1768.py AnalyzeEmbeddedPEFileSub2).

    Wire format (all big-endian):
        field_id  uint16    (0 = end of config)
        type      uint16    (1=uint16, 2=uint32, 3=bytes)
        length    uint16
        value     <length> bytes

    Returns dict: field_id (int) -> {name, type, raw, value}.
    """
    fields = {}
    pos = 0
    while pos + 6 <= len(data):
        fid   = struct.unpack_from('>H', data, pos)[0]; pos += 2
        if fid == 0:
            break
        ftype = struct.unpack_from('>H', data, pos)[0]; pos += 2
        flen  = struct.unpack_from('>H', data, pos)[0]; pos += 2
        if pos + flen > len(data):
            break
        raw  = data[pos: pos + flen]; pos += flen

        value = None
        try:
            if ftype == 1 and flen == 2:
                value = struct.unpack('>H', raw)[0]
            elif ftype == 2 and flen == 4:
                value = struct.unpack('>I', raw)[0]
            elif ftype == 3:
                value = raw.rstrip(b'\x00').decode('utf-8', errors='replace')
        except Exception:
            value = raw

        fields[fid] = {
            'name':  CS_FIELD_NAMES.get(fid, f'field_0x{fid:04x}'),
            'type':  ftype,
            'raw':   raw,
            'value': value,
        }
    return fields


def _cs_decode_instructions(raw: bytes, itype: int) -> list:
    """
    Decode a Malleable C2 instruction stream (adapted from 1768.py DecodeInstructions).

    itype: 1 = server→client (MalleableC2 field 0x000b)
           2 = GET  header transforms (field 0x000c)
           3 = POST header transforms (field 0x000d)

    Opcode semantics differ between itype==1 and itype==2/3:
      opcodes 1 & 2 carry an integer operand (remove N bytes) in itype==1,
      but a length-prefixed string operand (append/prepend data) in itype==2/3.
    """
    def _rint(buf, p):
        if p + 4 > len(buf): return None, p
        return struct.unpack_from('>I', buf, p)[0], p + 4

    def _rstr(buf, p):
        n, p = _rint(buf, p)
        if n is None or p + n > len(buf): return None, p
        return buf[p: p + n].decode('latin-1', errors='replace'), p + n

    MALLEABLE = 1
    instrs, pos = [], 0
    while pos + 4 <= len(raw):
        op = struct.unpack_from('>I', raw, pos)[0]; pos += 4
        if op == 0:   break
        if op == 1:   # APPEND / remove-from-end
            if itype == MALLEABLE:
                n, pos = _rint(raw, pos); instrs.append(f'Remove {n} bytes from end')
            else:
                s, pos = _rstr(raw, pos); instrs.append(f'Append {repr(s)}')
        elif op == 2: # PREPEND / remove-from-begin
            if itype == MALLEABLE:
                n, pos = _rint(raw, pos); instrs.append(f'Remove {n} bytes from begin')
            else:
                s, pos = _rstr(raw, pos); instrs.append(f'Prepend {repr(s)}')
        elif op == 3:  instrs.append('BASE64')
        elif op == 4:  instrs.append('Print')
        elif op == 5:  s, pos = _rstr(raw, pos); instrs.append(f'Parameter {repr(s)}')
        elif op == 6:  s, pos = _rstr(raw, pos); instrs.append(f'Header {repr(s)}')
        elif op == 7:  # BUILD
            n, pos = _rint(raw, pos)
            label = {0: 'SessionId', 1: 'Output'}.get(n, 'Metadata') if itype == 3 else 'Metadata'
            instrs.append(f'Build {label}')
        elif op == 8:  instrs.append('NETBIOS lowercase')
        elif op == 9:  s, pos = _rstr(raw, pos); instrs.append(f'Const_parameter {repr(s)}')
        elif op == 10: s, pos = _rstr(raw, pos); instrs.append(f'Const_header {repr(s)}')
        elif op == 11: instrs.append('NETBIOS uppercase')
        elif op == 12: instrs.append('Uri_append')
        elif op == 13: instrs.append('BASE64 URL')
        elif op == 14:
            s1, pos = _rstr(raw, pos); s2, pos = _rstr(raw, pos)
            instrs.append(f'STRREP {repr(s1)} -> {repr(s2)}')
        elif op == 15: instrs.append('XOR with 4-byte random key (mask)')
        elif op == 16: s, pos = _rstr(raw, pos); instrs.append(f'Const_host_header {repr(s)}')
        else:          instrs.append(f'Unknown(0x{op:02x})')
    return instrs


def _cs_guess_version(fields: dict) -> str:
    """Estimate CS version from highest field ID (mirrors 1768.py DetermineCSVersionFromConfig)."""
    if not fields: return 'unknown'
    m = max(fields.keys())
    if m < 55:  return '3.x'
    if m == 55: return '4.0'
    if m < 58:  return '4.1'
    if m == 58: return '4.2'
    if m == 70: return '4.3'
    return '4.4+'


def _cs_sanity_check(fields: dict) -> bool:
    """
    Validate extracted config (mirrors 1768.py SanityCheckExtractedConfig):
      - field 0x0001 (beacon type) must be present and a known value
      - field 0x0007 (public key) must start with ASN.1 SEQUENCE prefix 0x308...
    """
    if 0x0001 not in fields or 0x0007 not in fields:
        return False
    if fields[0x0001]['value'] not in CS_BEACON_TYPES:
        return False
    return fields[0x0007]['raw'].hex().startswith('308')


def _hunt_cs_beacon(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Scan all captured memory segments for Cobalt Strike beacon configurations.

    Algorithm (adapted from 1768.py by Didier Stevens, public domain):
      1. Walk every captured memory segment in the minidump.
      2. Search each segment for the XOR-encoded TLV signature with keys
         0x69 (CS3) and 0x2E (CS4).
      3. On a hit: XOR-decode, parse TLV records, run sanity check.
      4. Extract and display: beacon type, C2 server/port/URI, User-Agent,
         pipe name, license ID, sleep/jitter, SpawnTo, Malleable C2 profile
         transforms, process injection settings, SSH/DNS transport fields.
      5. Report VA (process address) + file offset (.dmp byte position) for
         each hit, consistent with Dumpex address labeling conventions.

    Address note:
      hit VA         = segment.start_virtual_address + offset_within_segment
      hit file offset = segment.start_file_address   + offset_within_segment
    """
    _print_hunt_header("Cobalt Strike Beacon Config")
    findings = {'configs': [], 'score': 0}

    segs = []
    if mf.memory_segments_64 and mf.memory_segments_64.memory_segments:
        segs = mf.memory_segments_64.memory_segments
    elif mf.memory_segments and mf.memory_segments.memory_segments:
        segs = mf.memory_segments.memory_segments

    if not segs:
        print(YELLOW("  [~] No memory segments in dump — cannot scan for beacon config.\n"))
        return findings

    skipped, hits = 0, []
    reader = mf.get_reader()

    print(DIM(f"  [*] Scanning {len(segs)} segment(s) for beacon signature …"))

    for seg in segs:
        if seg.size > CS_MAX_SEG_SCAN:
            skipped += 1
            continue
        try:
            data = reader.read(seg.start_virtual_address, seg.size)
        except Exception:
            continue

        for xor_key, hit_va, hit_fo, cfg_bytes in _cs_scan_segment(
                data, seg.start_virtual_address, seg.start_file_address):
            fields = _cs_parse_tlv(cfg_bytes)
            if not fields or not _cs_sanity_check(fields):
                continue
            if not any(h[1] == hit_va for h in hits):   # deduplicate by VA
                hits.append((xor_key, hit_va, hit_fo, fields))

    scan_note = f" ({skipped} segment(s) >50 MB skipped)" if skipped else ""
    print(DIM(f"  [*] Scan complete{scan_note}."))

    if not hits:
        _print_check("Cobalt Strike beacon config",
                     GREEN("CLEAN — no beacon config found in memory"))
        print()
        return findings

    findings['score'] = len(hits)
    print()

    for idx, (xor_key, hit_va, hit_fo, fields) in enumerate(hits, 1):
        cs_ver   = _cs_guess_version(fields)
        key_desc = {0x69: "0x69 'i'  (CS3 encoding)",
                    0x2e: "0x2E '.'  (CS4 encoding)"}.get(xor_key, f'0x{xor_key:02x}')

        print(RED(f"  [!] Beacon config #{idx}  ──────────────────────────────────────────────"))
        print(f"  {'VA (process)':<26} 0x{hit_va:016x}  {DIM('← virtual address in target process')}")
        print(f"  {'File offset (.dmp)':<26} 0x{hit_fo:016x}  {DIM('← byte offset inside .dmp file')}")
        print(f"  {'XOR key':<26} {key_desc}")
        print(f"  {'CS version (estimated)':<26} {YELLOW(cs_ver)}")
        print()

        f = fields

        # ── C2 / Identity / Transport ──────────────────────────────────
        print(f"  {BOLD('── C2 / Identity / Transport ──────────────────────────────────────')}")

        if 0x0001 in f:
            btype     = f[0x0001]['value']
            btype_str = CS_BEACON_TYPES.get(btype, f'unknown ({btype})')
            color     = RED if btype in (1, 2) else YELLOW   # DNS/SMB = more covert
            print(f"  {'BeaconType':<26} {color(btype_str)}")

        if 0x0008 in f:
            c2raw = (f[0x0008]['value'] or '').strip('\x00')
            if ',' in c2raw:
                host, uri = c2raw.split(',', 1)
                print(f"  {'C2 Host':<26} {RED(host.strip())}")
                print(f"  {'C2 GET URI':<26} {uri.strip()}")
            else:
                print(f"  {'C2 Server':<26} {RED(c2raw)}")

        if 0x0002 in f:
            print(f"  {'Port':<26} {f[0x0002]['value']}")

        if 0x000a in f:
            v = (f[0x000a]['value'] or '').strip('\x00')
            if v: print(f"  {'HTTP POST URI':<26} {v}")

        if 0x0009 in f:
            ua = (f[0x0009]['value'] or '').strip('\x00')
            if ua: print(f"  {'UserAgent':<26} {ua}")

        if 0x0036 in f:
            hh = (f[0x0036]['value'] or '').strip('\x00')
            if hh: print(f"  {'HostHeader':<26} {hh}")

        if 0x000f in f:
            pipe = (f[0x000f]['value'] or '').strip('\x00')
            if pipe: print(f"  {'PipeName':<26} {RED(pipe)}")

        if 0x0025 in f:
            print(f"  {'LicenseID':<26} {YELLOW(str(f[0x0025]['value']))}")

        if 0x0003 in f:
            sleep_ms = f[0x0003]['value'] or 0
            jitter   = f[0x0005]['value'] if 0x0005 in f else 0
            print(f"  {'Sleep / Jitter':<26} {sleep_ms} ms / {jitter}%")

        if 0x0028 in f and f[0x0028]['value']:
            print(f"  {'KillDate':<26} {f[0x0028]['value']}")

        if 0x001a in f:
            v = (f[0x001a]['value'] or '').strip('\x00')
            if v: print(f"  {'HTTP GET Verb':<26} {v}")
        if 0x001b in f:
            v = (f[0x001b]['value'] or '').strip('\x00')
            if v: print(f"  {'HTTP POST Verb':<26} {v}")

        if 0x001d in f:
            v = (f[0x001d]['value'] or '').strip('\x00')
            if v: print(f"  {'SpawnTo x86':<26} {v}")
        if 0x001e in f:
            v = (f[0x001e]['value'] or '').strip('\x00')
            if v: print(f"  {'SpawnTo x64':<26} {v}")

        if 0x0020 in f:
            proxy = (f[0x0020]['value'] or '').strip('\x00')
            ptype = CS_PROXY_TYPES.get(f[0x0023]['value'] if 0x0023 in f else 0, '')
            if proxy: print(f"  {'Proxy':<26} {proxy}  [{ptype}]")

        # ── Process injection ──────────────────────────────────────────
        inj_ids = {0x002b, 0x002c, 0x002d, 0x002e, 0x002f, 0x0033, 0x0034, 0x0035}
        inj = {k: f[k] for k in inj_ids if k in f}
        if inj:
            print(f"\n  {BOLD('── Process Injection ──────────────────────────────────────────────')}")
            for fid in sorted(inj):
                rec = inj[fid]
                if fid in (0x002b, 0x002c):
                    val = CS_INJECT_PERMS.get(rec['value'], str(rec['value']))
                elif rec['type'] == 3:
                    val = (rec['value'] or '').strip('\x00') or rec['raw'].hex()[:60]
                else:
                    val = str(rec['value'])
                print(f"  {rec['name']:<26} {val}")

        # ── Malleable C2 / GET / POST transforms ───────────────────────
        for fid, label, itype in (
            (0x000b, 'Malleable C2  (server→client transform)', 1),
            (0x000c, 'HTTP GET  header transforms',             2),
            (0x000d, 'HTTP POST header transforms',             3),
        ):
            if fid in f and f[fid]['raw']:
                try:
                    instrs = _cs_decode_instructions(f[fid]['raw'], itype)
                    if instrs:
                        print(f"\n  {BOLD(f'── {label}')}")
                        for step in instrs:
                            print(f"    {DIM('›')} {step}")
                except Exception:
                    pass

        # ── SSH transport ──────────────────────────────────────────────
        ssh_ids = (0x0015, 0x0016, 0x0017, 0x0018, 0x0038)
        ssh = {k: f[k] for k in ssh_ids if k in f}
        if ssh:
            print(f"\n  {BOLD('── SSH Transport ──────────────────────────────────────────────────')}")
            for fid, rec in sorted(ssh.items()):
                val = (rec['value'] or '').strip('\x00') if rec['type'] == 3 else str(rec['value'])
                if val: print(f"  {rec['name']:<26} {val}")

        # ── DNS transport ──────────────────────────────────────────────
        dns_ids = range(0x003c, 0x0047)
        dns = {k: f[k] for k in dns_ids if k in f}
        if dns:
            print(f"\n  {BOLD('── DNS Transport ──────────────────────────────────────────────────')}")
            for fid, rec in sorted(dns.items()):
                val = (rec['value'] or '').strip('\x00') if rec['type'] == 3 else str(rec['value'])
                if val: print(f"  {rec['name']:<26} {val}")

        # ── Full field table (--verbose only) ──────────────────────────
        if verbose:
            print(f"\n  {BOLD('── Full Config Field Table ────────────────────────────────────────')}")
            w = max((len(v['name']) for v in f.values()), default=20)
            for fid in sorted(f.keys()):
                rec = f[fid]
                if rec['type'] == 3:
                    txt  = (rec['value'] or '').strip('\x00') if isinstance(rec['value'], str) else ''
                    hexs = rec['raw'].hex()
                    if txt:
                        display = f"{repr(txt)}  [{hexs[:48]}{'...' if len(hexs) > 48 else ''}]"
                    else:
                        display = f"[{hexs[:64]}{'...' if len(hexs) > 64 else ''}]"
                else:
                    display = str(rec['value'])
                print(f"    0x{fid:04x}  {rec['name']:<{w}}  {display}")

        print()
        findings['configs'].append({
            'va': hit_va, 'file_offset': hit_fo,
            'xor_key': xor_key, 'cs_version': cs_ver, 'fields': fields,
        })

    print(f"  {BOLD('[ VERDICT ]')}  "
          f"{RED(f'COBALT STRIKE — {len(hits)} beacon config(s) found in memory')}\n")
    if not verbose:
        print(DIM("  Use --verbose to dump all config fields.\n"))

    return findings



def cmd_hunt(mf: MinidumpFile, ttp: str, verbose: bool = False):
    """Run TTP-specific detection playbooks."""
    valid = {"injection", "hollowing", "stomping", "pipe", "cs-beacon", "all"}
    if ttp not in valid:
        print(RED(f"[!] Unknown TTP '{ttp}'. Choose from: {', '.join(sorted(valid))}"))
        sys.exit(1)

    run_injection  = ttp in ("injection",  "all")
    run_hollowing  = ttp in ("hollowing",  "all")
    run_stomping   = ttp in ("stomping",   "all")
    run_pipe       = ttp in ("pipe",       "all")
    run_cs_beacon  = ttp in ("cs-beacon",  "all")

    results = {}

    if run_injection:
        results["injection"]  = _hunt_injection(mf, verbose=verbose)
    if run_hollowing:
        results["hollowing"]  = _hunt_hollowing(mf, verbose=verbose)
    if run_stomping:
        results["stomping"]   = _hunt_stomping(mf,  verbose=verbose)
    if run_pipe:
        results["pipe"]       = _hunt_pipe(mf, verbose=verbose)
    if run_cs_beacon:
        results["cs-beacon"]  = _hunt_cs_beacon(mf, verbose=verbose)

    # Summary card for --hunt all
    if ttp == "all":
        print(BOLD("══════════════════════════════════════════"))
        print(BOLD("  HUNT SUMMARY"))
        print(BOLD("══════════════════════════════════════════"))
        labels = {
            "injection": ("Process Injection",          results["injection"]["score"],  3),
            "hollowing": ("Process Hollowing",          results["hollowing"]["score"],  4),
            "stomping":  ("Module Stomping",            results["stomping"]["score"],   2),
            "pipe":      ("Named Pipe C2 / Lat. Move.", results["pipe"]["score"],       4),
            "cs-beacon": ("Cobalt Strike Beacon",       results["cs-beacon"]["score"],  1),
        }
        any_hit = False
        for key, (name, score, max_score) in labels.items():
            if score == 0:
                verdict = GREEN("CLEAN")
            elif key == "cs-beacon":
                verdict = RED(f"BEACON CONFIG FOUND ({score} config(s))")
                any_hit = True
            elif score >= max_score - 1:
                verdict = RED("HIGH CONFIDENCE")
                any_hit = True
            else:
                verdict = YELLOW("POSSIBLE")
                any_hit = True
            suffix = f"  ({score}/{max_score})" if key != "cs-beacon" else ""
            print(f"  {name:<25} {verdict}{suffix}")
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
    mode.add_argument("--pid",          action="store_true", help="Show the Process ID recorded in the dump")
    mode.add_argument("--sysinfo",      action="store_true", help="Show OS, host, process and CPU summary")
    mode.add_argument("--diff",         metavar="DUMP2",     help="Diff against a second .DMP file")
    mode.add_argument("--report",        action="store_true", help="Generate triage report anchored to a TID, address, or string")
    mode.add_argument("--hunt",          metavar="TTP",       help="TTP detection: injection | hollowing | stomping | pipe | cs-beacon | all")

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
    elif args.pid:          cmd_pid(mf)
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