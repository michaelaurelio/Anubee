"""On-device anubee control for the MCP server.

Drives the anubee binary on a connected device over adb to (a) list the native
libraries an app loads and (b) dump a (possibly decrypted) library from the app's
live memory, pulling the rebuilt .so back to the host. Listing uses the stealthy
`anubee lib` engine (kprobe, injectionless); memory dumping uses `anubee dump`. anubee
is run under `timeout -s INT <seconds>` so it traces for a bounded window and then
receives the SIGINT that triggers its flush / exit-time memory dump.

Configuration (environment):
  ANUBEE_ADB           adb executable (default: "adb")
  ANUBEE_BIN           anubee path on device (default: /data/local/tmp/anubee)
  ANUBEE_SHELL_PREFIX  wrap the device command, e.g. "su -c" on a Magisk device
                     (anubee needs root; set this if adbd isn't already root)
  ANUBEE_SERIAL        target a specific device (adb -s <serial>)

The line parsers (`parse_lib_lines` / `parse_dump_lines`) are pure functions over
anubee's stdout/stderr and are unit-tested without a device.
"""

import os
import re
import shlex
import subprocess
import uuid

ADB = os.environ.get("ANUBEE_ADB", "adb")
BIN = os.environ.get("ANUBEE_BIN", "/data/local/tmp/anubee")
SHELL_PREFIX = os.environ.get("ANUBEE_SHELL_PREFIX", "").strip()
SERIAL = os.environ.get("ANUBEE_SERIAL", "").strip()

MAX_SECONDS = 120
_PKG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]*$")

# [lib] pid 17267  libstagefright.so   [0x7e35e66000, 0x7e35e69000)  off=0x209  inode=28284833
_LIB_RE = re.compile(
    r"^\[lib\]\s+pid\s+(\d+)\s+(\S+)\s+"
    r"\[0x([0-9a-fA-F]+),\s*0x([0-9a-fA-F]+)\)\s+"
    r"off=0x([0-9a-fA-F]+)\s+inode=(\d+)")

# [dump] e_22045 (pid 22045) -> ./e_22045.22045.7aea238000.so  (1778456 bytes, 1777664 from memory, rebuilt)
_DUMP_RE = re.compile(
    r"^\[dump\]\s+(.+?)\s+\(pid\s+(\d+)\)\s+->\s+(\S+)\s+"
    r"\((\d+)\s+bytes,\s+(\d+)\s+from memory,\s+([^)]+)\)")

# ts_print() (human_out.c) prepends "HH:MM:SS " to some lines; tolerate it.
_TS_RE = re.compile(r"^\d\d:\d\d:\d\d\s+")


# ---- input validation -----------------------------------------------------

def _check_pkg(package):
    if not isinstance(package, str) or not _PKG_RE.match(package):
        raise ValueError(f"invalid package name: {package!r}")


def _clamp_seconds(seconds):
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        seconds = 8
    return max(1, min(seconds, MAX_SECONDS))


# ---- output parsing (pure) ------------------------------------------------

def parse_lib_lines(text):
    """Parse `anubee lib` output into a list of per-segment mapping records."""
    out = []
    for line in text.splitlines():
        m = _LIB_RE.match(_TS_RE.sub("", line.strip()))
        if not m:
            continue
        out.append({
            "pid": int(m.group(1)),
            "library": m.group(2),
            "start": int(m.group(3), 16),
            "end": int(m.group(4), 16),
            "pgoff": int(m.group(5), 16),
            "inode": int(m.group(6)),
        })
    return out


def parse_dump_lines(text):
    """Parse `anubee dump` per-module `[dump]` lines into structured records."""
    out = []
    for line in text.splitlines():
        m = _DUMP_RE.match(_TS_RE.sub("", line.strip()))
        if not m:
            continue
        out.append({
            "name": m.group(1),
            "pid": int(m.group(2)),
            "device_path": m.group(3),
            "bytes": int(m.group(4)),
            "from_memory": int(m.group(5)),
            "mode": m.group(6).strip(),
        })
    return out


def aggregate_libraries(segments):
    """Collapse per-segment mappings into one record per (pid, library)."""
    agg = {}
    for s in segments:
        key = (s["pid"], s["library"])
        a = agg.get(key)
        if a is None:
            a = agg[key] = {"pid": s["pid"], "library": s["library"],
                            "segments": 0, "start": s["start"], "end": s["end"],
                            "inode": s["inode"]}
        a["segments"] += 1
        a["start"] = min(a["start"], s["start"])
        a["end"] = max(a["end"], s["end"])
    out = sorted(agg.values(), key=lambda r: (r["pid"], r["library"]))
    for r in out:
        r["start"] = hex(r["start"])
        r["end"] = hex(r["end"])
    return out


# ---- ELF sanity (host side) -----------------------------------------------

def _elf_info(path):
    """Lightweight check that a pulled file is a plausible ELF, for the report."""
    info = {"size": None, "elf": False}
    try:
        info["size"] = os.path.getsize(path)
        with open(path, "rb") as f:
            hdr = f.read(64)
    except OSError as e:
        info["error"] = str(e)
        return info
    if len(hdr) < 64 or hdr[:4] != b"\x7fELF":
        return info
    import struct
    info["elf"] = True
    info["class"] = "ELF64" if hdr[4] == 2 else "ELF32"
    info["type"] = struct.unpack_from("<H", hdr, 16)[0]      # e_type (3 = DYN)
    info["machine"] = struct.unpack_from("<H", hdr, 18)[0]   # 183 = AArch64
    info["sections"] = struct.unpack_from("<H", hdr, 60)[0]  # e_shnum
    return info


# ---- adb plumbing ---------------------------------------------------------

def _adb(args, timeout=120):
    cmd = [ADB] + (["-s", SERIAL] if SERIAL else []) + list(args)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError(f"adb not found ({ADB!r}); set ANUBEE_ADB")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"adb {args[0] if args else ''} timed out")
    if p.returncode != 0:
        raise RuntimeError(f"adb {' '.join(args)} failed: {p.stderr.strip() or p.stdout.strip()}")
    return p.stdout


def _adb_shell(cmd_str, timeout=120):
    """Run a plain shell command on the device (no root wrapper)."""
    return _adb(["shell", cmd_str], timeout=timeout)


def _run_anubee(subcmd, args, seconds):
    """Run `anubee <subcmd> <args>` on the device for `seconds` (SIGINT-terminated
    via timeout), as root if ANUBEE_SHELL_PREFIX is set. Returns combined
    stdout+stderr."""
    inner = "timeout -s INT %d %s %s %s" % (
        seconds, shlex.quote(BIN), subcmd,
        " ".join(shlex.quote(a) for a in args))
    cmd = "%s %s" % (SHELL_PREFIX, shlex.quote(inner)) if SHELL_PREFIX else inner
    full = [ADB] + (["-s", SERIAL] if SERIAL else []) + ["shell", cmd]
    try:
        p = subprocess.run(full, capture_output=True, text=True, timeout=seconds + 45)
    except FileNotFoundError:
        raise RuntimeError(f"adb not found ({ADB!r}); set ANUBEE_ADB")
    except subprocess.TimeoutExpired as e:
        # timeout should have stopped anubee device-side; return what we got
        out = (e.stdout or "") + (e.stderr or "")
        return out if isinstance(out, str) else out.decode("utf-8", "replace")
    return (p.stdout or "") + (p.stderr or "")


# ---- public operations ----------------------------------------------------

def list_libraries(package, seconds=8, activity=None):
    """Launch the app via `anubee lib` for `seconds`, then return the native
    libraries it loaded (one record per pid/library, with merged ranges)."""
    _check_pkg(package)
    secs = _clamp_seconds(seconds)
    args = [package] + ([activity] if activity else [])
    log = _run_anubee("lib", args, secs)
    segments = parse_lib_lines(log)
    libs = aggregate_libraries(segments)
    return {
        "package": package,
        "seconds": secs,
        "library_count": len(libs),
        "segment_count": len(segments),
        "libraries": libs,
        "error": None if segments else _diagnose(log),
    }


def dump_library(package, pattern, seconds=12, activity=None, out_dir=None):
    """Run `anubee dump -d <dir> -q <package> <pattern>` on the device for
    `seconds`, dumping every loaded library whose basename matches `pattern`
    (glob ok, e.g. 'e_*') from live memory on exit, then pull the rebuilt
    .so(s) to the host."""
    _check_pkg(package)
    if not isinstance(pattern, str) or not pattern or len(pattern) > 128:
        raise ValueError("pattern must be a non-empty string (<=128 chars)")
    secs = _clamp_seconds(seconds)
    out_dir = os.path.abspath(out_dir or os.path.join(os.getcwd(), "anubee-dumps"))
    os.makedirs(out_dir, exist_ok=True)

    devdir = "/data/local/tmp/anubee-mcp-" + uuid.uuid4().hex[:12]
    _adb_shell("mkdir -p " + shlex.quote(devdir))
    try:
        args = ["-d", devdir, "-q", package, pattern] + \
               ([activity] if activity else [])
        log = _run_anubee("dump", args, secs)
        dumped = parse_dump_lines(log)

        listing = _adb_shell("ls -1 %s 2>/dev/null || true" % shlex.quote(devdir))
        files = [f.strip() for f in listing.splitlines()
                 if f.strip().endswith(".so")]

        pulled = []
        for fn in files:
            host_path = os.path.join(out_dir, fn)
            _adb(["pull", devdir + "/" + fn, host_path])
            info = _elf_info(host_path)
            info["name"] = fn
            info["host_path"] = host_path
            pulled.append(info)
    finally:
        _adb_shell("rm -rf " + shlex.quote(devdir) + " || true")

    return {
        "package": package,
        "pattern": pattern,
        "seconds": secs,
        "out_dir": out_dir,
        "dumped_on_device": dumped,
        "pulled": pulled,
        "error": None if pulled else _diagnose(log),
    }


def _diagnose(log):
    """Best-effort hint when nothing was produced, surfaced to the model."""
    low = log.lower()
    if "not found" in low or "no such file" in low:
        return ("anubee not found on device — push it to %s "
                "(make push) or set ANUBEE_BIN" % BIN)
    if "run as root" in low or "permission denied" in low or "operation not permitted" in low:
        return ("anubee needs root — set ANUBEE_SHELL_PREFIX='su -c' "
                "or run `adb root`")
    if "could not resolve uid" in low:
        return "package not installed or not launchable on this device"
    snippet = "\n".join(log.strip().splitlines()[-6:])
    return "no output matched; tail of anubee log:\n" + snippet if snippet else "no output from anubee"
