#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
""""What's new" view of an `anubee mod` run: only the behaviour that benign
apps on the same device never showed.

A device noise profile is learned from baseline runs of ordinary apps traced
the same way as the samples (same analyzers, same grants). Every record is
reduced to a (section, key) pair -- the binder method, the probed path with
package / pid / numbers normalized out, the destination, the command line --
and a key the baseline apps produced is device noise. The tracer output is
never changed: hidden records are counted per section, record types this
module doesn't know are always shown, and coverage health is carried along so
an empty section can't be mistaken for "checked, nothing there".

Stdlib only, so the lab harness can run it without the MCP server:
  mod_findings.py profile OUT.json RUN.jsonl [RUN.jsonl ...] [--min-apps N]
  mod_findings.py report  PROFILE.json RUN.jsonl [--json]
"""
import json
import math
import os
import re
import sys

PROFILE_VERSION = 1
SKIP = object()          # record carries no behaviour (snapshot, summary, own files)

_INSTALL_DIR = re.compile(r"/data/app/~~[^/]+/[^/]+-[^/]+/")
_PROC_PID = re.compile(r"/proc/\d+")
_TASK_TID = re.compile(r"/task/\d+")
_HEX = re.compile(r"0x[0-9a-fA-F]+")
_LONG_NUM = re.compile(r"\d{6,}")   # timestamps, random numeric names; not ports


def norm(s, pkg):
    """Volatile parts of a path or command out: package, install dir, pids, numbers."""
    if not s:
        return ""
    if pkg:
        s = s.replace(pkg, "<pkg>")
    s = _INSTALL_DIR.sub("/data/app/<install>/", s)
    s = _PROC_PID.sub("/proc/<pid>", s)
    s = _TASK_TID.sub("/task/<tid>", s)
    s = _HEX.sub("<hex>", s)
    return _LONG_NUM.sub("<n>", s)


def record_key(r, pkg):
    """(section, key) for a behaviour record, SKIP for one that isn't behaviour,
    or (type, type) with known=False for record types this module doesn't know."""
    t = r.get("type", "")
    if t == "coverage" or t.endswith("_summary"):
        return SKIP
    if t == "binder_api":
        m = r.get("method") or f"#{r.get('code')}"
        return ("binder", f"{r.get('interface')}.{m}")
    if t == "file_access":
        if "own_app_dir" in (r.get("categories") or []):
            return SKIP
        return ("file", norm(r.get("path"), pkg))
    if t == "execve":
        argv = r.get("argv") or [os.path.basename(r.get("filename") or "")]
        return ("exec", norm(" ".join(argv), pkg))
    if t == "net":
        if r.get("event") == "close":
            return SKIP
        return ("net", f"{r.get('proto')} {norm(r.get('host') or r.get('dest'), pkg)}")
    if t == "perm_change":
        if r.get("change") == "baseline":
            return SKIP
        return ("perm", f"{r.get('category')} {r.get('name')} -> {r.get('new')}")
    if t == "accessibility_detect":
        return ("a11y", f"{r.get('category')} {r.get('method')}")
    if t == "dexload_detect":
        return ("dexload", f"{r.get('stage')} {r.get('kind')} {norm(r.get('path'), pkg)}")
    if t == "prop_read":
        return ("prop", str(r.get("name") or r.get("property")))
    if t == "proc_exit":
        return ("proc", f"exit signal {r.get('signal')}")
    if t == "spawn":
        return ("proc", "spawn")
    return (t, t)


KNOWN_SECTIONS = {"binder", "file", "exec", "net", "perm", "a11y", "dexload", "prop", "proc"}


def _records(path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except ValueError:
                continue


def infer_package(path):
    """The traced package: perm-watch's records name it."""
    for r in _records(path):
        if r.get("type") == "perm_change" and r.get("package"):
            return r["package"]
    return None


def empty_profile():
    return {"version": PROFILE_VERSION, "apps": [], "min_apps": 1, "keys": {}}


def build_profile(runs, min_apps=None):
    """runs: [(jsonl_path, package or None)]. A key counts once per app."""
    prof = empty_profile()
    for path, pkg in runs:
        pkg = pkg or infer_package(path)
        prof["apps"].append(pkg or os.path.basename(path))
        keys = set()
        for r in _records(path):
            k = record_key(r, pkg)
            if k is SKIP or k[0] not in KNOWN_SECTIONS:
                continue
            keys.add(f"{k[0]}\t{k[1]}")
        for k in keys:
            prof["keys"][k] = prof["keys"].get(k, 0) + 1
    n = len(prof["apps"])
    prof["min_apps"] = min_apps if min_apps else max(1, math.ceil(n / 2))
    return prof


def save_profile(prof, path):
    with open(path, "w") as f:
        json.dump(prof, f, indent=1, sort_keys=True)


def load_profile(path):
    with open(path) as f:
        prof = json.load(f)
    if prof.get("version") != PROFILE_VERSION:
        raise ValueError(f"{path}: profile version {prof.get('version')}, expected {PROFILE_VERSION}")
    return prof


def is_noise(prof, section, key):
    if section not in KNOWN_SECTIONS:
        return False
    return prof["keys"].get(f"{section}\t{key}", 0) >= prof.get("min_apps", 1)


def findings(path, prof, pkg=None):
    pkg = pkg or infer_package(path)
    t0 = None
    sections, hidden = {}, {}
    index = {}
    cov = {"records": 0, "degraded": []}
    for r in _records(path):
        ts = r.get("ts_ns")
        if ts is not None and (t0 is None or ts < t0):
            t0 = ts
        if r.get("type") == "coverage":
            cov["records"] += 1
            if not r.get("clean") and not r.get("exempt"):
                cov["degraded"].append(r.get("engine"))
        k = record_key(r, pkg)
        if k is SKIP:
            continue
        sec, key = k
        if is_noise(prof, sec, key):
            h = hidden.setdefault(sec, {"records": 0, "keys": set()})
            h["records"] += 1
            h["keys"].add(key)
            continue
        f = index.get((sec, key))
        if f is None:
            f = {"key": key, "count": 0, "first_ts_ns": ts, "errors": {}, "example": r}
            index[(sec, key)] = f
            sections.setdefault(sec, []).append(f)
        f["count"] += 1
        if r.get("error"):
            f["errors"][r["error"]] = f["errors"].get(r["error"], 0) + 1
    for lst in sections.values():
        for f in lst:
            ts = f.pop("first_ts_ns")
            f["first_s"] = (ts - t0) / 1e9 if ts is not None and t0 is not None else None
    order = sorted(sections, key=lambda s: min((f["first_s"] if f["first_s"] is not None else 1e18)
                                               for f in sections[s]))
    return {
        "package": pkg,
        "profile_apps": len(prof.get("apps", [])),
        "sections": {s: sections[s] for s in order},
        "hidden": {s: {"records": h["records"], "keys": len(h["keys"])} for s, h in hidden.items()},
        "coverage": cov,
    }


def render_text(f, width=110):
    out = [f"findings for {f['package'] or '?'} -- behaviour no baseline app showed "
           f"(profile: {f['profile_apps']} app(s))"]
    if not f["sections"]:
        out.append("  (nothing beyond device noise)")
    for sec, lst in f["sections"].items():
        out.append(f"[{sec}] {len(lst)} finding(s)")
        for x in lst:
            err = ""
            if x["errors"]:
                err = "  failed: " + ", ".join(f"{e} x{n}" for e, n in sorted(x["errors"].items()))
            t = f"+{x['first_s']:.1f}s" if x["first_s"] is not None else "?"
            out.append(f"  {t:>8}  x{x['count']:<4} {x['key']}{err}"[:width])
    if f["hidden"]:
        parts = ", ".join(f"{s} {h['records']} ({h['keys']} distinct)" for s, h in sorted(f["hidden"].items()))
        out.append(f"hidden as device noise: {parts}")
    cov = f["coverage"]
    if cov["degraded"]:
        out.append(f"coverage degraded: {', '.join(map(str, cov['degraded']))} -- a missing finding there "
                   f"may be a blind spot")
    elif cov["records"] == 0:
        out.append("no coverage records -- can't tell 'checked, nothing there' from 'not checked'")
    return "\n".join(out)


def _main(argv):
    if len(argv) >= 3 and argv[0] == "profile":
        min_apps = None
        if "--min-apps" in argv:
            i = argv.index("--min-apps")
            min_apps = int(argv[i + 1])
            argv = argv[:i] + argv[i + 2:]
        prof = build_profile([(p, None) for p in argv[2:]], min_apps)
        save_profile(prof, argv[1])
        print(f"profile: {len(prof['apps'])} app(s), {len(prof['keys'])} keys, "
              f"noise = seen in >= {prof['min_apps']} app(s) -> {argv[1]}")
        return 0
    if len(argv) >= 3 and argv[0] == "report":
        prof = load_profile(argv[1]) if os.path.exists(argv[1]) else empty_profile()
        f = findings(argv[2], prof)
        if "--json" in argv:
            for lst in f["sections"].values():
                for x in lst:
                    x.pop("example", None)
            print(json.dumps(f, indent=1))
        else:
            print(render_text(f))
        return 0
    print(__doc__.split("\n\n")[-1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
