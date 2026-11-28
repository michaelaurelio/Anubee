#!/usr/bin/env python3
# Standalone self-asserting test for mod_findings: a device noise profile
# built from benign baseline runs, and the "what's new" view of a sample run.
# Run: python3 tools/anubee-mcp/test_mod_findings.py  (no pytest dependency)
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mod_findings as mf  # noqa: E402

checks = 0
failures = 0


def check(cond, msg):
    global checks, failures
    checks += 1
    if not cond:
        failures += 1
        print(f"  FAIL: {msg}")


def write(dirpath, name, recs):
    p = os.path.join(dirpath, name)
    with open(p, "w") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    return p


def startup(pkg, pid, t0):
    """What every app does on start on this device."""
    return [
        {"type": "perm_change", "ts_ns": t0, "package": pkg, "category": "installed",
         "name": "installed", "change": "baseline", "old": None, "new": "yes"},
        {"type": "binder_api", "pid": pid, "ts_ns": t0 + 1, "interface": "android.app.IActivityManager",
         "method": "attachApplication", "code": 17},
        {"type": "file_access", "pid": pid, "ts_ns": t0 + 2,
         "path": "/data/data/com.vendor.gpu/driver_debug.config", "categories": ["foreign_app_dir"],
         "result": -2, "error": "ENOENT"},
        {"type": "file_access", "pid": pid, "ts_ns": t0 + 3, "path": f"/proc/{pid}/task",
         "categories": ["proc_self"], "result": 40},
        {"type": "file_access", "pid": pid, "ts_ns": t0 + 4,
         "path": f"/data/user/0/{pkg}/cache/x", "categories": ["own_app_dir"], "result": 41},
        {"type": "perm_change", "ts_ns": t0 + 5, "package": pkg, "category": "appop",
         "name": "SYSTEM_ALERT_WINDOW", "change": "granted", "old": "default", "new": "allow"},
    ]


def main():
    with tempfile.TemporaryDirectory() as d:
        b1 = write(d, "b1.jsonl", startup("org.example.benign.one", 100, 1000) + [
            # only one benign app does this: below the default threshold for 2 apps? no --
            # threshold is half the apps (1 of 2), so it counts as noise too
            {"type": "net", "pid": 100, "ts_ns": 2000, "event": "open", "proto": "tcp",
             "dest": "10.0.0.1:443", "host": "connectivitycheck.example.com"},
            {"type": "coverage", "engine": "net", "clean": True},
            {"type": "net_summary", "destination_count": 1},
        ])
        b2 = write(d, "b2.jsonl", startup("org.example.benign.two", 200, 5000))

        prof = mf.build_profile([(b1, None), (b2, None)])
        check(prof["apps"] == ["org.example.benign.one", "org.example.benign.two"],
              f"package inferred from perm_change records (got {prof['apps']})")
        check(mf.is_noise(prof, "binder", "android.app.IActivityManager.attachApplication"),
              "binder call made by every benign app is noise")
        check(mf.is_noise(prof, "file", "/data/data/com.vendor.gpu/driver_debug.config"),
              "driver probe seen in the baseline is noise -- learned, not hard-coded")
        check(mf.is_noise(prof, "file", "/proc/<pid>/task"), "pid normalized out of /proc paths")
        check(not any(k.startswith("perm\tinstalled") for k in prof["keys"]),
              "perm_change baseline snapshot is not behaviour")

        ppath = os.path.join(d, "profile.json")
        mf.save_profile(prof, ppath)
        prof = mf.load_profile(ppath)
        check(prof["apps"][0] == "org.example.benign.one", "profile round-trips through JSON")

        pkg = "com.example.sample"
        sample = startup(pkg, 300, 10_000_000_000) + [
            {"type": "net", "pid": 300, "ts_ns": 12_000_000_000, "event": "open", "proto": "tcp",
             "dest": "203.0.113.5:3434", "host": "203.0.113.5:3434"},
            {"type": "net", "pid": 300, "ts_ns": 13_000_000_000, "event": "open", "proto": "tcp",
             "dest": "203.0.113.5:3434", "host": "203.0.113.5:3434"},
            {"type": "net", "pid": 300, "ts_ns": 12_500_000_000, "event": "close", "proto": "tcp",
             "dest": "203.0.113.5:3434", "host": "203.0.113.5:3434"},
            {"type": "net", "pid": 300, "ts_ns": 13_500_000_000, "event": "close", "proto": "tcp",
             "dest": "203.0.113.5:3434", "host": "203.0.113.5:3434"},
            {"type": "execve", "pid": 301, "ts_ns": 14_000_000_000, "filename": "/product/bin/ping",
             "argv": ["ping", "-c", "2", "example.com"], "result": -2, "error": "ENOENT"},
            {"type": "execve", "pid": 301, "ts_ns": 14_000_000_100, "filename": "/system/bin/ping",
             "argv": ["ping", "-c", "2", "example.com"], "result": 0},
            {"type": "dexload_detect", "pid": 300, "ts_ns": 15_000_000_000, "stage": "drop", "kind": "dex",
             "path": f"/data/data/{pkg}/app_x/0.bin", "saved": None},
            {"type": "file_access", "pid": 300, "ts_ns": 16_000_000_000,
             "path": "/data/data/com.example.bank/shared_prefs/a.xml",
             "categories": ["foreign_app_dir"], "result": -13, "error": "EACCES"},
            {"type": "brand_new_analyzer", "pid": 300, "ts_ns": 17_000_000_000, "what": "x"},
            {"type": "coverage", "engine": "net", "clean": True},
            {"type": "coverage", "engine": "file-access", "truncated": 3},
        ]
        s = write(d, "s.jsonl", sample)
        f = mf.findings(s, prof)

        sec = f["sections"]
        check(f["package"] == pkg, "sample package inferred")
        check("binder" not in sec, "baseline-only binder calls hidden")
        check(f["hidden"].get("binder", {}).get("records") == 1, "hidden records are counted, not lost")
        files = [x["key"] for x in sec.get("file", [])]
        check(files == ["/data/data/com.example.bank/shared_prefs/a.xml"],
              f"only the new file probe remains (got {files})")
        check(sec["file"][0]["errors"] == {"EACCES": 1}, "failed outcomes summarized per finding")
        check(not any("cache/x" in k for k in files), "own app dir opens are not findings")
        net = sec.get("net", [])
        check(len(net) == 1 and net[0]["count"] == 2 and net[0]["key"] == "tcp 203.0.113.5:3434",
              "repeated connections collapse into one finding with a count")
        check(len(net) == 1 and net[0]["count"] == 2, "a connection is counted once, not per open+close record")
        check(abs(net[0]["first_s"] - 2.0) < 1e-6, "first-seen time is seconds since the run's first record")
        ex = sec.get("exec", [])
        check(len(ex) == 1 and ex[0]["count"] == 2 and ex[0]["errors"] == {"ENOENT": 1},
              "PATH search: one finding, attempts counted, failures shown")
        check(len(sec.get("dexload", [])) == 1, "dexload drop is a finding")
        check("brand_new_analyzer" in sec, "unknown record types are always shown, never filtered")
        perms = [x["key"] for x in sec.get("perm", [])]
        check(perms == [], f"grant every baseline app also got is hidden (got {perms})")
        check(f["coverage"] == {"records": 2, "degraded": ["file-access"]},
              f"coverage health carried into the view (got {f['coverage']})")
        order = list(sec.keys())
        check(order.index("net") < order.index("exec"), "sections ordered by first appearance")

        txt = mf.render_text(f)
        check("203.0.113.5:3434" in txt and "x2" in txt, "text view lists findings with counts")
        check("hidden as device noise" in txt, "text view says what was hidden")
        check("file-access" in txt and "degraded" in txt, "text view flags degraded coverage")

        # empty profile (no baseline yet): nothing is hidden
        f0 = mf.findings(s, mf.empty_profile())
        check("binder" in f0["sections"], "no profile -> every behaviour shown")

    print(f"test_mod_findings: {checks} checks, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
