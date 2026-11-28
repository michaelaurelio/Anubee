#!/usr/bin/env python3
# Standalone self-asserting test for mod_findings: a device noise profile
# built from benign baseline runs, and the "what's new" view of a sample run.
# Run: python3 tools/anubee-mcp/test_mod_findings.py  (no pytest dependency)
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

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


TD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "mod-view", "testdata")


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


def write_big_run(dirpath, n):
    """The shared fixture plus n noise binder calls (the first and last record among them), a kill whose respawned pid
    shows up only in a noise record (respawns count it), and a noise connection
    before the drop (the payload wording reads it)."""
    with open(os.path.join(TD, "sample-run.jsonl")) as fh:
        base = [json.loads(line) for line in fh if line.strip()]
    t0 = min(r["ts_ns"] for r in base if "ts_ns" in r)
    noise = [{"type": "net", "pid": 13620, "ts_ns": t0 + 2_000_000_000, "event": "open", "proto": "tcp",
              "dest": "198.51.100.7:443", "host": "198.51.100.7:443", "host_source": "sni"}]
    noise.append({"type": "proc_exit", "pid": 13620, "ts_ns": t0 + 249_000_000_000, "signal": 9})
    noise.append({"type": "binder_api", "pid": 45000, "tid": 45000, "ts_ns": t0 + 249_500_000_000,
                  "interface": "android.app.IActivityManager", "method": "attachApplication", "code": 17})
    # the run's first and last records are noise: the view's times read them
    call = {"type": "binder_api", "interface": "android.app.IActivityManager", "method": "attachApplication"}
    noise += [dict(call, ts_ns=t0 - 1_000_000_000), dict(call, pid=13620, ts_ns=t0 + 300_000_000_000)]
    for i in range(n - 3):
        noise.append({"type": "binder_api", "pid": 40000 + i % 50, "tid": 40000 + i % 50,
                      "ts_ns": t0 + 60_000_000_000 + i * 1000, "comm": "sample.app",
                      "interface": "android.app.IActivityManager", "method": "attachApplication",
                      "code": 17, "oneway": False})
    return write(dirpath, "big.jsonl", base[:3] + noise + base[3:])


def embedded(html):
    m = re.search(r'<script type="application/json" id="anubee-run">(.*?)</script>', html, re.S)
    return json.loads(m.group(1)) if m else None


PARITY_JS = r"""
const fs = require('fs'), assert = require('assert');
const D = process.argv[1], M = require(D + '/model.js');
const [full, emb] = [process.argv[2], process.argv[3]].map((p) => JSON.parse(fs.readFileSync(p, 'utf8')));
full.records = fs.readFileSync(full.records, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
full.templates = emb.templates;
assert.deepStrictEqual(M.buildView(emb), M.buildView(full));
console.log('same view');
"""


def same_view(dirpath, run, prof, html, marks=None, meta=None, badging=None):
    """The embedded, trimmed data builds the same View as the whole run."""
    full = os.path.join(dirpath, "full.json")
    with open(full, "w") as fh:
        json.dump({"records": run, "marksText": marks, "profile": prof, "meta": meta,
                   "badging": badging, "staticApk": None}, fh)
    emb = os.path.join(dirpath, "emb.json")
    with open(emb, "w") as fh:
        json.dump(embedded(html), fh)
    p = subprocess.run(["node", "-e", PARITY_JS, os.path.join(TD, ".."), full, emb],
                       capture_output=True, text=True)
    if p.returncode:
        print(p.stderr[-2000:])
    return p.returncode == 0


def html_tests():
    fixture = os.path.join(TD, "sample-run.jsonl")
    prof = mf.load_profile(os.path.join(TD, "profile.json"))
    with open(os.path.join(TD, "sample-run.marks")) as fh:
        marks = fh.read()
    with tempfile.TemporaryDirectory() as d:
        html = mf.build_html(fixture, prof, marks_text=marks)
        check("<script src=" not in html and "http://" not in html, "report loads nothing from the network")
        check(all(u.startswith("https://attack.mitre.org/") for u in re.findall(r'https://[^"\'\s<]+', html)),
              "only ATT&CK links")
        check("AnubeeModView" in html and "sample-run" not in html, "view code and data inlined, no file references")
        check("payloads/" not in html, "no device payload file paths embedded")
        check("com.example.benign" not in html, "baseline app names stay in the lab (only their number is shown)")
        big = write_big_run(d, 50_000)       # 50k records, mostly noise binder calls
        bprof = json.loads(json.dumps(prof))
        bprof["keys"]["net\ttcp 198.51.100.7:443"] = 1
        bhtml = mf.build_html(big, bprof)
        check(len(bhtml) < 3_000_000, "large run is trimmed to what the view needs")

        data = embedded(html)
        check(data is not None and data["marksText"] == marks, "marks embedded as given")
        recs = data["records"] if data else []
        saved = [r["saved"] for r in recs if isinstance(r.get("saved"), dict)]
        check(saved and all("file" not in s and s.get("sha256") for s in saved),
              "saved copies keep hash and size, never the device file path")
        summ = [r for r in recs if r.get("type") == "dexload_detect_summary"]
        check(summ and all("file" not in (f.get("saved") or {}) for f in summ[0]["files"]),
              "summary's saved copies lose the device path too")
        check(sum(r.get("method") == "attachApplication" for r in recs) <= 1, "noise records are not embedded")
        check(data["hidden"] == {"binder": {"records": 1, "keys": 1}}, f"hidden counts passed along (got {data and data['hidden']})")
        check(any(r.get("type") == "coverage" for r in recs) and any(r.get("type") == "net_summary" for r in recs),
              "coverage and summary records embedded")
        bdata = embedded(bhtml)
        check(sum(r.get("method") == "attachApplication" for r in bdata["records"]) <= 54,
              "only each pid's first noise record and the run's first and last stay")
        check(bdata["hidden"]["binder"]["records"] == 50_001, "hidden count is the whole run's, not the trimmed one's")
        check(any(r.get("dest") == "198.51.100.7:443" for r in bdata["records"]),
              "noise connections stay: the payload wording reads them")
        check(set(bdata["profile"]["keys"]) <= {"net\ttcp 198.51.100.7:443",
                                                 "binder\tandroid.app.IActivityManager.attachApplication"},
              "profile cut to the keys of the embedded records")

        if shutil.which("node"):
            check(same_view(d, fixture, prof, html, marks), "embedded data builds the same view as the whole run")
            check(same_view(d, big, bprof, bhtml), "trimmed large run builds the same view as the whole run")
            # a grant the profile hides still counts as granted for the declared-only footer
            with open(fixture) as fh:
                base = [json.loads(line) for line in fh if line.strip()]
            pg = write(d, "pg.jsonl", base + [
                {"type": "perm_change", "ts_ns": base[0]["ts_ns"] + 49_000_000_000, "package": "com.example.sample",
                 "category": "permission", "name": "android.permission.READ_CALENDAR", "change": "granted",
                 "old": "denied", "new": "granted"}])
            pprof = json.loads(json.dumps(prof))
            pprof["keys"]["perm\tpermission android.permission.READ_CALENDAR -> granted"] = 1
            badg = {"permissions": ["android.permission.READ_CALENDAR", "android.permission.CAMERA"]}
            pmeta = {"family": "ExampleFam", "familySource": "MalwareBazaar tag", "sha256": "ab" * 32}
            phtml = mf.build_html(pg, pprof, marks_text=marks, meta=pmeta, badging=badg)
            check(sum(r.get("name") == "android.permission.READ_CALENDAR" for r in embedded(phtml)["records"]) == 1,
                  "every perm_change record is embedded, hidden or not")
            check(same_view(d, pg, pprof, phtml, marks, pmeta, badg),
                  "hidden grant: embedded data builds the same footer as the whole run")
        else:
            print("  skip: node not available for the view parity checks")

        evil = write(d, "evil.jsonl", [
            {"type": "perm_change", "ts_ns": 1, "package": "com.example.sample", "category": "installed",
             "name": "installed", "change": "baseline", "old": None, "new": "yes"},
            {"type": "brand_new_analyzer", "ts_ns": 2, "pid": 1,
             "what": "</script><script>alert(1)</script><!-- \u2028\u2029"}])
        ehtml = mf.build_html(evil, mf.empty_profile())
        check("</script><script>alert" not in ehtml and "<\\/script>" in ehtml, "</ escaped inside the embedded JSON")
        check("\u2028" not in ehtml and "\u2029" not in ehtml and "<!--" not in ehtml,
              "line separators and comment openers escaped")
        check(embedded(ehtml)["records"][1]["what"].startswith("</script>"), "escaped JSON still parses to the text")

        meta = mf.parse_meta("family=ExampleFam\npackage=com.example.sample\nsha256=" + "ab" * 32 +
                             "\nstarted=2026-11-26T00:41:27+07:00\nstopped=2026-11-26T00:45:52+07:00\njunk\n")
        check(meta == {"family": "ExampleFam", "familySource": "MalwareBazaar tag", "sha256": "ab" * 32,
                       "started": "2026-11-26T00:41:27+07:00", "stopped": "2026-11-26T00:45:52+07:00"},
              f"meta.txt parsed to the view's fields (got {meta})")
        check(mf.parse_meta("sha256=" + "ab" * 32) == {"sha256": "ab" * 32}, "no family, no family source")
        bad = mf.parse_badging("package: name='com.example.sample' versionCode='1'\n"
                               "uses-permission: name='android.permission.READ_SMS'\n"
                               "uses-permission: name='android.permission.READ_SMS'\n"
                               "uses-permission: name='android.permission.CAMERA' maxSdkVersion='28'\n")
        check(bad == {"permissions": ["android.permission.READ_SMS", "android.permission.CAMERA"]},
              f"badging permissions, once each (got {bad})")

        apk = os.path.join(d, "s.apk")
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("classes.dex", b"dex\n035\0" + b"\0" * 100)
            z.writestr("assets/blob.bin", b"\x01" * 777)
        out = os.path.join(d, "view.html")
        rc = mf._main(["report", os.path.join(TD, "profile.json"), fixture, "--html", out,
                       "--marks", os.path.join(TD, "sample-run.marks"), "--apk", apk])
        with open(out) as fh:
            cli = embedded(fh.read())
        check(rc == 0 and cli["staticApk"] == {"entries": [{"name": "classes.dex", "size": 108, "isDex": True},
                                                           {"name": "assets/blob.bin", "size": 777, "isDex": False}]},
              f"--apk lists entries in memory (got {cli and cli['staticApk']})")
        check(cli["marksText"] == marks and cli["meta"] is None and cli["badging"] is None,
              "CLI passes the optional inputs it was given, nothing else")
        check(os.listdir(d) and not any(n.endswith(".dex") or n == "assets" for n in os.listdir(d)),
              "the APK is never extracted")

        # hostile APKs: the page is still written, nothing is extracted
        garbage = os.path.join(d, "garbage.apk")
        with open(garbage, "wb") as fh:
            fh.write(b"PK\x03\x04 not really a zip")
        empty = os.path.join(d, "empty.apk")
        open(empty, "wb").close()
        trunc = os.path.join(d, "trunc.apk")
        with open(apk, "rb") as fh:
            whole = fh.read()
        with open(trunc, "wb") as fh:
            fh.write(whole[:len(whole) // 2])
        for bad_apk in (garbage, empty, trunc):
            o = os.path.join(d, "bad.html")
            try:
                rc = mf._main(["report", os.path.join(TD, "profile.json"), fixture, "--html", o, "--apk", bad_apk])
                with open(o) as fh:
                    got = embedded(fh.read())
                ok = rc == 0 and got["staticApk"] is None
            except Exception as e:  # noqa: BLE001
                ok = False
                print(f"  {os.path.basename(bad_apk)}: {type(e).__name__}: {e}")
            check(ok, f"unreadable APK {os.path.basename(bad_apk)} is skipped, page still written")
        # fake encryption bit and an unsupported compression method: the entry stays, isDex unknown
        hostile = os.path.join(d, "hostile.apk")
        with zipfile.ZipFile(hostile, "w") as z:
            z.writestr("classes.dex", b"dex\n035\0" + b"\0" * 20)
            z.writestr("enc.bin", b"\x02" * 50)
            z.writestr("odd.bin", b"\x03" * 60)
        raw = bytearray(open(hostile, "rb").read())
        with zipfile.ZipFile(hostile) as z:
            infos = {i.filename: i for i in z.infolist()}
        pos = 0                    # patch the central directory entries
        while True:
            pos = raw.find(b"PK\x01\x02", pos)
            if pos < 0:
                break
            nlen = int.from_bytes(raw[pos + 28:pos + 30], "little")
            name = raw[pos + 46:pos + 46 + nlen].decode()
            lh = infos[name].header_offset
            if name == "enc.bin":
                raw[pos + 8] |= 1          # general purpose flag: encrypted
                raw[lh + 6] |= 1
            if name == "odd.bin":
                raw[pos + 10:pos + 12] = (99).to_bytes(2, "little")   # unknown method
                raw[lh + 8:lh + 10] = (99).to_bytes(2, "little")
            pos += 4
        with open(hostile, "wb") as fh:
            fh.write(raw)
        try:
            st = mf.static_apk(hostile)
        except Exception as e:  # noqa: BLE001
            st = None
            print(f"  hostile.apk: {type(e).__name__}: {e}")
        check(st == {"entries": [{"name": "classes.dex", "size": 28, "isDex": True},
                                 {"name": "enc.bin", "size": 50, "isDex": None},
                                 {"name": "odd.bin", "size": 60, "isDex": None}]},
              f"encrypted / unknown-method entries are listed with isDex unknown (got {st})")

        # bad data under every compression method, then byte flips over the central directory
        def methods_zip(path, method, data):
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("classes.dex", b"dex\n035\0" + b"\0" * 40)
                z.writestr("x.bin", data)
            b = bytearray(open(path, "rb").read())
            q = 0
            while True:
                q = b.find(b"PK\x01\x02", q)
                if q < 0:
                    break
                n = int.from_bytes(b[q + 28:q + 30], "little")
                if b[q + 46:q + 46 + n] == b"x.bin":
                    b[q + 10:q + 12] = method.to_bytes(2, "little")
                    lh = int.from_bytes(b[q + 42:q + 46], "little")
                    b[lh + 8:lh + 10] = method.to_bytes(2, "little")
                q += 4
            with open(path, "wb") as fh:
                fh.write(b)
            return bytes(b)
        mp = os.path.join(d, "m.apk")
        for method, data in ((14, b"\x00" * 60), (14, b"\x09\x14\x05\x00\x5d\x00\x00\x10\x00" + b"\xff" * 50),
                             (12, b"BZh9garbage" * 5), (8, b"\xff" * 60), (9, b"\x00" * 60)):
            methods_zip(mp, method, data)
            try:
                got = mf.static_apk(mp)["entries"][1]["isDex"]
            except Exception as e:  # noqa: BLE001
                got = f"{type(e).__name__}: {e}"
            check(got is None, f"method {method} with bad data: entry listed, DEX check unknown (got {got})")
        import random
        whole = methods_zip(mp, 8, b"hello" * 20)
        cdir = whole.find(b"PK\x01\x02")
        rng, crashed = random.Random(1), []
        for _ in range(1500):
            b = bytearray(whole)
            for _ in range(rng.randint(1, 6)):
                b[rng.randrange(cdir, len(b)) if rng.random() < 0.7 else rng.randrange(len(b))] = rng.randrange(256)
            with open(mp, "wb") as fh:
                fh.write(b)
            try:
                mf._static_apk_or_none(mp)
            except Exception as e:  # noqa: BLE001
                crashed.append(f"{type(e).__name__}: {e}")
        check(not crashed, f"byte-flipped zips never raise (first: {crashed[:3]})")

        # raw bytes and lone surrogates in a malware-controlled path never crash the report
        rawrun = os.path.join(d, "raw.jsonl")
        with open(rawrun, "wb") as fh:
            fh.write(json.dumps({"type": "perm_change", "ts_ns": 1, "package": "com.example.sample",
                                 "category": "installed", "name": "installed", "change": "baseline",
                                 "old": None, "new": "yes"}).encode() + b"\n")
            fh.write(b'{"type":"file_access","pid":1,"ts_ns":2,"path":"/sdcard/\xff\xfe.bin","categories":[]}\n')
            fh.write(b'{"type":"file_access","pid":1,"ts_ns":3,"path":"/sdcard/\\ud800.bin","categories":[]}\n')
        try:
            rh = mf.build_html(rawrun, mf.empty_profile())
            ok = len(embedded(rh)["records"]) == 3
            rf = mf.findings(rawrun, mf.empty_profile())
            ok = ok and len(rf["sections"].get("file", [])) == 2
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  raw.jsonl: {type(e).__name__}: {e}")
        check(ok, "invalid UTF-8 and lone surrogates are replaced, never fatal")
        here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mod_findings.py")
        env = dict(os.environ, PYTHONIOENCODING="utf-8:strict")
        for extra in ([], ["--json"]):
            pr = subprocess.run([sys.executable, "-I", here, "report", os.path.join(d, "none.json"), rawrun] + extra,
                                capture_output=True, text=True, env=env)
            check(pr.returncode == 0 and "/sdcard/" in pr.stdout,
                  f"printed {'JSON' if extra else 'text'} report survives a lone surrogate (rc {pr.returncode}: {pr.stderr[-200:]})")

        bom = os.path.join(d, "bom.jsonl")
        with open(fixture, "rb") as fh, open(bom, "wb") as out:
            out.write(b"\xef\xbb\xbf" + fh.read())
        n_plain = len(embedded(mf.build_html(fixture, prof))["records"])
        check(len(embedded(mf.build_html(bom, prof))["records"]) == n_plain and mf.infer_package(bom) == "com.example.sample",
              "a byte-order mark doesn't drop the run's first record")

        check(mf.parse_meta("\ufefffamily=ExampleFam\n") == {"family": "ExampleFam", "familySource": "MalwareBazaar tag"},
              "meta.txt with a byte-order mark")
        try:
            mf._main(["report", os.path.join(TD, "profile.json"), fixture, "--html", "--marks", "x"])
            ok = False
        except SystemExit as e:
            ok = "--html" in str(e.code)
        check(ok, "a flag is never taken as the previous flag's value")


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

    # parity: the browser view's golden file is generated from this module
    td = TD
    gf = mf.findings(os.path.join(td, "sample-run.jsonl"), mf.load_profile(os.path.join(td, "profile.json")),
                     "com.example.sample")
    stripped = {"sections": {sec: [{"key": x["key"], "count": x["count"], "errors": x["errors"]} for x in lst]
                             for sec, lst in gf["sections"].items()},
                "hidden": gf["hidden"], "coverage": gf["coverage"]}
    with open(os.path.join(td, "expected-findings.json")) as fh:
        check(stripped == json.load(fh), "findings on the shared fixture equal the JS golden file")

    html_tests()

    print(f"test_mod_findings: {checks} checks, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
