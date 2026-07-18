#!/usr/bin/env python3
# Standalone self-asserting test for device.py's pure line parsers.
# Regression guard for the ts_print() "HH:MM:SS " prefix that anubee's [lib]/[dump]
# console lines picked up (src/common/human_out.c) -- the parsers used to be anchored
# to the literal "[lib]"/"[dump]" start and silently dropped every timestamped line.
# Run: python3 tools/anubee-mcp/test_device.py  (no pytest dependency)
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from device import (parse_lib_lines, parse_dump_lines,  # noqa: E402
                     parse_lib_packed_lines, aggregate_libraries)

checks = 0
failures = 0


def check(cond, msg):
    global checks, failures
    checks += 1
    if not cond:
        failures += 1
        print(f"  FAIL: {msg}")


def main():
    ts_line = "19:33:07 [lib] pid 17267 libfoo.so [0x1000, 0x2000) off=0x10 inode=42"
    recs = parse_lib_lines(ts_line)
    check(len(recs) == 1, f"timestamped [lib] line parses (got {len(recs)} records)")
    if recs:
        r = recs[0]
        check(r == {"pid": 17267, "library": "libfoo.so", "start": 0x1000,
                     "end": 0x2000, "pgoff": 0x10, "inode": 42, "deleted": False,
                     "soname": None},
              f"timestamped [lib] line fields correct (got {r})")

    plain_line = "[lib] pid 17267 libfoo.so [0x1000, 0x2000) off=0x10 inode=42"
    recs = parse_lib_lines(plain_line)
    check(len(recs) == 1, f"un-timestamped [lib] line still parses (got {len(recs)} records)")

    # Real emitter format (src/common/lib_trace.c): full path, trailing
    # "ppid=<P>" and an optional " -> <soname>", both parsed.
    real_line = ("19:33:07 [lib] pid 17267 /system/lib64/libstagefright.so "
                 "[0x7e35e66000, 0x7e35e69000) off=0x209 inode=28284833 "
                 "ppid=1234 -> libstagefright.so")
    recs = parse_lib_lines(real_line)
    check(len(recs) == 1, f"real-format [lib] line parses (got {len(recs)} records)")
    if recs:
        r = recs[0]
        check(r["library"] == "/system/lib64/libstagefright.so"
              and r["soname"] == "libstagefright.so",
              f"real-format [lib] line keeps full path + captures soname (got {r})")

    # libsentinel.so (dev.anubee.detector) is bundled uncompressed inside
    # base.apk (extractNativeLibs=false) and mapped straight out of it: anubee
    # reports the apk as `library` and tacks on "-> libsentinel.so" for the
    # real identity. Observed live via `anubee lib -P dev.anubee.detector`.
    apk_lib_line = (
        "14:54:58 [lib] pid 20447 "
        "/data/app/~~qz0jsqGXKGU8fFUmQGHt7A==/dev.anubee.detector-SQikQp31cjh3ezqJWyxQjw==/base.apk "
        "[0x6e00ea2000, 0x6e00eac000) off=0x890 inode=40351 ppid=1329 -> libsentinel.so")
    recs = parse_lib_lines(apk_lib_line)
    check(len(recs) == 1, f"APK-embedded [lib] line parses (got {len(recs)} records)")
    if recs:
        r = recs[0]
        check(r["library"].endswith("base.apk") and r["soname"] == "libsentinel.so",
              f"APK-embedded [lib] line: library=apk, soname=libsentinel.so (got {r})")

    # [lib-packed]: the proactive per-APK manifest — fires once per newly-seen
    # APK regardless of whether that .so has been dlopen'd yet this run.
    packed_line = (
        "14:54:58 [lib-packed] "
        "/data/app/~~qz0jsqGXKGU8fFUmQGHt7A==/dev.anubee.detector-SQikQp31cjh3ezqJWyxQjw==/base.apk "
        "-> libsentinel.so @0x890000 (43592 b)")
    packed = parse_lib_packed_lines(packed_line)
    check(len(packed) == 1, f"[lib-packed] line parses (got {len(packed)} records)")
    if packed:
        p = packed[0]
        check(p["soname"] == "libsentinel.so" and p["offset"] == 0x890000
              and p["size"] == 43592 and p["apk"].endswith("base.apk"),
              f"[lib-packed] line fields correct (got {p})")

    # A protector lib written to a private path, mmap'd, then unlink()'d (a
    # common anti-dump trick) gets a kernel-added " (deleted)" marker in the
    # resolved path -- observed live: `dev.anubee.detector`'s libsentinel.so.
    deleted_line = ("14:48:39 [lib] pid 19265 "
                     "/data/data/dev.anubee.detector/libsentinel.so_19265 (deleted) "
                     "[0x6ea6c3d000, 0x6ea6d60000) off=0x30 inode=51618 ppid=1329")
    recs = parse_lib_lines(deleted_line)
    check(len(recs) == 1, f"'(deleted)' [lib] line parses (got {len(recs)} records)")
    if recs:
        r = recs[0]
        check(r["library"] == "/data/data/dev.anubee.detector/libsentinel.so_19265"
              and r["deleted"] is True,
              f"'(deleted)' [lib] line keeps path, flags deleted=True (got {r})")
        agg = aggregate_libraries(recs)
        check(len(agg) == 1 and agg[0]["deleted"] is True,
              f"aggregate_libraries propagates deleted=True (got {agg})")

    ts_dump = ("19:33:07 [dump] e_22045 (pid 22045) -> ./e_22045.22045.7aea238000.so "
               "(1778456 bytes, 1777664 from memory, rebuilt)")
    recs = parse_dump_lines(ts_dump)
    check(len(recs) == 1, f"timestamped [dump] line parses (got {len(recs)} records)")
    if recs:
        r = recs[0]
        check(r["name"] == "e_22045" and r["pid"] == 22045 and r["bytes"] == 1778456,
              f"timestamped [dump] line fields correct (got {r})")

    print(f"{checks} checks, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
