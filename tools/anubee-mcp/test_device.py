#!/usr/bin/env python3
# Standalone self-asserting test for device.py's pure line parsers.
# Regression guard for the ts_print() "HH:MM:SS " prefix that anubee's [lib]/[dump]
# console lines picked up (src/common/human_out.c) -- the parsers used to be anchored
# to the literal "[lib]"/"[dump]" start and silently dropped every timestamped line.
# Run: python3 tools/anubee-mcp/test_device.py  (no pytest dependency)
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from device import parse_lib_lines, parse_dump_lines  # noqa: E402

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
                     "end": 0x2000, "pgoff": 0x10, "inode": 42},
              f"timestamped [lib] line fields correct (got {r})")

    plain_line = "[lib] pid 17267 libfoo.so [0x1000, 0x2000) off=0x10 inode=42"
    recs = parse_lib_lines(plain_line)
    check(len(recs) == 1, f"un-timestamped [lib] line still parses (got {len(recs)} records)")

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
