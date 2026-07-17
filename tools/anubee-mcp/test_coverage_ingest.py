#!/usr/bin/env python3
# Standalone self-asserting test for the coverage ingest path.
# Run: python3 tools/anubee-mcp/test_coverage_ingest.py  (no pytest dependency)
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trace_store import TraceStore  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "coverage.jsonl")

checks = 0
failures = 0


def check(cond, msg):
    global checks, failures
    checks += 1
    if not cond:
        failures += 1
        print(f"  FAIL: {msg}")


def main():
    ts = TraceStore()
    _, skipped = ts.load_structured(FIX)

    check(skipped == 0, f"no skipped lines (got {skipped})")

    rows = ts.coverage()
    check(len(rows) == 2, f"two coverage rows (got {len(rows)})")

    clean = next((r for r in rows if r["engine"] == "syscalls"), None)
    degraded = next((r for r in rows if r["engine"] == "funcs"), None)
    check(clean is not None, "syscalls (clean) row present")
    check(degraded is not None, "funcs (degraded) row present")

    if clean:
        check(clean["clean"] is True, "syscalls row is clean")
        check(clean["is_clean"] is True, "syscalls row is_clean")
        check(clean["ring_drops"] == 0, f"clean row ring_drops defaults to 0 (got {clean['ring_drops']})")

    if degraded:
        check(degraded["clean"] is False, "funcs row is not clean")
        check(degraded["is_clean"] is False, "funcs row is_clean False")
        check(degraded["ring_drops"] == 7, f"ring_drops flattened to 7 (got {degraded['ring_drops']})")
        check(degraded["queue_drops"] == 0, f"queue_drops flattened to 0 (got {degraded['queue_drops']})")
        check(degraded["prearm_drops"] == 5, f"prearm_drops 5 (got {degraded['prearm_drops']})")
        check(degraded["snaps_total"] == 40, f"snaps_total 40 (got {degraded['snaps_total']})")
        check(degraded["snaps_truncated"] == 2, f"snaps_truncated 2 (got {degraded['snaps_truncated']})")
        check(degraded["cfi_walks"] == 100, f"cfi_walks 100 (got {degraded['cfi_walks']})")
        check(degraded["returns_spans"] == 40, f"returns_spans 40 (got {degraded['returns_spans']})")
        check(degraded["returns_captured"] == 38, f"returns_captured 38 (got {degraded['returns_captured']})")
        stops = dict(degraded["cfi_stops"] or {})
        check(stops.get("no_fde") == 3, f"cfi_stops.no_fde == 3 (got {stops.get('no_fde')})")
        check(stops.get("ra_readfault") == 1, f"cfi_stops.ra_readfault == 1 (got {stops.get('ra_readfault')})")

    print(f"{checks} checks, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
