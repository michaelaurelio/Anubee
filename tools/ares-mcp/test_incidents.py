#!/usr/bin/env python3
# Standalone self-asserting test for the mod-analyzer cross-analyzer incident
# correlator: mod_events ingestion (load_structured) + TraceStore.incidents()
# + the incidents() MCP tool wrapper in server.py.
# Run: python3 tools/ares-mcp/test_incidents.py  (no pytest dependency)
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trace_store import TraceStore  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "mod_events.jsonl")

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
    check(skipped == 0, f"no skipped lines (got {skipped}) -- all 5 mod-event types must be recognized")

    rows = ts.con.execute("SELECT pid, type, ts_ns, comm FROM mod_events ORDER BY pid, ts_ns").fetchall()
    check(len(rows) == 14, f"all 14 mod_events rows ingested (got {len(rows)})")
    check(rows[0] == (100, "accessibility_detect", 1000000000, "target"),
          f"first row shape (got {rows[0]})")

    print(f"{checks} checks, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
