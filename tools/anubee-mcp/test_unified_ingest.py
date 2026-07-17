#!/usr/bin/env python3
# Standalone self-asserting test for the unified (funcs/correlate) ingest path.
# Run: python3 tools/anubee-mcp/test_unified_ingest.py  (no pytest dependency)
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trace_store import TraceStore  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "unified.jsonl")

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

    # The two legacy {ts,...,message} wrapper lines have no "type" -> skipped.
    check(skipped == 2, f"skipped 2 wrapper lines (got {skipped})")

    spans = ts.correlate_spans()
    # span 5: one syscall (openat) under one func entry.
    check(len(spans) == 1, f"one correlated span row (got {len(spans)})")
    row = spans[0]
    check(row["span"] == 5, "span id 5")
    check(row["syscall"] == "openat", "syscall openat")
    check("O_RDONLY" in (row.get("decoded") or ""), "decoded carries O_RDONLY")

    print(f"{checks} checks, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
