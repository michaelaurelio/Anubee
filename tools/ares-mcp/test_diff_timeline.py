#!/usr/bin/env python3
# Standalone self-asserting test for diff_calls and span_timeline.
# Run: python3 tools/ares-mcp/test_diff_timeline.py  (no pytest dependency)
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trace_store import TraceStore  # noqa: E402

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")
BASELINE = os.path.join(DATA, "spans.jsonl")
COMPARE = os.path.join(DATA, "spans_b.jsonl")

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

    # -- diff_calls: compare adds one call-site (libssl.so/SSL_read) and one
    # in-span syscall (ptrace) not present in the baseline.
    diff = ts.diff_calls(BASELINE, COMPARE)
    check(diff["baseline"] == os.path.abspath(BASELINE), "diff_calls reports baseline path")
    check(diff["compare"] == os.path.abspath(COMPARE), "diff_calls reports compare path")

    new_calls = diff["new_calls"]
    check(len(new_calls) == 1, f"exactly one new call-site (got {len(new_calls)})")
    if new_calls:
        check(new_calls[0]["module"] == "libssl.so", "new call-site module is libssl.so")
        check(new_calls[0]["symbol"] == "SSL_read", "new call-site symbol is SSL_read")

    new_sys = diff["new_span_syscalls"]
    check(len(new_sys) == 1, f"exactly one new in-span syscall (got {len(new_sys)})")
    if new_sys:
        check(new_sys[0]["syscall"] == "ptrace", "new in-span syscall is ptrace")

    # -- diff_calls with baseline/compare swapped: no new calls or syscalls
    # (spans.jsonl's open/openat/connect are all a subset of spans_b.jsonl's).
    reverse = ts.diff_calls(COMPARE, BASELINE)
    check(reverse["new_calls"] == [], "no new calls when baseline is the superset run")
    check(reverse["new_span_syscalls"] == [], "no new span syscalls when baseline is the superset run")

    # -- span_timeline: ascending span order with correct per-span syscall counts.
    ts2 = TraceStore()
    ts2.load_structured(COMPARE)
    timeline = ts2.span_timeline()
    check(len(timeline) == 3, f"three spans in the timeline (got {len(timeline)})")
    spans_order = [r["span"] for r in timeline]
    check(spans_order == sorted(spans_order), f"timeline is in ascending span order (got {spans_order})")

    counts = {r["span"]: r["syscall_count"] for r in timeline}
    check(counts.get(5) == 0, f"span 5 has no direct in-span syscalls (got {counts.get(5)})")
    check(counts.get(6) == 1, f"span 6 has 1 in-span syscall (got {counts.get(6)})")
    check(counts.get(7) == 2, f"span 7 has 2 in-span syscalls (got {counts.get(7)})")

    filtered = ts2.span_timeline(tid=102)
    check(len(filtered) == 1, f"tid filter narrows to 1 span (got {len(filtered)})")
    if filtered:
        check(filtered[0]["span"] == 7, "tid=102 timeline row is span 7")

    print(f"{checks} checks, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
