#!/usr/bin/env python3
# Standalone self-asserting test for the calls/returns analysis queries.
# Run: python3 tools/anubee-mcp/test_call_analysis.py  (no pytest dependency)
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
    ts.load_structured(FIX)

    # -- call_histogram: fixture has exactly one call, libc.so/open.
    hist = ts.call_histogram()
    check(len(hist) == 1, f"one histogram row (got {len(hist)})")
    if hist:
        check(hist[0]["module"] == "libc.so", "histogram module libc.so")
        check(hist[0]["symbol"] == "open", "histogram symbol open")
        check(hist[0]["n"] == 1, f"histogram n == 1 (got {hist[0]['n']})")

    hist_mod = ts.call_histogram(module="libc.so")
    check(len(hist_mod) == 1, "histogram filtered by module matches")
    hist_none = ts.call_histogram(module="nope.so")
    check(len(hist_none) == 0, "histogram filtered by unknown module empty")

    # -- call_timing: fixture has exactly one return, elapsed_ns=4096.
    timing = ts.call_timing()
    check(len(timing) == 1, f"one timing row (got {len(timing)})")
    if timing:
        t = timing[0]
        check(t["module"] == "libc.so", "timing module libc.so")
        check(t["symbol"] == "open", "timing symbol open")
        check(t["count"] == 1, f"timing count == 1 (got {t['count']})")
        check(t["min"] == 4096, f"timing min == 4096 (got {t['min']})")
        check(t["max"] == 4096, f"timing max == 4096 (got {t['max']})")
        check(t["avg"] == 4096, f"timing avg == 4096 (got {t['avg']})")
        check(t["p50"] == 4096, f"timing p50 == 4096 (got {t['p50']})")
        check(t["p95"] == 4096, f"timing p95 == 4096 (got {t['p95']})")

    timing_sym = ts.call_timing(symbol="open")
    check(len(timing_sym) == 1, "timing filtered by symbol matches")
    timing_none = ts.call_timing(symbol="nope")
    check(len(timing_none) == 0, "timing filtered by unknown symbol empty")

    # -- calls_where: fixture has exactly one call record.
    all_calls = ts.calls_where()
    check(len(all_calls) == 1, f"one call row unfiltered (got {len(all_calls)})")

    by_module = ts.calls_where(module="libc.so")
    check(len(by_module) == 1, "calls_where module=libc.so returns the one call")
    if by_module:
        check(by_module[0]["symbol"] == "open", "calls_where row symbol open")
        check(by_module[0]["pid"] == 100, "calls_where row pid 100")
        check(by_module[0]["tid"] == 101, "calls_where row tid 101")

    by_symbol = ts.calls_where(symbol="open")
    check(len(by_symbol) == 1, "calls_where symbol=open returns the one call")

    no_match = ts.calls_where(module="nope.so")
    check(len(no_match) == 0, "calls_where with non-matching module returns empty")

    no_match_symbol = ts.calls_where(symbol="nope")
    check(len(no_match_symbol) == 0, "calls_where with non-matching symbol returns empty")

    print(f"{checks} checks, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
