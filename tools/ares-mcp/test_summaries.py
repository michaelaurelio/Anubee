#!/usr/bin/env python3
# Standalone self-asserting test for the *_summary ingest path.
# Run: python3 tools/ares-mcp/test_summaries.py  (no pytest dependency)
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trace_store import TraceStore  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "summaries.jsonl")

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
    check(skipped == 0, f"no skipped lines (got {skipped}) -- summaries must not hit the skip bucket")

    all_summaries = ts.summaries()
    expected_kinds = {"execve_summary", "prop_read_summary", "file_access_summary",
                       "massdelete_detect_summary", "proc_event_summary"}
    check(set(all_summaries.keys()) == expected_kinds,
          f"all 5 kinds present (got {set(all_summaries.keys())})")

    proc_ev = ts.summaries("proc_event_summary")
    check(len(proc_ev) == 1, f"one proc_event_summary record (got {len(proc_ev)})")
    if proc_ev:
        check(proc_ev[0]["forks"] == 10, f"forks == 10 (got {proc_ev[0]['forks']})")
        check(proc_ev[0]["exits"] == 9, f"exits == 9 (got {proc_ev[0]['exits']})")
        check(proc_ev[0]["signal_exits"] == 1, f"signal_exits == 1 (got {proc_ev[0]['signal_exits']})")

    execve = ts.summaries("execve_summary")
    check(len(execve) == 1, f"one execve_summary record (got {len(execve)})")
    if execve:
        bins = execve[0]["binaries"]
        check(len(bins) == 2, f"both binaries present (got {len(bins)})")
        check(bins[0]["path"] == "/system/bin/su", "top binary by count is su")
        check(bins[0]["suspicious"] is True, "su binary flagged suspicious")

    fa = ts.summaries("file_access_summary")
    if fa:
        check(fa[0]["paths"][0]["categories"] == ["credential_pattern"],
              f"top path category is credential_pattern (got {fa[0]['paths'][0]['categories']})")

    rb = ts.summaries("massdelete_detect_summary")
    if rb:
        check(rb[0]["processes"][0]["max_distinct"] == -1,
              f"max_distinct preserves negative value (got {rb[0]['processes'][0]['max_distinct']})")

    # capping: top=1 keeps only the highest-count binary.
    capped = ts.summaries("execve_summary", top=1)
    if capped:
        check(len(capped[0]["binaries"]) == 1, f"top=1 caps nested list to 1 (got {len(capped[0]['binaries'])})")

    check(ts.summaries("nope") == [], "unknown kind returns empty list")

    print(f"{checks} checks, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
