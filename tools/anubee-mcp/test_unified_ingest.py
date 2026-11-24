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

    # mod perm-watch's perm_change records carry no pid (package-scoped
    # state) and must still ingest into mod_events.
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        f.write('{"type":"perm_change","ts_ns":5,"package":"com.example.app","category":"appop",'
                '"name":"SYSTEM_ALERT_WINDOW","change":"changed","old":"default","new":"allow"}\n')
        perm_path = f.name
    pts = TraceStore()
    _, perm_skipped = pts.load_structured(perm_path)
    os.unlink(perm_path)
    check(perm_skipped == 0, f"perm_change line recognized (skipped {perm_skipped})")
    perm_rows = pts.mod_events(kind="perm_change")
    check(len(perm_rows) == 1 and perm_rows[0].get("name") == "SYSTEM_ALERT_WINDOW",
          f"perm_change queryable via mod_events(kind=) (got {perm_rows})")

    # mod binder-api: per-event binder_api records and the binder_api_summary.
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        f.write('{"type":"binder_api","pid":7,"tid":7,"ts_ns":9,"comm":"x",'
                '"interface":"android.content.IContentProvider","method":"QUERY","code":1,'
                '"oneway":false,"uri":"content://sms/inbox"}\n')
        f.write('{"type":"binder_api_summary","processes":[{"pid":7,"calls":[]}],'
                '"content_access":[{"pid":7,"method":"QUERY","detail":"content://sms/inbox","count":3}]}\n')
        ba_path = f.name
    bts = TraceStore()
    _, ba_skipped = bts.load_structured(ba_path)
    os.unlink(ba_path)
    check(ba_skipped == 0, f"binder_api + summary recognized (skipped {ba_skipped})")
    ba_rows = bts.mod_events(kind="binder_api")
    check(len(ba_rows) == 1 and ba_rows[0].get("uri") == "content://sms/inbox",
          f"binder_api queryable via mod_events(kind=) (got {ba_rows})")
    ba_sum = bts.summaries(kind="binder_api_summary")
    check(len(ba_sum) == 1 and ba_sum[0]["content_access"][0]["count"] == 3,
          f"binder_api_summary queryable, content_access kept (got {ba_sum})")

    print(f"{checks} checks, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
