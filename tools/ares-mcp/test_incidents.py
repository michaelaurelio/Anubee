#!/usr/bin/env python3
# Standalone self-asserting test for the mod-analyzer cross-analyzer incident
# correlator: mod_events ingestion (load_structured) + TraceStore.incidents()
# + the incidents() MCP tool wrapper in server.py.
# Run: python3 tools/ares-mcp/test_incidents.py  (no pytest dependency)
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trace_store import TraceStore  # noqa: E402
import server  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "mod_events.jsonl")
CUSTOM_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "custom_rules.json")
INVALID_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "invalid_rules.json")
FIX_EMPTY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "summaries.jsonl")

checks = 0
failures = 0


def check(cond, msg):
    global checks, failures
    checks += 1
    if not cond:
        failures += 1
        print(f"  FAIL: {msg}")


def by_pid(incidents, pid):
    return [i for i in incidents if i["pid"] == pid]


def main():
    ts = TraceStore()
    _, skipped = ts.load_structured(FIX)
    check(skipped == 0, f"no skipped lines (got {skipped}) -- all 10 mod-event types must be recognized")

    rows = ts.con.execute("SELECT pid, type, ts_ns, comm FROM mod_events ORDER BY pid, ts_ns").fetchall()
    check(len(rows) == 19, f"all 19 mod_events rows ingested (got {len(rows)})")
    check(rows[0] == (100, "accessibility_detect", 1000000000, "target"),
          f"first row shape (got {rows[0]})")

    new_types = ts.con.execute(
        "SELECT type FROM mod_events WHERE pid = 700 ORDER BY ts_ns"
    ).fetchall()
    check(new_types == [("spawn",), ("prop",), ("execve",), ("file_access",)],
          f"pid 700's 4 new-type rows in ts_ns order (got {new_types})")

    exit_row = ts.con.execute(
        "SELECT type, pid FROM mod_events WHERE type = 'proc_exit'"
    ).fetchall()
    check(exit_row == [("proc_exit", 701)], f"proc_exit row is pid 701 (got {exit_row})")

    incidents = ts.incidents()

    pid100 = by_pid(incidents, 100)
    check(len(pid100) == 1, f"pid 100: one accessibility-exfil incident (got {len(pid100)})")
    if pid100:
        check(pid100[0]["rule"] == "accessibility-exfil", f"pid 100 rule name (got {pid100[0]['rule']})")
        check(pid100[0]["span_ms"] == 5000.0, f"pid 100 span_ms == 5000.0 (got {pid100[0]['span_ms']})")
        check(pid100[0]["events"][0]["type"] == "accessibility_detect", "pid 100 first evidence event type")
        check(pid100[0]["events"][1]["type"] == "exfil_detect", "pid 100 second evidence event type")

    pid200 = by_pid(incidents, 200)
    check(len(pid200) == 0, f"pid 200: out-of-window screencapture->exfil must not match (got {len(pid200)})")

    pid300 = by_pid(incidents, 300)
    check(len(pid300) == 0, f"pid 300: massdelete-before-exfil must not match destroy-after-exfil (got {len(pid300)})")

    pid400 = by_pid(incidents, 400)
    check(len(pid400) == 1, f"pid 400: nearest-pairing picks exactly one incident (got {len(pid400)})")
    if pid400:
        check(pid400[0]["span_ms"] == 2000.0,
              f"pid 400 nearest match is the 2s exfil, not the 8s one (got {pid400[0]['span_ms']})")

    pid500 = by_pid(incidents, 500)
    check(len(pid500) == 2, f"pid 500: two accessibility_detect anchors both claim the one exfil (got {len(pid500)})")
    if len(pid500) == 2:
        spans = sorted(i["span_ms"] for i in pid500)
        check(spans == [4000.0, 5000.0], f"pid 500 spans are 4000.0 and 5000.0 (got {spans})")

    pid600_default = by_pid(incidents, 600)
    check(len(pid600_default) == 1 and pid600_default[0]["rule"] == "fileless-payload-exfil",
          f"pid 600: default rules match fileless-payload-exfil (got {pid600_default})")

    custom = ts.incidents(rules_path=CUSTOM_RULES)
    check(len(custom) == 1, f"custom rules_path: exactly one incident (got {len(custom)})")
    if custom:
        check(custom[0]["rule"] == "custom-fileless-exfil",
              f"custom rules_path uses the custom rule set only, not the bundled default (got {custom[0]['rule']})")

    ts_empty = TraceStore()
    ts_empty.load_structured(FIX_EMPTY)
    check(ts_empty.incidents() == [], "trace with no mod-event types yields zero incidents, not an error")

    try:
        ts.incidents(rules_path="/nonexistent/rules.json")
        check(False, "missing rules_path should raise, not silently fall back to the default")
    except FileNotFoundError:
        check(True, "missing rules_path raises FileNotFoundError")

    try:
        ts.incidents(rules_path=INVALID_RULES)
        check(False, "invalid rules_path JSON should raise, not silently fall back")
    except ValueError:
        check(True, "invalid rules_path JSON raises ValueError (json.JSONDecodeError)")

    # MCP tool wiring: same fixture/expectation as the direct TraceStore call above.
    server.load_trace_structured(FIX)
    mcp_incidents = server.incidents()
    check(len(by_pid(mcp_incidents, 100)) == 1, "incidents() MCP tool reaches TraceStore.incidents()")

    spawn_only = ts.mod_events(kind="spawn")
    check(len(spawn_only) == 1 and spawn_only[0]["child_pid"] == 701,
          f"mod_events(kind='spawn') returns the one spawn record with child_pid 701 (got {spawn_only})")

    pid700_events = ts.mod_events(pid=700)
    check(len(pid700_events) == 4,
          f"mod_events(pid=700) returns its 4 events, not proc_exit (pid 701) (got {len(pid700_events)})")

    execve_700 = ts.mod_events(kind="execve", pid=700)
    check(len(execve_700) == 1 and execve_700[0]["filename"] == "/system/bin/su",
          f"mod_events(kind='execve', pid=700) combines both filters (got {execve_700})")

    all_events = ts.mod_events(top=200)
    check(len(all_events) == 19, f"mod_events() with no filters returns all 19 rows (got {len(all_events)})")

    still_reachable = ts.mod_events(kind="accessibility_detect")
    check(len(still_reachable) == 4,
          f"widened set didn't break the original 5 detect types -- 4 accessibility_detect rows (pid 100 x1, pid 400 x1, pid 500 x2) (got {len(still_reachable)})")

    print(f"{checks} checks, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
