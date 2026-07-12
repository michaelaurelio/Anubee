#!/usr/bin/env python3
# Standalone self-asserting test for EPIC I1/I4's MCP-reachability fix: the
# structured tools (call_histogram/spans/coverage/.../correlate_spans) only
# work once load_trace_structured() has populated the active connection -
# previously nothing exposed that loader as an MCP tool, so an MCP client
# could never reach them. This calls the actual server.py tool functions
# (not trace_store.py directly), proving the MCP wiring itself, not just the
# store methods test_unified_ingest.py already covers.
# Run: python3 tools/ares-mcp/test_mcp_structured_tools.py  (no pytest dependency)
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server  # noqa: E402

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
    report = server.load_trace_structured(FIX)
    check(report.get("skipped") == 2, f"skipped 2 wrapper lines (got {report})")

    # Previously-orphaned tool (I1): unreachable before this fix since nothing
    # ever populated calls/returns/func_spans/span_syscalls/coverage via MCP.
    hist = server.call_histogram()
    check(len(hist) == 1, f"one call_histogram row (got {hist})")
    check(hist[0]["module"] == "libc.so" and hist[0]["symbol"] == "open", "call_histogram row is libc.so!open")

    # Newly-registered tool (I4): same fixture/expectation as
    # test_unified_ingest.py's direct TraceStore.correlate_spans() call.
    spans = server.correlate_spans()
    check(len(spans) == 1, f"one correlated span row (got {spans})")
    check(spans[0]["span"] == 5, "span id 5")
    check(spans[0]["syscall"] == "openat", "syscall openat")

    print(f"{checks} checks, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
