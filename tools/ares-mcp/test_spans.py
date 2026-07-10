#!/usr/bin/env python3
# Standalone self-asserting test for the span query tools (func_spans/span_syscalls).
# Run: python3 tools/ares-mcp/test_spans.py  (no pytest dependency)
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trace_store import TraceStore  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "spans.jsonl")

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

    # -- spans: fixture has span 5 (root) with children 6, 7.
    children = ts.spans(parent_span=5)
    check(len(children) == 2, f"two children of span 5 (got {len(children)})")

    by_pid = ts.spans(pid=100)
    check(len(by_pid) == 3, f"three spans for pid 100 (got {len(by_pid)})")

    by_tid = ts.spans(tid=102)
    check(len(by_tid) == 1, f"one span for tid 102 (got {len(by_tid)})")
    if by_tid:
        check(by_tid[0]["span"] == 7, f"tid 102 span is 7 (got {by_tid[0]['span']})")

    no_match = ts.spans(parent_span=999)
    check(len(no_match) == 0, "spans with unknown parent_span returns empty")

    # -- span_tree: root 5 + its 2 children = 3 rows, depths {0,1,1}.
    tree = ts.span_tree(5)
    check(len(tree) == 3, f"span_tree(5) has 3 rows (got {len(tree)})")
    depths = sorted(r["depth"] for r in tree)
    check(depths == [0, 1, 1], f"span_tree(5) depths are [0,1,1] (got {depths})")

    root_only = ts.span_tree(5, max_depth=0)
    check(len(root_only) == 1, f"span_tree(5, max_depth=0) returns just the root (got {len(root_only)})")
    if root_only:
        check(root_only[0]["span"] == 5, "root_only row is span 5")

    leaf_tree = ts.span_tree(6)
    check(len(leaf_tree) == 1, f"span_tree(6) (a leaf) returns just itself (got {len(leaf_tree)})")

    # -- span_syscalls_where: span 6 has one openat with decoded flags.
    sys6 = ts.span_syscalls_where(span=6)
    check(len(sys6) == 1, f"one syscall under span 6 (got {len(sys6)})")
    if sys6:
        check(sys6[0]["syscall"] == "openat", "span 6 syscall is openat")
        check("O_RDONLY" in sys6[0]["decoded"], f"decoded flags present (got {sys6[0]['decoded']!r})")

    by_syscall = ts.span_syscalls_where(syscall="connect")
    check(len(by_syscall) == 1, "span_syscalls_where(syscall='connect') matches one row")
    if by_syscall:
        check(by_syscall[0]["span"] == 7, "connect syscall is under span 7")

    no_syscall = ts.span_syscalls_where(syscall="nope")
    check(len(no_syscall) == 0, "span_syscalls_where with unknown syscall returns empty")

    print(f"{checks} checks, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
