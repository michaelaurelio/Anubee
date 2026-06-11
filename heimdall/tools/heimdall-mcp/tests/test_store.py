"""Integration tests for TraceStore over a small synthetic JSONL trace."""

import json
import os
import tempfile

import pytest

from trace_store import TraceStore, MAX_ROWS


def _ev(i, tid, syscall, retval=0, strs=None, fds=None, via=None, sock=None):
    bt = []
    if via:
        bt = [{"frame": 0, "addr": "0x1000", "symbol": via},
              {"frame": 1, "addr": "0x2000", "symbol": "libc.so!__openat"}]
    return {
        "id": i, "pid": 1, "tid": tid, "syscall_nr": 0, "syscall": syscall,
        "retval": retval, "args": ["0x0"],
        "string_args": strs or {}, "fd_args": fds or {}, "decoded_args": {},
        "sock_addr": sock, "backtrace": bt,
    }


def _write_jsonl(records, extra_lines=()):
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
        for ln in extra_lines:
            f.write(ln + "\n")
    return path


@pytest.fixture
def store():
    recs = []
    i = 1
    for _ in range(3):                              # 3 iterations of a loop
        recs.append(_ev(i, 100, "openat", retval=i + 2,
                        strs={"1": "/data/a"}, via="libfoo.so!do_thing")); i += 1
        recs.append(_ev(i, 100, "read", retval=10, fds={"0": "fd=3 </data/a>"})); i += 1
        recs.append(_ev(i, 100, "close", retval=0, fds={"0": "fd=3"})); i += 1
    recs.append(_ev(i, 100, "newfstatat", retval=-2, strs={"1": "/missing"})); i += 1
    recs.append(_ev(i, 101, "connect", retval=0, sock="1.2.3.4:443")); i += 1
    path = _write_jsonl(recs)
    s = TraceStore()
    ov = s.load(path)
    s._ov = ov
    yield s
    os.unlink(path)


def test_overview_and_load_report(store):
    ov = store._ov
    assert ov["events"] == 11
    assert ov["load_report"]["rows"] == 11
    assert "skipped" not in ov["load_report"]
    top = {r["syscall"]: r["count"] for r in ov["top_syscalls"]}
    assert top["openat"] == 3 and top["read"] == 3 and top["close"] == 3


def test_query_filters(store):
    assert store.query(syscall="openat")["matched"] == 3
    errs = store.query(only_errors=True)
    assert errs["matched"] == 1
    assert errs["events"][0]["syscall"] == "newfstatat"
    assert errs["events"][0]["err"]                       # errno name decoded
    # `via` matches the originating frame symbol substring
    assert store.query(via="libfoo")["matched"] == 3
    assert store.query(path_contains="/missing")["matched"] == 1


def test_limit_clamping(store):
    # negative / absurd limits must not raise and must stay within bounds
    assert store.query(limit=-5)["returned"] >= 0
    big = store.query(syscall="openat,read,close", limit=10_000)
    assert big["limit"] <= MAX_ROWS
    assert big["returned"] <= MAX_ROWS


def test_hot_loops_collapse(store):
    loops = store.hot_loops(min_reps=3)
    assert loops, "expected at least one folded loop"
    top = loops[0]
    assert top["body"] == ["openat", "read", "close"]
    assert top["iterations_total"] == 3


def test_sockets_and_search(store):
    eps = {e["endpoint"] for e in store.sockets()["endpoints"]}
    assert "1.2.3.4:443" in eps
    hits = store.search("/missing")
    assert any(h["syscall"] == "newfstatat" for h in hits)


def test_skipped_rows_reported():
    recs = [_ev(1, 1, "openat"), _ev(2, 1, "read")]
    path = _write_jsonl(recs, extra_lines=["{this is not valid json"])
    try:
        s = TraceStore()
        ov = s.load(path)
        assert ov["load_report"]["rows"] == 2
        assert ov["load_report"].get("skipped") == 1
    finally:
        os.unlink(path)
