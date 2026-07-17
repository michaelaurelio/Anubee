#!/usr/bin/env python3
"""anubee-mcp — an MCP server exposing an anubee trace to an LLM client
(Claude Code / Claude Desktop) as queryable tools.

Today it analyzes the structured syscall JSONL emitted by `anubee syscalls`
(records with "type":"syscall"). The trace schema is type-discriminated, so a
future release adds tools for `anubee funcs` structured records ("type":"call" etc.)
to this same server — see DOCUMENTATION.md "Unified trace schema".

The model drives analysis by retrieval: start broad (overview, hot_loops,
histograms), then drill down (query, get_event). Every tool returns bounded,
pre-aggregated data so a multi-million-event trace stays analyzable without
flooding the context window.

Run:  python server.py            (stdio transport)
      ANUBEE_TRACE=/path.jsonl python server.py    (preload a trace)
"""

import os
import sys
from typing import Optional

from mcp.server.fastmcp import FastMCP

import device
from trace_store import TraceStore

mcp = FastMCP("anubee")
store = TraceStore()


@mcp.tool()
def load_trace(path: str) -> dict:
    """Load an anubee trace file (JSON array or JSONL) and make it the active
    trace, switching away from any previously loaded one. Returns an overview.
    Call this first (or set ANUBEE_TRACE)."""
    return store.load(path)


@mcp.tool()
def load_trace_structured(path: str) -> dict:
    """Load a type-discriminated funcs/correlate trace (funcs -J / correlate -o)
    into calls/returns/func_spans/span_syscalls/coverage tables, switching away
    from any previously loaded trace (including one loaded via load_trace) -
    the two loaders are mutually exclusive on the active connection. Call this
    instead of load_trace when you want call_histogram/call_timing/spans/
    span_tree/span_syscalls/span_timeline/coverage/summaries/correlate_spans;
    syscall-oriented tools (overview, hot_loops, ...) need load_trace instead."""
    path_, skipped = store.load_structured(path)
    report = {"path": path_}
    if skipped:
        report["skipped"] = skipped
    return report


@mcp.tool()
def overview() -> dict:
    """High-level summary of the active trace: total events, id range, per-thread
    counts, the top syscalls, distinct-file count, socket-call count, and the most
    common errors. ALWAYS start here to orient before querying details."""
    return store.overview()


@mcp.tool()
def hot_loops(min_reps: int = 3, max_period: int = 32,
             tid: Optional[int] = None, top: int = 30) -> list:
    """Detect repeated consecutive syscall sequences (loops) per thread and return
    each loop body + total iterations. This is the biggest data reducer — a
    10,000-iteration scan collapses to one entry. Use it early to understand what
    the app does repeatedly. `min_reps` = minimum iterations to fold."""
    return store.hot_loops(min_reps=min_reps, max_period=max_period, tid=tid, top=top)


@mcp.tool()
def syscall_histogram(top: int = 40, tid: Optional[int] = None) -> list:
    """Count of events per syscall (optionally for one thread), most frequent
    first. Cheap way to see the syscall mix."""
    return store.syscall_histogram(top=top, tid=tid)


@mcp.tool()
def files(top: int = 50, contains: Optional[str] = None) -> list:
    """Distinct file paths the app touched (from resolved path arguments) with
    access counts. Optional `contains` substring filter (e.g. '/proc/self')."""
    return store.files(top=top, contains=contains)


@mcp.tool()
def threads() -> list:
    """Per-thread (tid) breakdown: event count and that thread's dominant
    syscalls. Use it to find which thread does the interesting work."""
    return store.threads()


@mcp.tool()
def sockets() -> dict:
    """Network/socket activity. Returns {endpoints, calls}: `endpoints` is the
    decoded peer addresses (ip:port, [ip6]:port, unix:/path, unix:@abstract) with
    counts — i.e. *which servers the app talks to*; `calls` lists the socket
    syscalls with fd + result."""
    return store.sockets()


@mcp.tool()
def errors(top: int = 40) -> list:
    """Failing syscalls grouped by (syscall, errno) with counts and the decoded
    errno name. Good for spotting probes (e.g. newfstatat on a path that doesn't
    exist) and access denials."""
    return store.errors(top=top)


@mcp.tool()
def distinct_backtraces(syscall: Optional[str] = None,
                       via: Optional[str] = None, top: int = 20) -> list:
    """Distinct call stacks (deduplicated) with how many events share each, plus
    an example event id. Optional `syscall` and `via` (a substring that must
    appear in some frame, e.g. a library or function name) filters. Reveals the
    few code paths behind many events without dumping every backtrace."""
    return store.distinct_backtraces(syscall=syscall, via=via, top=top)


@mcp.tool()
def query(syscall: Optional[str] = None, tid: Optional[int] = None,
          path_contains: Optional[str] = None, via: Optional[str] = None,
          only_errors: bool = False, retval: Optional[int] = None,
          id_min: Optional[int] = None, id_max: Optional[int] = None,
          limit: int = 50) -> dict:
    """Filtered list of events (compact: id, tid, syscall, retval, key string/fd
    args, decoded flags). Returns {matched, returned, limit, events} — `matched`
    is the full count even when truncated to `limit` (capped at 200). Filters
    (AND-combined): `syscall` (comma list), `tid`, `path_contains`, `via`
    (substring in a backtrace frame — the library/function the call came from),
    `only_errors`, exact `retval`, `id_min`/`id_max`. For full detail of one event
    use get_event."""
    return store.query(syscall=syscall, tid=tid, path_contains=path_contains,
                       via=via, only_errors=only_errors, retval=retval,
                       id_min=id_min, id_max=id_max, limit=limit)


@mcp.tool()
def coverage() -> list:
    """Per-engine coverage-health records ingested from `type":"coverage"` lines
    (funcs/syscalls/correlate -J/-o output): snapshot truncation, CFI unwind
    stops, ring/queue drops, and function-return capture rate. Use it to gauge
    how much of a trace is trustworthy vs blind spots before drawing conclusions
    from it."""
    return store.coverage()


@mcp.tool()
def summaries(kind: Optional[str] = None, top: int = 50):
    """Mod-analyzer teardown *_summary records ingested from a `-o` trace:
    execve_summary, prop_read_summary, file_access_summary,
    massdelete_detect_summary, proc_event_summary. Without `kind`, returns all
    ingested kinds as {kind: [records]}; with `kind`, returns just that kind's
    records (empty list if the trace had none). Each record's own nested list
    (binaries/props/paths/processes) is capped to the top `top` entries by
    `count` so a large run stays token-bounded."""
    return store.summaries(kind=kind, top=top)


@mcp.tool()
def spans(parent_span: Optional[int] = None, pid: Optional[int] = None,
         tid: Optional[int] = None, limit: int = 50) -> list:
    """Filtered list of raw func_spans records (span, parent_span, pid, tid,
    entry_addr, args) from a correlate -o trace. `parent_span=N` answers
    "what's directly under span N". Filters (AND-combined): `parent_span`,
    `pid`, `tid`."""
    return store.spans(parent_span=parent_span, pid=pid, tid=tid, limit=limit)


@mcp.tool()
def span_tree(root: int, max_depth: Optional[int] = None, limit: int = 200) -> list:
    """Call-tree subtree rooted at `root` span: the root plus all descendants,
    each row tagged with `depth` (0 = root). Optional `max_depth` bounds how
    many levels below root are included (`max_depth=0` returns just the root).
    Use this to walk call-tree nesting from a span found via `spans`."""
    return store.span_tree(root=root, max_depth=max_depth, limit=limit)


@mcp.tool()
def span_syscalls(span: Optional[int] = None, syscall: Optional[str] = None,
                  pid: Optional[int] = None, tid: Optional[int] = None,
                  limit: int = 50) -> list:
    """Filtered list of in-span syscall records (span, pid, tid, nr, syscall,
    args, decoded flags) from a correlate -o trace. Filters (AND-combined):
    `span`, `syscall`, `pid`, `tid`."""
    return store.span_syscalls_where(span=span, syscall=syscall, pid=pid, tid=tid,
                                     limit=limit)


@mcp.tool()
def span_timeline(pid: Optional[int] = None, tid: Optional[int] = None,
                  limit: int = 200) -> list:
    """Spans in chronological/allocation order (by span id) with parent_span,
    pid, tid, entry_addr, and how many syscalls fired inside each span — the
    call-ordering view a histogram doesn't give. Optional `pid`/`tid` filters."""
    return store.span_timeline(pid=pid, tid=tid, limit=limit)


@mcp.tool()
def correlate_spans(top: int = 50) -> list:
    """Join span syscalls to their enclosing function span (requires
    load_trace_structured). One row per in-span syscall, carrying the func
    entry_addr it ran inside."""
    return store.correlate_spans(top=top)


@mcp.tool()
def incidents(rules_path: Optional[str] = None, top: int = 50) -> list:
    """Cross-analyzer incident correlator over the loaded mod-analyzer trace
    (requires load_trace_structured). Fuses ordered analyzer-type chains
    (e.g. accessibility_detect -> exfil_detect on the same pid within a time
    window) into higher-confidence incident records carrying the raw matched
    events as evidence -- no baked severity, judge from the fields. rules_path
    optionally points at a custom rule-chain JSON file for this engagement
    instead of the bundled default (tools/anubee-mcp/correlation_rules.json)."""
    return store.incidents(rules_path, top)


@mcp.tool()
def mod_events(kind: Optional[str] = None, pid: Optional[int] = None, top: int = 50) -> list:
    """Individual per-event mod-analyzer records (requires
    load_trace_structured): spawn, proc_exit, execve, prop, file_access,
    accessibility_detect, screencapture_detect, exfil_detect,
    massdelete_detect, fileless_detect. Drill-down complement to summaries()
    -- raw individual events, not aggregated tallies. Filter by kind and/or
    pid; omit both to see everything (capped at top)."""
    return store.mod_events(kind, pid, top)


@mcp.tool()
def diff_calls(baseline: str, compare: str, top: int = 50) -> dict:
    """Compare two correlate/funcs structured traces (JSONL from `anubee funcs -J`
    or `anubee correlate -o`) and report call-sites and in-span syscalls seen ONLY
    in `compare` — the diff_traces analog for funcs-span data. `new_calls` are
    (module, symbol) call-sites absent from `baseline`; `new_span_syscalls` are
    syscall names that appeared only inside compare's spans. Both files are
    loaded fresh; the active trace is untouched."""
    return store.diff_calls(baseline=baseline, compare=compare, top=top)


@mcp.tool()
def call_histogram(top: int = 40, module: Optional[str] = None) -> list:
    """Count of function calls per (module, symbol) from a funcs trace, most
    frequent first. Optional `module` filter."""
    return store.call_histogram(top=top, module=module)


@mcp.tool()
def call_timing(top: int = 40, symbol: Optional[str] = None,
                module: Optional[str] = None) -> list:
    """Per (module, symbol) call-latency stats (count, min/max/avg, p50/p95 of
    `elapsed_ns`) from a funcs trace, slowest average first. Optional
    `symbol`/`module` filters."""
    return store.call_timing(top=top, symbol=symbol, module=module)


@mcp.tool()
def calls_where(module: Optional[str] = None, symbol: Optional[str] = None,
                pid: Optional[int] = None, tid: Optional[int] = None,
                limit: int = 50) -> list:
    """Filtered list of raw function-call records (pid, tid, module, symbol,
    entry_addr, args). Filters (AND-combined): `module`, `symbol`, `pid`, `tid`."""
    return store.calls_where(module=module, symbol=symbol, pid=pid, tid=tid, limit=limit)


@mcp.tool()
def get_event(event_id: int) -> Optional[dict]:
    """Full detail of a single event by id: all args, string/fd/decoded args, and
    the complete symbolized backtrace."""
    return store.get_event(event_id)


@mcp.tool()
def search(text: str, limit: int = 50) -> list:
    """Find events whose resolved paths/args or backtrace symbols contain `text`
    (e.g. a path fragment, a library name, a function)."""
    return store.search(text=text, limit=limit)


@mcp.tool()
def wx_scan(top: int = 50) -> dict:
    """Find self-modifying / unpacking memory behavior in the active trace — the
    decrypt-then-execute signal of packers and JIT-decrypt RASP, and a top RASP
    tell. Returns {summary, rwx_maps, w_then_x, self_inspection}: `rwx_maps` are
    mmap/mprotect calls that make memory writable+executable at once; `w_then_x`
    are regions made executable AFTER being writable (code written, then run);
    `self_inspection` are process_vm_readv/process_vm_writev/ptrace targeting the
    app's OWN process (integrity self-checks / anti-debug). Each entry is grouped
    by call site (symbolized stack) with a count and an example_id for get_event
    — so you see exactly which library/offset does the unpacking or self-check."""
    return store.wx_scan(top=top)


@mcp.tool()
def diff_traces(baseline: str, compare: str, top: int = 50,
                via: Optional[str] = None) -> dict:
    """Compare two trace files and report what fired ONLY in `compare` — the
    single highest-leverage view for RASP triage: run the app on a clean device
    (`baseline`) and on a rooted/hooked/emulator device (`compare`), and this
    surfaces which checks/branches/resources are new. Returns {summary,
    new_syscalls, new_paths, new_stacks, new_errors, new_endpoints}: `new_stacks`
    are call sites (symbolized, ASLR-invariant) seen only in compare — i.e. the
    checks that activated; `new_paths` are probed files (volatile numeric
    segments normalized) like a sudden `/sbin/su` stat; `new_errors` are new
    failing probes. `via` restricts new_stacks to a library/function substring.
    Both paths are loaded fresh; the active trace is untouched."""
    return store.diff(baseline=baseline, compare=compare, top=top, via=via)


# ---- on-device operations (require adb + anubee on the device) ----------

@mcp.tool()
def mapped_libraries(package: str, seconds: int = 8,
                     activity: Optional[str] = None) -> dict:
    """Launch the app on the connected device (via `anubee lib`) for
    `seconds`, then return the native libraries (.so) it loaded — one record per
    (pid, library) with the merged address range, segment count and inode. Use
    this to discover what's loaded (and the exact/randomized name of a protector
    payload) before dump_library. Needs adb + anubee on the device; see the
    ANUBEE_* env in the README. Returns {libraries, error}: check `error` if
    `library_count` is 0."""
    return device.list_libraries(package, seconds=seconds, activity=activity)


@mcp.tool()
def dump_library(package: str, pattern: str, seconds: int = 12,
                 activity: Optional[str] = None,
                 out_dir: Optional[str] = None) -> dict:
    """Dump a (possibly decrypted/unpacked) native library from the app's LIVE
    memory and pull the rebuilt .so to the host. Runs `anubee dump <package>
    <pattern>` on the device for `seconds` — long enough to decrypt the library
    — then on exit dumps every loaded library whose basename matches `pattern`
    and rebuilds a loadable ELF. `pattern` is a glob over the basename, e.g.
    'e_*' / 'e_[0-9]*' for a payload loaded under a randomized per-run name, or
    'libfoo.so'. Increase `seconds` if the dump looks like ciphertext (the lib
    hadn't finished decrypting). Returns {pulled, dumped_on_device, out_dir,
    error}; each `pulled` entry reports the host path and an ELF sanity check."""
    return device.dump_library(package, pattern, seconds=seconds,
                               activity=activity, out_dir=out_dir)


def main():
    preload = os.environ.get("ANUBEE_TRACE")
    if preload:
        try:
            store.load(preload)
        except Exception as e:
            # Don't abort startup, but don't fail silently either — a typo'd
            # ANUBEE_TRACE is otherwise an invisible mystery.
            print(f"anubee-mcp: failed to preload ANUBEE_TRACE={preload!r}: {e}",
                  file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
