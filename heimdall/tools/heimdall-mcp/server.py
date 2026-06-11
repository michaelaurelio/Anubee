#!/usr/bin/env python3
"""heimdall-mcp — an MCP server exposing a heimdall syscall trace to an LLM client
(Claude Code / Claude Desktop) as queryable tools.

The model drives analysis by retrieval: start broad (overview, hot_loops,
histograms), then drill down (query, get_event). Every tool returns bounded,
pre-aggregated data so a multi-million-event trace stays analyzable without
flooding the context window.

Run:  python server.py            (stdio transport)
      HEIMDALL_TRACE=/path.jsonl python server.py    (preload a trace)
"""

import os
import sys
from typing import Optional

from mcp.server.fastmcp import FastMCP

import device
from trace_store import TraceStore

mcp = FastMCP("heimdall")
store = TraceStore()


@mcp.tool()
def load_trace(path: str) -> dict:
    """Load a heimdall trace file (JSON array or JSONL) and make it the active
    trace, switching away from any previously loaded one. Returns an overview.
    Call this first (or set HEIMDALL_TRACE)."""
    return store.load(path)


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
def get_event(event_id: int) -> Optional[dict]:
    """Full detail of a single event by id: all args, string/fd/decoded args, and
    the complete symbolized backtrace."""
    return store.get_event(event_id)


@mcp.tool()
def search(text: str, limit: int = 50) -> list:
    """Find events whose resolved paths/args or backtrace symbols contain `text`
    (e.g. a path fragment, a library name, a function)."""
    return store.search(text=text, limit=limit)


# ---- on-device operations (require adb + heimdall on the device) ----------

@mcp.tool()
def mapped_libraries(package: str, seconds: int = 8,
                     activity: Optional[str] = None) -> dict:
    """Launch the app on the connected device (via heimdall -l) for `seconds`,
    then return the native libraries (.so) it loaded — one record per
    (pid, library) with the merged address range, segment count and inode. Use
    this to discover what's loaded (and the exact/randomized name of a protector
    payload) before dump_library. Needs adb + heimdall on the device; see the
    HEIMDALL_* env in the README. Returns {libraries, error}: check `error` if
    `library_count` is 0."""
    return device.list_libraries(package, seconds=seconds, activity=activity)


@mcp.tool()
def dump_library(package: str, pattern: str, seconds: int = 12,
                 activity: Optional[str] = None,
                 out_dir: Optional[str] = None) -> dict:
    """Dump a (possibly decrypted/unpacked) native library from the app's LIVE
    memory and pull the rebuilt .so to the host. Runs heimdall `-l -D <pattern>`
    on the device for `seconds` — long enough for the app to decrypt the library
    — then on exit dumps every loaded library whose basename matches `pattern`
    and rebuilds a loadable ELF. `pattern` is a glob over the basename, e.g.
    'e_*' / 'e_[0-9]*' for a payload loaded under a randomized per-run name, or
    'libfoo.so'. Increase `seconds` if the dump looks like ciphertext (the lib
    hadn't finished decrypting). Returns {pulled, dumped_on_device, out_dir,
    error}; each `pulled` entry reports the host path and an ELF sanity check."""
    return device.dump_library(package, pattern, seconds=seconds,
                               activity=activity, out_dir=out_dir)


def main():
    preload = os.environ.get("HEIMDALL_TRACE")
    if preload:
        try:
            store.load(preload)
        except Exception as e:
            # Don't abort startup, but don't fail silently either — a typo'd
            # HEIMDALL_TRACE is otherwise an invisible mystery.
            print(f"heimdall-mcp: failed to preload HEIMDALL_TRACE={preload!r}: {e}",
                  file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
