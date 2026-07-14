# MCP server: query traces from Claude

`tools/ares-mcp` exposes a captured trace (or a live device) to Claude Code /
Claude Desktop as **queryable tools**, backed by an in-memory DuckDB, so you
analyze a multi-million-event trace by asking for small, pre-aggregated slices
instead of pasting the whole file into context.

## Setup

```sh
cd tools/ares-mcp
python3 -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e .                # add [dev] for the test suite
```

Register it with Claude Code:

```sh
claude mcp add ares -- /ABS/PATH/tools/ares-mcp/.venv/bin/python \
                       /ABS/PATH/tools/ares-mcp/server.py
```

...or add a `.mcp.json` in your project:

```json
{
  "mcpServers": {
    "ares": {
      "command": "/ABS/PATH/tools/ares-mcp/.venv/bin/python",
      "args": ["/ABS/PATH/tools/ares-mcp/server.py"],
      "env": { "ARES_TRACE": "/ABS/PATH/trace.jsonl" }
    }
  }
}
```

`ARES_TRACE` is optional (preloads a trace); you can also call `load_trace` from
chat. For Claude Desktop, edit `claude_desktop_config.json`
(`~/.config/Claude/` on Linux, `%APPDATA%\Claude\` on Windows) the same way, and
restart the app after editing.

## What it can analyze

- **`ares syscalls`** structured JSONL (`"type":"syscall"` records): the
  primary trace source.
- **`ares funcs -o`** / **`ares correlate -o`** structured JSONL, via
  `load_structured(path)`: calls, returns, and span→syscall correlation.

## Tools (offline, over a loaded trace)

| Tool | Purpose |
|---|---|
| `load_trace(path)` | Load/switch the active trace. **Start here.** |
| `overview()` | Counts, threads, top syscalls, files, sockets, top errors |
| `hot_loops(min_reps,…)` | Fold repeated syscall sequences per thread; biggest reducer for huge traces |
| `syscall_histogram(top,tid)` | Counts per syscall |
| `files(top,contains)` | Distinct file paths touched + counts |
| `threads()` | Per-tid event counts + dominant syscalls |
| `sockets()` | Decoded peer endpoints (`ip:port` / unix path) + counts |
| `errors(top)` | Failing syscalls grouped by (syscall, errno) |
| `distinct_backtraces(syscall,via,top)` | Deduped call stacks + counts; `via` filters by substring in any frame |
| `wx_scan(top)` | Self-modifying/unpacking + anti-tamper ops: RWX maps, W→X transitions, self-`ptrace` |
| `query(...)` / `get_event(id)` / `search(text)` | Filtered/full-detail/text-search event lookup |
| `diff_traces(baseline,compare,top,via)` | What fired only in `compare` vs `baseline`: the go-to for clean-vs-rooted RASP triage |
| `load_structured(path)` | Ingest `funcs -o` / `correlate -o` JSONL into `calls`/`returns`/`func_spans`/`span_syscalls` |
| `correlate_spans(top)` | Join `span_syscalls`→`func_spans`: one row per in-span syscall with its enclosing function |
| `coverage()` | Per-engine coverage-health rows: was the trace clean? (see [`reading-traces.md`](reading-traces.md)) |
| `call_histogram()` / `call_timing()` / `calls_where(...)` | Call counts / timing stats / filtered raw calls, from `funcs` data |
| `spans()` / `span_tree()` / `span_timeline()` | Call-tree structure and per-span syscall counts, from `correlate` data |
| `summaries(kind)` | The ingested end-of-run `*_summary` teardown records |

## Tools (live, drives the device over `adb`)

| Tool | Purpose |
|---|---|
| `mapped_libraries(package, seconds, activity)` | Launch via `ares lib`, return native libraries loaded; use to discover a randomized protector-payload name |
| `dump_library(package, pattern, seconds, activity, out_dir)` | Run `ares dump` for `seconds`, pull matching `.so`(s) rebuilt from live memory to the host |

Configure via env vars in the MCP client config's `env` block:

| Var | Default | Meaning |
|---|---|---|
| `ARES_ADB` | `adb` | adb executable |
| `ARES_BIN` | `/data/local/tmp/ares` | `ares` path on the device |
| `ARES_SHELL_PREFIX` | *(empty)* | wrap the device command, e.g. `su -c`, if adbd isn't already root |
| `ARES_SERIAL` | *(empty)* | target a specific device (`adb -s`) |

## Example workflow

```
capture on device: ares syscalls -a -q -b 64 -o /data/local/tmp/t.jsonl <pkg>
pull to host:       adb pull /data/local/tmp/t.jsonl
in chat:  "load_trace('/path/t.jsonl'), give me the overview and hot loops,
           then show me everything from librasp that touches /proc or fails."
```

For RASP triage: capture the same app clean and rooted, then ask
`diff_traces('/clean.jsonl', '/rooted.jsonl')`. The new call stacks and probed
paths (e.g. a sudden `newfstatat('/sbin/su')`) point at the detection logic.

## Gotchas

- **Trace is held in memory** (DuckDB). Very large traces use RAM; pre-filter
  at capture time (`-s`/`-x`) for multi-GB traces.
- **Query results are capped at 200 rows.** `matched` in the response gives
  the true count so you can narrow filters instead of assuming truncation.
- **An empty result from a live tool means check `error`**, not "nothing
  found." It surfaces the common causes (`ares` not pushed, needs root,
  package not installed).
- **`recvfrom`/`accept` peer addresses aren't in `sockets()`** yet. Only
  `connect`/`bind`/`sendto` are resolved.
