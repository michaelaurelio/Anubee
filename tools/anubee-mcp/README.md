# anubee-mcp

An MCP server that exposes an **anubee** trace to an LLM client (Claude Code /
Claude Desktop) as **queryable tools**, so you analyze a multi-million-event
firehose trace by *retrieval* — the model pulls small, pre-aggregated slices on
demand — instead of pasting the whole trace into the context window.

It's backed by **DuckDB** (the trace is loaded into an in-memory columnar DB), and
it reuses anubee's loop-folding to collapse repetition.

> **Scope today:** this server analyzes the **structured syscall JSONL** emitted by
> `anubee syscalls` (records with `"type":"syscall"`), and also ingests the
> type-discriminated records emitted by `anubee funcs -J` and `anubee correlate -o`
> via `load_structured` — exposing a span-join that correlates syscalls to their
> enclosing function spans.

## Why DuckDB

The workload is analytical — histograms, group-by (syscall / path / origin),
deduped backtraces, loop folding — over potentially huge traces. DuckDB is the
right fit: columnar (aggregations are milliseconds over millions of rows), reads
JSON/JSONL natively, handles the nested `string_args`/`backtrace` fields with
`MAP`/`STRUCT` types, embeds with zero server, and is cross-platform.

## Setup

Requires Python ≥ 3.10.

```sh
cd tools/anubee-mcp
python3 -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e .                # add [dev] for the test suite: pip install -e ".[dev]"
```

Use the **absolute path to the venv's Python** in the client config below
(`.venv/bin/python` on Linux, `.venv\Scripts\python.exe` on Windows), or the
installed `anubee-mcp` console script.

## Tools

Aggregation-first — the model is told to start broad, then drill down:

| Tool | Purpose |
|---|---|
| `load_trace(path)` | Load/switch the active trace (JSON array or JSONL). |
| `overview()` | Counts, threads, top syscalls, files, socket calls, top errors. **Start here.** |
| `hot_loops(min_reps,…)` | Fold repeated syscall sequences per thread → body + iterations. Biggest reducer. |
| `syscall_histogram(top,tid)` | Counts per syscall. |
| `files(top,contains)` | Distinct file paths touched + counts. |
| `threads()` | Per-tid event counts + dominant syscalls. |
| `sockets()` | Decoded peer endpoints (ip:port / unix path) with counts + the socket calls. |
| `errors(top)` | Failing syscalls grouped by (syscall, errno). |
| `distinct_backtraces(syscall,via,top)` | Deduped call stacks + counts. |
| `wx_scan(top)` | Self-modifying/unpacking + anti-tamper memory ops: RWX maps, W→X transitions, and self-targeted `process_vm_readv`/`ptrace`, grouped by call site. |
| `query(syscall,tid,path_contains,via,only_errors,retval,id_min,id_max,limit)` | Filtered event list (capped at 200; `matched` is the true count). |
| `get_event(id)` | Full detail of one event incl. backtrace. |
| `search(text,limit)` | Events whose paths/args/symbols contain `text`. |
| `diff_traces(baseline,compare,top,via)` | What fired only in `compare` vs `baseline` — new call stacks, probed paths, syscalls, errors, endpoints. Highest-leverage RASP triage (clean vs rooted run). |

### Unified ingest (funcs / correlate)

`load_structured(path)` ingests a type-discriminated JSONL file produced by
`anubee funcs -J` or `anubee correlate -o` into four DuckDB tables:
`calls`, `returns`, `func_spans`, and `span_syscalls`. It returns
`(abspath, skipped_count)` where `skipped_count` counts lines without a `"type"`
field — the legacy `{ts,stream,tag,message}` wrapper lines that `anubee` emits
alongside the structured records in the same output file.

Key design notes:
- `return` records from `anubee funcs -J` already carry `elapsed_ns` — no
  call→return join is needed for timing; the data is self-contained per record.
- Lines with `"type":"syscall"` but **no** `"span"` field (plain `anubee syscalls`
  engine records) are counted as skipped, not ingested, keeping the two ingest
  paths separate.

`correlate_spans(top=50)` joins `span_syscalls` to `func_spans` on `span` and
returns one row per in-span syscall: `[{span, tid, syscall, func_entry, decoded}]`.
`func_entry` is the entry address of the enclosing function span; `decoded` is the
space-joined decoded argument string (e.g. `"O_RDONLY"`).

`via` matches a substring in any backtrace frame — i.e. *which library/function
the syscall came from* (e.g. `via="librasp"`), the key dimension for RASP work.

### On-device tools (live)

These drive the `anubee` binary on a connected device (they need `adb` and `anubee`
pushed to the device), rather than querying a captured trace. They use the
stealthy `anubee syscalls` engine:

| Tool | Purpose |
|---|---|
| `mapped_libraries(package, seconds, activity)` | Launch the app via `anubee syscalls -l` for a few seconds and return the native libraries it loaded — one record per (pid, library) with merged range + inode. Use it to discover the (possibly randomized) name of a protector payload. |
| `dump_library(package, pattern, seconds, activity, out_dir)` | Run `anubee syscalls -l -D <pattern>` for `seconds` (long enough for the app to decrypt), dump every loaded library whose **basename** matches `pattern` from live memory, rebuild a loadable `.so`, and pull it to the host. `pattern` is a glob: `'e_*'` / `'e_[0-9]*'` for a randomized per-run name, or `'libfoo.so'`. Each result carries an ELF sanity check; bump `seconds` if a dump looks like ciphertext. |

Configure how `anubee` is invoked via environment (set these in the MCP client
config's `env`):

| Var | Default | Meaning |
|---|---|---|
| `ANUBEE_ADB` | `adb` | adb executable |
| `ANUBEE_BIN` | `/data/local/tmp/anubee` | anubee path on the device |
| `ANUBEE_SHELL_PREFIX` | *(empty)* | wrap the device command, e.g. `su -c`, when adbd isn't already root |
| `ANUBEE_SERIAL` | *(empty)* | target a specific device (`adb -s`) |

`anubee` is run under `timeout -s INT <seconds>` so it traces for the bounded window
and then gets the SIGINT that triggers its exit-time memory dump. If a tool returns
an empty result, check the `error` field — it surfaces the common causes (anubee not
pushed, needs root, package not installed).

## Claude Code

Either register it:

```sh
claude mcp add anubee -- /ABS/PATH/tools/anubee-mcp/.venv/bin/python \
                       /ABS/PATH/tools/anubee-mcp/server.py
```

…or add a `.mcp.json` in your project:

```json
{
  "mcpServers": {
    "anubee": {
      "command": "/ABS/PATH/tools/anubee-mcp/.venv/bin/python",
      "args": ["/ABS/PATH/tools/anubee-mcp/server.py"],
      "env": { "ANUBEE_TRACE": "/ABS/PATH/trace.jsonl" }
    }
  }
}
```

`ANUBEE_TRACE` is optional (preloads a trace); you can also just call `load_trace`
from chat.

## Claude Desktop

Edit `claude_desktop_config.json`:
- Linux: `~/.config/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "anubee": {
      "command": "C:\\ABS\\PATH\\tools\\anubee-mcp\\.venv\\Scripts\\python.exe",
      "args": ["C:\\ABS\\PATH\\tools\\anubee-mcp\\server.py"]
    }
  }
}
```

(On Linux use the `.venv/bin/python` path.) Restart Claude Desktop after editing.

The on-device tools read the `ANUBEE_*` env above; put them in the same `env` block,
e.g. `"env": { "ANUBEE_SHELL_PREFIX": "su -c" }`.

## Workflow

**Offline (analyze a captured trace):**

1. Capture on device: `anubee syscalls -a -q -b 64 -o /data/local/tmp/t.jsonl <pkg>`
2. Pull to host: `adb pull /data/local/tmp/t.jsonl`
3. In chat: *"load_trace('/path/t.jsonl'), give me the overview and hot loops,
   then show me everything from librasp that touches /proc or fails."*

The model uses `overview`/`hot_loops` to orient, then `query`/`get_event` to dig —
each call stays small, so even a giant trace is tractable.

For RASP triage, capture the same app on a clean device and a rooted/hooked one,
then: *"diff_traces('/clean.jsonl', '/rooted.jsonl') — which checks fired only on
the rooted device?"* The new call stacks and probed paths (e.g. a sudden
`newfstatat('/sbin/su')`) point straight at the detection logic.

**Live (drive the device):**

*"mapped_libraries('com.example.app') — what native libs load? Then
dump_library('com.example.app', 'e_*', seconds=15) and tell me if the pulled
.so looks decrypted."* The model lists the modules, dumps the protector payload
from live memory, and inspects the rebuilt ELF — all without leaving chat.

## Notes / limits

- Trace is held **in memory** (DuckDB). Very large traces use RAM; DuckDB spills,
  but for multi-GB traces consider pre-filtering at capture (`-s`/`-x`) or with
  `tools/anubee-fold.py`.
- Result sizes are capped (200 rows / query) to protect the context window;
  `matched` tells the model the true count so it can narrow filters.
- `sockets()` resolves peer addresses from the syscalls engine's sockaddr decode
  (connect/bind/sendto). recvfrom/accept addresses are filled at syscall return
  and aren't captured yet.
