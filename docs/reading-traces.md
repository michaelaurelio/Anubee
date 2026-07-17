# Reading trace output

Every engine writes two independent channels: **console** (human-readable text,
silenced by `-q`) and **`-o FILE`** (JSONL, the complete authoritative record of
a run, always present when `-o` is given, regardless of `-q`/`-v`). Treat the
file as ground truth; the console is a convenience, not a subset guarantee.

Every JSONL record carries a `"type"` field so a mixed stream (or a mixed
capture from `anubee trace`) can be consumed by one reader. Feed a trace to
[`mcp.md`](mcp.md) to query it interactively instead of reading raw JSONL.

## Record types by engine

| Engine | Record types |
|---|---|
| `syscalls` | `syscall` (id, pid, tid, syscall, args, decoded_args, sock_addr, backtrace, java_stack) |
| `funcs` | `call`, `return` (id, module, symbol, args/retval, elapsed_ns, backtrace) |
| `correlate` | `func`, `syscall` (join on `span`/`parent_span`), `return` (only with `--returns`) |
| `lib` / any engine's MAP events | `lib`, `unlib` |
| `dump` | `dump` (module, path, base, pid, raw): one per module written to disk |
| any engine | `coverage` (see below) |
| `syscalls`/`funcs`/`correlate` | `<engine>_summary` at teardown |
| `mod` | `<analyzer>_summary` at teardown, e.g. `execve_summary`, `massdelete_detect_summary` |

`correlate`'s `func`/`syscall`/`return` records carry no `backtrace` array.
Join `span` → `parent_span` across `func` records to reconstruct the call chain
instead.

Summary records (`*_summary`) are omitted entirely when the engine/analyzer saw
no relevant events, so a clean run leaves no empty record.

## `--snapshot` and the `.stacks` sidecar

`syscalls --snapshot` and `funcs --snapshot` (both require `-o <file>`) write a
`<file>.stacks` sidecar alongside the main output:

- `{"type":"stack",...}`: a frozen register file + captured user-stack bytes at
  the trap point. `truncated:1` means the 32 KB capture window filled without
  reaching the real stack base, so the walk may be incomplete.
- `{"type":"cfi_stack","stack_id":N,"cfi_backtrace":[...]}`: the DWARF-unwound
  backtrace for that snapshot, joinable by `stack_id`. Each frame carries `kind`:
  `native` | `jni-trampoline` | `managed` | `interp`.

The main record's inline `java_stack` field is a bounded, best-effort summary of
the same walk; the sidecar's `cfi_stack` is the full, authoritative version.

**Java/managed naming is experimental.** An absent `java_stack` means "not
verified this run" (e.g. an untracked ART build silently disables it), never
"the app used no Java."

## The coverage record

Every engine emits exactly one `{"type":"coverage","engine":"..."}` record at
teardown (also as a `[coverage] <engine>: ...` stderr banner) so a partial
capture is never silently mistaken for a complete one:

- **`"clean":true`**: no truncation, drops, or blind spots this run.
- **Degraded**: only the fields that actually fired are present, e.g.
  `snaps.truncated`, `drops.ring`/`drops.queue`, `managed_naming_off`,
  `prearm_drops`, `depth_capped`. Zero/false fields are omitted.
- **`"exempt":true,"reason":"..."`**: `lib` and `dump` have no coverage
  surface to report (no drop map / single-shot read); this is a third,
  distinct shape from both of the above.

Check this record before treating an absence of some event in the trace as
proof the app never did it; it may mean the tracer missed it instead.

## Gotchas

- **Console output can show less than the file.** Syscall args print
  undecoded on the console in places the file carries the full `decoded` array.
  Never infer file contents from what scrolled by on screen.
- **A degraded `coverage` record silently changes what "absence" means.** Check
  it first, especially before drawing a negative conclusion ("the app never
  touched X") from a trace.
- **`ts_ns` is boot-relative**, not wall-clock. Comparable only within one
  run/device-boot, never across separate runs.
