# anubee: file-output vs stdout-output asymmetry

> **STATUS: RESOLVED — SYM1, 2026-07-13.** Every gap this document identifies
> is closed. 11 phased, independently-gated commits
> (`ANUBEE` `1fced42`..`906d6c1`, Phase 0 through 5c) implemented the plan this
> analysis fed into (§7 below, as agreed with the user 2026-07-12). Full
> changelog entry: `ANUBEE/BACKLOG.md` "SYM1" (2026-07-13). This document's
> analysis was accurate at the time and is kept below as the historical
> record of the problem being fixed — it no longer describes current
> behavior. **§6 "Summary of every asymmetry" is annotated with a resolution
> note per item; §1-§5, §7-§8 are left as originally written.**

**Purpose of this document:** a complete map of how each `anubee` engine's stdout
(human) output diverges from its `-o FILE` (JSON) output, with exact file:line
pointers, so a fix can be planned/implemented without re-deriving this from
scratch. Written 2026-07-12 against `/home/archiver/Documents/projects/anubee-project/ANUBEE/`.

`anubee` is a C + eBPF Android RASP / malware-analysis tracer (not a Rust
project — no `println!`; all output is `printf`/`fprintf`/`fputs`/`vprintf`).
It ships several "engines," each a subcommand: `syscalls`, `funcs`, `lib`,
`dump`, `correlate`, plus `trace` (a coordinator that runs several engines from
one launch) and `mod` (a dispatcher for five smaller "analyzers"). Every
engine can emit two kinds of output:

- **stdout** — a live, human-readable rendering of events, startup status
  lines, and (mod only) an end-of-run summary table.
- **`-o FILE`** — structured JSON, written via the shared serializer/sink in
  `src/common/emit.{c,h}` (`struct jbuf` + `struct anubee_sink`). The sink
  *always* `fopen`s a real file — there is no `-o -`/stdout-JSON convention
  anywhere in the codebase.
- **stderr** — diagnostics, the `wrote N … to PATH` report
  (`anubee_sink_report`, `emit.c:157`), and the `[coverage]` banner
  (`src/common/coverage.c`).

---

## 1. The one rule that's already consistent

Every engine ties the two channels together with the same line:

```c
g_quiet = args.quiet || (args.output_file != NULL);
```

i.e. **`-o` implies `-q`** — passing `-o` silences per-event stdout. This
appears (with local variable names) at:

- `src/syscalls/syscalls.c:1236`
- `src/funcs/funcs.c:888`
- `src/lib/lib.c:147`
- `src/correlate/correlate.c:702`
- documented in the shared help text: `src/common/engine_args.h:30` ("`-o`
  ... implies `-q`")
- `mod` reaches the same effect via its own quiet wiring in `src/modules/mod.c`

**Net effect: file XOR stdout, never both simultaneously, for any engine.**
This is the one piece of symmetry that already holds uniformly. Everything
below is where the symmetry breaks down.

---

## 2. The shared plumbing (what's reusable)

### 2.1 JSON sink — `src/common/emit.{c,h}`

- `struct jbuf` (`emit.h:15`): growable in-memory buffer; builders `jb_s`,
  `jb_c`, `jb_u64`, `jb_i64`, `jb_hex`, `jb_esc`, `jb_b64` (`emit.h:20-26`,
  impl `emit.c:32-84,169`). No per-field `fprintf` — bulk memcpy + manual
  digit/escape encoding.
- `struct anubee_sink` (`emit.h:33-42`): owns `FILE*`, an embedded `jbuf`,
  record `count`, `path`, `noun` (e.g. `"syscall"`/`"event"`), a `jsonl` flag
  (1 = newline-per-record, 0 = JSON array with commas), flush counter, and a
  latched write-error (`werr`).
- `anubee_sink_open()` (`emit.c:93`): `fopen(path, "w")` + an 8 MB `_IOFBF`
  buffer; array mode writes the opening `[`.
- `anubee_sink_emit()` (`emit.c:113`): writes the record built into `s->jb`
  with framing, resets `jb.len`, flushes every `SINK_FLUSH_DEFAULT` (8192)
  records (`ANUBEE_FLUSH_MASK`, `emit.h:19`).
- `anubee_sink_close()` (`emit.c:144`): array mode writes `\n]\n`, flush,
  `fclose`.
- `anubee_sink_report()` (`emit.c:157`): prints `wrote N <noun>(s) to <path>`
  to **stderr**, plus a `WARNING: write error on … output is incomplete`
  line if any write failed.

Each engine keeps one global `g_sink`, builds a bare `{…}` object into
`g_sink.jb`, then calls `anubee_sink_emit`. `funcs` is multi-writer (drain
thread emits lib/unlib, worker thread emits call/return) and serializes both
under `g_sink_lock`; everyone else is single-writer.

### 2.2 Shared CLI flags — `src/common/engine_args.h:17-35`

| Flag | Field | Effect |
|---|---|---|
| `-o, --output FILE` | `output_file` | Export structured JSON(L) to FILE. **Implies `-q`.** NULL = console-only. |
| `-J, --jsonl` | `jsonl` | Force JSON Lines framing instead of a JSON array. |
| `-q, --quiet` | `quiet` | Suppress per-event console output. |
| `-v, --verbose` | `verbose` | Extra console lines (semantics vary per engine, see §4). |
| `-b, --bufsize MB` | ring buffer size | Not output-format related. |
| `-Q, --queue MB` | worker queue size | Not output-format related. |

Parsed by `parse_common_arg()` (`engine_args.h:40-59`). `dump` does **not**
use `COMMON_ARGP_OPTIONS` — see §4.5.

**Framing auto-detect:** most engines also switch to JSONL if the output path
ends in `.jsonl`: `jsonl = c.jsonl || ends_with(output_file, ".jsonl")`
(`funcs.c:891`, `syscalls.c:1237-1238`). But the **default** (no `-J`, no
`.jsonl` extension) differs per engine — see §5.1.

### 2.3 The reference dual-channel pattern — `src/common/lib_trace.c:130-157`

`anubee_libtrace_emit_lib()` / `anubee_libtrace_emit_unlib()` are the *only*
functions in the codebase that already render one event to both channels from
a single call site:

```c
void anubee_libtrace_emit_lib(struct anubee_sink *sink, int quiet, ...) {
    if (!quiet) { ...; printf("%s\n", line); }              // human: "[lib] pid ... [0x..,0x..) off=.. inode=.. ppid=.."
    if (sink && sink->f) { ...; jb_s(...); anubee_sink_emit(sink); }  // JSON: {"type":"lib","pid":..,"library":..}
}
```

This is the template to generalize.

### 2.4 The one *already-generalized* two-channel contract — `src/common/analyzer.h:26-51`

`anubee mod` analyzers implement `anubee_analyzer_t`:

```c
typedef struct {
    const char *name;
    const char *description;
    struct ring_buffer *(*setup)(int uid, struct anubee_mod_ctx *mc);
    void (*teardown)(void);
    void (*print_summary)(void);              // stdout
    void (*emit_summary)(struct anubee_sink *sink);  // file
    unsigned long long (*drops)(void);
} anubee_analyzer_t;
```

`print_summary` (stdout table) and `emit_summary` (JSON `*_summary` record)
are two renderings of the same aggregate data, both called at teardown
(`src/modules/mod.c:214`-ish). **This is the target model** — it just needs to
be (a) extended to per-event records, not only summaries, and (b) generalized
from `mod` to the five top-level engines (`syscalls`, `funcs`, `lib`, `dump`,
`correlate`), which have no equivalent struct today — they hand-roll
`printf` calls and a separate `anubee_sink_emit` call at each event site.

### 2.5 Coverage — `src/common/coverage.{c,h}`

`anubee_coverage_report(sink, cov)` (`coverage.h:37`, impl `coverage.c`) is
already dual-channel by design: one call emits **both** a stderr banner
(`cov_banner`, `coverage.c:96`, format `[coverage] <engine>: ...` or
`full coverage - no truncation, drops, or blind spots`) **and** a
`{"type":"coverage","engine":...}` JSON line to the sink (`coverage.c:49-93`,
only if a sink is open). This is a second working example of the
build-once/render-twice pattern — but its *use* is inconsistent across
engines (see §6).

---

## 3. Per-engine event schema: file vs stdout content

This is the core of the asymmetry — what fields exist in the JSON record vs
what's printed to the console for the *same* event.

### 3.1 `syscalls` — `src/syscalls/syscalls.c`

**stdout** (`!g_quiet`):
- Call line: `==> #<id> [pid/tid] name(arg, arg, ...)` (`:909-916`)
- Stack frames: `      #<n> <sym>` (`:924`)
- Return line: `<== #<id> name = <ret>` (`:940`)
- `-v` adds `map pid ... [0x..,0x..) off=..` (`:966`)
- Startup status lines (also stdout): pid/package/uid (`:1260-1264`), ring
  buffer size (`:1300`), syscall filter (`:1309`), stack-snapshot path
  (`:1333`), return-probe count (`:1398`), queue size (`:1420`)

**file** (`-o`, `json_emit()` `:731-826`): one record type
`{"type":"syscall", "id", "pid", "tid", "syscall_nr", "syscall", "args":[..hex],
"retval", "string_args":{}, "fd_args":{} (fd→path), "decoded_args":{},
"sock_addr"?, "stack_id"?, "java_stack"?, "backtrace":[{frame,addr,symbol,java?,fp_unwind_end?}]}`
plus a separate `{"type":"stack",...}` **sidecar** file (`<output>.stacks`,
opened `:1277-1326`) for `--snapshot`, and `{"type":"cfi_stack",...}` emitted
right after each stack record (`emit_cfi_backtrace`, DOCUMENTATION.md §2.1).

**Gap:** `decoded_args`, `sock_addr`, `string_args`, `fd_args`, `java_stack`,
and the entire stack/cfi_stack sidecar exist **only** in the file. Worse: in
quiet mode the code **skips the symbolization and fd-readlink work
entirely** for speed (`:898-901`, `:943`) — so it's not just a formatting
difference, the *file* record for a syscall can contain resolved symbols and
decoded args that were **never computed** for a would-be stdout rendering,
and vice versa nothing is lost from stdout since stdout doesn't run in this
mode. The asymmetry is architectural: decode work is conditioned on which
channel is active, not run once and shared.

### 3.2 `funcs` — `src/funcs/funcs.c`, `src/funcs/funcs_emit.c`

**stdout**, via three helpers serialized by `g_out_lock`:
`out_print` (`:233`, plain `vprintf`), `ts_print` (`:256-268`, prepends
`HH:MM:SS `), `err_print` (`:244`, `vfprintf(stderr)`).
- Call: `ts_print("[event] > [CALL] PID:.. PPID:.. mod!func @ 0x..")` (`:543`)
- Per-arg lines with fd→path readlink, sockaddr decode, string values
  (`:576-628`)
- `caller:` + backtrace `#n` frames (`:634+`)
- Return line with elapsed `+Nns/+N.us/+N.ms` and retval (`:675-691`)

**file** (`funcs_emit_call`/`funcs_emit_return`, `funcs_emit.c:19-154`):
- `"call"`: `type, pid, tid, ppid, module, symbol, entry_addr, offset?,
  args[8 hex], stack_id?, java_stack?, backtrace[{frame,addr,symbol}],
  string_args{}, fd_args{}, sock_args{}`
- `"return"`: `type, pid, tid, module, symbol, offset?, retval, elapsed_ns,
  backtrace[], retval_str?, out_args{}`

**Gap — smallest of any engine, and explicitly documented as intentional:**
`funcs_emit.c:46-47,119-120` contain comments asserting console/file field
parity. The only real differences: the `HH:MM:SS` timestamp is stdout-only,
and the `.stacks` sidecar (`--snapshot`) is file-only. But this parity is
**maintained by hand** — two independent code paths (`ts_print`/`out_print`
block in `process_call_return`, vs the `funcs_emit_*` builders) that a future
edit to one and not the other will silently desync. There is no structural
guarantee, just a comment.

### 3.3 `correlate` — `src/correlate/correlate.c`, `src/correlate/corr_emit.c`

**stdout** (`!g_quiet`):
- `[func]    > span=.. parent=.. pid=.. tid=.. @ 0x..` (`:402`)
- `[syscall] > span=.. pid=.. tid=.. name (nr=..)` (`:414`) — **name only**
- `[return]  > span=.. retval=0x.. elapsed=..ns @ 0x..` (`:427`, only with `-R/--returns`)
- Attach lines `[spec] > mod!func @ 0x..` (`:482`, stderr FAILED variant)
- `[lib]`/`[unlib]` via the shared `lib_trace` emitter

**file** (`corr_emit.c`):
- `"func"` (`:22`): `type, span, parent_span, pid, tid, entry_addr, args[]`
- `"syscall"` (`:35`): `type, span, pid, tid, nr, syscall, args[],
  decoded[]` — `decoded[]` is a parallel array: string (captured path) → fd
  path (`render_fd`) → sockaddr (`ip:port`) → flag/enum expansion
  (`flags_decode_arg`), same precedence as `syscalls`' `render_arg`
- `"return"` (`:73`): `type, span, pid, tid, entry_addr, retval, elapsed_ns`

**Gap:** the console syscall line prints only the syscall **name** (`nr`);
the entire `decoded[]` array — the actual human-useful part (paths, fds,
sockaddrs, flag names) — exists **only in the file**. This is the sharpest
content gap of any engine: the live console view is strictly less useful
than what's silently written to disk.

### 3.4 `lib` — `src/lib/lib.c`, shared `src/common/lib_trace.c`

**stdout**: `[lib] pid <N> <fullpath> [start,end) off=.. inode=.. ppid=..`
always; `[unlib] ...` **only with `-v`** (`lib_trace.c:130-157`); startup
`tracing uid N (library loads) ... Ctrl-C to stop` (`:238`).

**file**: `"lib"` (`lib_trace.c:130`): `type, pid, tid, ppid, library, start,
end, pgoff, inode, soname?`. `"unlib"` (`:157`): `type, pid, tid, start,
end`. The JSONL **always** records both lib and unlib, regardless of `-v`.

**Gap:** small and mostly about *visibility*, not content — `-v` gates
`[unlib]` on stdout but the file always has it. Minor but inconsistent with
how `-v` behaves in other engines (`syscalls`' `-v` adds *map* lines, i.e.
adds content, not toggles an existing record type).

### 3.5 `dump` — `src/dump/dump.c`, `src/dump/rebuild.c`

**stdout**: `[dump] on-map: pid ... @0x..` (`:120`, only with `--on-map` and
`!g_quiet`); startup `tracing uid N, dumping '...' ... Ctrl-C to stop`
(`:315`).

**stderr** (not stdout, not file): result summary — `[dump] wrote N module
image(s) matching '...' to <dir>` (`:330`) or `[dump] no app process mapped
anything` (`:323`).

**file**: **none.** `dump`'s real output is rebuilt ELF `.so` files written
via `write_file()` in `src/dump/rebuild.c:505-519`
(`open(O_WRONLY|O_CREAT|O_TRUNC,0644)`), path pattern
`<outdir>/<name>.<pid>.<base>.so` (`rebuild.c:651-653`). There is **no JSON
sink at all** — `dump`'s argp table does not include `COMMON_ARGP_OPTIONS`
(`dump.c:155-165`), so it has no `-o` flag, no `-q`... it uses its own
`-d/--dump-dir DIR` (default `.`) and its own `-q`.

**Gap:** total. This is the only engine with zero machine-readable output —
no manifest of what was dumped, when, from where, with what base address.
Nothing to diff two runs against, nothing for the MCP server to ingest the
way it does every other engine's JSONL.

**Related bug:** `anubee trace`'s `-o <prefix>` fan-out
(`src/trace/trace_args.c`, injection site `src/trace/trace.c:168`)
*unconditionally* builds `-o <prefix>.dump.jsonl` and passes it to the dump
section — but since `dump` has no `-o` option, this flag is silently a
no-op (or would error, depending on argp strictness) and `<prefix>.dump.jsonl`
is never produced. `trace.c:59-62,181-182` acknowledge in comments that dump
is "not a live stream" but the injected flag is still dead weight pointing at
a channel that doesn't exist.

### 3.6 `mod` analyzers — `src/modules/*.c`, `src/modules/mod_emit.c`

Each analyzer prints a live `[tag]`-prefixed stream to stdout, then an
end-of-run **summary table**, and (with `-o`) emits per-event JSON via
`mod_emit.c` plus a final `*_summary` JSON record.

Per-event JSON records (`mod_emit.c`):
- `"spawn"` (`:10`): `child_pid, comm`
- `"proc_exit"` (`:21`): `comm, signal | exit_status`
- `"execve"` (`:40`): `comm, filename, argc, argv[], backtrace[]`
- `"prop"` (`:71`): `op, comm, name, value, is_ret, found`
- `"file_access"` (`:97`): `comm, path, flags[], categories[]`
- `"ransomware_burst"` (`:134`): `comm, touch_count, distinct_estimate,
  window_ms, sample_path, manage_external_storage`

Live stdout per analyzer:
- `execve.c`: `[exec] > [EXEC] PID:.. (comm) file argv[...]` (`:103`) +
  caller/backtrace lines
- `prop_read.c`: `[prop] GET/FIND/SCAN/READCB ...` (`:275-303`)
- `file_access.c`: `[file] <tag> PID:.. (comm) path` (`:92`)
- `proc_event.c`: `[proc] > [FORK]/[EXIT] ...` (`:42-63`)
- `ransomware_burst.c`: `[burst] ...` (`:111`)

**Summary tables (stdout only unless `-o`):** UTF-8 box-drawing chars
(`\xe2\x94\x80`, "─"), e.g. `execve.c:241,247-264` ("Exec Summary"),
`prop_read.c:112` ("Property Access Summary"), similarly in
`file_access.c:188-194`, `proc_event.c:84-88`, `ransomware_burst.c:214-221`.
**`execve.c`/`prop_read.c` additionally use ANSI color** — bold-yellow
`\033[1;33m...\033[0m` for suspicious/RASP-flagged rows, gated by
`int use_color = isatty(STDOUT_FILENO)` (`execve.c:231`, used `:252-253`;
`prop_read.c:101,122-123`). **No other engine has any color anywhere.**

**Summary JSON (only when `-o` active)** — the dual-channel model already
implemented, via `emit_summary` (`analyzer.h`):
- `{"type":"execve_summary","total_execs":N,"unique_binaries":N,"flagged":N,"binaries":[{"path":..,"count":N,"suspicious":bool},..]}`
- `{"type":"prop_read_summary","total":N,"unique_props":N,"rasp_count":N,"props":[{"name":..,"count":N,"rasp":bool},..]}`
- `{"type":"file_access_summary","total":N,"unique_paths":N,"flagged":N,"paths":[{"path":..,"count":N,"categories":[..]},..]}`
- `{"type":"ransomware_burst_summary","process_count":N,"processes":[{"pid":N,"comm":..,"bursts":N,"max_touch_count":N,"max_distinct":N},..]}`
- `{"type":"proc_event_summary","forks":N,"exits":N,"signal_exits":N}`

Omitted entirely when the analyzer saw no relevant events (mirrors
`print_summary`'s own early-return) — a good, deliberate convention worth
copying for other engines' future summaries.

**Gap:** small at the per-event level (the live line and the JSON record are
close), but the summary-table content is richer than the JSON in places
(e.g. table formatting/column layout has no direct JSON equivalent, though
the *data* is present) — this is the mildest asymmetry of any engine, mostly
a cosmetic (ANSI/box-drawing) difference rather than a content one.

### 3.7 `trace` (coordinator) — `src/trace/trace.c`

Owns no output of its own beyond stderr usage/warnings: "the engines'
console output will interleave" if `-o` isn't given (`:106`). With `-o
<prefix>`, `trace_build_argv` (`src/trace/trace_args.c:6-26`) expands to:

- `<prefix>.syscalls.jsonl` (`trace.c:128-129`)
- `<prefix>.funcs.jsonl` (`trace.c:142-143`)
- `<prefix>.lib.jsonl` (`trace.c:155-156`)
- `<prefix>.dump.jsonl` (`trace.c:168-169`) — **dead, see §3.5**
- `<prefix>.event.jsonl` (correlate, `trace.c:192-193`)

**Gap:** no merged/unified stream — each child engine's channels stay
independent; without `-o`, multiple engines' stdout physically interleaves
line-by-line with no engine tag to disambiguate, which is unusable in
practice (hence the warning).

---

## 4. Cross-engine inconsistencies (not single-engine content gaps)

### 4.1 Default JSON framing differs per engine

| Engine | Sink open site | Default framing (no `-J`, no `.jsonl` ext) |
|---|---|---|
| `lib` | `lib.c:160` | JSONL (`jsonl=1` hardcoded) |
| `mod` | `mod.c:165` | JSONL (`jsonl=1` hardcoded) |
| `syscalls` | `syscalls.c:1316` | **JSON array** |
| `correlate` | `correlate.c:704` | **JSON array** |
| `funcs` | `funcs.c:892` | JSONL if path ends `.jsonl`, else array |

Same `-o FILE` flag, same underlying sink code, but different on-disk shape
depending purely on which engine you ran — a downstream parser (including
the MCP server) has to special-case this per engine.

### 4.2 `-v` semantics differ

- `syscalls`: `-v` **adds content** (map/unmap trace lines) beyond the
  default event stream.
- `lib`: `-v` **toggles visibility** of an existing record type (`[unlib]`)
  that the file always has anyway.
- `funcs`/`correlate`: `-v` is not consistently documented as controlling
  the same thing.

### 4.3 stdout vs stderr placement is inconsistent

- `syscalls` puts startup/status info on **stdout** (`:1260-1420`).
- `dump` puts its end-of-run result on **stderr** (`:323,330`), while its
  live per-event lines are on stdout.
- `correlate`'s failed-attach lines go to stderr while successful attach
  lines go to stdout (`:482` region).
- No documented rule for "this kind of line goes here" — it's whatever each
  engine's author did locally.

### 4.4 Event-line grammar has 4+ distinct styles

- syscalls: `==> #<id> [pid/tid] name(args)` / `<== #<id> name = ret`
- funcs: `HH:MM:SS [event] > [CALL] PID:.. PPID:.. mod!func @ 0x..`
- correlate: `[func] > span=.. parent=.. pid=.. tid=.. @ 0x..`
- lib: `[lib] pid <N> <fullpath> [start,end) off=.. inode=.. ppid=..`
- mod analyzers: `[exec] > [EXEC] ...`, `[prop] GET/FIND/SCAN/READCB ...`, etc.

Only `funcs` timestamps its lines. Only `mod`'s `execve`/`prop_read` color
anything, and only those two check `isatty`. No shared formatting helper is
used across engines — each rolled its own `printf` calls.

### 4.5 `dump`'s CLI shape doesn't match the other engines

`dump.c:155-165` defines its own argp table that does **not** include
`COMMON_ARGP_OPTIONS` (the shared `-o`/`-J`/`-q`/`-b`/`-Q` block every other
engine uses). It has its own `-q` and a `-d/--dump-dir DIR` in place of `-o`.
This is why `trace`'s blind `-o <prefix>.dump.jsonl` injection (§3.5) is
dead — the flag literally doesn't exist in dump's parser.

---

## 5. Coverage-record asymmetry (§2.5's mechanism, applied inconsistently)

`anubee_coverage_report(sink, cov)` gives clean, exempt-vs-degraded semantics
for free, but its *use* varies:

| Engine | Coverage record | Fields tracked |
|---|---|---|
| `syscalls` | **Full** | snaps, cfi, drops, managed_naming_off, prearm_drops, depth_capped, decode_partial |
| `funcs` | **Full** | same minus prearm_drops (syscalls-only field) |
| `correlate` | **Full** | drops, depth_capped, + `returns:{spans,captured}` under `-R` |
| `lib` | **Exempt (v1)** — no record at all, explicitly documented as "no drop map or snapshot path" | — |
| `dump` | **Exempt (v1)** — "single-shot read, no run-long coverage to accumulate" | — |
| `mod` | **Minimal** — each analyzer reports only its own `drops.ring` count via the same mechanism, no snapshot/CFI/managed-naming/decode surface | drops.ring only |

The design intent ("silence never means didn't-check" — DOCUMENTATION.md §7.5)
is undermined by `lib`/`dump` being silently exempt rather than emitting an
explicit "not applicable" record, and by `mod`'s partial coverage giving a
false sense that everything relevant was checked.

---

## 6. Summary of every asymmetry (indexed)

1. **Content parity gap** — file records are strictly richer than stdout for
   `syscalls` (§3.1) and `correlate` (§3.3); `funcs` (§3.2) is close only by
   manual synchronization, not structural guarantee. Root cause: each channel
   is built by a **separate render call site**, not from one shared decoded
   struct.
   > **RESOLVED (mostly).** `syscalls` (Phase 4a) and `correlate` (Phase 2 —
   > `corr_decode_arg` shared by both channels) content gaps fully closed;
   > stdout is no longer poorer than the file. `funcs`' own caveat stands
   > **unchanged**: its console (`process_call_return`) and file
   > (`funcs_emit.c`) paths are still two independent code sites, now both
   > using the shared `human_out` *formatter*, but not a shared *decode*
   > struct — "manual sync, not structural guarantee" remains true for funcs
   > specifically. Not a regression, just not this item's full closure.
2. **No shared per-event output contract for the five top-level engines** —
   only `mod` analyzers have the `print_summary`/`emit_summary` split
   (`analyzer.h`, §2.4); `syscalls`/`funcs`/`lib`/`dump`/`correlate` each
   hand-roll `printf` + a separate `anubee_sink_emit` call at every event site.
   > **RESOLVED.** `common/human_out.{c,h}` (Phase 0) is now that shared
   > contract for the stdout half, adopted by all five engines (4a-4d) —
   > deliberately plain formatter functions, not a `print_event`/`emit_event`
   > vtable (see the plan's own design note on why). The JSON half was
   > already unified pre-SYM1 (`common/emit.h` + `trace_schema.h`).
3. **Summary asymmetry** — only `mod` has an end-of-run summary on both
   channels (§3.6). `syscalls`/`funcs`/`correlate` have `coverage` but no
   content summary; `lib`/`dump` have neither.
   > **RESOLVED for syscalls/funcs/correlate** (Phase 5c: `syscalls_summary`/
   > `funcs_summary`/`correlate_summary`, mirroring `mod`'s split).
   > **`lib`/`dump` still have no content summary** — never in SYM1's scope
   > (only their *coverage* record was addressed, item 4); genuinely open if
   > wanted later.
4. **Coverage asymmetry** — full for syscalls/funcs/correlate, exempt for
   lib/dump, minimal (drops-only) for mod (§5).
   > **RESOLVED.** Same tiering, but "exempt" is now an explicit third record
   > shape (`{"exempt":true,"reason":...}`, Phase 5b) instead of silence —
   > that was this item's actual complaint ("silence never means
   > didn't-check" being undermined by lib/dump's total silence).
5. **`dump` has no machine channel at all** — ELF files + a stderr line only
   (§3.5); this also causes a live dead-code bug in `trace`'s `-o` fan-out
   (§3.5, §4.5).
   > **RESOLVED** (Phase 3: `-o` + `dump_emit.c` manifest).
6. **stdout grammar divergence** — 4+ distinct event-line styles, timestamp
   only in `funcs`, ANSI color only in `mod`'s `execve`/`prop_read`, summary
   tables only in `mod` (§4.4).
   > **RESOLVED, with a deliberate scope decision made explicit.** Every
   > engine now shares the `human_out` skeleton (timestamp prefix, indented
   > continuation lines) — but each keeps its **own bracket tag**
   > (`[syscall]`, `[lib]`, `[exec]`, …) rather than funcs' literal wording
   > everywhere (user decision, mid-Phase-4). ANSI color / box-drawing
   > summary tables remain `mod`-only, intentionally not extended (decorative,
   > not the actual ask).
7. **`-v`/status-line/stdout-vs-stderr conventions differ** per engine, with
   no shared rule for "event → stdout, diagnostic/report → stderr" (§4.2, §4.3).
   > **NOT ADDRESSED — genuinely still open.** Dual-channel-always (Phase 1)
   > fixed the `-o`/`-q` coupling this item is adjacent to, but `-v`'s
   > per-engine meaning (syscalls: adds content; lib: toggles an existing
   > record's visibility) and the stdout-vs-stderr placement inconsistency
   > were never in any SYM1 phase's scope. If this still matters, it's a
   > fresh, separate piece of work, not a SYM1 follow-up.
8. **Default JSON framing differs per engine** — `lib`/`mod` default JSONL;
   `syscalls`/`correlate` default array; `funcs` conditional on `.jsonl`
   extension (§4.1). Same `-o` flag, different on-disk shape.
   > **RESOLVED** (Phase 5a: JSONL is now the unconditional default
   > everywhere; `-J`/`.jsonl`-detection is a harmless no-op, not removed).
9. **`trace`→`dump` output injection is dead code** — `trace_build_argv`
   (`src/trace/trace_args.c`, call site `trace.c:168`) injects
   `-o <prefix>.dump.jsonl` into the dump section, but `dump`'s argp table
   has no `-o` option (`dump.c:155-165`) (§3.5, §4.5).
   > **RESOLVED** (Phase 3 gave `dump` a real `-o`, so this injection — and
   > its pre-existing `-q`-under-`-o` inject, both already present in
   > `trace.c` before SYM1 touched it — is live, not dead).

---

## 7. Where to start (suggested fix order)

This mirrors priorities already agreed with the user: **content parity
first**, then the shared contract, then coverage/summaries, then dump's
machine channel, then cosmetic/surface unification.

1. **Content parity (§3.1–§3.3).** For `syscalls`, `funcs`, `correlate`:
   restructure so each event's decoded fields (symbols, `decoded_args`,
   `sock_addr`, `fd_args`, `decoded[]`) are computed **once** into a struct,
   then fed to *both* the JSON builder and a human-line printer. Use
   `anubee_libtrace_emit_lib/unlib` (`lib_trace.c:130-157`, §2.3) as the
   reference pattern — it already does this for one event type. Also decide
   whether `-q`/quiet mode should still skip decode work (`syscalls.c:898-901`)
   now that both channels may want it, or whether decode should always run
   and only the *print* be skipped.
2. **Shared render contract.** Generalize `anubee_analyzer_t`
   (`analyzer.h:26-51`, §2.4) — or a new sibling struct — from mod-only,
   summary-only to all five engines, per-event: something like
   `emit_event`/`print_event`/`emit_summary`/`print_summary`, declared
   alongside `ANUBEE_ENGINE_DRIVER` in `src/common/engine_driver.h`.
3. **Universal coverage + summaries (§5).** Give `lib`/`dump` an explicit
   coverage record (clean/exempt, not silence); add end-of-run summaries to
   `syscalls`/`funcs`/`correlate` using the same `*_summary` + `emit_summary`
   convention `mod` already established, including its "omit if nothing
   happened" rule.
4. **`dump` machine channel (§3.5, §4.5).** Add `-o` to `dump`'s argp
   (currently missing `COMMON_ARGP_OPTIONS`, `dump.c:155-165`); open an
   `anubee_sink`; emit one manifest record per dumped module, e.g.
   `{"type":"dump","module":..,"path":..,"base":..,"pid":..,"raw":bool}`
   from the rebuild path (`rebuild.c:651`). This also makes `trace`'s
   existing `-o <prefix>.dump.jsonl` injection (`trace.c:168`) real instead
   of dead.
5. **Surface unification (§4).** Pick one default JSON framing (JSONL is the
   natural choice — matches `lib`/`mod` and the MCP structured-ingest path);
   unify the event-line grammar/timestamp policy; extend the `isatty`-gated
   color helper from `mod` to all engines if desired; make the
   stdout-vs-stderr split consistent (events → stdout, reports/warnings →
   stderr) and fix the specific outliers named in §4.3.

## 8. Decision already made with the user (2026-07-12)

The user chose the **dual-channel-always model**: drop `-o` ⇒ `-q` (§1) so
`-o FILE` writes JSON to the file **and** still prints human text to stdout
at the same time; `-q` remains as the explicit, independent stdout silencer.
Content parity (item 1 above) was named the top priority; all other items
above are in scope but lower priority. This decision, plus a phased
implementation plan, was also recorded in
`/home/archiver/Documents/projects/anubee-project/ANUBEE/BACKLOG.md` under a
`### SYM1 — file/stdout output symmetry across all engines` entry (Major
section) — cross-reference that entry for the tracking ID and any newer
status updates before starting implementation.
