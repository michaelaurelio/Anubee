# ARES backlog

Forward-looking work and known tech debt. The **current** state of each engine
lives in [DOCUMENTATION.md](DOCUMENTATION.md); this file holds what's left to do
plus a condensed log of what's already landed.

Open work is bucketed by priority:

- [Urgent](#urgent--architectural--correctness-critical) — architectural keystones
  and correctness-critical bugs. Address before building more on top.
- [Major](#major--features--substantial-work) — features and substantial refactors.
- [Minor](#minor--cleanups-perf-nits-cosmetic-verification) — small cleanups, perf
  nits, cosmetic, and pending verification.
- [Resolved / Done](#resolved--done) — condensed changelog of shipped work.

Each item keeps its original tracking id (`R#`, `C#`, `A#`, `X#`, `U#`, `Phase #`)
so history stays traceable.

---

## Urgent — architectural / correctness-critical

No outstanding urgent items.

---

## Major — features / substantial work

### GA2 — Engine lifecycle asymmetry (graph audit 2026-06-26) — **DONE 2026-06-26**

Core split + `lib`→`trace` wiring shipped. Deferred items remain open individually:
- **Wiring `correlate` into `trace`** — `correlate_setup` must keep its inline `-P` launch
  to get the child PID for uprobe attachment; "caller launches once" contract requires
  `ares_launch_app` to return a PID first (→ GA6).
- **Wiring `dump` into `trace`** — output model is ELF files + on-exit rescan, not a
  concurrent stream; low-value combined run. Deferred by design.

Per-engine comparison (post-GA2):

| Dimension | syscalls | funcs | lib | dump | correlate | trace |
|---|---|---|---|---|---|---|
| Lifecycle | setup/run/teardown | setup/run/teardown | setup/run/teardown | **setup/run/teardown** ✓ | **setup/run/teardown** ✓ | coordinator |
| App launch | shared `ares_launch_app` | shared | shared | shared | own inline launch (needs GA6) | shared |
| Output path | SPSC evq + drain/worker | SPSC evq + drain/worker | sink, inline poll | bypasses sink/evq/jb (ELF dumps) | sink, inline poll | per-engine |
| Symbolized stacks / `--snapshot` | yes | yes | no | no | SP ids only | inherits |
| Return values | yes (kretprobe) | yes (uretprobe) | no | no | no | inherits |
| Stop handler | shared 2-stage SIGINT+TERM | shared | shared | **shared 2-stage** ✓ | **shared 2-stage** ✓ | hand-rolled 2-stage |
| Wired into `trace` | yes | yes | **yes** ✓ | no (deferred) | no (needs GA6) | — |

### `correlate` engine — remaining capability

- **`--returns`** — opt-in uretprobe for return values + exact exit timing. LOUD:
  adds a stack trampoline (a second detection surface beyond the entry `BRK`).
- **Syscall arg / sockaddr / fd / string decoding** — PARTIAL: userspace flag-decode
  done (`flags_decode_arg` via `corr_emit_syscall`; hex args + parallel `decoded[]`).
  fd-path rendering, sockaddr blob capture, and string capture still need BPF
  event-struct changes to carry the raw bytes.
- **Regex (`-I/-i`) targeting** — currently custom specs (`-e`/`-F`) only.
- **`-P` attach timing** — `-P` uprobe attach is best-effort (post-launch
  `/proc/maps` scan); tighten launch→attach timing so early calls aren't missed.

### Shared-core de-dup (consolidation roadmap)

The engines were merged with minimal edits, so duplicated logic remains. Folds into
the thin-presets migration (Urgent).

- **C2 — ring-buffer setup + poll loop.** **DONE (2026-06-23/24).** `ares_rb_poll_until`
  / `ares_rb_poll_until_cb` in `src/common/runtime.h`; all five engines on the shared
  drain helper.
- **C3 — symbolizer maps parsing.** **DONE (2026-06-24/25).** Phase 1: `symbolize.{c,h}`
  moved to `src/common/` and shared by both engines. Phase 2: `src/common/maps.{c,h}`
  adds `ares_parse_maps_line` — all six `/proc/<pid>/maps` consumers now use it (symbolize,
  lib_trace, probe_resolve, correlate, dump/rebuild, funcs). Full iterator-sharing
  (one open/read/close for all consumers) is **explicitly declined** as over-engineering
  for once-per-attach one-shot scans.
- **C4 — kernel-side UID filter.** **DONE (2026-06-24).** `src/common/uid_filter.bpf.h`
  (`target_uids` HASH-set map + `uid_matches()`); all five `.bpf.c` files include it.
- **C7 — symbol/caller resolution.** **DONE (2026-06-24).** See C3 Phase 1. `funcs`
  now gets real function names from `.dynsym`/`.symtab`/`.gnu_debugdata`, ART/JIT
  frames, and vDSO resolution.
- **C8 — misc duplication.** **DONE (2026-06-24).** `libbpf_print_fn` (three local
  copies) → `ares_libbpf_quiet` from `common/runtime.h`; `dropped`
  map/`bump_dropped()` → `src/common/bpf_drop.bpf.h`; `syscalls_hdr` alias removed.
  Remaining: `vmlinux.h` dedup (see Minor).

### `funcs` structured records — module events (deferred)

- CALL/RETURN: **done.** MAP/UNMAP: **done (2026-06-25)** via `ares_libtrace_emit_lib/unlib`
  under `g_sink_lock` (Option A — drain emits directly, attach stays prompt).
- **SPAWN/PROC_EXIT/EXECVE/PROP** still open: needs new `funcs_emit_*` builders
  (one per type, host-tested) and a sink path on the module `handle_event` signature
  (`module.h:19` currently has no output channel).
- **B2 — route all map/unmap/module events through the worker queue** (syscalls
  `process_event` model): converges funcs to single-writer, enables retiring the
  `g_out_lock` dual-writer split. Bigger lift; revisit when module events are scoped
  in (at that point B2 becomes cheaper than wiring more lock sites into modules).

### CFI stack unwinder — all three tasks landed

W1, W2, and W3 all landed (W2+W3: 2026-06-26; W1: 2026-06-27 — see Resolved).

- **W1 — DONE (2026-06-27): CFI unwinder wired to runtime; cross-trampoline confirmed.**
  `cfi_unwind_snapshot` (in `src/common/symbolize.c`, declared in `symbolize.h`) loops
  `cfi_get` + `cfi_step` over the frozen snapshot window. Reads only the frozen
  `snap->snap[]` bytes — no live target memory. Called from `emit_cfi_backtrace`
  in `syscalls.c` immediately after each raw `{"type":"stack"}` sidecar write; emits
  a companion `{"type":"cfi_stack","stack_id":N,"cfi_backtrace":[{frame,addr,symbol,kind},...]}`.
  `kind` ∈ `native | jni-trampoline | managed | interp`. `cfi_unwind.c` + `dwarf.c`
  added to `COMMON_CSRC`; `cfi_unwind_snapshot` exported via `COMMON_API`.
  Device test arm `syscalls-cfi` asserts jni-trampoline→managed cross (SKIP on timing
  miss; hard-fail only on BPF-load error). On-device proof deferred to controller run.

- **Deferred — interpreter frame naming:** frames tagged `"kind":"interp"` are detected
  by `is_interp_frame` (ART interpreter entrypoints) but the managed method name is not
  recovered. Naming them requires an ART managed-stack (ShadowFrame) walk — out of scope
  for the CFI unwinder. Parked alongside Phase 2b findings.

### Managed-frame symbolization (OAT / ODEX / VDEX)

Goal: name the Java method behind a native backtrace frame that lands in
AOT-compiled / interpreter-adjacent regions. OAT/ODEX Java methods already resolve in
practice via the `.gnu_debugdata` mini-debug-info `dex2oat` embeds (existing ELF
symbol path); vDSO frames are named (Phase 1).

- **Phase 2a — DONE (2026-06-24):** version-stable DEX offset→method core
  (`src/common/dex.{c,h}`, host-tested against a committed fixture). Not yet wired
  into any capability.
- **Phase 2b — DONE (2026-06-24): PARK both frame types; 2c/2d NOT greenlit.** On
  A15/AOT, captured `classes.vdex+0x..` offsets all land in DEX *data*, not
  `code_item`s — they're FP-unwinder mis-captures, not bytecode `dex_pc`s. Naming
  them needs a proper ART managed-stack (ShadowFrame) walk, not the DEX resolver.
  Evidence: `docs/superpowers/research/2026-06-24-vdex-dex-frame-spike-findings.md`.
- **Phase 2c — PARKED by 2b:** locate the DEX image inside `base.vdex` /
  `[anon:dalvik-DEX data]` and feed `dex_map_build`. Parked: 2b showed the PCs aren't
  code_item offsets, so a locator would feed garbage.
- **Phase 2d — PARKED by 2b:** wire the two frame types through `symbolize.c` with a
  per-image cache, emitting `base.vdex!pkg.Class.method+0x..`.
- **OAT/ODEX native PC → Java method (future):** App `.odex`/`.oat` AOT code is
  method-index-keyed, not ELF symbols; resolving a PC needs real OAT parsing
  (oatdump-class, **ART-version-coupled** — the main risk). Phase-2a core stays
  valuable for these genuine method-index→name paths. Specs:
  `docs/superpowers/specs/2026-06-23-jit-named-cache-symbolization-design.md`,
  `docs/superpowers/specs/2026-06-24-dex-method-resolver-core-design.md`.

---

## Minor — cleanups, perf nits, cosmetic, verification

- **F2 — PID attach mode error in `ares funcs` (and others). NEEDS REPRO.** The `-p`
  parse and uprobe attach loop are structurally sound; the failure is likely runtime
  (attach perms / per-PID `/proc` symbol resolution). Share exact `stderr` output +
  invocation before assigning a root cause. Also check `correlate -p`.
- **R9 — `syscall_name()` linear scan per syscall event** (`correlate` + the
  equivalent in `syscalls`). Fine at current volume; if rates climb, sort the
  generated table once and `bsearch`, or index by `nr`.
- **C8 (remaining) — duplicate `vmlinux.h`** — signal handlers, `dropped`
  map/`bump_dropped()`, and `syscalls_hdr` alias are unified; `vmlinux.h` dedup still
  open.
- **C9 — `funcs` could borrow `syscalls`' `decode_sockaddr`** (funcs has no sockaddr
  decoding).
- **U1/U2 — console style diverges.** `funcs` uses timestamped tagged lines
  (`[spawn] >`, `[uprobe] >`, …); other engines use prose banners. Masked under
  `trace -o`. Low value / high cosmetic churn across 5 files — **not recommended**.
  (`[lib]`/`[unlib]` are output lines, not banners — keep their format.)
- **Drop the 6 MB committed `vmlinux.btf`** in favor of regenerate-on-demand.
- **Unified MCP richness (follow-on).** Minimal ingest + span join done; remaining:
  call histograms, timing views, symbol/module filters, full `server.py` tool surface
  for the new types.
- **Pending on-device verification:** combined `trace` run; `correlate` hardening
  (R3/R4/X2 — host tests pass, device tier not yet run).

### Graph audit (2026-06-26)

- **GA3 — sink swallows all write/flush/close errors.** `ares_sink_emit` ignores every
  `fwrite`/`fputs`/`fputc` return and increments `count` regardless (`emit.c:104-120`);
  `ares_sink_flush`/`_close` ignore `fflush`/`fclose` (`emit.c:126,135`); `ares_sink_open`
  hands `setvbuf` an unchecked `malloc(8 MB)` (`emit.c:93`). ENOSPC/EIO and a
  flush-failure-at-close silently truncate the JSONL with zero signal. Fix: check the
  hot-path returns, latch a sticky write-error, and report it at teardown.
- **GA4 — event-queue pop clamp can desync the whole stream.** `ares_evq_pop` does
  `if (n > outcap) n = outcap` then advances `tail` by only `n` (`evqueue.c:68-72`); the
  remaining `sz-n` bytes are then read as the next length prefix, desyncing every
  subsequent record. The inline comment ("records are always bounded") asserts the
  invariant in prose but nothing enforces it. Currently safe only because worker buffers
  are sized to the max record (`syscalls.c:861`). Fix: `assert(sz <= outcap)` (or drop the
  whole record + count it) instead of a silent partial read.
- **GA5 — stop-handler inconsistency across engines. PARTIAL (2026-06-26).**
  `dump` and `correlate` now both use the shared `ares_install_stop_handler` (2-stage
  SIGINT+SIGTERM) — fixed as a free byproduct of the GA2 lifecycle split. Remaining:
  `trace` coordinator still hand-rolls its `on_sigint` (`trace.c:31`); it's already
  2-stage (`_exit(130)` on second Ctrl-C) and catches only SIGINT, but doesn't respond
  to SIGTERM. Low risk — the coordinator case is intentionally different (multiple
  concurrent drain threads share `g_stop`). Fix separately if SIGTERM matters for `trace`.
- **GA6 — `correlate` uses an inline launcher, not shared `ares_launch_app`**
  (`correlate.c:300`; the inline comment says the helper "doesn't return the pid"). Fold
  back by returning the pid from `ares_launch_app` so `correlate` stops cloning launch
  logic. Consolidation, pairs with GA2.
- **GA7 — `probe_resolve` residual fragility (post-R2-fix).** `vaddr_to_file_off` is
  correct for normal ELF, but: a vaddr in no PT_LOAD is returned unchanged → silently wrong
  offset (`probe_resolve.c:22`); the PT_LOAD table is capped at 32 segments, extras ignored
  (`:32`); a user-supplied `@offset` in a custom spec is used as a raw file offset with no
  conversion (`:408`). Harden the no-segment-match and over-cap cases to fail loudly.
- _Checked, not a bug:_ `correlate`'s `-p`/`-e`/`-F` parsing was suspected of unbounded
  append into `pids[64]`/`specs[64]`, but it is correctly guarded with user warnings
  (`correlate.c:233,242,251`). No action. (R2 raw-`st_value`-offset is likewise already
  fixed — see Resolved.)

---

## Resolved / Done

Reverse-chronological. Identifiers preserved for traceability; full technical detail
is in DOCUMENTATION.md and the referenced specs.

### 2026-06-26 (session 4)

- **GA1 — `jbuf` OOM path is a heap overflow (fixed).** Added `int err` field to
  `struct jbuf` (`emit.h`); `jb_need` sets it on failed `realloc`; every `jb_*` writer
  bails early when set (no write past `cap`); `ares_sink_emit` drops and resets a
  poisoned record. Regression test in `tests/test_emit.c` (3 new checks, 21 total).
- **GA2 — Engine lifecycle symmetry + `lib`→`trace` wiring.** `dump.c` and `correlate.c`
  each split into `<engine>_setup` / `_run` / `_teardown` + thin `cmd_*` wrapper, fully
  symmetric with `syscalls`/`funcs`/`lib`. Both engines switched to the shared 2-stage
  stop handler (`ares_install_stop_handler`) — closes GA5 for dump and correlate. `lib`
  wired into `trace`: new `--lib` section in `trace_args` + coordinator (`trace.c`),
  section-boundary scan fixed for 3 delimiters (was 2), `test_trace_args` extended with
  3-section and reorder cases. Makefile: `CORR_PART`/`DUMP_PART` keep-global updated for
  6 new driver symbols. Deferred: wiring correlate/dump into `trace` (see GA2 in Major).

### 2026-06-26 (session 3)

- **funcs JSON backtrace — close syscalls/funcs `-o` asymmetry.** `funcs` CALL records now
  carry a `"backtrace":[{"frame":N,"addr":"0x.."},…]` array in their structured `-o` JSON,
  built from the always-on `bpf_get_stack` capture (independent of `--snapshot`). Mirrors
  the `"backtrace"` array in `syscalls`' JSON emitter (`syscalls.c:654`). Addr-only (no
  inline `sym_resolve`) to keep `funcs_emit.c` pure and host-testable. Change: `funcs_emit.c`
  (+backtrace loop), `test_funcs_emit` extended (20 checks). Docs updated.

### 2026-06-26 (session 2)

- **W2+W3 — Shared snapshot extraction + funcs stack snapshot (closes W2, W3).** Moved
  the register-file + stack snapshot into a shared core: `src/common/stack_snapshot.{h,bpf.h,c}`
  (`struct ares_stack_snapshot`, `ARES_SNAP_MAX/SMALL/NREG`, `ares_hash_stack`,
  `ares_emit_stack_snapshot`, `ares_stack_snapshot_emit_json`, `ares_unwind_regs` +
  `unwind_regs_from_snapshot`). Both the `syscalls` (kprobe) and `funcs` (uprobe) engines
  `#include` the shared BPF helpers via the `ARES_SNAPSHOT_RB` macro idiom (mirrors the
  existing `uid_filter.bpf.h` / `lib_trace.bpf.h` pattern). W3 closed: `unwind_regs.h`
  deleted from `src/syscalls/`; adapter now lives in `common/stack_snapshot.h`, engine-neutral.
  `funcs` gains `--snapshot` (requires `-o`): deduped by FNV-1a stack hash, sidecar file
  `<output>.stacks` (JSONL, identical schema to syscalls sidecar), `"stack_id"` field on
  CALL records for join. `ARES_EVENT_STACK=12` added to `enum event_type`. New host tests:
  `test_stack_snapshot` (JSON emitter round-trip); `test_unwind_regs` migrated to
  `common/stack_snapshot.h`; `test_funcs_emit` extended (17 checks). W1 (runtime unwind
  driver) remains open.

### 2026-06-26 (session 1)

- **Merge `origin/main`: DWARF CFI unwinder + syscalls register-file snapshot.**
  `src/common/dwarf.{c,h}`: bounded byte cursor (ULEB128/SLEB128/fixed-width reads).
  `src/common/cfi_unwind.{c,h}`: `.debug_frame` CIE/FDE parser (O(log n) PC binary
  search), CFI rule interpreter (`cfi_run_program`), and single-frame stepper
  (`cfi_step`). `syscalls_stack_snapshot` extended: adds `regs[31]` (x0..x30 full
  GP file, CFI initial state) and `truncated` flag (1 = snapshot smaller than stack
  used); JSON output gains `"regs":["0x...",…]` (31 elements) and `"truncated":0/1`.
  `src/syscalls/unwind_regs.h`: `struct ares_unwind_regs` + `unwind_regs_from_snapshot()`
  adapter. `scripts/device-test.sh` syscalls-regs/-family arms corrected (`-P`, `-l`,
  `--snapshot` flags). Four new host tests (`test_dwarf`, `test_cfi_parse`,
  `test_cfi_step`, `test_unwind_regs`) wired into `make test`. CFI wiring to runtime
  and generalization to other engines deferred → W1–W3 in Major above.

### 2026-06-25 (session 3)

- **Thin presets keystone — `lib` phase split (coordinator-ready).** `cmd_lib`
  refactored into `lib_setup(argc, argv, rc)` / `lib_run(stop)` / `lib_teardown()` +
  thin `cmd_lib` wrapper, fully symmetric with `syscalls` and `funcs`. `struct
  ares_run_ctx` accepted so a future coordinator can pre-resolve the UID and drive
  `lib` alongside other engines without a second launch. `on_sigint` retired in
  favour of the shared `ares_install_stop_handler`. Makefile `LIB_PART` updated to
  export all four entry points (`cmd_lib` + three phases). No behaviour change.

### 2026-06-25 (session 2)

- **Y1 — funcs cap-overflow warnings.** Six silent truncation caps in `parse_opts`
  (`-p/-I/-i/-e/-F/-r`) now emit `"funcs: warning — … cap (N) reached; '…' ignored"`
  to stderr, matching correlate's wording.
- **Y2 — `rctx` use-after-return fixed.** Promoted `struct probe_resolve_ctx rctx`
  from stack-local in `funcs_setup` to file-static `g_rctx`; all five setup-time
  `&rctx` references repointed. `handle_event` dereferences safely after setup returns.
- **Y3 — live drop ticker for funcs.** `funcs_drops_tick` mirrors `syscalls_drops_tick`
  (BPF ring drops + worker queue drops, ~1 s cadence); wired into `funcs_run` via
  `ares_rb_poll_until_cb`.
- **Y4 (map/unmap) — funcs structured lib/unlib records.** funcs now emits
  `{"type":"lib",...}` / `{"type":"unlib",...}` on every library load/unload via the
  shared `ares_libtrace_emit_lib`/`emit_unlib` (`src/common/lib_trace.c`). Threading:
  Option A — new `g_sink_lock` serializes drain-thread lib/unlib writes against
  worker-thread call/return writes; `ares_sink_flush` stays unlocked (fflush is
  thread-safe). Console `[lib]`/`[unlib]` lines gated on `-v` (funcs already prints
  attach lines). Module events (spawn/proc_exit/execve/prop) deferred → see Major above.

### 2026-06-25 (session 1)

- **C3 Phase 2 — shared `/proc/<pid>/maps` line parser + symbolizer cache bounds.**
  `src/common/maps.{c,h}` adds `ares_parse_maps_line` (the one canonical `sscanf`),
  `ares_module_base_idx` (load-base walk-back), and `ares_map_files_path` (deleted-file
  fallback path). All six consumers migrated off hand-rolled `sscanf` copies; `struct
  mapping` (symbolize) and `struct dmap` (rebuild) collapsed into `struct ares_map_line`.
  Correctness fix: paths with embedded spaces no longer truncate (old copies used `%255s`,
  new parser uses `%255[^\n]`). Short-lived-pid visibility: `gone` flag on ENOENT
  → `[pid N gone]` in symbolizer + stderr log in rebuild. Symbolizer cache bounded:
  LRU eviction at `PM_MAX_PIDS=128` pids, `SC_MAX_CAP=256k` symbol hash ceiling;
  `sym_flush_pid` wired to `ARES_EVENT_PROC_EXIT`. 25 host-unit checks in
  `tests/test_maps.c`.

### 2026-06-24

- **`correlate` hardening — R3 + R4 + X2 (correlate half).** R3: uprobe `bpf_link`s
  tracked (`g_uprobe_links`) and `bpf_link__destroy`'d on teardown + ring-buffer-fail
  path (no longer leaked to process exit). R4: the `-p` (64 PIDs), `-e`/`-F` (64
  specs), and per-pid dedup (256) caps warn when hit instead of silently truncating.
  X2: output migrated from raw `FILE*` + per-event `fflush` to the shared `ares_sink`
  (8 MB buffer, periodic flush, JSONL framing, `wrote N event(s)` report). **R5
  closed as stale** — the `jstr_args` `snprintf` underflow path no longer exists
  (correlate builds JSON through the bounds-safe `jbuf`/`corr_emit.c` serializer).
- **X2 (lib half) — `lib` migrated to `ares_sink`.** `lib.c` output moved from
  raw `FILE*` to the shared sink; `ares_libtrace_emit_lib/unlib` signatures changed
  from `FILE *jsonl` to `struct ares_sink *sink`; `json_write_str` removed.
  New host test: `tests/test_lib_trace_emit.c` (11 checks).
- **F1 — FD & string resolution in `ares funcs`.** `funcs_emit_call` /
  `funcs_emit_return` accept a `probe_target_t *target` and emit `string_args`
  (BPF-captured strings), `fd_args` (FD→path via `render_fd`), `retval_str`, and
  `out_args` into the JSONL record. `test_funcs_emit` extended to 15 checks covering
  string, FD, and retval_str resolution.
- **CLI consistency / argp (A.0, A5, R6, F3, F4, U3).** All six engines on GNU argp (auto
  `--help`/`--usage`/`--version`); `lib`/`dump`/`correlate` migrated off hand-rolled
  loops; `lib`/`dump` gained `-P`/`-A` (positionals kept as aliases) and route launch
  through `ares_launch_app()`; `correlate -q` documented (R6); `funcs --help`
  documents dual console+file output (U3). `-o` implies `-q` unified across all engines
  (F4). `--version` handled centrally in `src/main.c` (F3). Won't-do: `dump -v`,
  `lib`/`dump`/`correlate` `-b`/`-Q` (no behavior to attach — would recreate the A1
  dead-flag bug).
- **BPF de-dup + arg-parse normalization (C4, C8).** `src/common/uid_filter.bpf.h`
  (`target_uids` HASH-set map + `uid_matches()`); `src/common/bpf_drop.bpf.h`
  (shared `dropped` map + atomic `bump_dropped()`); `struct trace_event_header`
  replaces the `syscalls_hdr` alias; `ARES_FLUSH_MASK`; `src/common/engine_args.h`
  (`common_args` + `COMMON_ARGP_OPTIONS`); `syscalls`/`funcs`/`trace` normalized;
  `inject_pkg` removed from `trace_build_argv()`. `ares_libbpf_quiet` replaces three
  local `libbpf_print_fn` copies.
- **Managed-frame symbolization Phase 2a + 2b** (DEX core + on-device spike) — see
  Major above for the parked outcome.

### 2026-06-23

- **Engine unification round 2.** Phase A: `src/common/runtime.{c,h}` (shared
  stop-handler / drops-report / pow2 helpers). Phase B: `funcs -b/--bufsize`
  configurable ring. Phase C1: `src/common/evqueue.{c,h}` SPSC byte-queue (`syscalls`
  migrated). Phase C2: `funcs` decoupled drain on a worker thread. `ares_rb_poll_until`
  / `ares_rb_poll_until_cb` added; all five engines on the shared poll helper (C2 done).
- **Shared `ares_sink` + funcs output unification (C1).** `emit.h` exports
  `struct ares_sink`; `syscalls` and `funcs` migrated; legacy `{ts,stream,tag,message}`
  wrapper and CSV removed; `jb_esc` dedup. 6 sink host tests.
- **R2** — `vaddr_to_file_off()` in `probe_resolve.c` (vaddr→file-offset via PT_LOAD
  table). **R7** — `FUNC_CFLAGS` aligned to `-Wall -Wextra`.

### 2026-06-22

- **`ares trace` runner — Phases 1–4.** Phase 1: shared `ares_launch_app()`. Phase 2:
  engine setup/run/teardown split + `struct ares_run_ctx`. Phase 3: `src/trace/trace.c`
  coordinator (one launch, two drain threads, per-engine `-o` files). Phase 4:
  `trace_args.c` argv-section split (host-tested). Inherently LOUD. Remaining: on-device
  verification (→ Minor).
- **`trace` audit fixes** — second Ctrl-C force-quit; warn on missing `-o`; ring drain
  bails on stop flag; warn on arg-section overflow.

### 2026-06-21

- **Structured JSONL for `funcs` CALL/RETURN (Task 4)** — `-J`/`--structured`;
  `funcs_emit.c` (pure, host-tested).
- **C5.1 — firewall-aware capability registry** (`capabilities.{c,h}`). Advisory by
  design: each subcommand loads one object of known/documented loudness; enforcement
  is only meaningful under an intent-based preset/composition layer (not built).

### 2026-06-20

- **Testing tiers (R8)** — host unit tests (`make test`), CI cross-build
  (`ci.yml`), device acceptance (`device-test.sh`).

### 2026-06-18

- **Launch/UID helper de-dup (R1 / C5)** — `sh_exec`/`resolve_uid`/`resolve_component`
  unified into `src/common/launch.{c,h}` (~150 dup lines removed).

### 2026-06-17

- **Fused-core + `correlate` shipped.** `span_stack.bpf.h` (per-tid stack, fixes the
  single-slot `entry_map` clobber bug); shared-core extractions (`launch`,
  `probe_resolve`); the `correlate` engine (entry uprobes + span-gated `do_el0_svc`
  kprobe, flat `func`/`syscall` JSONL joined on `span`). Detectability firewall
  **reframed**: the one invariant is "a stealthy run attaches zero uprobes"; the
  per-engine BPF object + partial-link localization are merge scaffolding, not sacred.
- **Unified `ares-mcp` ingest (Task 3)** — `load_structured` + `correlate_spans`
  (join syscalls by `span`); host-tested. Richness follow-on → Minor.

### 2026-06-16

- **`ares dump` engine (C6)** — replaced the syscalls/funcs dumpers; ELF rebuild in
  `src/dump/rebuild.c`; `/proc/<pid>/mem` reader lifted to `src/common/proc_mem`.
