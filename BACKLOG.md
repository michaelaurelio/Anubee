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

- **`rctx` use-after-return in `funcs_setup` (latent bug).** `struct
  probe_resolve_ctx rctx` is a stack local in `funcs_setup` (ares-tracer.c:~1172)
  passed to `ring_buffer__new`; the MAP handler dereferences it *after*
  `funcs_setup` returns. Pre-existing, unrelated to the C2 worker split (the worker
  never touches `rctx`). **Fix:** promote `rctx` to file-static.
- **Thin presets over the formal core (architectural keystone).** PARTIAL —
  `syscalls` and `funcs` are split into setup/run/teardown phases (the first step).
  Remaining: split `lib` the same way and retire the partial-link symbol-localization
  scaffolding where it's no longer needed. This is the migration the consolidation
  roadmap (C2/C3/C4/C7 below) folds into; the immediate consumer was the `trace`
  runner.
- **Firewall quiet-mode enforcement.** The C5.1 capability registry
  (`src/common/capabilities.{c,h}`) records which BPF objects write target memory,
  but it is **advisory only** — nothing calls `ares_quiet_config_ok` to *refuse*
  loading a loud object in a quiet preset. The one real invariant ("a stealthy run
  attaches zero uprobes") is currently held only by convention. Wire the gate when
  the thin-presets work lands so a quiet preset cannot silently load a uprobe object.

---

## Major — features / substantial work

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

- **C2 — ring-buffer setup + poll loop.** `ring_buffer__new`/`__poll` duplicated
  across engines → one shared drain helper.
- **C3 — symbolizer maps parsing.** `/proc/<pid>/maps` parsing is consolidated in
  `src/common/lib_trace.c` (`ares_libtrace_resolve_path`) for lib-load tracing, but
  `symbolize.c` still has its own maps parser for stack symbolization → fold into one
  maps/symbol module.
- **C4 — kernel-side UID filter.** `uid_matches()` + the target-uid BPF map
  (`target_uid` vs `target_uids`) → shared BPF header.
- **C7 — symbol/caller resolution.** addr→module+offset via maps + dynsym,
  duplicated across engines.

### `funcs` structured records

- MAP/UNMAP/SPAWN/PROC_EXIT/EXECVE/PROP structured JSONL records (extend
  `funcs_emit.c`, same one-builder-per-type pattern, each pinned by a host test). The
  `handle_event()` SEAM already routes every event type; hook each case. (CALL/RETURN
  already done.)

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

- **R9 — `syscall_name()` linear scan per syscall event** (`correlate` + the
  equivalent in `syscalls`). Fine at current volume; if rates climb, sort the
  generated table once and `bsearch`, or index by `nr`.
- **X2 (remaining) — migrate `lib` onto `ares_sink`.** `syscalls`/`funcs`/`correlate`
  use the shared sink; `lib` still writes a raw `FILE*` (line-framed, no `-J`, no
  "wrote N records" report). `dump` writes binary ELF (out of scope).
- **C8 (remaining) — `libbpf_print_fn` + duplicate `vmlinux.h`.** Signal handlers,
  the `dropped` map/`bump_dropped()`, and the `syscalls_hdr` alias are already unified.
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

---

## Resolved / Done

Reverse-chronological. Identifiers preserved for traceability; full technical detail
is in DOCUMENTATION.md and the referenced specs.

### 2026-06-24

- **`correlate` hardening — R3 + R4 + X2 (correlate half).** R3: uprobe `bpf_link`s
  tracked (`g_uprobe_links`) and `bpf_link__destroy`'d on teardown + ring-buffer-fail
  path (no longer leaked to process exit). R4: the `-p` (64 PIDs), `-e`/`-F` (64
  specs), and per-pid dedup (256) caps warn when hit instead of silently truncating.
  X2: output migrated from raw `FILE*` + per-event `fflush` to the shared `ares_sink`
  (8 MB buffer, periodic flush, JSONL framing, `wrote N event(s)` report). **R5
  closed as stale** — the `jstr_args` `snprintf` underflow path no longer exists
  (correlate builds JSON through the bounds-safe `jbuf`/`corr_emit.c` serializer).
- **CLI consistency / argp (A.0, A5, R6, U3).** All six engines on GNU argp (auto
  `--help`/`--usage`/`--version`); `lib`/`dump`/`correlate` migrated off hand-rolled
  loops; `lib`/`dump` gained `-P`/`-A` (positionals kept as aliases) and route launch
  through `ares_launch_app()`; `correlate -q` documented (R6); `funcs --help`
  documents dual console+file output (U3). Won't-do: `dump -v`,
  `lib`/`dump`/`correlate` `-b`/`-Q` (no behavior to attach — would recreate the A1
  dead-flag bug).
- **BPF de-dup + arg-parse normalization.** `src/common/bpf_drop.bpf.h` (shared
  `dropped` map + atomic `bump_dropped()`); `struct trace_event_header` replaces the
  `syscalls_hdr` alias; `ARES_FLUSH_MASK`; `src/common/engine_args.h`
  (`common_args` + `COMMON_ARGP_OPTIONS`); `syscalls`/`funcs`/`trace` normalized;
  `inject_pkg` removed from `trace_build_argv()`.
- **Managed-frame symbolization Phase 2a + 2b** (DEX core + on-device spike) — see
  Major above for the parked outcome.

### 2026-06-23

- **Engine unification round 2.** Phase A: `src/common/runtime.{c,h}` (shared
  stop-handler / drops-report / pow2 helpers). Phase B: `funcs -b/--bufsize`
  configurable ring. Phase C1: `src/common/evqueue.{c,h}` SPSC byte-queue (`syscalls`
  migrated). Phase C2: `funcs` decoupled drain on a worker thread.
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
- **C5.1 — firewall-aware capability registry** (`capabilities.{c,h}`, advisory;
  enforcement still open — see Urgent).

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
