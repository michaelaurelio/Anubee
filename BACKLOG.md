# ARES backlog

Deferred architecture work and known tech debt. The **current** state of each
engine is in [DOCUMENTATION.md](DOCUMENTATION.md); this file holds the
forward-looking items only.

**Contents**

- [Shipped](#shipped)
- [Open issues — review 2026-06-17 (R3, R4, R5, R9)](#open-issues--review-2026-06-17)
- [Consolidation roadmap — shared-code de-dup (C1–C9)](#consolidation-roadmap--shared-code-de-dup)
- [`correlate` — remaining work](#correlate--remaining-work)
- [Planned — structured emitter + unified MCP](#planned--structured-emitter--unified-mcp)
- [Deferred tech debt](#deferred-tech-debt)

---

## Shipped

### CLI consistency / asymmetry — 2026-06-24

All six engines now use GNU argp (auto `--help`/`--usage`/`--version`). `lib`, `dump`,
and `correlate` migrated from hand-rolled `argv` loops to argp (A.0). During the
migration: `lib`/`dump` gained `-P`/`-A` flags with positional aliases kept for
back-compat (A5); `lib`/`dump` launch now routes through `ares_launch_app()` deleting
the inline force-stop/resolve/start sequences and gaining the death-wait loop and
`am start -S`; `correlate` -q is now documented in `--help` (R6 closed). All six
engines report identity via `--version` (syscalls: `ares syscalls`; others likewise).
`funcs --help` documents the dual console+file output mode (U3). The `argp_program_bug_address`
fields reflect the two-author split: `funcs` → `vincent.kwee@binus.ac.id`; all others
→ `michael.windarta@binus.ac.id`. Won't-do items noted (dump -v, lib/dump/correlate
`-b`/`-Q` — no behavior to attach; would recreate the A1 dead-flag bug).

### BPF de-dup + argument-parsing normalization — 2026-06-24

**BPF infrastructure de-dup:**

- `src/common/bpf_drop.bpf.h` — consolidated the identical `dropped`
  PERCPU_ARRAY map and `bump_dropped()` helper that `syscalls.bpf.c` and
  `ares-tracer.bpf.c` each defined locally. syscalls had a non-atomic
  `(*c)++`; both now use `__sync_fetch_and_add` uniformly.
- `struct syscalls_hdr` in `src/syscalls/syscalls.h` replaced with
  `struct trace_event_header` (identical layout, removes the local alias).
- `#define ARES_FLUSH_MASK 0x3fff` added to `src/common/emit.h`; both
  worker threads' flush intervals now reference the named constant.

**Argument parsing normalization (syscalls + funcs + trace coordinator):**

- `src/common/engine_args.h` (new) — `struct common_args` (six shared
  flags), `COMMON_ARGS_INIT`, `COMMON_ARGP_OPTIONS` macro, and
  `parse_common_arg()` inline delegate. Single source of truth for
  `-o`/`-v`/`-q`/`-J`/`-b`/`-Q`.
- `syscalls.c` — replaced hand-rolled strcmp loop + positional parsing
  with GNU argp (`struct sysc_args`, `sysc_options[]`, `parse_sysc_opts()`).
  Option ordering no longer matters; `--help` is auto-generated. Positional
  `<lib>` replaced with `-l <selector>`. `COMMON_ARGP_OPTIONS` embedded.
- `ares-tracer.c` — `struct args` embeds `struct common_args c`; `options[]`
  uses `COMMON_ARGP_OPTIONS`; `parse_opts` delegates common keys via
  `parse_common_arg()`. Added `-q` (quiet: gates all console prints via
  `g_quiet` global). Added `-Q <MB>` (configurable worker queue size,
  replaces hardcoded 16 MiB; default 256 MiB). Package pre-filled from
  `rc->pkg` before `argp_parse`.
- `inject_pkg` removed from `trace_build_argv()` (`trace_args.h`,
  `trace_args.c`, both call sites in `trace.c`, assertions in
  `tests/test_trace_args.c`). Both engines pre-fill the package from
  `rc->pkg`; the coordinator no longer injects `-P` into either section.

### Engine unification round 2 — 2026-06-23

**Phases A, B, C1, C2 shipped.**

- **Phase A — shared runtime plumbing.** `src/common/runtime.{c,h}` — shared
  `ares_install_stop_handler`, `ares_drops_report`, `ares_round_pow2`, and the
  inline BPF helpers `ares_libbpf_quiet`/`ares_drops_read` (gated on
  `__LIBBPF_LIBBPF_H`). Both `syscalls` and `funcs` private copies deleted;
  `tests/test_runtime.c` (12 checks).
- **Phase B — configurable ring size for `funcs`.** `-b/--bufsize MB` flag; ring
  rounded to next power of two via `ares_round_pow2`; `bpf_map__set_max_entries`
  called before BPF load. Default unchanged (4 MiB).
- **Phase C1 — shared byte-queue.** `src/common/evqueue.{c,h}` — `struct ares_evq`
  SPSC ring with `[4-byte len][payload]` framing, cond-var handoff, and `dropped`
  counter. `syscalls` migrated; private `struct queue` deleted.
  `tests/test_evqueue.c` (19 checks).
- **Phase C2 — decoupled drain for `funcs`.** CALL/RETURN events pushed into
  `struct ares_evq g_q` (16 MiB) from `handle_event` and processed on a dedicated
  `funcs_worker_main` thread. MAP/UNMAP/module events stay inline (race the
  mmap). `g_targets_lock` guards `probe_targets[]` between the MAP attach path
  and the worker's `find_target_by_entry_addr`; `g_out_lock` serializes
  stdout/stderr lines between threads. `g_sink` is worker-only during run; the
  poll-thread flush removed. Drop report now includes queue drops.

### Shared output sink + funcs output unification — 2026-06-23

**C1 (JSON escaping dup) + funcs mixed-schema resolved.**

`src/common/emit.h` now exports `struct ares_sink` and `ares_sink_{open,emit,
flush,close,report}`. The sink owns: the output `FILE*`, an 8 MB `_IOFBF` write
buffer, a reused `jbuf`, the record count, JSONL/array framing, periodic flush,
and the "wrote N records to PATH" report. Single-writer, no lock.

- **`syscalls`** migrated: `g_json`/`g_json_count`/`g_json_path`/`g_jb` replaced
  by `static struct ares_sink g_sink`. Output format byte-identical to before;
  "wrote N" now goes to stderr (was stdout). Framing (comma sep / array brackets)
  moved from `json_emit` into the sink.
- **`funcs`** fully unified: `g_csv`, `g_jsonl`, `csv_write/open/close`,
  `json_fwrite_str`, `jsonl_write/open/close`, and the legacy
  `{ts,stream,tag,message}` wrapper deleted. `-o FILE` now opens a structured
  JSONL sink; CALL/RETURN records built into `g_sink.jb` via `funcs_emit_call`/
  `funcs_emit_return` and emitted via `ares_sink_emit`. `-J`/`--structured`
  accepted as a no-op (structured is the default). "wrote N event(s)" report
  added (was absent). Per-write CSV `fflush` removed; uses the sink's periodic
  8192-emit flush instead.
- CSV export removed (no known consumer).
- Host tests: 6 new sink cases in `tests/test_emit.c` (JSONL + array framing,
  record count, exact byte content).

### `ares trace` audit fixes — 2026-06-22

Post-Phase-4 audit (coordinator logic, engine integration, build wiring). Build
wiring, symbol exports, capabilities, UID-arming order, and the arg parser verified
sound; "setup-failure leak" reports were false (both setups self-clean). Applied
four low-risk fixes: (1) second Ctrl-C force-quits the coordinator (`on_sigint` →
`_exit(130)`); (2) warn when `-o` is absent (two engines' console output
interleaves); (3) `syscalls` ring drain (`enqueue_event`) now bails on the
coordinator's stop flag via a file-static `g_stopp` set in `syscalls_run` (no-op
standalone); (4) warn on `--syscalls`/`--funcs` section arg-overflow instead of
silent truncation. Skipped as cosmetic/YAGNI: `libbpf_set_print` last-wins, the
`(char *)pkg` cast, `verbose` naming, output-mutex/dispatcher abstractions. Files:
`src/trace/trace.c`, `src/syscalls/syscalls.c`. On-device verification of a combined
run still pending.

### `ares trace` Phase 3 — combined kprobe+uprobe coordinator — 2026-06-22

`ares trace` runs the `syscalls` and `funcs` engines together from one app launch.
New `src/trace/trace.c` (`cmd_trace`): parses `-P <pkg>` / `-o <prefix>` and the
`--syscalls` / `--funcs` arg sections, resolves the UID once, calls
`syscalls_setup` + `funcs_setup` (both arm probes + UID via `struct ares_run_ctx`,
no launch), launches once with `ares_launch_app`, then drains both ring buffers on
two pthreads sharing a `volatile sig_atomic_t` stop flag, and tears both down.
Output: `<prefix>.syscalls.jsonl` + `<prefix>.funcs.jsonl` (no shared `FILE*`;
both MCP-ingestable). Small additive change: `syscalls_setup`/`funcs_setup` take
the package from `rc->pkg` (NULL `rc` = unchanged standalone). Wiring: `main.c`
dispatch + usage, `capabilities.c` `{ "trace", true }` (loud) + test, and the
Makefile keeps `syscalls_setup/_run/_teardown` + `funcs_*` global through the
partial-link so `trace.part.o` links them. `trace` owns no BPF object. Inherently
LOUD — never stealthy. Remaining: pure host test for the argv split + on-device
verification.

### `ares trace` Phase 2 — engine setup/run/teardown split — 2026-06-22

Groundwork for the combined `trace` runner (see "Planned" below). `cmd_syscalls`
(`src/syscalls/syscalls.c`) and `cmd_funcs` (`src/funcs/ares-tracer.c`) are each
split into `<engine>_setup(argc, argv, rc)` / `<engine>_run(volatile sig_atomic_t
*stop)` / `<engine>_teardown()`, with `cmd_<engine>` reduced to a thin wrapper that
preserves standalone behavior exactly. Cross-phase locals (`skel`, ring buffer,
worker thread, dropfd) were promoted to file-static globals; the app launch was
lifted out of `setup` into the caller; funcs' `exiting` flag changed
`bool`→`sig_atomic_t` so both engines' run-loops share one stop-flag type. New
`struct ares_run_ctx` (`src/common/launch.h`) carries a pre-resolved UID +
`external_launch`. Driver prototypes live in `syscalls.h` (guarded
`#ifndef __VMLINUX_H__`) and `ares-tracer-priv.h`. This is the partial landing of
"thin presets over the formal core" for these two engines.

### `ares trace` Phase 1 — shared app-launch helper — 2026-06-22

`ares_launch_app(pkg, activity)` added to `src/common/launch.{c,h}` (exported via
`COMMON_API`): the canonical clean relaunch — force-stop → wait-for-stop → resolve
component (or use explicit activity) → `am start -S -n <component>`. The `syscalls`
and `funcs` engines now call it instead of inlining their own divergent sequences.
Benign harmonization: `syscalls` gained the wait-for-stop + `-S` flag (more
reliable relaunch); `funcs` behavior unchanged. Device-verified on both paths.

### Structured JSONL mode for `ares funcs` CALL/RETURN (Task 4) — 2026-06-21

`-J`/`--structured` flag added to `ares funcs`. When a JSONL sink is open (`-o`),
each CALL and RETURN event also emits a structured record via `src/funcs/funcs_emit.c`
(pure, no libbpf deps, host-testable). Records use the shared `emit.h` serializer and
`trace_schema.h` discriminator (`"type":"call"` / `"type":"return"`), compatible with
the ares-mcp unified schema. Host test: `tests/test_funcs_emit.c` (9 checks). Additive
— existing text output and legacy `{ts,stream,tag,message}` wrapper are unchanged.
MAP/UNMAP/SPAWN/PROC_EXIT/EXECVE/PROP records and unified MCP ingest remain planned.

### Testing flow — host unit tests + CI + device smoke (R8) — 2026-06-20

R8 closed. Three tiers now exist, each runnable on its own:

- **Host unit tests** (`tests/test_probe_spec.c`, `make test`) — pure-logic checks
  of the `parse_custom_probe_spec` grammar (`MOD!FUNC(S,V,F)>V`, `@offset`, malformed
  inputs); 34 checks, no device and no cross-toolchain (host `cc` + `-lelf`).
- **CI** (`.github/workflows/ci.yml`) — runs `make test` and the containerized
  `scripts/build.sh` cross-build on every PR/push so the binary can't silently stop
  compiling. The device tier is intentionally excluded (needs a physical device).
- **Device acceptance** (`scripts/device-test.sh`, `make device-test`) — pushes the
  fresh binary (md5-skip when unchanged) and asserts each capability attaches and
  emits real output (`lib` → `[lib]` + bionic `libc.so`; `syscalls` → attach banner
  or live events). Run-judgment (own `su -c`, `timeout -s INT`, reading failures) is
  captured in the `testing-ares-on-device` skill.

### `ares dump` engine — 2026-06-16

Replaced the syscalls & funcs dumpers, dropped the `-l` libs-only mode from
`ares syscalls`, and lifted the `/proc/<pid>/mem` reader into
`src/common/proc_mem`.

### `correlate` (function→syscall) — 2026-06-17

The fused-core + `correlate` work shipped (Phase 1 + 2a–2c). The detectability
firewall is **reframed**: the one real invariant is "a stealthy run attaches zero
uprobes"; "each engine owns its BPF object" and the partial-link symbol-localization
are merge scaffolding, not sacred.

Done & device-verified:

- **Span stack** (`src/common/span_stack.bpf.h`) — per-tid stack replacing funcs'
  single-slot `entry_map` (fixed a latent nested/recursive clobber bug → missing
  RETURN events / wrong `elapsed_ns`); SP-based reconcile; `span_id`/`parent_span`
  + atomic id allocator.
- **Shared core extractions** — `src/common/launch` (UID/spawn helpers) and
  `src/common/probe_resolve` (spec→target resolver, de-globalized onto a
  `probe_resolve_ctx`), exported via `COMMON_API`; funcs drives them.
- **`correlate` engine** (`src/correlate/`) — entry uprobes + span-gated
  `do_el0_svc` kprobe sharing the span stack; flat `func`/`syscall` JSONL joined on
  `span`. Verified on-device (`libc.so!open` → its `openat`/`fstat`/`read`/`close`).

### Launch/UID helper de-dup (R1 / C5) — 2026-06-18

`sh_exec` / `resolve_uid` / `resolve_component` were triplicated in the `syscalls`,
`dump`, and `lib` engines. All three now `#include "common/launch.h"` and call the
shared `ares_*` implementations (already used by `funcs`/`correlate`), removing
~150 duplicated lines with no behavior change. Cross-build verified.

---

## Device-test findings — 2026-06-24

From testing against `com.bmri.kopramobile` / `libpb88.so`. F1/F3/F4 are root-caused;
F2 is open pending repro details.

- **F1 — FD & string resolution not written to output file. DONE 2026-06-24.**
  `funcs_emit_call` / `funcs_emit_return` (`src/funcs/funcs_emit.c`) now accept a
  `probe_target_t *target` and emit `string_args` (BPF-captured strings), `fd_args`
  (FD→path via `render_fd`), `retval_str`, and `out_args` into the JSONL record.
  `syscalls` was already correct (not affected). `test_funcs_emit` extended to 15 checks
  covering string, FD, and retval_str resolution. `make test` green (10/10).

- **F2 — PID attach mode error in `ares funcs` (and others). P1 bug. NEEDS REPRO.**
  The `-p` parse (`src/funcs/ares-tracer.c:105`) and uprobe attach loop (`:1206-1280`)
  are structurally sound; the failure is likely runtime (attach perms / per-PID `/proc`
  symbol resolution). *Action required:* share the exact `stderr` output + invocation
  before assigning a root cause. Also check `correlate -p` (`src/correlate/correlate.c`).

- **F3 — `--version` not recognized (all engines). DONE 2026-06-24.**
  Handled centrally in `src/main.c`: before dispatch, intercept `--version`/`-V` for any
  known subcommand and print `ares <cmd>`. Deleted five dead `argp_program_version`
  globals (funcs, syscalls, lib, dump, correlate). `make test` 10/10.

- **F4 — `-o` ⇒ quiet inconsistent across engines. DONE 2026-06-24.**
  Added `|| (output_file != NULL)` to the quiet assignment in funcs, lib, and correlate
  (syscalls already had it). Updated `-o` help text (`(implies -q)`) in all four engines
  via `COMMON_ARGP_OPTIONS` + lib/correlate option tables. Updated funcs `doc[]` to drop
  the "dual output intentional" note. `make test` 10/10.

---

## Open issues — review 2026-06-17

Repo-wide review pass. Ordered by severity; most are small and self-contained.
R2, R6, R7 closed — see Shipped above.

### Correctness / robustness

- **R2 — DONE (2026-06-23).** `vaddr_to_file_off()` added to `src/common/probe_resolve.c`:
  builds a `PT_LOAD` table from the open ELF handle and converts `sym.st_value` (virtual
  address) to a file offset via `file_off = vaddr - (seg.p_vaddr - seg.p_offset)` for the
  containing segment. All three resolution paths in `probe_resolve.c` now call it (lines
  ~184, ~273, ~436). Verified device-side on a `.so` with non-zero `p_vaddr − p_offset`.
- **R3 — `correlate` leaks its uprobe `bpf_link`s.** `attach_uprobes_for_pid` stores
  each `bpf_program__attach_uprobe` result in a local `link` that is never tracked or
  `bpf_link__destroy`'d (only the syscall kprobe `kp` is). Cleanup relies on process
  exit. Track them in an array and destroy on teardown (mirrors how `funcs` keeps
  `probe_links[]`).
- **R4 — Silent truncation at fixed caps in `correlate`.** `pids[64]`, `specs[64]`,
  and the `done[256]` attach-dedup buffer all stop filling with no warning when
  exceeded (`pid_count < 64`, `nspec < 64`, `ndone < 256`). Emit a warning when a cap
  is hit so a large `-F` spec file or wide package isn't quietly under-instrumented.
- **R5 — `jstr_args` size_t underflow (latent).** In `src/correlate/correlate.c`,
  `snprintf(buf + off, bufsz - off, ...)` with `off` a `size_t`: if `off` ever
  reaches/exceeds `bufsz`, `bufsz - off` wraps to a huge value. Bounded today by the
  512-byte buffer vs. small arg counts, but it breaks the moment arg widths grow.
  Guard with an explicit `off < bufsz` check feeding a clamped remaining length.

### Consistency / docs

- **R6 — DONE (2026-06-24).** `correlate` migrated to argp; `-q` is now in
  `corr_options[]` and appears in `--help` automatically. No separate `usage()` remains.
- **R7 — DONE (2026-06-23).** `FUNC_CFLAGS` aligned to `-Wall -Wextra` in the Makefile.

### Perf (minor)

- **R9 — `syscall_name()` is a linear scan per syscall event** (`correlate`, and the
  equivalent in `syscalls`). Fine at current volume; if event rates climb, sort the
  generated table once and `bsearch`, or index by `nr`.

---

## Consolidation roadmap — shared-code de-dup

The two engines were merged with **minimal edits** (surgical), so they still carry
duplicated logic. The library-load tracing slice is consolidated into
`src/common/lib_trace.*` (mmap/munmap capture, `/proc` resolution, `[lib]` emitter,
unified `lib_map_event`/`lib_unmap_event`). Remaining items, rough priority:

- **C1 — JSON/JSONL string escaping** — **DONE (2026-06-23).** `funcs`'
  `json_fwrite_str` deleted; both engines use `jb_esc` from `src/common/emit.c`
  through the shared `ares_sink`.
- **C2 — Ring-buffer setup + poll loop** — `ring_buffer__new`/`__poll` in both →
  shared drain helper.
- **C3 — `/proc/<pid>/maps` parsing + basename→fullpath cache** — now in
  `src/common/lib_trace.c` (`ares_libtrace_resolve_path`), shared by all three
  engines. *Remaining:* `symbolize.c`'s own maps parsing (for stack symbolization)
  is still separate → fold into one maps/symbol module.
- **C4 — Kernel-side UID filter** — `uid_matches()` + target-uid BPF map
  (`target_uid` vs `target_uids`) → shared BPF header.
- **C5 — `resolve_uid()` + app launch/force-stop + install-UID-before-launch** —
  **DONE (2026-06-18, R1).** All engines now call the shared `ares_*` helpers in
  `src/common/launch.{c,h}`; the private per-engine copies are removed.
- **C5.1 — Firewall-aware capability registry (single audit point)** — **DONE (2026-06-21).**
  `src/common/capabilities.{c,h}` holds the static table of every BPF object and
  whether it writes into the target's userspace memory (the detectability firewall
  bit). Only uprobe-bearing capabilities (`funcs`, `correlate`) set
  `writes_target_memory = true`. This is advisory today (no quiet-mode flag consumes it
  yet) and exists as the single audit point + regression guard; the future thin-presets
  work will use it to refuse a loud object in a quiet preset (call
  `ares_quiet_config_ok` before loading engines). Backed by `tests/test_capabilities.c`
  (9 checks, host-unit-testable).
- **C6 — ELF reconstruction** — merged into `src/dump/rebuild.c` (the single
  `ares dump` engine); the old per-engine dump files are removed.
- **C7 — Symbol/caller resolution** — addr→module+offset via maps + dynsym, in both.
- **C8 — Misc duplication** — `libbpf_print_fn` + signal handlers; duplicate
  `vmlinux.h`. (Near-identical `map_event` struct and vendored libbpf are already
  unified.) BPF dropped-counter dup (`dropped` map + `bump_dropped()`) and the
  `syscalls_hdr` alias resolved (2026-06-24). Remaining: `libbpf_print_fn`, `vmlinux.h`.
- **C9 — Capability the funcs engine could borrow:** the syscalls engine's
  `decode_sockaddr` (the funcs engine has no sockaddr decoding).

---

## `correlate` — remaining work

Follow-on (2d / future) for the engine shipped above:

- **`--returns`** — opt-in uretprobe for return values + exact exit timing (loud —
  adds a stack trampoline, a second detection surface).
- **Syscall arg/sockaddr decoding** in `correlate` — PARTIAL: userspace flag-decode
  done (`flags_decode_arg` via `corr_emit_syscall`; args hex + parallel `decoded[]`
  array). fd-path rendering, sockaddr blob capture, and string capture still need
  BPF event-struct changes to carry the raw bytes.
- **Regex (`-I/-i`) targeting** in `correlate` (currently custom specs `-e/-F` only).
- **`-P` attach timing** — `-P` uprobe attach is best-effort (post-launch
  `/proc/maps` scan); tighten the launch→attach timing so early calls aren't missed.
- **Thin presets over the formal core** — PARTIAL: `syscalls` and `funcs` are now
  split into setup/run/teardown phases (shipped 2026-06-22, see above), the first
  step toward thin presets. Migrating `lib` likewise and retiring the localization
  where no longer needed remains deferred (folds in the consolidation roadmap items
  above). The immediate consumer is the combined `trace` runner (see "Planned").
- **MCP ingest** — ~~teach `ares-mcp` to ingest `correlate` output (join syscalls by
  `span`)~~ — **DONE (Task 3 / step 7).** `load_structured` ingests `funcs -J` /
  `correlate -o` JSONL into `calls`/`returns`/`func_spans`/`span_syscalls` tables;
  `correlate_spans` joins them on `span`. Legacy wrapper lines (no `type` field)
  are skipped and counted. Host test: `tools/ares-mcp/test_unified_ingest.py`
  (5 checks, integrated into `make test`).
  Follow-on MCP richness (histograms, timing tools, symbol/module filters, full
  `server.py` tool surface for the new types) remains deferred — see "Planned"
  section below.

---

## Planned — combined `trace` runner (kprobe + uprobe in one run)

New `ares trace` subcommand: run the `syscalls` (kprobe) and `funcs` (uprobe)
engines together from a **single app launch**, full feature parity, uncorrelated.
A *coordinator* reuses both real engines (no re-implemented combined probe), which
is why Phases 1–2 (shared `ares_launch_app`, setup/run/teardown split) landed
first. Inherently LOUD (uprobe BRK + kprobe) — never a stealthy engine.

- **Phase 1 — DONE (2026-06-22):** shared `ares_launch_app` (see Shipped).
- **Phase 2 — DONE (2026-06-22):** engine setup/run/teardown split (see Shipped).
- **Phase 3 — DONE (2026-06-22):** `src/trace/trace.c` coordinator + build wiring
  (see Shipped). `cmd_trace` resolves the UID once, calls `syscalls_setup` +
  `funcs_setup` (package via `rc->pkg`, no per-section package), launches once via
  `ares_launch_app`, then drains both ring buffers on two pthreads sharing a
  `sig_atomic_t` stop flag, separate per-engine `-o` files (both MCP-ingestable).
  `main.c`/`capabilities.c`/`Makefile` wired; engine driver symbols kept global.
- **Phase 4:** argv-section split extracted to `src/trace/trace_args.c` (pure,
  host-tested via `tests/test_trace_args.c`, in `make test`) — DONE 2026-06-22.
  Remaining: on-device verification of a combined `trace` run.

## Planned — structured emitter + unified MCP

- **Structured JSONL emitter for `ares funcs` — CALL/RETURN unified (2026-06-23).**
  `-o FILE` now emits pure structured JSONL via the shared `ares_sink`; the legacy
  wrapper and CSV are removed (see Shipped above). Remaining:
  - MAP/UNMAP/SPAWN/PROC_EXIT/EXECVE/PROP structured records (extend `funcs_emit.c`,
    same pattern — one builder per type, each pinned by a host test).
  - The SEAM in `handle_event()` already routes all event types; hook each case.
- **Unified `ares-mcp` ingest — DONE (Task 3).** `load_structured` + `correlate_spans`
  land the minimal ingest + span join. Remaining richness (call histograms, timing
  views, symbol/module filters, full `server.py` tool surface for the new types)
  is follow-on.

---

## Planned — managed-frame symbolization (OAT / ODEX / VDEX)

**Status update (2026-06-24).** OAT/ODEX Java methods already resolve in practice
via the `.gnu_debugdata` mini-debug-info `dex2oat` embeds in `.odex`/`.oat` (the
existing ELF symbol path), so a dedicated OAT-header parser is **not** needed for
the common case. vDSO frames are now named (`[vdso]!`, Phase 1 — see spec
`docs/superpowers/specs/2026-06-24-vdso-symbolization-and-frame-audit-design.md`).
The remaining real work is **Phase 2: a shared dex method-name resolver** for
`base.vdex` and `[anon:dalvik-DEX data]` frames; `[anon:dalvik-main space]` frames
are unwind noise and out of scope.

**Phase 2a shipped (2026-06-24).** The version-stable core — `src/common/dex.{c,h}`,
a pure standard-DEX offset→method parser (`dex_map_build`/`dex_map_lookup`/
`dex_map_free`, output `pkg.Class.method`) — is implemented and host-tested against
a committed `.dex` fixture (`tests/test_dex.c`). It is **not yet wired into any
capability** (no caller; compiled only by `make test`, absent from `build/ares`).
Spec: `docs/superpowers/specs/2026-06-24-dex-method-resolver-core-design.md`.
Remaining phases, in dependency order:

- **Phase 2b — on-device research spike** (needs the rooted device): capture
  `base.vdex` / `[anon:dalvik-DEX data]` frames, dump bytes at the offsets,
  determine dex-vs-cdex, vdex version, and whether the PC is a `code_item.insns`
  offset. Greenlights or kills integration.
- **Phase 2c — vdex container + anon-region locate:** find the DEX image inside
  `base.vdex` (version-gated) and in `[anon:dalvik-DEX data]`; feed it to
  `dex_map_build`. CompactDex (`cdex001`) support lands here if 2b shows the device
  uses it.
- **Phase 2d — `symbolize.c` integration:** wire the two frame types through the
  resolver with a per-image cache (mirroring the vDSO per-pid holder), emitting
  `base.vdex!pkg.Class.method+0x..`. MCP-format note + device-test assertion.

Follow-on to the JIT method-name work (spec
`docs/superpowers/specs/2026-06-23-jit-named-cache-symbolization-design.md`, which
covers **JIT only**). Goal: name the Java method behind a native backtrace frame
that lands in AOT-compiled or interpreter-adjacent regions, not just the JIT cache.

- **OAT / ODEX native PC → Java method.** `boot.oat` already symbolizes via the
  normal ELF dynsym path (e.g. `boot.oat!art_jni_trampoline+0x70`) because it ships
  ELF symbols. App `.odex`/`.oat` AOT method code is **method-index-keyed, not ELF
  symbols**, so resolving a PC to a method name needs real OAT parsing: walk the OAT
  header → `OatDexFile` → per-method `OatMethod` code-offset table to map the PC to
  a `dex_method_idx`, then resolve that index against the embedded dex
  (class/name/signature). This is oatdump-class work and **ART-version-coupled** (OAT
  version differs across Android releases) — the main risk.
- **VDEX PC → dex method.** A frame landing in `base.vdex+0x..` is the open research
  item: vdex holds **verified dex bytecode + quickening info, not native code**, so a
  native PC there is unexpected (likely an interpreter / quickened bridge path).
  Needs investigation into what the PC actually is before a resolution strategy can
  be picked; mapping it to a method still bottoms out in dex method tables.
- **Shared concern:** all three (JIT, OAT, VDEX) ultimately resolve a `dex_method_idx`
  → human name through an embedded dex parser. If/when OAT/VDEX land, factor a small
  dex method-name resolver shared with any future dex-aware feature rather than
  duplicating per source.

## CLI consistency — deferred items

From the full consistency audit documented in `CONSISTENCY_AUDIT.md` (2026-06-24).
Shipped in order: Tier 1 (A1, A4, A2, A7), Tier 2 minus A5 (A3, X3, X4, C1), then
2026-06-24: Quick wins + A.0 keystone (see below). Items still deferred follow.

### Shipped 2026-06-24

- **A5** — `-P`/`-A` flags on `lib`/`dump` (keeping positionals as aliases): done
  as part of the A.0 argp migration.
- **A.0** — `lib`/`dump`/`correlate` migrated to GNU argp + `argp_program_version`.
  `lib` and `dump` also route launch through `ares_launch_app()` (launch dedup, gains
  death-wait + `am start -S`). Correlate launch stays inline (needs pid back from pidof).
- **`syscalls --version` (partial)** — `argp_program_version = "ares syscalls"` added to
  all five argp engines. The version *strings* exist but `--version` dispatch is broken
  at runtime due to Makefile symbol localization (see F3 in Device-test findings).
- **U3 doc** — `funcs --help` now documents the dual console+file output mode. **Decision
  revised (F4, 2026-06-24):** unify on `-o` ⇒ quiet across all engines; implementation
  pending (see F4 in Device-test findings).

### Won't do (dead-flag trap — see evaluation in plan)

- `dump -v` — dump has no verbose-tier output to gate; a flag would be wired to nothing.
- `lib`/`dump`/`correlate` `-b`/`-Q` — these engines poll the ring buffer directly with
  no configurable ring size or worker queue; advertising the flags would recreate the A1
  dead-flag bug.

### X2 — Three structured-output code paths — DONE 2026-06-24

`lib` and `correlate` migrated onto `ares_sink` (periodic flush, "wrote N records"
report at teardown, `jb_esc` escaper). `ares_libtrace_emit_lib/unlib` signatures
changed from `FILE *jsonl` to `struct ares_sink *sink`; `json_write_str` in `lib_trace.c`
removed. `C8`: three local `libbpf_print_fn` copies (lib/dump/correlate) replaced by
`ares_libbpf_quiet` from `common/runtime.h`. New host test: `tests/test_lib_trace_emit.c`
(11 checks). `make test` green (11/11 suites).

### U1/U2 — Console style diverges between engines (Tier 3)

`funcs` uses timestamped tagged lines (`[spawn] >`, `[work] >`, `[uprobe] >`,
`[event] >`). All other engines use plain prose banners. Under `trace -o` the interleave
is masked, but standalone runs feel like two different tools. Fix: pick one convention
and align. `[lib]` / `[unlib]` in `lib` are output lines, not banners — keep their
format. Note: low value / high cosmetic churn across 5 files; not recommended.

---

## Deferred tech debt

- Dropping the 6 MB committed `vmlinux.btf` in favor of regenerate-on-demand.
- **`rctx` use-after-return in `funcs_setup`** — `struct probe_resolve_ctx rctx`
  is declared as a stack local in `funcs_setup` (ares-tracer.c:~1172) and passed
  to `ring_buffer__new`; the MAP handler dereferences it after `funcs_setup`
  returns. Pre-existing; unrelated to the C2 worker split (the worker never
  touches `rctx`). Fix: promote `rctx` to file-static.

