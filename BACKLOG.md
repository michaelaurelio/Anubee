# ARES backlog

Deferred architecture work and known tech debt. The **current** state of each
engine is in [DOCUMENTATION.md](DOCUMENTATION.md); this file holds the
forward-looking items only.

**Contents**

- [Shipped](#shipped)
- [Open issues — review 2026-06-17 (R2–R7, R9)](#open-issues--review-2026-06-17)
- [Consolidation roadmap — shared-code de-dup (C1–C9)](#consolidation-roadmap--shared-code-de-dup)
- [`correlate` — remaining work](#correlate--remaining-work)
- [Planned — structured emitter + unified MCP](#planned--structured-emitter--unified-mcp)
- [Deferred tech debt](#deferred-tech-debt)

---

## Shipped

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

## Open issues — review 2026-06-17

Repo-wide review pass. Ordered by severity; most are small and self-contained.

### Correctness / robustness

- **R2 — uprobe offset uses `sym.st_value` (a virtual address) directly as the
  uprobe file offset** in both `correlate` (`resolve_custom_spec_for_path` /
  `resolve_targets*` in `src/common/probe_resolve.c`) and `funcs`. libbpf's
  `bpf_program__attach_uprobe` wants a **file offset**; `st_value == file_offset`
  only when the containing `PT_LOAD`'s `p_vaddr == p_offset` (true for most Android
  `.so`s, so on-device tests pass). For libraries whose executable segment has
  `p_vaddr != p_offset` the probe lands at the wrong address. Fix: convert via the
  program headers (`file_off = st_value - (seg.p_vaddr - seg.p_offset)` for the
  segment that contains `st_value`).
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

- **R6 — `correlate -q` is parsed but undocumented** — `usage()` omits the `-q`
  (quiet) flag that `cmd_correlate` handles.
- **R7 — `FUNC_CFLAGS` lacks `-Wextra`** (Makefile) while every other engine's CFLAGS
  has it. `funcs` is the largest C unit (1.5k lines) and gets the *weakest* warning
  coverage. Align it to `-Wall -Wextra`.

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
  unified.)
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

## Deferred tech debt

- Dropping the 6 MB committed `vmlinux.btf` in favor of regenerate-on-demand.

