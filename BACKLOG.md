# ARES backlog

Deferred architecture work and known tech debt. The **current** state of each
engine is in [DOCUMENTATION.md](DOCUMENTATION.md); this file holds the
forward-looking items only.

**Contents**

- [Shipped](#shipped)
- [Open issues — review 2026-06-17 (R2–R9)](#open-issues--review-2026-06-17)
- [Consolidation roadmap — shared-code de-dup (C1–C9)](#consolidation-roadmap--shared-code-de-dup)
- [`correlate` — remaining work](#correlate--remaining-work)
- [Planned — structured emitter + unified MCP](#planned--structured-emitter--unified-mcp)
- [Deferred tech debt](#deferred-tech-debt)

---

## Shipped

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

### Testing / CI (architectural gap)

- **R8 — No automated tests and no CI.**,
  There is zero test harness and no `.github` workflow. This is the first thing
  that breaks as the team/feature count grows. Cheapest high-value start:
  `parse_custom_probe_spec` is a **pure, host-compilable** function — unit-test the
  spec grammar (`MOD!FUNC(S,V,F)>V`, `@offset`, malformed inputs) without a device.
  Add a GitHub Actions job that runs `scripts/build.sh` (containerized cross-build)
  on PRs so the binary can't silently stop compiling.

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

- **C1 — JSON/JSONL string escaping** — identical switch in both
  (`src/syscalls/heimdall.c` `jb_*` vs `src/funcs/ares-tracer.c` `json_fwrite_str`);
  differs only in output sink → one `json_escape(sink)`.
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
- **Syscall arg/sockaddr decoding** in `correlate` (currently raw `args[0..5]`) —
  reuse the heimdall decoder + string/sockaddr capture.
- **Regex (`-I/-i`) targeting** in `correlate` (currently custom specs `-e/-F` only).
- **`-P` attach timing** — `-P` uprobe attach is best-effort (post-launch
  `/proc/maps` scan); tighten the launch→attach timing so early calls aren't missed.
- **Thin presets over the formal core** — migrating `syscalls`/`funcs`/`lib` to thin
  presets and retiring the localization where no longer needed remains deferred
  (folds in the consolidation roadmap items above).
- **MCP ingest** — teach `ares-mcp` to ingest `correlate` output (join syscalls by
  `span`).

---

## Planned — structured emitter + unified MCP

- **Structured JSONL emitter for `ares funcs`** so its events become first-class,
  analyzable records under the same `type` discriminator. Hook point: the `SEAM`
  comment atop `handle_event()` in `src/funcs/ares-tracer.c`; the event structs in
  `src/funcs/ares-tracer.h` already carry the fields.
- **A unified `ares-mcp`** that treats `ares funcs` structured output as a
  first-class trace source alongside syscalls (function-call histograms, filter by
  symbol/module, call→return timing, distinct stacks, prop/exec/spawn views), sharing
  the filtering layer. Depends on the structured-funcs emitter.

---

## Deferred tech debt

- Dropping the 6 MB committed `vmlinux.btf` in favor of regenerate-on-demand.
- Rebranding the syscalls engine's internal `HEIMDALL_*` env vars / `heimdall.*`
  filenames to `ares-*` (cosmetic; left to avoid churn during the merge).
