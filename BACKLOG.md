# ARES backlog

Deferred architecture work and known tech debt. The **current** state of each
engine is in [DOCUMENTATION.md](DOCUMENTATION.md); this file holds the
forward-looking items only.

## Done

- **`ares dump` engine landed 2026-06-16** — replaced the syscalls & funcs dumpers,
  dropped the `-l` libs-only mode from `ares syscalls`, and lifted the
  `/proc/<pid>/mem` reader into `src/common/proc_mem`.

## Shared-code / consolidation roadmap

The two engines were merged with **minimal edits** (surgical), so they still carry
duplicated logic. The library-load tracing slice is consolidated into
`src/common/lib_trace.*` (mmap/munmap capture, `/proc` resolution, `[lib]` emitter,
unified `lib_map_event`/`lib_unmap_event`). Remaining items, rough priority:

1. **JSON/JSONL string escaping** — identical switch in both
   (`src/syscalls/heimdall.c` `jb_*` vs `src/funcs/ares-tracer.c` `json_fwrite_str`);
   differs only in output sink → one `json_escape(sink)`.
2. **Ring-buffer setup + poll loop** — `ring_buffer__new`/`__poll` in both → shared
   drain helper.
3. **`/proc/<pid>/maps` parsing + basename→fullpath cache** — now in
   `src/common/lib_trace.c` (`ares_libtrace_resolve_path`), shared by all three
   engines. *Remaining:* `symbolize.c`'s own maps parsing (for stack symbolization)
   is still separate → fold into one maps/symbol module.
4. **Kernel-side UID filter** — `uid_matches()` + target-uid BPF map (`target_uid`
   vs `target_uids`) → shared BPF header.
5. **`resolve_uid()` + app launch/force-stop + install-UID-before-launch** — same
   flow in all engines → shared device/launch helper.
6. **ELF reconstruction** — merged into `src/dump/rebuild.c` (the single `ares dump`
   engine); the old per-engine dump files are removed.
7. **Symbol/caller resolution** — addr→module+offset via maps + dynsym, in both.
8. **Misc duplication** — `libbpf_print_fn` + signal handlers; duplicate `vmlinux.h`.
   (Near-identical `map_event` struct and vendored libbpf are already unified.)
9. **Capability the funcs engine could borrow:** the syscalls engine's
   `decode_sockaddr` (the funcs engine has no sockaddr decoding).

## `correlate` (function→syscall) — landed 2026-06-17

The fused-core + `correlate` work shipped (Phase 1 + 2a–2c). The detectability
firewall is **reframed**: the one real invariant is "a stealthy run attaches zero
uprobes"; "each engine owns its BPF object" and the partial-link symbol-localization
are merge scaffolding, not sacred.

**Done & device-verified:**
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

**Remaining (2d / future):**
- `--returns`: opt-in uretprobe for return values + exact exit timing (loud — adds a
  stack trampoline, a second detection surface).
- Syscall **arg/sockaddr decoding** in `correlate` (currently raw `args[0..5]`) —
  reuse the heimdall decoder + string/sockaddr capture.
- Regex (`-I/-i`) targeting in `correlate` (currently custom specs `-e/-F` only).
- `-P` uprobe attach is **best-effort** (post-launch `/proc/maps` scan) — tighten
  the launch→attach timing so early calls aren't missed.
- Migrating `syscalls`/`funcs`/`lib` to thin presets over the formal core, and
  retiring the localization where no longer needed, remains deferred (folds in the
  consolidation roadmap items above).
- MCP: teach `ares-mcp` to ingest `correlate` output (join syscalls by `span`).

## Planned: structured emitter + unified MCP

- Structured JSONL emitter for `ares funcs` so its events become first-class,
  analyzable records under the same `type` discriminator. Hook point: the `SEAM`
  comment atop `handle_event()` in `src/funcs/ares-tracer.c`; the event structs in
  `src/funcs/ares-tracer.h` already carry the fields.
- A unified `ares-mcp` that treats `ares funcs` structured output as a first-class
  trace source alongside syscalls (function-call histograms, filter by symbol/module,
  call→return timing, distinct stacks, prop/exec/spawn views), sharing the filtering
  layer. Depends on the structured-funcs emitter.

## Other deferred tech debt

- Dropping the 6 MB committed `vmlinux.btf` in favor of regenerate-on-demand.
- Rebranding the syscalls engine's internal `HEIMDALL_*` env vars / `heimdall.*`
  filenames to `ares-*` (cosmetic; left to avoid churn during the merge).
