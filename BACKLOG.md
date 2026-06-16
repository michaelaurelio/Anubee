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

- Correlated simultaneous syscall + function tracing in a single pass (out of scope
  to preserve the detectability firewall).
- Dropping the 6 MB committed `vmlinux.btf` in favor of regenerate-on-demand.
- Rebranding the syscalls engine's internal `HEIMDALL_*` env vars / `heimdall.*`
  filenames to `ares-*` (cosmetic; left to avoid churn during the merge).
