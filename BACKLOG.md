# ARES backlog

Deferred architecture work and known tech debt. The **current** state of each
engine is in [DOCUMENTATION.md](DOCUMENTATION.md); this file holds the
forward-looking items only.

## Proposed: `ares dump` engine (consolidate memory dumping)

Today the live-memory dump + ELF-rebuild capability is implemented twice:

- `src/syscalls/dump.c` (~776 lines) — on-exit dump across recorded PIDs; the more
  sophisticated rebuild (program-header fixup, inter-segment gap capture, full
  section-header reconstruction, relative-relocation un-applying incl. DT_RELR,
  `.dynamic` de-rebasing). aarch64 / ELF64 only. Driven by `ares syscalls -l -D`
  (the `-l` libs-only mode disables the syscall dispatcher hook, so dumping runs
  with zero syscall overhead).
- `src/funcs/so_repair.c` (~684 lines) + `dump_library_full()` in
  `src/funcs/ares-tracer.c` — dump-at-map-time during function tracing; phdr
  `p_offset` fixup, RELATIVE-reloc removal, section-header reconstruction. Includes
  a 32-bit path (`repair32`).

These overlap heavily (already flagged below as roadmap item 6). Proposal: a single
standalone **`ares dump`** engine — kprobe-based (stealthy, like `ares lib`): launch
the app under a pre-installed UID filter, track maps, dump matching modules, rebuild
the ELF — replacing both dumpers with one implementation.

**Couplings to untangle first (analysis 2026-06-16; none are blockers):**

1. `src/syscalls/dump.c` also exports `proc_mem_open` / `proc_mem_read`, **reused by
   the symbolizer** (`src/syscalls/symbolize.c`) to walk ART's in-process JIT debug
   descriptor. Moving `dump.c` out of the syscalls engine requires splitting this
   generic `/proc/<pid>/mem` reader into `src/common` (or leaving it in the syscalls
   engine) so the symbolizer keeps working.
2. funcs `-D` dumps a module the instant it maps, *during* function tracing. A
   standalone `ares dump` (launch + dump-on-exit) drops trace-and-dump-in-one-pass.
   Minor — and funcs dump rides the detectable uprobe path anyway, so it is the
   weaker of the two for stealth.

**Removals this unblocks:**

- Delete dumping from `funcs` (`dump_library_full`, `so_repair.c`, the `-D`/`-d`
  options) and from `syscalls` (`dump.c`, the `-D`/`--dump-dir`/`--dump-raw` options).
- **Delete `ares syscalls -l`.** Its only remaining justification is being the
  lightweight dump driver; once dumping lives in `ares dump`, standalone library
  listing is fully covered by `ares lib`.
- Retarget the MCP server: `tools/ares-mcp/device.py` `dump_library` → `ares dump`;
  `mapped_libraries` → `ares lib` (the `[lib]` text line is identical across engines
  and `_LIB_RE` already matches). Requires generalizing `device.py`'s `_run_ares`,
  which currently hardcodes the `syscalls` subcommand, and updating `server.py`
  docstrings + `README.md`.

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
6. **ELF reconstruction** — `dump.c` (dump live memory + rebuild) vs `so_repair.c`
   (repair a dump); mergeable into one ELF dump/repair module (see `ares dump` above).
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
