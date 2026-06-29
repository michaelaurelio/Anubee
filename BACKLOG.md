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

## Open work — at a glance

**Urgent:** none.

**Major:**
- GA2 deferred: wire `correlate`→`trace`, `dump`→`trace`
- `correlate` remaining: `--returns`; syscall/sockaddr/fd/string decode; regex `-I/-i`; `-P` attach timing
- CFI live cross: W3-window (snapshot 32 KB read faults → 8 KB) + W5 (JIT `[anon]` CFI) — see below
- Managed-frame OAT/ODEX: future — parked pending proper ART parsing

**Minor:**
- F2 — `ares funcs -p` PID attach, needs repro
- R9 — `syscall_name()` linear scan → bsearch; C9 — `funcs` sockaddr decode
- `vmlinux.h` dedup; drop committed `vmlinux.btf`
- MCP richness follow-on; pending device verification (`trace` combined run, `correlate` R3/R4/X2)
- U1/U2 console style unification (not recommended — high churn, low value)
- `ares mod` audit (open): U2 `-v` asymmetry, O2 structured backtrace symbols, O3 prop schema, F1 `-p PID`, F2 auto-stop, F3 summaries, F4 `-b` ring wire

---

## Urgent — architectural / correctness-critical

### B1 — prop-read RASP summary was silently empty under `-o` — **DONE 2026-06-28**

`prop_stat_add()` calls hoisted out of the `if (!mc->quiet)` guard in `src/modules/prop_read.c`.
Tally now always runs; `pr_print_summary` prints correctly whether or not `-o` is active.

---

## Major — features / substantial work

### GA2 — Engine lifecycle asymmetry (graph audit 2026-06-26) — **DONE 2026-06-26**

GA2 core done (see Resolved/Done 2026-06-26). Deferred wiring remains:
- **Wiring `correlate` into `trace`** — requires a post-launch `correlate_attach(pid)` step
  (uprobes must attach after the child PID is known, which means a 5th public function and
  coordinator special-casing). Deliberately deferred: the PID-return barrier is gone (GA6
  keystone done), but the 5th-fn asymmetry is not worth buying for a marginal combined
  funcs+correlate run.
- **Wiring `dump` into `trace`** — output model is ELF files + on-exit rescan, not a
  concurrent stream; low-value combined run. Deferred by design.

Per-engine comparison (post-GA2):

| Dimension | syscalls | funcs | lib | dump | correlate | trace |
|---|---|---|---|---|---|---|
| Lifecycle | setup/run/teardown | setup/run/teardown | setup/run/teardown | **setup/run/teardown** ✓ | **setup/run/teardown** ✓ | coordinator |
| App launch | shared `ares_launch_app` | shared | shared | shared | **shared (GA6 ✓)** | shared |
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

### `funcs` structured records — module events — **DONE 2026-06-28**

- CALL/RETURN: **done.** MAP/UNMAP: **done (2026-06-25)** via `ares_libtrace_emit_lib/unlib`
  under `g_sink_lock` (Option A — drain emits directly, attach stays prompt).
- **SPAWN/PROC_EXIT/EXECVE/PROP** — **done (2026-06-28)** via `ares mod` migration
  (Phases 1–3); output channel in `src/modules/mod_emit.c`. See Resolved/Done 2026-06-28.
- **B2** — worker-queue convergence was scoped for post-module-events; moot after
  `ares mod` migration (module events no longer route through the funcs worker queue).

### CFI stack unwinder — engine + wiring landed; live cross has 2 walls left

W1, W2, W3 landed; W6 (capture gating) + the maps-cache staleness blocker fixed
2026-06-29 (see Resolved/Done). The CFI engine unwinds native frames correctly on-device
and now, under capture-all, walks the full native chain on JNI-originated stacks
(`libc → … → libandroid_runtime`). A *live* jni-trampoline→managed cross still does not
complete — **two** walls remain (the **W3-window** snapshot-truncation wall and **W5**),
characterised on-device 2026-06-29:

- **W3-window (NEW, the current blocker) — the 32 KB snapshot read faults to 8 KB.** The
  W4 "32 KB window" does not deliver 32 KB at runtime: the single `bpf_probe_read_user`
  of `ARES_SNAP_MAX` faults (the stack range near `sp` crosses unmapped pages) and the
  3-tier fallback drops to **8 KB** (`MID`) or 2 KB (`SMALL`). On-device: **299/307
  snapshots `truncated:1`; only 8 captured 32 KB, 259 got 8 KB.** The spilled RA that
  would step `libandroid_runtime`→`art_jni_trampoline` sits *beyond* the 8 KB captured,
  so `cfi_step`'s bounded `read64` fails and the unwind dies **one frame short of the
  trampoline** (82/307 records terminate in `libandroid_runtime.so`, which *does* have
  `.eh_frame`). Fix: capture the stack in page-sized chunks (loop `bpf_probe_read_user`,
  stop at the first faulting chunk) so as much contiguous stack as exists is kept, instead
  of all-or-nothing. Verifier-sensitive (bounded/unrolled loop). This is the gating wall —
  W5 is unreachable until a snapshot reaches the trampoline.

- **W1 — DONE (2026-06-27): CFI unwinder wired to runtime.**
  `cfi_unwind_snapshot` (in `src/common/symbolize.c`, declared in `symbolize.h`) loops
  `cfi_get` + `cfi_step` over the frozen snapshot window. Reads only the frozen
  `snap->snap[]` bytes — no live target memory. Called from `emit_cfi_backtrace`
  in `syscalls.c` immediately after each raw `{"type":"stack"}` sidecar write; emits
  a companion `{"type":"cfi_stack","stack_id":N,"cfi_backtrace":[{frame,addr,symbol,kind},...]}`.
  `kind` ∈ `native | jni-trampoline | managed | interp`. `cfi_unwind.c` + `dwarf.c`
  added to `COMMON_CSRC`; `cfi_unwind_snapshot` exported via `COMMON_API`.
  **On-device (2026-06-27):** the RA-default fix (commit `ee5ed5f`) took native unwinding
  from 1 frame to the full 18-frame libc→linker64 chain; the `art_jni_trampoline` FDE in
  the real `boot.oat` resolves `CFA=sp, RA=same` → recovers the managed caller PC (verified
  offline). The live cross is blocked by W4–W6 below; the `syscalls-cfi` arm SKIPs honestly
  until they land.

- **W4 — DONE (2026-06-27): snapshot window enlarged 8 KB → 32 KB + 3-tier fault fallback.**
  Deep frames' spilled-RA slots (e.g. `libandroid_runtime` at `CFA-56`) sat past `sp+8192`,
  so `cfi_step`'s bounds-checked `read64` failed and the unwind truncated mid-native before
  the trampoline. `ARES_SNAP_MAX` is now 32768 with a `MAX → MID(8192) → SMALL(2048)` read
  cascade (a fault on the big read still yields a useful window; `truncated` flags any fallback).
  Cost: 32 KB ring record per snapshot, but records are deduped per distinct stack so it's
  bounded. **Superseded 2026-06-29 by W3-window above:** on-device the 32 KB
  `bpf_probe_read_user` itself *faults* and the fallback drops to 8 KB in 259/307 cases —
  so the effective window is 8 KB, not 32 KB. The chunked/streamed capture noted here as a
  future lever is now the required fix (W3-window), not optional.

- **W5 — JIT code-cache frames have no file-backed CFI. (Still open; unreachable until
  W3-window lands — the unwind dies in `libandroid_runtime` before reaching any JIT frame.)**
  Between the framework lib and
  `art_jni_trampoline` sits a JIT-compiled Java frame (`[anon]+…` / `[anon_shmem:dalvik-jit-code-cache]`).
  `cfi_get` skips pseudo paths → returns NULL → unwind stops. ART publishes per-method
  unwind info as in-memory mini-ELFs (with `.eh_frame`) via the GDB JIT interface — ARES
  already reads these for *symbols* (`jit_resolve` / `art_refresh`). Extend that path to
  `cfi_load_elf` the JIT mini-ELF and feed it to `cfi_get`. (AOT-compiled callers, in
  `base.odex`/`boot.oat`, do NOT hit this — they have `.debug_frame` — so fully-AOT JNI
  paths can cross once W4 lands.)

- **W6 — DONE 2026-06-29 (W6-A decouple): snapshots now flow under capture-all.** The
  original framing ("root-cause the lib-filter `stack_hits` miss") was the wrong lever —
  the lib-filter is a *narrow-targeting* feature; full JNI unwinding needs capture-all
  breadth. Fix: dropped the `!capture_all` term in the `want_snapshots` gate
  (`syscalls.c`), so `--snapshot` works with `-a` (warn-and-proceed firehose guard when no
  `-s`/`-x` filter). On-device: `.stacks` sidecar went 0 → 307 records under `-a`. See
  Resolved/Done 2026-06-29. **Separate open bug (left unfixed, sidestepped):** lib-filter
  on `libc.so` *should* match every `openat` (frame-0 is always `libc!__openat`) yet drops
  the runtime/JNI ones, keeping only native process-init — a real `stack_hits` defect, but
  W6-A bypasses it so it no longer gates the cross.

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

- **`ares mod` audit findings (2026-06-28). B1/U1/O1/U3 fixed 2026-06-28. Remaining deferred.**

  **UX / CLI:**
  - **U1 — dead flags advertised. DONE 2026-06-28.** `mod_options` hand-picks `-o/-v/-q` now
    (mirrors `lib.c`); `-J/-b/-Q` dropped from `--help`.
  - **U2 — `-v` honored only by execve.** `mc->verbose` checked in `execve.c` but ignored by
    proc-event and prop-read. Add verbose output to the other two, or document as execve-only.
  - **U3 — setup banners standardized. DONE 2026-06-28.** Per-analyzer "enabled" lines removed from
    `execve.c` and `prop_read.c`; only dispatcher banner remains.

  **Output / schema:**
  - **O1 — execve prefix fixed. DONE 2026-06-28.** `execve.c` now prints `[exec]` (was `[proc]`).
  - **O2 — structured execve backtrace addr-only.** Console resolves via `sym_resolve`
    (`execve.c:53`); `-o` JSONL emits raw addresses only (`mod_emit.c:53-61`). Fix (medium):
    resolve in analyzer, pass symbol strings into a richer emit path.
  - **O3 — prop schema over-emits.** SCAN events emit `name`/`value`/`is_ret`/`found` even when
    empty/zero. Minor; optional per-op field trimming.

  **Functionality:**
  - **F1 — launch-only; no `-p PID`.** `-P` required; always `ares_launch_app`s. Opportunity:
    resolve uid from pid, skip launch.
  - **F2 — no `-d SECONDS` auto-stop.** Scripts wrap with `timeout`.
  - **F3 — no summary for proc-event or execve.** `print_summary` is NULL for both. Cheap wins:
    proc-event → fork/exit counts; execve → per-binary exec tally.
  - **F4 — `-b` ring size wired nowhere.** Each analyzer hardcodes 1 MiB `events_rb`. Wire
    `bpf_map__set_max_entries` before load if `-b` is ever re-added.

- _Checked, not a bug (2026-06-26 audit):_ `correlate`'s `-p`/`-e`/`-F` parsing was suspected of
  unbounded append into `pids[64]`/`specs[64]`, but it is correctly guarded with user warnings
  (`correlate.c:233,242,251`). No action. (R2 raw-`st_value`-offset likewise already fixed — see
  Resolved.) GA3–GA7 from the same audit all shipped — see Resolved/Done (session 5).

---

## Resolved / Done

Reverse-chronological. Identifiers preserved for traceability; full technical detail
is in DOCUMENTATION.md and the referenced specs.

### 2026-06-29

- **W6-A — capture-all stack snapshots (decouple snapshot capture from lib-filter).**
  Dropped the `!capture_all` term in the `want_snapshots` gate (`syscalls.c`); host-testable
  predicates extracted to `src/syscalls/snapshot_gate.h` (`sysc_want_snapshots`,
  `sysc_snapshot_firehose_warn`) with `tests/test_snapshot_gate.c`. Warn-and-proceed firehose
  guard when `-a --snapshot` has no `-s`/`-x` filter. `device-test.sh` CFI arm repointed at
  `-a`. On-device: `.stacks` sidecar 0 → 307 records under capture-all. Closes W6. Commits
  `8992405`, `b73134d`, `0bd983e`. Spec/plan: `docs/superpowers/{specs,plans}/2026-06-29-w6-*`.
- **Maps-cache staleness fix — capture-all CFI unwinds past frame 0.** Under capture-all the
  symbolizer first reads a pid's `/proc/<pid>/maps` mid-launch (libc not yet at its final
  base) and caches it; the `REFRESH_MS=250` throttle suppressed the corrective re-read during
  the drain burst, so snapshot PCs resolved `[unmapped]` and the CFI walk died at frame 0
  (same pid+addr: 235 `[unmapped]` vs 59 resolved in one run). Factored refresh-on-miss into a
  shared `find_mapping_refresh` (used by `sym_resolve` + the CFI walk) and added a one-shot
  throttle-ignoring re-read in `cfi_unwind_snapshot` (bounded by per-distinct-stack dedup;
  FP-storm path untouched). On-device: unwinds went 1-frame → full native chain
  (`libc → … → libandroid_runtime`). Reads-only; firewall intact. Commit `fd4138a`. This
  exposed the next wall (**W3-window**, see CFI section above): the 32 KB snapshot read faults
  to 8 KB, so the unwind still dies one frame short of `art_jni_trampoline`.

### 2026-06-28

- **proc-event/execve/prop-read → `ares mod` migration (Phases 1–3).** SPAWN/PROC_EXIT/EXECVE/PROP
  events migrated from the open `funcs` module-events backlog to the `ares mod` analyzer subsystem
  (proc-event, execve, prop-read); output channel in `src/modules/mod_emit.c`. Closes the
  SPAWN/PROC_EXIT/EXECVE/PROP deferred item and retires B2 as moot.

### 2026-06-27 (session 5)

- **GA6 (keystone) — `ares_launch_app` returns the launched PID; `correlate` dedups its
  inline launcher.** Added `pid_t *out_pid` out-param to `ares_launch_app` (`launch.{c,h}`);
  polls `pidof` after `am start -S` when non-NULL. `correlate_setup` replaces ~14 lines of
  duplicated force-stop/resolve-component/am-start/pidof with a single `ares_launch_app(pkg, NULL, &p)`
  call. Five other callers (`syscalls`, `funcs`, `lib`, `dump`, `trace`) add `, NULL` — interface
  contract unchanged.
- **GA7 — `probe_resolve` no-PT_LOAD sentinel.** `seg_vaddr_to_off` and `vaddr_to_file_off` now
  return `SEG_VADDR_BAD` (`(unsigned long)-1`) instead of the raw vaddr when no PT_LOAD segment
  contains the address. All four callers (`resolve_targets`, `resolve_targets_for_file`,
  `resolve_custom_spec_for_path`, `prop_read.c`) guard the sentinel and skip+warn via verbose log
  rather than attaching a uprobe at a wrong file offset. The 32-segment cap is self-healing under
  the new contract (an out-of-range vaddr → sentinel → skip). `@offset` in custom specs documented
  as a file offset, not a readelf/nm vaddr. Two `test_probe_spec` assertions flipped to
  `SEG_VADDR_BAD`. `DOCUMENTATION.md` updated. Commit `7995126`.
- **GA5 — `trace` coordinator SIGTERM.** Replaced the hand-rolled `on_sigint` + `signal(SIGINT,
  on_sigint)` in `trace.c` with `ares_install_stop_handler(&g_stop)`. `trace` now responds to
  SIGTERM identically to SIGINT (graceful drain+flush; 2nd signal → `_exit(130)`), matching all
  five standalone engines. Bundled in commit `97c827f` with GA4.
- **GA4 — event-queue pop desync.** `ares_evq_pop` now loops: reads the 4-byte length, and if
  the record fits the caller's buffer copies it normally; if oversized, advances `tail` by the
  full `sz` (keeping the ring framed), increments `dropped`, and fetches the next record — never
  handing the caller a truncated or garbage record. `test_evqueue` extended: push 40-byte record
  then 5-byte record, pop with `outcap=16` → must receive the 5-byte record cleanly (26 checks
  total). Bundled in commit `97c827f` with GA5.
- **GA3 — sink write errors.** `ares_sink_emit` now latches `errno` into `s->werr` on `ferror`
  and on periodic `fflush`; `ares_sink_flush`/`_close` latch on `fflush`/`fclose` failure;
  `ares_sink_report` prints a WARNING line if `werr` is set. `setvbuf` malloc leak fixed (free on
  `setvbuf` failure). `test_emit` extended: `fmemopen` 16-byte buffer overflowed by 10 records
  confirms `s.werr != 0` (23 checks total). Commit `478c679`.

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
