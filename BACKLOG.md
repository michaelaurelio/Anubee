# ARES backlog

Forward-looking work and known tech debt. The **current** state of each engine
lives in [DOCUMENTATION.md](DOCUMENTATION.md); this file holds what's left to do
plus a condensed log of what's already landed.

Open work is bucketed by **influence on future work**:

- [Urgent](#urgent--architectural--correctness-critical) — architectural keystones
  and correctness-critical bugs. Blocks building more on top; address first.
- [Major](#major--features--substantial-work) — features and substantial refactors
  that unlock new capability or remove a real limitation.
- [Minor](#minor--cleanups-perf-nits-cosmetic-verification) — small cleanups, perf
  nits, cosmetic, and pending verification. Nothing downstream depends on them.
- [Resolved / Done](#resolved--done) — condensed changelog of shipped work.

Each item keeps its original tracking id (`R#`, `C#`, `A#`, `X#`, `U#`, `W#`,
`GA#`, `CR#`, `Phase #`) so history stays traceable. Full technical detail for resolved
items lives in DOCUMENTATION.md and the referenced specs.

---

## Open work — at a glance

**Major:**
- `correlate` remaining capability — `--returns`; syscall/sockaddr/fd/string decode;
  regex `-I/-i`; `-P` attach timing.
- GA2 deferred wiring — `correlate`→`trace`, `dump`→`trace`.
- CFI / managed-frame naming — **generalize beyond one ART build**: version gate keys
  on apex `370549100` only (BuildID is the stronger anchor); nterp recall is bounded
  by the snapshot window.
- Managed-frame **OAT/ODEX native-PC → Java method** — parked pending real ART OAT parsing.
- CR2 — `syscalls` attribution is "presence on stack," not "issued by" (+ FP-omit /
  vDSO / 32-bit-compat / pre-arm-window gaps).
- CR3 — `correlate` SP-based span pop corrupts on non-LIFO stacks (Kotlin coroutines).
- CR4 — managed-frame naming: version treadmill + guess-path is primary (see CFI item).
- AA3 — `trace`↔engine driver ABI held by two hand-maintained, uncross-checked lists
  (inline prototypes in `trace.c` vs. the Makefile's `--keep-global-symbol` lists).

**Minor:**
- CR5 follow-ons - MCP `coverage` ingest handler; `dump` coverage field.
- W5 — JIT `[anon]` frame CFI (deferred; ≈0 payoff on measured workloads).
- lib-filter `stack_hits` defect on `libc.so` runtime/JNI stacks (sidestepped by W6-A).
- Phase 3d — coordinator-wide `-p` in `trace`.
- C9 — `funcs` sockaddr decode.
- R9 residual — syscall table data compiled twice (two `syscalls_gen.h` copies).
- SW1 — switch-interp ShadowFrame walk follow-ups (hardening, BuildID rows).
- N1 — `funcs` CFI/managed-chain runs inline on the drain thread.
- `vmlinux.h` dedup (C8).
- MCP richness follow-on.
- U1/U2 console style unification (not recommended — high churn, low value).
- Pending on-device verification (`trace` combined run; `correlate` R3/R4/X2).
- AA4 — `funcs` per-event O(N) probe-target scan.
- AA5 — `cfi_unwind_snapshot` per-frame invariant rescans (pid/module lookups).
- AA6 — MCP `load_structured` per-row DuckDB insert loop.
- AA7 — `syscalls` `json_emit` per-event attribute table scans.
- AA8 — MCP `wx_scan` O(m²·log m) writable-range re-sort.
- AA9 — managed-chain per-stack 8 KB alloc churn + double frame symbolization.

---

## Urgent — architectural / correctness-critical

None currently open.

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

### GA2 — deferred engine→`trace` wiring

GA2 core landed 2026-06-26 (lifecycle symmetry + `lib`→`trace`; see Resolved/Done).
Two wirings remain deferred by design:

- **`correlate` into `trace`** — requires a post-launch `correlate_attach(pid)` step
  (uprobes must attach after the child PID is known → a 5th public function and
  coordinator special-casing). The PID-return barrier is gone (GA6 done), but the
  5th-fn asymmetry isn't worth a marginal combined funcs+correlate run.
- **`dump` into `trace`** — output model is ELF files + on-exit rescan, not a
  concurrent stream; low-value combined run.

Per-engine comparison (post-GA2):

| Dimension | syscalls | funcs | lib | dump | correlate | trace |
|---|---|---|---|---|---|---|
| Lifecycle | setup/run/teardown | setup/run/teardown | setup/run/teardown | setup/run/teardown ✓ | setup/run/teardown ✓ | coordinator |
| App launch | shared `ares_launch_app` | shared | shared | shared | shared (GA6 ✓) | shared |
| Output path | SPSC evq + drain/worker | SPSC evq + drain/worker | sink, inline poll | ELF dumps (bypasses sink/evq) | sink, inline poll | per-engine |
| Wired into `trace` | yes | yes | yes ✓ | no (deferred) | no (deferred) | — |

### CFI / managed-frame naming — generalize beyond one ART build

The CFI unwinder and managed-frame naming now work end-to-end on the measured
target: native unwind (W1/W4/W3-window), JNI-trampoline cross (CFI-misstep +
PAC fixes), nterp terminal + **full interpreted chain** naming with dex_pc
corroboration, and the switch-interpreter ShadowFrame walk (SW1) — all landed and
device-verified (see Resolved/Done). What remains is breadth, not a new wall:

- **Version-gate generalization — foundation DONE (#3-A, 2026-07-02).** Both the
  nterp and ShadowFrame paths now resolve offsets through one BuildID-keyed
  `struct art_offsets` (`art_buildid_offsets`); the `/apex` `KNOWN_ART_APEX` gate is
  retired. Unknown build → clean dual no-op + a one-time notice. Device-verified on
  apex `370549100` (naming preserved; BuildID resolves). **Remaining breadth:**
  (B) candidate-row iteration — **DONE #3-B (2026-07-02):** `ARES_ART_OFFSETS=<file>` loads a
  `key=value` row (BuildID + 13 offsets) that overrides `k_table` for a matching BuildID
  (fail-closed otherwise), so a new build's offsets iterate against the oracle without a
  recompile, then bake into `k_table`; (C) formal
  precision oracle closure — **DONE #3-C (2026-07-02):** the Frida/ART oracle
  (`scripts/nterp-oracle/`) now hooks `open64`/`__openat` (openat ground-truth 0→80) and
  scores a 3-way trust split; the ShadowFrame authoritative path measured **~89.5% precision
  vs ART StackVisitor** (near-100% modulo `(syscall,path)` join noise), the uncorroborated
  nterp fallback fired 0× and is now flagged with a trailing `?`. See
  `research/2026-07-02-nterp-precision-oracle-findings.md` Result 6. Adding rows per
  device/ART build is now one-row-per-device. Spec/plan:
  `docs/superpowers/specs/2026-07-02-buildid-unification-design.md`.
- **Recall bound.** nterp chain recall is bounded by the frozen snapshot window;
  frames spilled past the window aren't named. Precision is favored over recall
  (uncorroborated candidates are dropped).

### Managed-frame symbolization — OAT / ODEX (future)

Goal: name the Java method behind a native backtrace frame that lands in
AOT-compiled `.odex`/`.oat` code. OAT/ODEX Java methods already resolve in
practice via the `.gnu_debugdata` mini-debug-info `dex2oat` embeds (existing ELF
symbol path). The genuine method-index→name path is parked:

- **OAT/ODEX native PC → Java method (parked).** App `.odex`/`.oat` AOT code is
  method-index-keyed, not ELF symbols; resolving a PC needs real OAT parsing
  (oatdump-class, **ART-version-coupled** — the main risk). The Phase-2a DEX core
  (`src/common/dex.{c,h}`, host-tested) stays valuable for these paths. Specs:
  `docs/superpowers/specs/2026-06-23-jit-named-cache-symbolization-design.md`,
  `docs/superpowers/specs/2026-06-24-dex-method-resolver-core-design.md`.
- **Phase 2c/2d — PARKED by 2b.** On A15/AOT, captured `classes.vdex+0x..` offsets
  land in DEX *data*, not `code_item`s (FP-unwinder mis-captures, not `dex_pc`s), so
  a vdex DEX-image locator (2c) would feed the resolver garbage and the symbolize
  wiring (2d) has nothing valid to name. Evidence:
  `docs/superpowers/research/2026-06-24-vdex-dex-frame-spike-findings.md`.

### CR2 — `syscalls` library attribution is "presence on stack," not "issued by"

Source: 2026-07-03 architecture critique. `stack_hits` (`src/syscalls/syscalls.bpf.c:145`)
keeps a syscall if **any** captured frame IP lands in the target library's range — i.e.
the lib is *somewhere on the call chain*, not that it issued the syscall. Over-attributes:
`targetlib → malloc → mmap` is tagged as a target-lib syscall. Compounding silent gaps,
several concentrated on the flagship RASP clean-vs-rooted diffing use case:

- **Frame-pointer walk** (`bpf_get_stack`, `BPF_F_USER_STACK`): RASP/anti-tamper `.so` —
  the stated target — are routinely `-fomit-frame-pointer`/hand-asm, so the walk yields
  garbage or nothing → false neg/pos. Attribution is least reliable exactly where the
  tool's headline job lives.
- **vDSO calls invisible** (never execute `svc`, so `do_el0_svc` never fires);
  **32-bit compat path unhooked** (only `do_el0_svc`, not `el0_svc_compat`).
- **Pre-arm window (bug).** `push_lib_range` (`src/syscalls/syscalls.c:191`) arms ranges
  from userspace reacting to an async mmap ringbuf event; syscalls issued between the
  kernel mmap completing and the range being armed hit `count==0` → dropped. The
  `.bpf.c` "no filter gap" comment is wrong for this window.
- Depth cap on the `stack_hits` scan silently drops deep-chain attribution.

Actionable: approximate "issued by" via the return address immediately above the libc
syscall stub (who called the wrapper) instead of any-frame-in-range — kills the
malloc→mmap over-attribution class (won't fix FP-omitted libs; fundamental). Fix the
pre-arm window (arm before first schedulable target code, or gate on a kernel-side mmap
hook). **Disclose the FP dependency + vDSO/compat blind spots in README/DOCUMENTATION**
— currently undersold.

### CR3 — `correlate` SP-based span pop corrupts on non-LIFO stacks

Source: 2026-07-03 architecture critique. The quiet span close infers "function
returned" from stack-pointer movement at the next instrumented event
(`span_stack_reconcile`, `src/common/span_stack.bpf.h:80`), no uretprobe. The
LIFO-monotonic-SP assumption breaks on:

- **Coroutines / fibers / stack switching** — Kotlin coroutines are pervasive on Android;
  a scheduler swapping `cur_sp` to another stack makes reconcile spuriously pop live
  frames (higher addr) or never pop returned ones (lower addr). Silent attribution
  corruption on the platform's most common concurrency model.
- Cross-thread offload (already documented), tail calls (over-attribute to caller),
  recursion at the same SP (stale frame lingers; `MAX_SPAN_DEPTH=32` overflow
  mis-attributes — the code comment admits it), longjmp/exception windows, signal
  handlers on an altstack.

Actionable: document coroutine/stack-switch hostility explicitly (not an edge case for
Android); frame SP-pop as the best-effort *quiet* approximation and `--returns`
(uretprobe, planned) as the accuracy path — the two are currently framed as
near-equivalent.

### CR4 — managed-frame naming: version treadmill + guess-path is primary

Source: 2026-07-03 architecture critique. Extends the "generalize beyond one ART build"
item above with a strategic critique.

- **Version treadmill.** One `k_table` row (`src/common/art_buildid.c:12`) gates *all*
  Java naming, keyed on the exact libart BuildID. ART is an apex (mainline) module
  updated ~monthly; every ART update / vendor rebuild / new release → BuildID miss →
  managed naming **silently returns nothing** (bare `nterp_helper` terminal, Java frames
  vanish). The `ARES_ART_OFFSETS` override + Frida oracle (#3-B/C) softens onboarding but
  it is still one row of manual labor per device per ART build.
- **Guess-path is primary for nterp.** `art_nterp.c:204` guesses `ArtMethod*` from raw
  stack slots and corroborates via a dex_pc in a 512-byte window — which proves *method
  identity, not frame identity*, so two live/stale activations of the same method are
  indistinguishable (right name, wrong dex_pc / wrong activation), and the uncorroborated
  fallback can emit a wholly wrong `name?`. The **authoritative** path already exists
  (`src/common/art_shadow.c` reads ART's real `ShadowFrame.method_`, no guessing); it
  should be primary and the guess-path the fallback (tracked as "Path Y").

Strategic: this is the largest, most fragile surface in the repo, for best-effort output
on a tool whose real edge is stealthy syscalls. Consider labeling managed naming clearly
experimental so a silent BuildID miss doesn't read as "app used no Java," and finish the
authoritative-path migration before sinking more into offset tables.

### AA3 — `trace`↔engine driver ABI held by two hand-maintained lists, no compile check

Source: 2026-07-07 graph-informed audit. `trace.c:23-31` hand-declares the nine engine
entry-point prototypes (`syscalls_setup/_run/_teardown`, `funcs_*`, `lib_*`) inline,
noting it does so "to avoid pulling in each engine's header." The Makefile
independently keeps those same symbols global per engine via `--keep-global-symbol`
lists (`Makefile:307-342`) — for all five engines, though `trace` only wires three.

A signature change to any engine's `*_setup`/`*_run`/`*_teardown` produces **no compile
error** in `trace.c` — the linker resolves the localized-but-kept symbol against a stale
hand-written prototype, i.e. a silent ABI mismatch / UB at the coordinator boundary. The
Makefile keep-list and the `trace.c` prototype list also have no mechanism keeping them
in sync; drift in either is invisible until runtime. This is the same class of
convention-over-enforcement fragility as the tracked `cmd_*` partial-link/localization
hack, but on the coordinator-driver contract specifically, which the thin-presets
refactor note doesn't obviously cover.

Actionable: introduce one shared header (e.g. `common/engine_driver.h`) declaring the
`{ setup; run; teardown; }` driver contract per engine, include it from both the engines
and `trace.c`, and derive/generate the `--keep-global-symbol` list from it so the two
lists can't diverge silently.

---

## Minor — cleanups, perf nits, cosmetic, verification

- **CR5 follow-on: MCP-side `coverage` ingest handler.** `ares_coverage_report`
  writes `{"type":"coverage","engine":...}` to the `-o` sink, but
  `tools/ares-mcp/trace_store.py`'s `load_structured` has no branch for it (only
  `type:"syscall"` rows load into DuckDB today) and `server.py` has no tool
  surfacing it. Add a `coverage` branch that stores the record(s) alongside the
  trace and a small MCP tool (or a field on `overview`) that surfaces per-engine
  coverage so an MCP client can check "was this trace clean" without grepping
  the raw JSONL.

- **CR5 follow-on: `dump` coverage field.** `dump`/`lib` are exempt from CR5 v1
  (no drop map, single-shot read). `dump`'s live-memory read
  (`src/dump/rebuild.c`) can still hit partial `/proc/<pid>/mem` reads or an ELF
  rebuild gap (missing section, truncated segment); a minimal `ares_coverage`
  record for `dump` (no snapshot/CFI/managed fields, just a "the rebuilt ELF is
  incomplete" signal) would close that exemption without inventing new schema.

- **W5 — JIT code-cache frames have no file-backed CFI (deferred, ≈0 payoff).**
  JIT-compiled Java frames (`[anon]` / `[anon_shmem:dalvik-jit-code-cache]`) between
  a framework lib and `art_jni_trampoline` have no file-backed FDE; `cfi_get` skips
  pseudo paths → NULL → unwind stops. ART publishes per-method unwind info as
  in-memory mini-ELFs (with `.eh_frame`) via the GDB JIT interface — ARES already
  reads these for *symbols* (`jit_resolve` / `art_refresh`); extend that path to
  `cfi_load_elf` the mini-ELF and feed `cfi_get`. Demoted: JIT `[anon]` frames appear
  in only 9/201 stacks on the measured RASP target post-fix. Technically reachable
  now that CFI-misstep is fixed, but not the next wall. (AOT callers in
  `base.odex`/`boot.oat` don't hit this — they have `.debug_frame`.)

- **lib-filter `stack_hits` defect (sidestepped, not fixed).** lib-filter on `libc.so`
  *should* match every `openat` (frame-0 is always `libc!__openat`) yet drops the
  runtime/JNI ones, keeping only native process-init — a real `stack_hits` defect.
  W6-A (capture-all) bypasses it so it no longer gates the JNI cross, but the
  narrow-targeting path is still wrong.

- **Phase 3d (deferred) — coordinator-wide `-p` in `trace`.** The standalone engines
  each support `-p PID[,…]` (shipped 2026-06-30). The `trace` coordinator
  (`src/trace/trace.c`) resolves one UID from `-P` and drives `syscalls`/`funcs`/`lib`
  from a single launch; it does not use `engine_args.h` and has no `-p` today.
  Extending it needs a PID set in `struct ares_run_ctx` (`launch.h`), `-p` wired into
  `trace_args.h`'s bespoke splitter, and each engine's setup reading `rc->pids`.
  Revisit only if a single PID across the whole `trace` run is wanted.

- **C9 — `funcs` could borrow `syscalls`' `decode_sockaddr`** (funcs has no sockaddr
  decoding).

- **R9 residual — syscall table data compiled twice.** `syscall_name()` is now
  nr-indexed O(1) (`src/common/syscall_index.h`; R9 done 2026-07-01), but the table
  *data* is still compiled twice (`syscall_names[]` in `correlate`, `g_sys[]` in
  `syscalls` — two copies of `syscalls_gen.h`). Collapse into one shared
  `common/syscall_table` TU.

- **SW1 — switch-interp ShadowFrame walk follow-ups (non-blocking).** The walk shipped
  and is device-verified (`src/common/art_shadow.c`; see Resolved/Done). Deferred polish:
  - **`art_buildid` ELF-note parser hardening** (`src/common/art_buildid.c`,
    `read_build_id_hex`): section-header fields read at fixed offsets after
    `fread(sh, min(shentsize,64), …)`; a malformed `shentsize < 0x28` reads
    uninitialized `sh[]`. Harmless today (fails closed → gate off), but add a
    `shentsize < 0x28 → skip` guard.
  - **Unused `sf_dex_instr`** in `struct art_offsets` (`src/common/art_buildid.h`):
    populated but never read. Drop it or mark reserved.
  - **BuildID offset-table generalization** — see the Major CFI item; add rows per
    device/ART build.
  - **Formal precision cross-check** — validate named switch-interp frames against an
    in-process ART StackVisitor oracle (must hook `open64`/`__openat`, not only the
    public `openat` ART bypasses, so captures overlap the tracer's `openat` frames).
  - **Liveness tightening (optional)** — the chain is read live at drain (best-effort;
    the thread may have unwound by then). A future variant could capture the
    `ManagedStack` top-of-chain pointer in BPF at the syscall instant for exactness.
  - **`ARES_CFI_DEBUG` `[shadow]` diagnostics** are intentional (match CFI diag
    convention); keep unless a dedicated verbosity split is wanted.

- **N1 — `funcs` CFI/managed-chain runs inline on the drain thread.** In `funcs`
  (`funcs.c` STACK handler) the CFI walk (`cfi_unwind_snapshot`) and managed-chain
  build (`ares_managed_chain`) run inline on the ring-buffer drain thread, whereas
  `syscalls` runs the equivalent work on the worker thread (off the drain path). On the
  loud engine this raises drain latency and can increase drop rate under load.
  Correctness is unaffected (deduped per `stack_id`, bounded `n <= 64`). Deferred:
  move the `funcs` STACK-event CFI/chain work to the worker thread, mirroring `syscalls`.

- **C8 (remaining) — duplicate `vmlinux.h`.** Signal handlers, `dropped`
  map/`bump_dropped()`, and `syscalls_hdr` alias are unified; `vmlinux.h` dedup still
  open.

- **Unified MCP richness (follow-on).** Minimal ingest + span join done; remaining:
  call histograms, timing views, symbol/module filters, full `server.py` tool surface
  for the new types.

- **U1/U2 — console style diverges (not recommended).** `funcs` uses timestamped
  tagged lines (`[spawn] >`, `[uprobe] >`, …); other engines use prose banners. Masked
  under `trace -o`. Low value / high cosmetic churn across 5 files.
  (`[lib]`/`[unlib]` are output lines, not banners — keep their format.)

- **Pending on-device verification:** combined `trace` run; `correlate` hardening
  (R3/R4/X2 — host tests pass, device tier not yet run).

- **`funcs` uprobe fails to load on the current test device (pre-existing, not CR5).**
  On the test device (A15 kernel) `ares funcs -e libc.so!open -J --snapshot -P <pkg>`
  fails the BPF load: `uprobe_open` is rejected with `reg type unsupported for arg#0
  function uprobe_open#N` (-EACCES). Isolated to a pre-existing issue by building the
  pre-CR5 base and reproducing the identical failure (only the subprog index shifts,
  #79 base vs #83 post-CR5) - so CR5 did not cause it. Likely a verifier/kernel
  interaction with the large `uprobe_open` program (java_stack + CFI + span push) on
  this kernel (an outlined `.cold` subprogram carrying `ctx`, or a global-func arg-type
  check). Consequence for CR5: the `funcs` coverage-record wiring is code-reviewed and
  compiles, but its BPF-side additions (COV_TRUNC/COV_DEPTH_CAP bumps via the shared
  headers) are **unverified on any kernel where `funcs` actually loads** - `syscalls`
  (kprobe) and `correlate` are device-verified. Investigate separately: try a kernel
  where `funcs` loads, or reduce `uprobe_open` size / disable hot-cold-split for the BPF
  compile.

- _Checked, not a bug (2026-06-26 audit):_ `correlate`'s `-p`/`-e`/`-F` parsing was
  suspected of unbounded append into `pids[64]`/`specs[64]`, but it is correctly guarded
  with user warnings (`correlate.c:233,242,251`). No action.

- **AA4 — `funcs` per-event O(N) probe-target scan.** Source: 2026-07-07 graph-informed
  audit. `find_target_by_entry_addr` linear-scans `probe_targets[]` (up to
  `probe_target_count`, cap 4096) per CALL (`funcs.c:508`) and per RETURN (`funcs.c:607`)
  — even the fast path (`funcs.c:336-339`) is O(N); the `/proc/maps`-miss fallback
  (`:356-390`) adds a `strcmp` per row on top. Under a broad `-I/-i` regex resolving
  thousands of symbols this is the dominant per-event cost on the worker thread. Fix:
  add an `runtime_entry_addr → probe_target_t*` hash (mirrors the existing `sc_ent`/
  `fdc_ent` tables), populated where `runtime_entry_addr` is first assigned
  (`funcs.c:359,392`); fall back to the scan only on a hash miss.

- **AA5 — `cfi_unwind_snapshot` per-frame invariant rescans.** Source: 2026-07-07
  graph-informed audit. `pm_get(pid)` is called *inside* the per-frame unwind loop
  (`symbolize.c:296`) though `pid` never changes across a stack's frames; `cfi_get`/
  `dynsym_get` are linear scans with `strcmp` over every cached module
  (`sym_elf.c:450-453,321-323`). A 64-frame unwind does 64 redundant pid-table scans
  plus 64 module-table `strcmp` walks over every ELF the process has ever cached
  (dozens–hundreds on a real app). Fix: hoist `pm_get(pid)` out of the loop in
  `cfi_unwind_snapshot`; hash the `cfi_get`/`dynsym_get` caches on `(elf_off, path)` or
  intern the path pointer for identity compares instead of `strcmp`. Do together with
  AA1 (same function — add the lock and hoist `pm_get` in one pass).

- **AA6 — MCP `load_structured` per-row DuckDB insert loop.** Source: 2026-07-07
  graph-informed audit. `tools/ares-mcp/trace_store.py:171-186` issues one
  `con.execute("INSERT ... VALUES", ...)` per record across four Python loops for
  funcs/correlate records — O(rows) Python↔DuckDB round-trips, unlike the syscall
  loader's bulk `read_json(...)` path (`trace_store.py:65-69`). Visibly slow on large
  funcs/correlate traces for no structural reason. Fix: load via `read_json(path,
  format='newline_delimited', ...)` filtered by `type` in SQL (as `load()` does), or at
  minimum `executemany`/the DuckDB Appender.

- **AA7 — `syscalls` `json_emit` per-event attribute table scans.** Source: 2026-07-07
  graph-informed audit. Unlike `syscall_name()` (R9: nr-indexed O(1)), the sibling
  attribute tables are still linear scans per event: `arg_count` over `g_argc`
  (`syscalls.c:89-95`), `arg_fd_mask` over `g_fd_args` (`:489-495`), `arg_sock_index`
  over `g_sock_args` (`:513-519`); `json_emit` also recomputes `arg_fd_mask(e->nr)` once
  per *argument* inside its decode loop (`:662` then again `:675`), not once per event.
  Fix: build `by_nr[512]` indexes for each attribute at setup (same pattern as
  `ares_sysindex`), and hoist the per-record `arg_fd_mask`/`arg_count` calls in
  `json_emit` out of the per-argument loop.

- **AA8 — MCP `wx_scan` O(m²·log m) writable-range re-sort.** Source: 2026-07-07
  graph-informed audit. `add_ivl` appends then re-sorts and re-merges the *entire*
  accumulated `ever_w` list on every writable mapping (`trace_store.py:535-544`, called
  per W mapping at `:583-584`) — O(m²·log m) over *m* writable mmap/mprotect events,
  worst on exactly the packer/JIT-heavy RASP workloads `wx_scan` targets. Fix:
  `bisect.insort` + merge only the neighbors of the inserted interval (O(m) amortized),
  or collect all W intervals and sort+merge once.

- **AA9 — managed-chain per-stack 8 KB alloc churn + double frame symbolization.**
  Source: 2026-07-07 graph-informed audit. `ares_managed_chain` heap-allocates a `jbuf`
  whose first `jb_need` floors at 8192 bytes (`managed_frame.c:43`; `emit.c:16`), freed
  at `managed_frame.c:62-66`, once per distinct CFI stack — for an output fragment
  capped at `JC_FRAG=208` bytes. Separately, `emit_cfi_backtrace` symbolizes every frame
  twice per snapshot: `ares_emit_cfi_stack_json` resolves each frame (`symbolize.c:395`)
  and `ares_managed_chain` resolves the same frames again (`symbolize.c:368`), each
  under `g_lock` with its own `snprintf`. Fix: format `ares_managed_chain_build` into a
  small stack buffer sized to `cap` instead of a heap `jbuf`; resolve frame symbols once
  per snapshot and hand the resolved array to both call sites.

---

## Resolved / Done

Reverse-chronological. Identifiers preserved for traceability; full technical detail
is in DOCUMENTATION.md and the referenced specs.

### 2026-07-07

- **CR5 follow-on: `mod` coverage (fixed) — closes Tier 2.** `mod.c` now builds a
  minimal `struct ares_coverage { .engine = <analyzer name>, .ring_drops = <count> }`
  at teardown and reports it via `ares_coverage_report(&g_sink, &cov)`, replacing the
  legacy `ares_drops_report` call the drop-telemetry-parity fix added — `mod` now
  emits the same `{"type":"coverage",...}` JSON line (when `-o` is set) and
  `[coverage] <analyzer>: ...` stderr banner syscalls/funcs/correlate already do.
  `ares_coverage_report`'s own `if (sink && sink->f)` guard makes passing `&g_sink`
  safe even when `-o` was never given (banner only, no JSON). `DOCUMENTATION.md` §7.5
  updated: `mod` moved out of the "exempt in v1" list into its own minimal-variant
  note (no snapshot/CFI/managed-naming/decode surface, only `drops.ring`).
  Host-verified: `make test` unchanged; `mod.c` syntax-checked clean directly
  (`cc -fsyntax-only`, 0 errors — this file, unlike the 3 analyzer `.c` files touched
  by drop-telemetry parity, doesn't depend on the stale committed skeleton headers).
  This closes out Tier 2 (tasks #6–#10) of the 2026-07-07 graph-informed audit
  entirely.

- **`mod` drop-telemetry parity (fixed).** `ares_analyzer_t` (`src/common/analyzer.h`)
  gains a `drops()` accessor; all 3 analyzer BPF objects (`proc_event.bpf.c`,
  `execve.bpf.c`, `prop_read.bpf.c`) now `#include "common/bpf_drop.bpf.h"` and call
  `bump_dropped()` at every `bpf_ringbuf_reserve` failure (mirroring
  syscalls/funcs/correlate's existing pattern; `prop_read` needed only one call site
  since every event path already funnels through its shared `reserve_prop_event()`
  helper). Each analyzer's `.c` gets a matching `*_drops()` accessor
  (`ares_drops_read(bpf_map__fd(g_skel->maps.dropped))`) wired into its registration
  struct. `mod.c` reads the drop count via `an->drops()` **before** `an->teardown()`
  destroys the skeleton (the fd goes with it), then reports via the still-live
  `ares_drops_report` — `mod` previously had no drop signal at all. CR5 follow-on
  (swap that report call for `ares_coverage_report`) is the natural next step, tracked
  separately in Major. Host-verified (`make test` unchanged); `mod.c` syntax-checked
  clean directly. `proc_event.c`/`execve.c` couldn't be syntax-checked against the
  committed `build/*.skel.h` skeletons — those predate the entire PID-attach feature
  (dated 2026-06-28 vs. source's 2026-07-07; missing `target_pids`/`ares_follow_fork`
  entirely, not just the new `dropped` map), a pre-existing build-artifact staleness
  unrelated to this change, confirmed by the same "missing member" errors appearing on
  untouched pre-existing lines. `prop_read.c` blocked by missing `libelf-dev`. All are
  environment gaps (no aarch64 cross-toolchain / `clang -target bpf` / `libelf-dev` in
  this sandbox) rather than a code issue — every edit was applied via exact-anchor
  `Edit` against freshly-read source and manually reviewed for brace balance.

- **AA10/AA11/AA12 — engine setup/teardown parity batch (fixed).** Three small
  cross-engine inconsistencies closed together (Tier 2 of the graph-informed audit):
  **AA10** — `funcs.c`'s `--siblings` loop (`:1068-1076`) no longer installs UID 0
  when `ares_get_pid_uid` returns `0`; `correlate.c`'s equivalent loop (`:325-329`)
  now guards `install_uid` with `uid > 0` so a deliberate skip no longer prints
  `"install UID for PID N failed"` — both aligned to the silent-skip pattern
  syscalls/lib/dump already used. `install_uid()`'s body is untouched, preserving its
  second, genuinely-fatal caller on the `-P`/`-p` primary path (`correlate.c:311`).
  **AA11** — `syscalls.c`'s `out:` setup-failure block and `correlate.c`'s
  `err_skel:` block now `bpf_link__destroy(g_ff)` before falling through (previously
  only normal teardown did, which isn't reached on setup failure). **AA12** — (a)
  `syscalls.c`, `lib.c`, and `correlate.c`'s setup-failure paths now call
  `ares_sink_report()` after `ares_sink_close()`, matching `funcs`' existing behavior,
  so `"wrote 0 events to X"` now prints uniformly on a genuine setup failure instead
  of only for `funcs`; (b) `mod.c`'s own setup-fail and launch-fail paths do the same
  close+report pairing its success path already did; (c) `correlate.c`'s redundant
  inline `destroy_uprobe_links()` call on the ring-buffer-fail line (`:350`) removed —
  `err_skel:` already calls it. Host-verified (`make test` unchanged, all suites
  pass); full engine-binary compilation needs `libelf-dev` + the aarch64 cross-
  toolchain, neither present in this environment (same gap as the AA1/AA2 fixes) — the
  diffs were verified by exact-anchor `Edit` application against freshly-read source
  plus manual brace-balance review of the composed regions, not a full build.

- **AA2 — detectability-firewall runtime classifier fails open + dead enforcement fn
  (fixed).** `ares_object_writes_target` (`src/common/capabilities.c`) now returns
  `true` (loud) for a `NULL` or unregistered capability name instead of `false`
  (quiet) — fail closed. `src/modules/mod.c`'s loudness classify+print now happens
  right after `find_analyzer()` succeeds, before `an->setup()` can load or attach
  any BPF object (previously classified only after setup). The classify call itself
  now goes through `ares_quiet_config_ok(&mod_key, 1)` instead of the direct
  `ares_object_writes_target` call, giving the previously-dead runtime-assertion
  helper a real caller. `tests/test_capabilities.c`'s `unknown -> false` assertion
  updated to `unknown -> true (fail closed)` — the one behavior change the fix makes;
  every other registered capability's classification is unchanged.
  Also closed alongside: **CR1's `--selftest` gap** — `scripts/check-firewall.sh
  --selftest` previously only proved the `uprobe_sections`/`nm` primitives work; a
  new arm C drives the real gate routing (`check_sections`/`check_attach_whitelist`,
  via `map_bpf_obj`/`owner_of`/`is_loud`) against a throwaway build tree (`BUILD`
  overridden only inside a subshell — never touches the real `build/` or source),
  asserting a `FIREWALL BREACH` fires on an injected quiet-capability violation.
  Verified by deliberately neutering `check_attach_whitelist`'s `breach()` call and
  confirming the new arm caught it (selftest FAILED), then reverting. Host-verified
  (`make test` — updated `test_capabilities` passes 14/14; `--selftest` passes with
  `LLVM_NM=nm LLVM_OBJDUMP=objdump` overrides on a host without `llvm-nm`/`clang`).
  `make check-firewall` itself needs the aarch64 cross-toolchain, not present in this
  environment — the edits don't change any currently-registered capability's Check
  A/B verdict (only the unknown-name fallback and print timing), so this is a
  low-risk gap, not a skipped verification of the actual change.

- **AA1 — `trace` combined-run symbolizer data race (fixed).** `cfi_unwind_snapshot`
  (`src/common/symbolize.c`) mutated the shared symbolizer caches (`pm_get`/
  `read_proc_maps` realloc `g_pm`'s array and LRU-evict other pids' cached state;
  `cfi_get` reallocs its own cache in `sym_elf.c`) without taking `g_lock`, unlike
  `sym_resolve`/`sym_flush_pid` which already serialize on it. `trace` runs
  `syscalls_run` + `funcs_run` concurrently (`trace.c:170-171`), both calling
  `cfi_unwind_snapshot` — a real cross-thread race (torn read / use-after-realloc /
  double-evict) in the combined run; `trace.c`'s own comment claiming per-engine
  "symbol-localized globals" was the wrong assumption that let it go unnoticed. Fix:
  hold `g_lock` for the whole per-frame walk and hoist the loop-invariant
  `pm_get(pid)` call to once per walk instead of once per frame (folds in AA5's
  `pm_get` finding, same function). Corrected the stale `trace.c` comment.
  Host-verified only (`make test` unchanged, no behavioral diff for single-threaded
  callers); real confirmation is the already-tracked "pending on-device verification:
  combined `trace` run" (Minor) — this fix rides that same verification pass rather
  than a new item.

### 2026-07-05

- **CR1 - detectability firewall mechanized as a build gate.** The firewall's
  unchecked half ("a quiet object carries no uprobe") is now enforced.
  `tools/capdump.c` compiles the `capabilities.c` loudness table to `name\t0|1`
  rows; `scripts/check-firewall.sh` asserts, off those rows, that each quiet
  `.bpf.o` has zero prefix-anchored `uprobe`/`uretprobe` sections and each loud
  one does (Check A, bidirectional), and that `bpf_program__attach_uprobe` is
  referenced only in loud-owned engine objects (Check B, whitelist over
  `llvm-nm`, excluding vendored libbpf + `.part.o`). A row with no `.bpf.o` map
  fails (drift guard). `--selftest` injects a uprobe section and an attach ref
  into throwaway copies and asserts the gate flags both, so it can't rot to a
  vacuous pass. `make check-firewall` + a CI step (after the cross-build) run
  it every PR. Section match is prefix-anchored to avoid the `kprobe/uprobe_mmap`
  grep-trap CR1 called out. Spec/plan:
  `docs/superpowers/{specs/2026-07-05-firewall-gate-design.md,plans/2026-07-05-firewall-gate.md}`.

- **CR5 - per-run coverage-health record.** Every degradation site (truncated
  32 KB snapshot, blind CFI stop, ring/queue drop, unknown ART build, stack-
  depth cap, the CR2 pre-arm window, undecoded/raw syscall args) used to fail
  silently. `struct ares_coverage` (`src/common/coverage.h`/`.c`) plus
  `ares_coverage_report` now emit exactly one record per engine at teardown on
  two channels: a `[coverage] <engine>: ...` stderr banner (human) and a
  `{"type":"coverage","engine":...}` JSON line into the `-o` sink
  (machine/MCP), collapsing to `{"clean":true}` on a clean run. Wired into
  `syscalls`, `funcs`, and `correlate` (each with its own field subset - see
  DOCUMENTATION.md §7.5); subsumes the old `ares_drops_report` (drops are now
  coverage fields). `lib`/`dump`/`mod` are exempt in v1 (follow-on rows below).
  Generalizes the "silence never means didn't check" contract from a
  drops-only guarantee to the whole tracer.

### 2026-07-02

- **#3-B — `ARES_ART_OFFSETS` runtime offset-override seam.** A `key=value` row file
  (`buildid=` + the 13 unified offsets; `#` comments/whitespace tolerated) parsed by the pure
  host-tested `art_offsets_parse`; `art_buildid_offsets` consults it once per process and
  returns the override **only when its BuildID matches** the running libart (else fall through
  to `k_table` — fail-closed on mismatch, malformed, or unreadable, each a one-time warn).
  Lets a new device/ART build's hand-pinned offsets iterate against the `scripts/nterp-oracle/`
  validator without recompiling, then bake into `k_table`. Reads-only (own-process file); no
  target write. Host-tested (parse valid/missing/unknown/whitespace); device-verified on apex
  `370549100` (override note fires, app interp methods named identically to the compiled row;
  bad-path negative ignores + still names via `k_table`). Spec/plan:
  `docs/superpowers/{specs/2026-07-02-art-offsets-override-design.md,plans/2026-07-02-art-offsets-override.md}`.

- **#3-A — BuildID unification of managed-frame offset tables.** The nterp and
  ShadowFrame naming paths now resolve their version-coupled offsets through one
  BuildID-keyed `struct art_offsets` via `art_buildid_offsets(pid)`; the nterp
  path's compile-time `#define` offsets became struct fields (threaded as
  `const struct art_offsets *o` through `art_method_chase`/`art_method_resolve`/
  `nterp_pick`/`nterp_chain_pick` + `shadow_frame_pick`), and the `/apex`
  `KNOWN_ART_APEX` version gate + `art_version_ok()` were retired. Unknown build →
  clean dual no-op + a one-time notice (suppressed on transient pids whose libart
  BuildID can't be read). Unused `sf_dex_instr` dropped. Firewall unchanged
  (reads-only). Host-tested (`test_art_buildid` both families, `test_art_nterp` via
  a test offsets struct) and device-verified on apex `370549100` (naming preserved:
  the neutral app's own interpreted methods named, BuildID gate resolves). Onboarding
  a new device is now one `k_table` row. Remaining #3 breadth tracked under the CFI
  "generalize beyond one ART build" item: (B) on-device row-confirm helper, (C) formal
  precision oracle closure. Spec/plan:
  `docs/superpowers/specs/2026-07-02-buildid-unification-design.md`,
  `docs/superpowers/plans/2026-07-02-buildid-unification.md`.

- **BLD1 — BPF→skeleton→binary dependency graph reconnected.** Replaced the
  hand-maintained plain-header prerequisite lists (which missed shared headers like
  `stack_snapshot.h`, silently shipping a stale BPF struct — 0 snapshots, no error)
  with compiler-generated `-MMD -MP` dependencies on both the BPF and userspace
  compile classes, `-include`d at the Makefile tail; generated skeletons/table +
  `vmlinux.h` + `libbpf.a` stay explicit for first-build ordering. Guarded by
  `scripts/check-build-deps.sh` (touches `stack_snapshot.h`, asserts the BPF object,
  the userspace reader, and the final link all go out of date) wired into the CI
  cross-build via `ARES_CHECK_DEPS=1`. `make clean && make` is no longer required
  after a shared-header change.

- **Full interpreted-chain naming (`nterp_chain`) + TBI-tagged DexFile fix.** The nterp
  resolver now names the *entire* interpreted call chain, not just the terminal frame.
  `nterp_chain`/`nterp_chain_pick` (`src/common/art_nterp.c`) scan the frozen snapshot
  upward from the nterp terminal and emit every dex_pc-corroborated frame (innermost-first,
  `+0x<dexpc>` suffix) as consecutive `"kind":"interp"` cfi_stack frames; uncorroborated
  candidates are dropped (precision over recall). `nterp_name` stays the single-frame
  fallback (naming never regresses). Wired at both `symbolize.c` sites (`ares_managed_chain`,
  `ares_emit_cfi_stack_json`); `ares_managed_chain_build` now takes a chain of names.
  **Root-cause fix shipped alongside:** `art_method_chase` did not strip the Android
  top-byte pointer tag (TBI) from the native `DexCache.dex_file_` / `DexFile.begin_`
  pointers, so on targets that tag them the chase read a tagged address (`/proc/mem`
  rejects it) → `begin=0` → chase aborted → nterp naming silently resolved **nothing**.
  `ART_PTR_UNTAG` fixes it (host regression in `test_art_nterp`). Device-verified on the
  real RASP target: interpreted naming went 0 → deep chains (13+ frames; 85 multi-frame
  `cfi_stack` records in one run). Host-covered by `test_art_nterp` (chain + tagged-ptr)
  and `test_managed_frame` (multi-name build). Reads-only; firewall intact.

- **Switch-interpreter ShadowFrame walk (SW1 core) — shipped, device-verified.**
  `src/common/art_shadow.{c,h}` names interpreted app Java methods at an
  `ExecuteSwitchImpl` `cfi_stack` terminal via ART's live `Thread → ManagedStack →
  ShadowFrame` chain (the authoritative, version-coupled path for **off-stack**
  switch-interpreter frames that `nterp_chain`'s on-stack scan can't reach). Names on the
  authoritative `method_`, dex_pc suffix best-effort; reads-only, BuildID-gated default-off;
  wired in `symbolize.c`. Follow-up polish tracked as SW1 in Minor. Commits `1df257d`,
  `4135f85`.

### 2026-07-01

- **`java_stack` inline managed chain + funcs `cfi_stack` parity (Tasks 1–5).** Shared
  `ares_managed_frame_chain_build` extractor + `ares_jcache_{put,get,reset}` `stack_id`
  cache (thread-safe via mutex), both engines' CFI walks populate the cache on STACK
  events. `syscalls` and `funcs` CALL/RETURN records now carry optional `"java_stack":[...]`
  field (innermost-first, native frames elided) when a managed caller resolves; emitted
  only under `--snapshot` + `-o`. `funcs` now also writes `{"type":"cfi_stack",...}` records
  to its sidecar (parity with syscalls). Best-effort: AOT-compiled Java frames are reliable;
  interpreted (nterp) frames inherit documented precision/~39% hit-rate limits; the
  authoritative full native+managed walk stays in the `.stacks` sidecar, joinable by
  `stack_id`. **Residuals (resolve later):** (a) `correlate` not covered; (b) both `syscalls`
  and `funcs` each walk CFI on the STACK event (funcs' walk is net-new); (c) `java_stack`
  inherits nterp precision limits; (d) `ares_jcache_get` returns an internal pointer released
  before the caller copies it — a rare torn-string race under concurrent same-slot access,
  worth hardening later.

- **nterp naming precision — dex_pc corroboration + `+0x<dexpc>` suffix.** The nterp
  locator (`art_nterp.c`) no longer names the first resolvable `ArtMethod*` (which
  could be a stale spill → real-but-wrong method). It now accepts only a candidate
  the frame *corroborates* — a live dex_pc on the stack pointing into that same
  method's bytecode (via new `dex_lookup_range`, reusing existing code_item ranges;
  no nterp frame-layout offsets). The corroborating dex_pc yields the previously
  deferred `+0x<dexpc>` suffix. With false positives filtered structurally, the scan
  window widened 4096→8192 for hit-rate. Reads-only; firewall intact. Host-covered
  by `test_dex` (range lookup) + `test_art_nterp` (stale-vs-real selection, suffix,
  fallback). **Residual:** uncorroborated candidates fall back to a bare name, but retain
  the pre-fix wrong-method risk; full precision requires the ART `Thread→ManagedStack`
  walk (shipped as SW1, 2026-07-02).

- **R9 — `syscall_name()` nr-indexed O(1) lookup.** Both `correlate`'s `syscall_name`
  and `syscalls`' `sysname` now use an nr-indexed lookup (`src/common/syscall_index.h`,
  header-only `static inline`), built once at engine setup; O(1) hot path, retained cold
  linear fallback for `nr >= 512`. Host-tested (`tests/test_syscall_index.c`). Each
  engine's fallback string unchanged. **Residual (tracked in Minor):** the generated table
  *data* is still compiled twice (two copies of `syscalls_gen.h`).

- **Drop-telemetry parity — `correlate`.** `correlate` now shares `bpf_drop.bpf.h`
  (bump on both reserve sites) and reports at teardown (qdrops=0, no worker queue).
  `trace` already inherits its sub-engines' reports; `dump` is exempt (single-shot
  dumper). **`mod` still silent** — see Minor.

- **Drop the 6 MB committed `vmlinux.btf`.** Untracked + gitignored; `make regen-vmlinux
  ARES_VMLINUX_BTF=<btf>` regenerates the committed `vmlinux.h` (default
  `/sys/kernel/btf/vmlinux`). Regen guide in DOCUMENTATION.md.

### 2026-06-30

- **Global PID-attach mode — Phases 1–3 (all 6 standalone engines).** Real per-process
  PID-attach across every standalone engine (`funcs`, `correlate`, `dump`, `syscalls`, `lib`,
  `mod`). Shared infrastructure in `src/common/`: `pid_filter.bpf.h` (TGID-keyed
  `target_pids` map + `pid_matches()`), `follow_fork.bpf.h` (`ares_follow_fork` tracepoint
  self-propagates tracked TGIDs to forked children), `engine_args.h` (`struct target_args`,
  `TARGET_ARGP_OPTIONS`, `parse_target_arg` — `-p`/`--siblings`/`--no-follow-fork`). BPF
  gate in every engine is now `uid_matches() || pid_matches()`. Semantics: `-p` is precise
  (only listed TGIDs + forked children); `--siblings` also arms the PID's UID (widen);
  `--no-follow-fork` disables child-following. Phase 3d (coordinator-wide `-p` in `trace`)
  deferred — see Minor. Supersedes the old broken per-engine `-p` (F2) and the launch-only
  `ares mod` design (F1). Host-covered by `test_target_args`.

- **CFI-misstep (module_base gapped walk-back) — device-verified.**
  `ares_module_base_idx` (`src/common/maps.c`) now bridges gaps between inter-segment
  mappings using a monotonic offset walk-back (commit `73a9ceb`) and skips `[page size
  compat]` filler mappings (commit `e8fd9e2`). Root cause: `cfi_get` was handed
  `elf_off = 0xe0000` / exec-segment `load_base` instead of `0` / RO start, because the
  old strict-contiguity walk-back stopped at libandroid_runtime's 1-page RO→exec gap and
  returned the wrong base. The CFI walk now crosses `art_jni_trampoline` into AOT-compiled
  Java (`boot.oat!android.os.BinderProxy.transact`, full `…→ActivityThread.main` chains;
  ~95 crossings on deskclock). Blast radius beyond CFI: symbol naming also improved for
  gapped libs. Diagnostic instrumentation commits: `cd0c628`, `d861340`, `275d3a2`,
  `8b35511`. Spec: `docs/superpowers/specs/2026-06-29-cfi-misstep-fix-module-base-design.md`.

- **PAC `negate_ra_state` — device-verified.** ART apex libs (`libart`, `libjavacore`,
  `libnativeloader`, `libartbase`, `libdexfile`) are PAC-built and emit
  `DW_CFA_AARCH64_negate_ra_state` (opcode `0x2d`); the CFI program interpreter previously
  hit `default: return -1` → terminal `CFI_RUN_FAIL` (dominant failure: 167/201, 83%).
  Fix: `c905f78` (`ares_pac_strip` helper), `e2e026a` (handle opcode `0x2d` + `ra_signed`
  row state through remember/restore), `655314f` (PAC-strip recovered RA in `cfi_step`),
  `63f1570` (device-test arm asserts 0 `CFI_RUN_FAIL`). Measured on a real RASP-protected
  target: `CFI_RUN_FAIL` **167/201 → 0**; `art_jni_trampoline` crossings **59 → 131**;
  reached-managed-frame **21 → 74**. Re-measure:
  `docs/superpowers/research/2026-06-30-cfi-pac-fix-remeasure-findings.md`.

### 2026-06-29

- **W3-window — chunked fault-tolerant stack-snapshot capture (+ re-diagnosis of the JNI
  cross blocker).** Replaced the all-or-nothing 3-tier `bpf_probe_read_user` in
  `ares_emit_stack_snapshot` (`src/common/stack_snapshot.bpf.h`) with a bounded,
  fully-unrolled, no-`break` per-chunk loop (`ARES_SNAP_CHUNK` = 4 KB, `stack_snapshot.h`
  + `_Static_assert`) that stops at the first faulting page and keeps the full contiguous
  prefix; `truncated` redefined to `snap_len == ARES_SNAP_MAX`. Host guard test for non-tier
  `snap_len` round-trip (`tests/test_stack_snapshot.c`); device-test CFI arm asserts
  `snap_len>8192` + `jni-trampoline` reach. On-device: `snap_len` went bimodal-8192/32768 →
  4096→32768 spread (238/312 records >8 KB). **Key result — the window was never the cross
  blocker:** with 20–32 KB captured the walk still died one frame short at a non-code
  `libandroid_runtime.so+0xd6054` (`.eh_frame`, no FDE), re-framing the wall → CFI-misstep
  (fixed 2026-06-30). Commits `b6bbe42`, `be59585`, `022b31b`.

- **W6-A — capture-all stack snapshots (decouple snapshot capture from lib-filter).**
  Dropped the `!capture_all` term in the `want_snapshots` gate (`syscalls.c`); host-testable
  predicates extracted to `src/syscalls/snapshot_gate.h` (`sysc_want_snapshots`,
  `sysc_snapshot_firehose_warn`) with `tests/test_snapshot_gate.c`. Warn-and-proceed firehose
  guard when `-a --snapshot` has no `-s`/`-x` filter. `device-test.sh` CFI arm repointed at
  `-a`. On-device: `.stacks` sidecar 0 → 307 records under capture-all. Closes W6. Commits
  `8992405`, `b73134d`, `0bd983e`. The narrow lib-filter `stack_hits` defect it sidesteps is
  tracked in Minor.

- **Maps-cache staleness fix — capture-all CFI unwinds past frame 0.** Under capture-all the
  symbolizer first reads a pid's `/proc/<pid>/maps` mid-launch (libc not yet at its final
  base) and caches it; the `REFRESH_MS=250` throttle suppressed the corrective re-read during
  the drain burst, so snapshot PCs resolved `[unmapped]` and the CFI walk died at frame 0.
  Factored refresh-on-miss into a shared `find_mapping_refresh` (used by `sym_resolve` + the
  CFI walk) and added a one-shot throttle-ignoring re-read in `cfi_unwind_snapshot` (bounded
  by per-distinct-stack dedup). On-device: unwinds went 1-frame → full native chain. Commit
  `fd4138a`.

### 2026-06-28

- **B1 — prop-read RASP summary was silently empty under `-o` (was Urgent).**
  `prop_stat_add()` calls hoisted out of the `if (!mc->quiet)` guard in
  `src/modules/prop_read.c`. Tally now always runs; `pr_print_summary` prints correctly
  whether or not `-o` is active.

- **proc-event/execve/prop-read → `ares mod` migration (Phases 1–3).** SPAWN/PROC_EXIT/EXECVE/PROP
  events migrated from the open `funcs` module-events backlog to the `ares mod` analyzer subsystem
  (proc-event, execve, prop-read); output channel in `src/modules/mod_emit.c`. Closes the
  SPAWN/PROC_EXIT/EXECVE/PROP deferred item and retires B2 as moot.

- **funcs structured records — module events.** CALL/RETURN + MAP/UNMAP (via
  `ares_libtrace_emit_lib/unlib` under `g_sink_lock`, Option A) + SPAWN/PROC_EXIT/EXECVE/PROP
  (via the `ares mod` migration above). B2 (worker-queue convergence) moot — module events no
  longer route through the funcs worker queue.

- **`ares mod` audit (F1/F2/F3/F4, U1/U2/U3, O1/O2/O3).** Audit closed 2026-06-28.
  UX: `mod_options` hand-picks `-o/-v/-q` (U1); `-v` scoped execve-only (U2); per-analyzer
  banners removed (U3). Output: execve prefix `[exec]` (O1); structured execve backtrace
  symbolized via `mod_emit_execve(..., syms)` (O2); prop SCAN fields trimmed to
  `type/op/pid/tid/comm` (O3). Functionality: global PID-attach shipped (F1, see 2026-06-30);
  F2 moot (superseded); proc-event/execve summaries added (F3); F4 moot (no `-b` to wire).

### 2026-06-27 (session 5)

- **W1 — CFI unwinder wired to runtime.** `cfi_unwind_snapshot` (`src/common/symbolize.c`,
  declared in `symbolize.h`) loops `cfi_get` + `cfi_step` over the frozen snapshot window
  (reads only `snap->snap[]` — no live target memory). Called from `emit_cfi_backtrace`
  (`syscalls.c`) after each raw `{"type":"stack"}` sidecar write; emits a companion
  `{"type":"cfi_stack","stack_id":N,"cfi_backtrace":[{frame,addr,symbol,kind},…]}` with
  `kind ∈ native | jni-trampoline | managed | interp`. `cfi_unwind.c` + `dwarf.c` added to
  `COMMON_CSRC`; exported via `COMMON_API`. The RA-default fix (commit `ee5ed5f`) took native
  unwinding from 1 frame to the full 18-frame libc→linker64 chain.

- **W4 — snapshot window 8 KB → 32 KB + 3-tier fault fallback.** Deep frames' spilled-RA
  slots sat past `sp+8192`; `ARES_SNAP_MAX` raised to 32768 with a `MAX → MID(8192) →
  SMALL(2048)` read cascade (fault on the big read still yields a useful window).
  **Superseded 2026-06-29 by W3-window** — on-device the 32 KB read itself faults to 8 KB in
  259/307 cases, so chunked capture became the required fix, not this fallback.

- **GA6 (keystone) — `ares_launch_app` returns the launched PID; `correlate` dedups its
  inline launcher.** Added `pid_t *out_pid` out-param to `ares_launch_app` (`launch.{c,h}`);
  polls `pidof` after `am start -S` when non-NULL. `correlate_setup` replaces ~14 lines of
  duplicated force-stop/resolve-component/am-start/pidof with a single `ares_launch_app(pkg, NULL, &p)`
  call. Five other callers add `, NULL` — interface contract unchanged.
- **GA7 — `probe_resolve` no-PT_LOAD sentinel.** `seg_vaddr_to_off` and `vaddr_to_file_off` now
  return `SEG_VADDR_BAD` (`(unsigned long)-1`) instead of the raw vaddr when no PT_LOAD segment
  contains the address. All four callers guard the sentinel and skip+warn rather than attaching
  a uprobe at a wrong file offset. Commit `7995126`.
- **GA5 — `trace` coordinator SIGTERM.** Replaced the hand-rolled `on_sigint` in `trace.c`
  with `ares_install_stop_handler(&g_stop)`. `trace` now responds to SIGTERM identically to
  SIGINT. Bundled in commit `97c827f` with GA4.
- **GA4 — event-queue pop desync.** `ares_evq_pop` now loops: reads the 4-byte length, copies
  if it fits, else advances `tail` by the full `sz` (keeping the ring framed), increments
  `dropped`, and fetches the next record — never handing back a truncated record.
  `test_evqueue` extended (26 checks). Bundled in commit `97c827f`.
- **GA3 — sink write errors.** `ares_sink_emit` latches `errno` into `s->werr` on `ferror` and
  periodic `fflush`; `_flush`/`_close` latch on failure; `_report` prints a WARNING if set.
  `setvbuf` malloc leak fixed. `test_emit` extended (23 checks). Commit `478c679`.

### 2026-06-26 (session 4)

- **GA1 — `jbuf` OOM path is a heap overflow (fixed).** Added `int err` field to
  `struct jbuf` (`emit.h`); `jb_need` sets it on failed `realloc`; every `jb_*` writer
  bails early when set; `ares_sink_emit` drops and resets a poisoned record. Regression
  test in `tests/test_emit.c` (21 checks total).
- **GA2 (core) — Engine lifecycle symmetry + `lib`→`trace` wiring.** `dump.c` and `correlate.c`
  each split into `<engine>_setup` / `_run` / `_teardown` + thin `cmd_*` wrapper, fully
  symmetric with `syscalls`/`funcs`/`lib`. Both switched to the shared 2-stage stop handler
  (closes GA5 for dump/correlate). `lib` wired into `trace`: new `--lib` section in
  `trace_args` + coordinator, section-boundary scan fixed for 3 delimiters, `test_trace_args`
  extended. Deferred: wiring correlate/dump into `trace` (see Major GA2).

### 2026-06-26 (session 3)

- **funcs JSON backtrace — close syscalls/funcs `-o` asymmetry.** `funcs` CALL records now
  carry a `"backtrace":[{"frame":N,"addr":"0x.."},…]` array in their structured `-o` JSON,
  built from the always-on `bpf_get_stack` capture (independent of `--snapshot`). Addr-only
  to keep `funcs_emit.c` pure/host-testable. `test_funcs_emit` extended (20 checks).

### 2026-06-26 (session 2)

- **W2+W3 — Shared snapshot extraction + funcs stack snapshot.** Moved the register-file +
  stack snapshot into a shared core: `src/common/stack_snapshot.{h,bpf.h,c}`
  (`struct ares_stack_snapshot`, `ARES_SNAP_MAX/SMALL/NREG`, `ares_hash_stack`,
  `ares_emit_stack_snapshot`, `ares_stack_snapshot_emit_json`, `ares_unwind_regs`). Both
  `syscalls` (kprobe) and `funcs` (uprobe) `#include` the shared BPF helpers via the
  `ARES_SNAPSHOT_RB` macro idiom. W3 closed: `unwind_regs.h` deleted from `src/syscalls/`,
  adapter now engine-neutral in `common/stack_snapshot.h`. `funcs` gains `--snapshot`
  (requires `-o`): deduped by FNV-1a hash, sidecar `<output>.stacks` (JSONL), `"stack_id"`
  on CALL records for join. `ARES_EVENT_STACK=12` added. New host tests: `test_stack_snapshot`,
  `test_unwind_regs` (migrated), `test_funcs_emit` (17 checks).

### 2026-06-26 (session 1)

- **Merge `origin/main`: DWARF CFI unwinder + syscalls register-file snapshot.**
  `src/common/dwarf.{c,h}`: bounded byte cursor (ULEB128/SLEB128/fixed-width reads).
  `src/common/cfi_unwind.{c,h}`: `.debug_frame` CIE/FDE parser (O(log n) PC binary
  search), CFI rule interpreter (`cfi_run_program`), and single-frame stepper (`cfi_step`).
  `syscalls_stack_snapshot` extended: adds `regs[31]` (x0..x30 full GP file, CFI initial
  state) and `truncated` flag; JSON gains `"regs":[…]` (31 elements) and `"truncated":0/1`.
  `src/syscalls/unwind_regs.h`: `struct ares_unwind_regs` + `unwind_regs_from_snapshot()`.
  Four new host tests (`test_dwarf`, `test_cfi_parse`, `test_cfi_step`, `test_unwind_regs`).
  CFI wiring to runtime + generalization deferred → W1–W3.

### 2026-06-25 (session 3)

- **Thin presets keystone — `lib` phase split (coordinator-ready).** `cmd_lib`
  refactored into `lib_setup(argc, argv, rc)` / `lib_run(stop)` / `lib_teardown()` +
  thin `cmd_lib` wrapper, fully symmetric with `syscalls` and `funcs`. Accepts
  `struct ares_run_ctx` so a future coordinator can pre-resolve the UID. `on_sigint`
  retired for the shared `ares_install_stop_handler`. No behaviour change.

### 2026-06-25 (session 2)

- **Y1 — funcs cap-overflow warnings.** Six silent truncation caps in `parse_opts`
  (`-p/-I/-i/-e/-F/-r`) now emit warnings to stderr, matching correlate's wording.
- **Y2 — `rctx` use-after-return fixed.** Promoted `struct probe_resolve_ctx rctx`
  from stack-local in `funcs_setup` to file-static `g_rctx`.
- **Y3 — live drop ticker for funcs.** `funcs_drops_tick` mirrors `syscalls_drops_tick`
  (~1 s cadence); wired into `funcs_run`.
- **Y4 (map/unmap) — funcs structured lib/unlib records.** funcs emits `{"type":"lib",...}` /
  `{"type":"unlib",...}` via the shared `ares_libtrace_emit_lib`/`emit_unlib`. Threading:
  Option A — new `g_sink_lock` serializes drain-thread lib/unlib writes against worker-thread
  call/return writes. Console `[lib]`/`[unlib]` lines gated on `-v`.

### 2026-06-25 (session 1)

- **C3 Phase 2 — shared `/proc/<pid>/maps` line parser + symbolizer cache bounds.**
  `src/common/maps.{c,h}` adds `ares_parse_maps_line` (the one canonical `sscanf`),
  `ares_module_base_idx` (load-base walk-back), and `ares_map_files_path`. All six consumers
  migrated; `struct mapping` and `struct dmap` collapsed into `struct ares_map_line`.
  Correctness fix: paths with embedded spaces no longer truncate. Symbolizer cache bounded:
  LRU eviction at `PM_MAX_PIDS=128`, `SC_MAX_CAP=256k`; `sym_flush_pid` wired to
  `ARES_EVENT_PROC_EXIT`. 25 host-unit checks in `tests/test_maps.c`.

### 2026-06-24

- **`correlate` hardening — R3 + R4 + X2 (correlate half).** R3: uprobe `bpf_link`s tracked
  and destroyed on teardown + ring-buffer-fail path. R4: `-p`/`-e`/`-F`/per-pid-dedup caps
  warn instead of silently truncating. X2: output migrated to the shared `ares_sink`. **R5
  closed as stale** — the `jstr_args` `snprintf` underflow path no longer exists.
- **X2 (lib half) — `lib` migrated to `ares_sink`.** `ares_libtrace_emit_lib/unlib` signatures
  changed from `FILE *jsonl` to `struct ares_sink *sink`. New test `tests/test_lib_trace_emit.c`.
- **F1 — FD & string resolution in `ares funcs`.** `funcs_emit_call`/`funcs_emit_return`
  accept a `probe_target_t *target` and emit `string_args`, `fd_args` (FD→path via `render_fd`),
  `retval_str`, `out_args`. `test_funcs_emit` extended (15 checks).
- **CLI consistency / argp (A.0, A5, R6, F3, F4, U3).** All six engines on GNU argp;
  `lib`/`dump`/`correlate` migrated off hand-rolled loops; `lib`/`dump` gained `-P`/`-A`;
  `-o` implies `-q` unified; `--version` handled centrally in `src/main.c`.
- **BPF de-dup + arg-parse normalization (C4, C8).** `uid_filter.bpf.h` (`target_uids` +
  `uid_matches()`); `bpf_drop.bpf.h` (`dropped` map + `bump_dropped()`);
  `struct trace_event_header` replaces the `syscalls_hdr` alias; `engine_args.h`
  (`common_args` + `COMMON_ARGP_OPTIONS`). `ares_libbpf_quiet` replaces three local copies.
- **Managed-frame symbolization Phase 2a + 2b (DEX core + on-device spike).** Phase 2a:
  version-stable DEX offset→method core (`src/common/dex.{c,h}`, host-tested). Phase 2b:
  PARK both frame types — on A15/AOT captured `classes.vdex+0x..` offsets land in DEX data,
  not `code_item`s (FP mis-captures). 2c/2d parked by 2b — see Major.

### 2026-06-23

- **Engine unification round 2.** Phase A: `src/common/runtime.{c,h}` (shared
  stop-handler / drops-report / pow2). Phase B: `funcs -b/--bufsize`. Phase C1:
  `src/common/evqueue.{c,h}` SPSC byte-queue. Phase C2: `funcs` decoupled drain on a worker
  thread. All five engines on `ares_rb_poll_until`/`_cb`.
- **Shared `ares_sink` + funcs output unification (C1).** `emit.h` exports `struct ares_sink`;
  `syscalls` and `funcs` migrated; legacy wrapper + CSV removed. 6 sink host tests.
- **R2** — `vaddr_to_file_off()` in `probe_resolve.c`. **R7** — `FUNC_CFLAGS` aligned to
  `-Wall -Wextra`.

### 2026-06-22

- **`ares trace` runner — Phases 1–4.** Shared `ares_launch_app()`; engine setup/run/teardown
  split + `struct ares_run_ctx`; `src/trace/trace.c` coordinator (one launch, two drain
  threads, per-engine `-o` files); `trace_args.c` argv-section split (host-tested). Inherently
  LOUD.
- **`trace` audit fixes** — second Ctrl-C force-quit; warn on missing `-o`; ring drain bails
  on stop flag; warn on arg-section overflow.

### 2026-06-21

- **Structured JSONL for `funcs` CALL/RETURN (Task 4)** — `-J`/`--structured`;
  `funcs_emit.c` (pure, host-tested).
- **C5.1 — firewall-aware capability registry** (`capabilities.{c,h}`). Advisory by design.

### 2026-06-20

- **Testing tiers (R8)** — host unit tests (`make test`), CI cross-build (`ci.yml`),
  device acceptance (`device-test.sh`).

### 2026-06-18

- **Launch/UID helper de-dup (R1 / C5)** — `sh_exec`/`resolve_uid`/`resolve_component`
  unified into `src/common/launch.{c,h}` (~150 dup lines removed).

### 2026-06-17

- **Fused-core + `correlate` shipped.** `span_stack.bpf.h` (per-tid stack, fixes the
  single-slot `entry_map` clobber bug); shared-core extractions (`launch`, `probe_resolve`);
  the `correlate` engine (entry uprobes + span-gated `do_el0_svc` kprobe, flat
  `func`/`syscall` JSONL joined on `span`). Detectability firewall **reframed**: the one
  invariant is "a stealthy run attaches zero uprobes".
- **Unified `ares-mcp` ingest (Task 3)** — `load_structured` + `correlate_spans` (join
  syscalls by `span`); host-tested. Richness follow-on → Minor.

### 2026-06-16

- **`ares dump` engine (C6)** — replaced the syscalls/funcs dumpers; ELF rebuild in
  `src/dump/rebuild.c`; `/proc/<pid>/mem` reader lifted to `src/common/proc_mem`.
