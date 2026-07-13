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
- CFI / managed-frame naming — **generalize beyond one ART build**: version gate keys
  on apex `370549100` only (BuildID is the stronger anchor); nterp recall is bounded
  by the snapshot window.
- Managed-frame **OAT/ODEX native-PC → Java method** — parked pending real ART OAT parsing.
- CR4 — managed-frame naming: version treadmill (see CFI item) + nterp's own guess-path
  still primary for nterp terminals (ShadowFrame parity landed for its own terminal —
  see Resolved/Done; a genuinely authoritative nterp path is a separate, harder project).

**Minor:**
- CR5 follow-on: `dump` coverage field.
- W5 — JIT `[anon]` frame CFI (deferred; ≈0 payoff on measured workloads).
- SW1 — switch-interp ShadowFrame walk follow-ups (BuildID rows, precision cross-check,
  liveness tightening; ELF-note hardening done — see Resolved/Done).
- U1/U2 console style unification (not recommended — high churn, low value).
- Pending on-device verification (`trace` combined run incl. new `--dump`/`--correlate`
  wiring and `-p` attach mode; `correlate` R3/R4/X2; CR4 parity fix; Tier 5
  `--returns`/CR3, decode, `-P` poll timing; CR2 issuer-only
  attribution, compat hook, pre-arm window, `syscalls.skel.h` regen; lib-filter
  maps-seed fix — confirm `libc.so`-filtered runtime/JNI `openat`s now appear).
- AA9 — managed-chain per-stack 8 KB alloc churn (double frame symbolization fixed —
  see Resolved/Done; the alloc-churn half is deferred, see Minor detail for why).
- `mod file-access` dirfd-relative opens unresolved — needs entry+kretprobe
  `bpf_d_path` canonicalization to close (see Minor section below).
- `mod file-access`/`ransomware-burst` `.bpf.o` compiles clean here, but their
  `*.skel.h` are stale (no `dropped` map) and `bpftool` isn't available in this
  dev env to regenerate them — full userspace compile + on-device confirmation
  of nonzero `ring_drops` is pending (see 2026-07-10 Resolved/Done entry).
- `mod ransomware-burst` coverage is conditional on scoped-storage bypass
  (`MANAGE_EXTERNAL_STORAGE` or legacy targetSdk) and doesn't cover
  lock-overlay-style extortion (see Minor section below).

---

## Urgent — architectural / correctness-critical

None currently open.

---

## Major — features / substantial work

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

**Fixed 2026-07-08 via `--returns` — see Resolved/Done (Tier 5).** SP-pop remains the
default *quiet* best-effort close (unchanged, still hostile to the cases below);
`--returns` opts a target into an authoritative uretprobe pop, immune to all of them.
Kept open here as the historical description of the underlying SP-pop weakness, which
is by design, not eliminated, for targets that don't opt in.

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
(uretprobe, shipped 2026-07-06) as the accuracy path — the two are currently framed as
near-equivalent.

- **`--returns` return records inherit the mis-attribution (known drawback).** With
  `--returns` the uretprobe pops the innermost *tracked* frame, so the same defects
  emit *visibly wrong data* rather than a silent mis-gate: beyond `MAX_SPAN_DEPTH=32`
  nested probed calls the 33rd call is never pushed (`span_stack_push` returns 0) yet
  its return still fires and pops a live frame -> a spurious `{"type":"return"}` with
  the wrong span/entry_addr/elapsed_ns, cascading until the stack unwinds under the
  cap. Non-LIFO stacks (coroutines) corrupt the pop target the same way. The
  uretprobe/reconcile interaction itself is benign (delete-by-key + depth--; a later
  reconcile finds the frame already gone). Fix rides the CR3 accuracy work.

### CR4 — managed-frame naming: version treadmill + nterp guess-path

Source: 2026-07-03 architecture critique. Extends the "generalize beyond one ART build"
item above with a strategic critique.

- **Version treadmill (still open).** One `k_table` row (`src/common/art_buildid.c:12`)
  gates *all* Java naming, keyed on the exact libart BuildID. ART is an apex (mainline)
  module updated ~monthly; every ART update / vendor rebuild / new release → BuildID miss
  → managed naming **silently returns nothing** (bare `nterp_helper` terminal, Java frames
  vanish). The `ARES_ART_OFFSETS` override + Frida oracle (#3-B/C) softens onboarding but
  it is still one row of manual labor per device per ART build. Tracked under the CFI
  Major item above. **Data point (2026-07-08):** the POCO C85 (A15) took an OTA that
  rebuilt libart (`1f156fc6...` to `cecb684d...`); a new `k_table` row was needed for
  the new BuildID, but the 13 offsets were **identical**, Frida-oracle-verified. So
  within one AOSP source release a rebuild-only OTA is a BuildID-key add with reused
  offsets, not a re-derivation; only a genuine ART version bump shifts the layout.
  Softens the treadmill (key churn is not offset churn) but does not remove it.
- **ShadowFrame parity in the compact chain — fixed 2026-07-08.** The compact `managed[]`
  fragment shared by both engines (`ares_managed_chain`, `src/common/symbolize.c`) only
  ever tried the nterp guess-path, even at an `ExecuteSwitchImpl` (switch-interpreter)
  terminal — the authoritative ShadowFrame walk (`art_shadow.c`) was reachable only from
  the full `cfi_stack` JSON emitter, not the compact fragment used for the jcache. Both
  call sites now try `shadow_frame_chain` at its own terminal, at parity with the JSON
  path. See Resolved/Done.
- **Guess-path is still primary for nterp specifically (residual, tracked as "Path Y").**
  `art_nterp.c:204` guesses `ArtMethod*` from raw stack slots and corroborates via a
  dex_pc in a 512-byte window — which proves *method identity, not frame identity*, so
  two live/stale activations of the same method are indistinguishable (right name, wrong
  dex_pc / wrong activation), and the uncorroborated fallback can emit a wholly wrong
  `name?`. **Correction (2026-07-08 audit):** `art_shadow.c`'s ShadowFrame walk cannot
  substitute for nterp here — it reads `ManagedStack.top_shadow_frame_`, a field nterp
  doesn't use (nterp frames live on `top_quick_frame_`, which no reader in this repo
  parses today). A genuinely authoritative nterp path needs a **new**
  `top_quick_frame_` reader, not reuse of the existing shadow walk — a separate, harder,
  ART-internals-risky project, not bundled with the parity fix above.

Strategic: this is the largest, most fragile surface in the repo, for best-effort output
on a tool whose real edge is stealthy syscalls. Managed naming is now labeled
**experimental** in README/DOCUMENTATION (2026-07-08) so a silent BuildID miss doesn't
read as "app used no Java."

### SPEC1 — unified probe-spec v2 + `funcs`/`correlate` argument consolidation (planned, 2026-07-10)

**Status (2026-07-11):** H1-H12 done — EPIC H complete.

`funcs` currently has two parallel, overlapping ways to select what to probe: regex-based
(`-I` module, `-i` function, `-r` return-only function — each its own 32-entry array +
`regcomp` compile loop, `src/funcs/funcs.c`) and spec-based (`-e SPEC`, `-F FILE`, feeding
`common/probe_resolve.c`'s `MODULE!FUNC[@OFFSET][(ARGTYPES)][>RETTYPE]` grammar).
`correlate` duplicates the `-I`/`-i` regex arrays verbatim and re-implements `-e`/`-F` file
loading with different whitespace-trimming than `funcs` (`\n\r \t` vs `\n`-only). Three
more engines each have their own bespoke, spec-less selector: `syscalls` (`-l` library
scope + `-a`/`-s`/`-x` syscall name allow/deny), `dump` (positional glob/substring
PATTERN), `mod` (positional analyzer NAME). The glob-matching convention is independently
reimplemented three times with inconsistent trigger chars (`*?[` in `lib_seed.h`/
`rebuild.c` vs `*?` in `probe_resolve.c`). `funcs` is also missing a zero-target
validation `correlate` already has (`ARGP_KEY_END`) — a `funcs` invocation with no
`-I/-i/-e/-F` parses fine and only fails at runtime.

**Plan:** one spec grammar, one loader, one matcher, with a `KIND:` prefix so a single
spec file can drive selection on every engine, not just `funcs`/`correlate`:

```
[KIND:]TARGET[(ARGTYPES)][>RETTYPE]
```

| Kind | Prefix | TARGET grammar | Absorbs | ARGTYPES/RETTYPE |
|---|---|---|---|---|
| uprobe | `funcs:` or omitted (default — every existing `specs/*.spec` line keeps parsing unchanged) | `MODULE!FUNC[@OFFSET]`, each side exact/glob(`*?[`)/`/regex/` | `funcs -I/-i/-r`, `correlate -I/-i` | yes (S,V,F,A args; S,V return; bare `>RET` = return-only, replacing `-r`) |
| `syscall:` | — | `[!]NAME` (glob ok; leading `!` = deny) | `syscalls -s/-x` | no |
| `lib:` | — | `[!]PATTERN` (glob/substring) | `syscalls -l`, `dump`'s positional PATTERN | no |
| `mod:` | — | `NAME` (exact, analyzer registry) | `mod`'s positional NAME | no |

`custom_probe_spec_t` gains `spec_kind_t kind` (default 0 = `SPEC_KIND_FUNCS`, preserving
today's unprefixed semantics) and `bool deny`; all existing fields unchanged. Three new
shared modules replace the duplication above: `common/probe_spec_loader.{h,c}` (one
`-F` file reader, consistent trimming, existing 64-spec/8-file caps kept),
`common/pattern_match.{h,c}` (one exact/glob/regex matcher, retiring
`lib_selector_matches_name`, `dump_name_matches`, `custom_spec_matches_path`/`mod_matches`),
`common/target_validate.{h,c}` (one `-p`/`-P` exclusivity + zero-target check, retiring
three copy-pasted, differently-worded versions in `funcs.c`/`correlate.c`/`syscalls.c`).

**Per engine:** `funcs`'s `-I/-i/-r` deprecate (stderr warning naming the equivalent spec
line, e.g. `-e 'libc.so!/^encrypt/'`; behavior unchanged this release) rather than
hard-remove, so existing scripts/CI don't break — hard removal is a follow-up once
`specs/*.spec`, docs, and `ARES-Detector/sim/rasp-checks.spec` migrate. `correlate` moves
onto the shared loader/matcher and gains full `COMMON_ARGP_OPTIONS` for surface parity
(currently hand-rolls only `-o`/`-q`). `syscalls`/`dump`/`mod` each gain new, purely
additive `-e`/`-F` support reading the kind lines relevant to them — no existing flag
changes, first time these three can share a spec file with `funcs`/`correlate` at all.

**Explicitly out of scope for this item:** unifying the deeper per-mapping resolve+attach
driver duplication (`funcs`'s `apply_custom_specs_for_file` vs `correlate`'s
`attach_uprobes_for_pid` — same maps-walk+dedup+attach shape, different BPF skeleton
targets). That's a BPF-attach-path change, not an argument/spec-system change; noted here
as a natural follow-on once SPEC1 lands.

Tracked with concrete tasks in `ares-project/TODO.md` EPIC H. `tests/test_probe_spec.c`
is the grammar regression guard and must gain KIND/glob/regex cases while every existing
case (including the 6 malformed-input rejections) keeps passing unchanged.

**Status (2026-07-13):** Manual test reconfirms the consolidation need: `dump` positional
lib PATTERN, `mod` positional analyzer NAME + no-multi-analyzer, and `funcs` "spec only"
scope all map to SPEC1's `lib:`/`mod:` kinds and cross-engine `-F`. See MT4/MT7 (Minor).
**2026-07-13 reconciliation:** MT1/MT2/MT3 (Minor) landed as real fixes; MT4/MT5/MT6/MT7 were
mostly already covered by `docs: updated backlog and documentation to current state`
(`5aeeba1`), which landed 20 minutes before this manual-test pass filed them — see each
item's Minor entry below for what was genuinely still open vs. reconciled as already-done.
The line-222 "H1-H12 done — EPIC H complete" status is unaffected by any of this — it
describes the code (EPIC H), not the downstream doc/UX follow-ups tracked here.

---

## Minor — cleanups, perf nits, cosmetic, verification

### Cross-engine JSONL schema consistency — 2026-07-13

- **SC1 — `id` field naming overlap (funcs vs correlate).** `funcs` now emits `"id"`
  for its per-call span (surfaced `span_id`, pairs CALL↔RETURN — matches `syscalls`'
  `"id"`). But `correlate` emits the *same* underlying quantity as `"span"`
  (`corr_emit_*`). One value, two field names across engines. Unify on one key
  (likely `"id"` since two of three engines use it) when the schema is next
  consolidated — folds into the broader §7 "unified schema" cleanup.
- **SC2 — entry-event `type` discriminator differs.** `funcs` uses
  `{"type":"call"}`; `correlate` uses `{"type":"func"}` for the same uprobe-entry
  event. Consumers must special-case both. Reconcile alongside SC1.

### Manual CLI test findings — 2026-07-13

- **MT1 (correctness) — `--help`/`--usage`/bad args print then run instead of aborting.**
  `funcs`, `dump`, `lib`, `syscalls`, `correlate` all call
  `argp_parse(..., ARGP_NO_EXIT, ...)` (`funcs.c:906`, `dump.c:236`, `lib.c:143`,
  `syscalls.c:1026`, `correlate.c:467`), so argp prints help/usage/parse-error and
  *returns* — control falls through into attach/run. `mod` (flags `0`, `mod.c:124`)
  aborts correctly and is the reference. Fix: treat help/usage/parse-error as abort
  (handle `-h`/`--help` before parse, or check for the help/usage request and return
  nonzero). Repro: `ares funcs -P dev.ares.detector --help` still attaches.
  **Fixed 2026-07-13** (commit `0eb21b5`): bad args already aborted (`argp_parse`'s
  `!= 0` check catches them) — only help/usage leaked, since argp prints and returns
  `0` under `ARGP_NO_EXIT`. New shared `ares_wants_help()` (`common/engine_args.h`)
  detects `-h`/`--help`/`-?`/`--usage` before each standalone `cmd_*` calls `*_setup`,
  and calls `argp_help()` + returns 0 itself. Deliberately *not* switched to `mod`-style
  `flags 0` — the five `*_setup` functions are also called directly by the `trace`
  coordinator (`trace.c:241-263`), which relies on a nonzero return (not `exit()`) to
  tear down already-armed sibling engines on a parse failure.
- **MT2 — `mod` analyzer listing gap.** `list_analyzers()` only fires on an *unknown*
  name (`mod.c:90`); bare `ares mod` and `ares mod --help` don't list analyzers, though
  `main.c` usage claims `--help` does. Wire `list_analyzers()` into `--help` / no-arg.
  **Fixed 2026-07-13** (commit `c5b8a16`): `cmd_mod` now calls `list_analyzers()` on
  bare `ares mod` (`argc < 2`, returns 0) and augments `--help` with it (via the MT1
  `ares_wants_help()`) before argp prints its own usage — makes `main.c:44`'s claim true.
- **MT3 — `lib` misses in-APK natives (e.g. `libsentinel.so`).** With
  `extractNativeLibs=false` the lib maps as a `base.apk` region, not a standalone `.so`;
  lib enumerates maps only. Add APK(zip) enumeration of `lib/*/*.so` so packed natives
  surface.
  **Fixed 2026-07-13** (commits `a5841e0`/`af753f0`/`c93fdee`): new `apk_list_sos()`
  (`common/sym_apk.{h,c}`) enumerates every packed `lib/*/*.so` in an APK, reusing the
  existing ZIP central-directory parser (`apk_parse`/`apk_get`, previously only exposed
  the single-offset `apk_so_name` reverse lookup). `lib.c` emits the full packed list
  once per APK (new `lib_packed` record/`ares_libtrace_emit_packed`) and range-matches
  `[data_start, data_start+size)` — not exact-offset — to label the actually-loaded
  segment's `soname` on the existing `lib` record. Offset derived as
  `e->pgoff * sysconf(_SC_PAGESIZE)` (correct on 4K *and* 16K-page devices; `vm_pgoff`
  is in kernel-PAGE_SIZE units, not bytes — `pgoff << 12` would be wrong on 16K
  devices). Compressed (non-`method==0`) packed `.so` — the `extractNativeLibs=true`
  default — is unaffected, already handled by the normal on-disk mapping path.
- **MT4 — `trace` output file carries only funcs-side events** (call/return/lib/unlib);
  syscall events aren't merged in. Consolidate multi-source output into one file. The
  nested `--syscalls -a -s NAME --funcs -F FILE` sub-flag grammar (hand-rolled
  `trace_args.c`) is also awkward — ties SPEC1 argument consolidation.
  **Reconciled 2026-07-13 — stale finding, merge half already done.** `trace.c:334-353`
  already builds a `srcs[]` array from every requested engine
  (`syscalls`/`funcs`/`lib`/`correlate`) and calls the shared `jsonl_merge()`
  (`common/jsonl_merge.c`) into the literal `-o` path — landed as EPIC C3 (commit
  `986935b`, 2026-07-12 22:11), a confirmed git ancestor of the commit that filed this
  finding (`600e14e`, 2026-07-13 09:13, ~11 hours later). All four suffixes
  (`.syscalls/.funcs/.lib/.event.jsonl`) verified to match what each engine actually
  writes. Most likely cause: the on-device binary used for the manual test wasn't
  rebuilt/repushed after EPIC C3 landed — **re-verify on a freshly rebuilt/pushed
  binary** before assuming this is still open. Real remaining residual: the nested
  `--syscalls .../--funcs ...` sub-flag grammar is still hand-rolled and awkward — a
  SPEC1-tied UX nit, not a data-merge bug.
- **MT5 — `correlate` output undocumented.** stdout grammar unspecified; confirm whether
  backtraces are captured (cross-check CR3). Add an output-format doc.
  **Reconciled 2026-07-13 — mostly stale, one real gap closed.** §6
  (`DOCUMENTATION.md:774-851`) already documented `correlate`'s stdout line shapes and
  JSONL record fields in detail, landed by `5aeeba1` (2026-07-13 08:53) 20 minutes
  before this finding was filed (`600e14e`, 09:13) — same staleness pattern as MT4. The
  one genuine gap: §7 "Unified trace schema" (the systematic per-record-type reference)
  had bullets for `syscalls`/`funcs`/`lib`/`dump` but none for `correlate`, and nowhere
  stated the backtrace answer. Closed: added a `correlate` bullet to §7 and the direct
  answer to the cross-check — **no**, `correlate` captures no backtraces (verified
  against `corr_func_event`/`corr_syscall_event`/`corr_return_event`,
  `src/correlate/correlate.h:28-61` — no stack/backtrace field in any of the three,
  unlike `syscalls`/`funcs`); it tracks call/return via a per-tid span stack
  (`span`/`parent_span` IDs), not a captured stack snapshot.
- **MT6 — stdout↔file "parity" (funcs, lib).** Post-SYM1 the console and `-o` file are
  independent channels; decide + document whether they must emit identical content
  (relates to U1/U2 console-style unification).
  **Resolved 2026-07-13 — decision: independent by design, doc-only.** The `-o` file is
  the complete, authoritative JSONL; stdout is a human-readable convenience gated by
  `-q`/`-v`; the two are **not required to match** (file = source of truth). This was
  already the de facto behavior (stated piecemeal at 6+ places across
  `DOCUMENTATION.md`); ratified as one explicit paragraph at the top of §7. Distinct
  from U1/U2 (console *styling* unification, still not recommended, unchanged) —
  this is about content parity, not cosmetic format.
- **MT7 — `specs/common-file.spec` refresh + scope note.** Spec file needs updating;
  document that spec files are funcs/correlate-only today (SPEC1 makes them cross-engine,
  incl. syscalls/dump/mod).
  **Reconciled 2026-07-13 — doc already existed, spec file now points at it.** The
  cross-engine fact was already stated in prose at `DOCUMENTATION.md:522-524` (§3,
  landed by the same `5aeeba1`, predating this finding). None of the 8 `specs/*.spec`
  files had a header comment (checked all); added one to `common-file.spec` noting the
  file is cross-engine post-SPEC1 and pointing at §3 for the full grammar. Listed
  `libc.so!` symbols light-verified — unchanged, already correct since H11's
  `syscall:openat` migration. Lockstep test (`tests/test_probe_spec.c`, reads
  `specs/*.spec` directly, skips `#`/blank lines identically to the loader) reconfirmed
  green (111/111) with the new comment lines present.

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

- `mod file-access` dirfd-relative opens. An `openat(dirfd, "relative/path", ...)`
  where `dirfd` isn't `AT_FDCWD` won't prefix-match the in-kernel gate's 4 fixed
  strings and is silently dropped. Fix = switch from an entry-only kprobe to an
  entry+kretprobe pair (stash flags in a per-tid map at entry, like
  `prop_read.c`'s `prop_entry_map`), then at return walk the task's fd table to
  the newly-opened fd and call `bpf_d_path()` for the canonical absolute path.
  Deferred at ship time: adds a real dependency on `bpf_d_path` kernel-version
  availability (5.10+) and CO-RE reads into `fdtable` internals, and only
  matters when an app deliberately holds a cached dir fd for a sensitive/foreign
  path — narrow compared to the common case (absolute paths).
- `mod ransomware-burst` known v1 limitations (shipped 2026-07-08): coverage
  depends on the traced app holding `MANAGE_EXTERNAL_STORAGE` or targeting a
  legacy API level — scoped storage (Android 11+) otherwise blocks raw
  `renameat`/`unlinkat` on shared-storage files outright (surfaced via a
  startup permission-check banner, not silently assumed). Doesn't detect
  screen-lock/overlay-style extortion (DroidLock/HOOK-style) — different
  attack surface entirely, not file-syscall-observable. Fixed threshold (20
  touches/10s) is evadable by a sample that throttles itself. No exact
  same-file pairing across a rename and a later unlink (volume/mix is the
  signal, not proven per-file identity — see design doc). MediaStore-mediated
  bulk delete/rename is invisible (same structural blind spot as
  `file-access`'s `openat` detection) — **confirmed on-device 2026-07-08**,
  not just theoretical: Files by Google's "delete" never fired this
  regardless of `MANAGE_EXTERNAL_STORAGE`, because scoped-storage delete goes
  through MediaStore's `IS_TRASHED` column (a soft-delete rename to
  `.trashed-*`, still on disk) performed by the MediaProvider process, not
  the calling app's UID — a UID/PID-gated kprobe trace structurally cannot
  see it. Real-app-driven verification (as opposed to a synthetic PID
  trigger) is now `scripts/burstapp/build.sh install` — see
  DOCUMENTATION.md §"Testing tiers".
- `mod exfil-burst` known v1 limitations (shipped 2026-07-11): contacts/
  SMS/call-log exfil is invisible (Binder-mediated ContentProvider access,
  same structural blind spot as `ransomware-burst`'s MediaStore gap) —
  scoped deliberately to media/credential-file reads, which are visible as
  real `openat` calls. Byte counts are requested length at syscall entry
  (`write`/`writev`/`sendto`'s argument), not a kretprobe-verified
  delivered length — a failed or blocked send still counts toward the
  threshold; accepted since a real exfiltrating sample needs its sends to
  actually succeed to be worth anything. Threshold (512 KiB/30s) is
  evadable by a sample that throttles/chunks below it. Credential-pattern
  matching in the BPF-side gate checks the pattern anywhere in the path,
  not just the basename (`file_access_classify.c`'s stricter check) — a
  documented precision simplification, acceptable since it only affects
  arming (a soft precondition), not the byte-threshold detection itself.
  `writev()` calls with more than 8 iovecs undercount past the 8th entry
  (bounded-loop limit for verifier provability).
- `mod a11y-abuse` known v1 limitations (shipped 2026-07-12): no transaction-code
  decode — the analyzer proves "high Binder call volume to `system_server` while
  Accessibility-granted," not *which* privileged action fired (parked, same version-
  treadmill risk shape as ART's `k_table`/`ARES_ART_OFFSETS`). Only gates on
  `system_server` as the destination — misses accessibility routing through any
  OEM-specific separate framework process. Grant check
  (`enabled_accessibility_services`) is a package-substring match against a
  colon-separated settings string, not a structured parse — a package name that
  happens to be a substring of another entry could false-match. Threshold (50 calls/
  5s) evadable by throttling. `sys_server_pid_map` is resolved once at startup; a
  `system_server` restart mid-trace (rare) goes unnoticed and the gate silently stops
  matching.
- `mod fileless-exec` known v1 limitations (shipped 2026-07-12): false positives from
  legitimate non-ART JIT engines — WebView/Chrome (V8), Unity (Mono/IL2CPP), and
  Flutter (Dart) apps all create anonymous executable mappings untagged `dalvik-` and
  will be flagged. Only the "dalvik-" prefix is carved out; no allow-list for other
  known-benign JIT engines yet (parked as a follow-up in the design doc). `mprotect`-
  based W^X evasion (allocate RW, write payload, flip to RX afterward) is invisible to
  the `mmap`-only v1 hook. `memfd_create`-backed "fileless" loaders bypass the gate
  entirely — they have a `vm_file` (tmpfs-backed), so `vm_file == NULL` never matches;
  this is a real technique the analyzer is named for but does not yet catch. No
  payload-content signal (e.g. ELF-magic check) — the mapping is zero-filled at hook
  time, before the caller writes anything into it. Evadable by a loader that tags its
  own mapping `dalvik-fake` via `prctl` to dodge the carve-out (arms-race concern, not
  addressed in v1). The suppression mechanism assumes ART's
  `prctl(PR_SET_VMA_ANON_NAME, addr, ...)` call names the *exact* address `do_mmap`
  returned; implemented faithfully per design and spot-checked on-device (0 false
  positives across multiple runs against an ordinary app) but not exhaustively proven,
  since JIT compilation isn't guaranteed to occur within any given short observation
  window.
- Screen-lock/overlay extortion detector — separate `mod` analyzer, still open.
  Current Android "ransomware" (DroidLock, HOOK, 2024-2025) trends toward
  full-screen lock overlays + data-destruction threats rather than actual file
  encryption. This item previously assumed the whole category (Window Manager /
  `SYSTEM_ALERT_WINDOW` / accessibility-service abuse) was "not file syscalls" and
  therefore out of `ares`'s reach — that premise no longer holds for the
  accessibility-service-abuse slice: `mod a11y-abuse` (shipped 2026-07-12) proves
  Binder-mediated behavior is kernel-observable via the `binder_transaction`
  tracepoint. What remains genuinely open is the Window-Manager/overlay-specific
  mechanism itself (`SYSTEM_ALERT_WINDOW` window creation, screen-lock detection) —
  `a11y-abuse` v1 only signals "Binder-chatty with `system_server` while
  Accessibility-granted," not "created a full-screen overlay." A follow-on
  analyzer targeting `IWindowManager` binder traffic specifically (same
  `system_server`-destination-gating approach) is the natural next step — see
  `mod a11y-abuse`'s design doc Follow-up ideas.

- **SW1 — switch-interp ShadowFrame walk follow-ups (non-blocking).** The walk shipped
  and is device-verified (`src/common/art_shadow.c`; see Resolved/Done). ELF-note parser
  hardening (`shentsize < 0x28` guard) landed 2026-07-08 — see Resolved/Done. Remaining
  deferred polish:
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

- **AA9 — managed-chain double frame symbolization (fixed) + per-event alloc churn
  (deferred).** Source: 2026-07-07 graph-informed audit.
  - **Double symbolization — fixed 2026-07-08.** `emit_cfi_backtrace`/its `funcs`
    equivalent symbolized every frame twice per snapshot **event** (not just per distinct
    stack, since `ares_managed_chain` ran unconditionally before the jcache put — the
    audit's "once per distinct CFI stack" framing undersold it): `ares_emit_cfi_stack_json`
    resolved each frame and `ares_managed_chain` resolved the same frames again, each
    under `g_lock` with its own `snprintf`. Both public functions
    (`src/common/managed_frame.h`) now take an optional pre-resolved `syms` array; both
    call sites (`src/funcs/funcs.c`, `src/syscalls/syscalls.c`) resolve once and share it.
  - **8 KB alloc churn — deferred, not fixed.** `ares_managed_chain_build`
    (`managed_frame.c`) still heap-allocates a `jbuf` that floors its first grow at
    8192 bytes for an output fragment capped at `JC_FRAG=208`. The obvious fixes both have
    a real cost: building directly into the caller's `out` buffer breaks the documented
    "0 => out is left untouched" contract (an existing host test asserts a stale byte
    survives a no-managed-frames call — writing straight into `out` would corrupt it
    before the empty-result check runs); backing it with a fixed-size local scratch buffer
    instead avoids that, but hardcodes an internal cap independent of the caller's `cap`
    argument, silently narrowing the API for a hypothetical caller with a larger
    destination (today's two callers both use `frag[208]`, so it would work in practice,
    but the general-purpose pure builder would no longer honor its own documented
    contract). Left as-is; revisit only if profiling shows this alloc actually matters —
    it is not gated at 8192 bytes per snapshot, but it is a single small heap round-trip.

---

## Resolved / Done

Reverse-chronological. Identifiers preserved for traceability; full technical detail
is in DOCUMENTATION.md and the referenced specs.

### 2026-07-13

- **mediaproj-abuse analyzer (shipped 2026-07-13).** New `mod` analyzer
  detecting active `MediaProjection` screen-capture sessions — see
  DOCUMENTATION.md's `mod` analyzer list for the full design (including two
  design corrections made during development: the interface's
  ring-buffer-stub requirement turned out already precedented by
  `fileless-exec`, and the initially-planned burst-threshold Binder signal
  was rejected once the concrete event flow showed it doesn't transfer from
  `a11y-abuse`'s technique to this one). Known v1 limitations: 1s poll
  interval bounds detection latency; no transaction-code decode; legitimate
  screen-share/remote-support apps false-positive; no frame-content or
  exfil-volume corroboration (proves a session was active, not that data
  left the device).

- Manual test confirms `syscalls -o` no longer silences the run — SYM1 decoupled `-q`
  from `-o`; `g_quiet` is set only by `-q` (`syscalls.c:168,700`). `funcs`/`lib`/`dump`/
  `correlate` `-o` likewise print + write independently, as intended.

- **SYM1 — file/stdout output symmetry across all engines.** File output now
  matches `syscalls`' rich record schema and stdout matches `funcs`' grammar,
  uniformly across `syscalls`/`funcs`/`lib`/`correlate`/`dump`/`mod`. Phased,
  11 commits (Phase 0 through 5c), each independently gated and buildable —
  see `workspace/ares-output-asymmetry.md` for the original gap analysis this
  closes, and `ares-project/TODO.md` for phase-by-phase notes.
  - **Dual-channel-always** (Phase 1): dropped the old `-o` ⇒ `-q` coupling —
    `-o FILE` now writes JSON *and* prints stdout simultaneously; `-q` is the
    sole, independent stdout silencer. `trace`'s 5 concurrent child engines
    stay file-only under `-o` via an explicit `-q` injection (mirrors `dump`'s
    pre-existing pattern), preventing unusable interleaved stdout.
  - **Content parity** (Phase 2): `correlate`'s live console syscall line
    gained the same decoded paths/fds/sockaddrs/flag names the file already
    had (`corr_decode_arg`, shared by both channels — the sharpest single gap
    in the original analysis).
  - **`dump`'s total machine-channel gap closed** (Phase 3): new `-o` support
    + `dump_emit.c` manifest (`{"type":"dump",...}` per rebuilt module),
    making `trace`'s long-dead `-o <prefix>.dump.jsonl` fan-out real.
  - **Full stdout grammar unification** (Phase 4a-4d): every engine's live
    event lines now share one skeleton — `common/human_out.{c,h}`'s
    `ts_print`/`human_detail`, timestamp-prefixed, indented continuation
    lines — while keeping each engine's own bracket tag (`[syscall]`, `[lib]`,
    `[exec]`, …) rather than forcing funcs' literal wording everywhere.
    `lib_trace.c`'s shared emitter fix alone covers `lib`/`funcs`/`correlate`'s
    `[lib]`/`[unlib]` lines in one file.
  - **Surface consistency** (Phase 5a-5c): JSONL is now the uniform default
    framing (was array-by-default for `syscalls`/`funcs` only); `lib`/`dump`
    emit an explicit `{"exempt":true,...}` coverage record instead of silent
    "no message" (previously indistinguishable from "checked, all clean");
    `syscalls`/`funcs`/`correlate` gained end-of-run content summaries
    (per-syscall-name / per-symbol tallies, span/syscall/return counts),
    mirroring `mod`'s existing `print_summary`/`emit_summary` split and its
    omit-if-nothing-happened rule.
  - Verified throughout via the host `tests/test_*_emit.c` suite (JSON schema
    regression oracle — byte-identical except where a phase intentionally
    added a field/record type) plus balance/grep checks on the engine `.c`
    files the BPF-skeleton gate keeps un-host-compilable. Cross-repo: 341/341
    ARES-Desktop tests pass unmodified — the new record types land as
    retained-but-unhandled rows (EPIC A3's design), no ingest change needed.
    On-device capture confirming the real stdout/file shapes is the
    remaining open step (same standing gate as every BPF-touching change).
  - **Real cross-compile caught one bug, same day, unrelated to SYM1 itself:**
    `syscalls.c`'s own dense-cache `arg_fd_mask`/`arg_sock_index` wrappers
    (EPIC I2's fast path, `syscalls.c:365,379`) had the exact same names as
    the plain linear-scan forms `common/syscall_argtypes.h` declares —
    latent since I2 landed, invisible in the sandbox this whole plan was
    built in (no `bpftool`/aarch64 toolchain there to compile `syscalls.c`
    at all). A real `make` on a full toolchain hit it as a static-declaration
    conflict; fixed by renaming the local wrappers to
    `arg_fd_mask_cached`/`arg_sock_index_cached` (commit `b398781`). Confirms
    the standing "needs a real toolchain" caveat repeated throughout this
    plan was not just boilerplate.

### 2026-07-11

- **SPEC1 / EPIC H — unified probe-spec v2.** One spec grammar
  (`[KIND:]TARGET[(ARGTYPES)][>RETTYPE]`) now drives target selection on `funcs`,
  `correlate`, `syscalls`, `dump`, and `mod` alike, via three new shared modules
  (`common/pattern_match.{h,c}`, `common/probe_spec_loader.{h,c}`,
  `common/target_validate.{h,c}`) retiring most of the previously-duplicated
  glob/file-reading/validation logic. `funcs`'s old `-I`/`-i`/`-r` regex flags are
  deprecated (one-time stderr warning naming the `-e` equivalent) but still work
  unchanged; `correlate` gained full `COMMON_ARGP_OPTIONS` parity and its `-F` trim
  bug is fixed; `syscalls`/`dump`/`mod` each gained new, purely-additive `-e`/`-F`
  spec-file support they never had before. `specs/*.spec` and
  `ARES-Detector/sim/rasp-checks.spec` migrated to add `syscall:`/`lib:` lines
  alongside their existing uprobe lines, making the latter a genuine multi-engine
  capture-driving file. Two real bugs were found and fixed along the way (not just
  noted): a NULL-logger crash in `parse_custom_probe_spec` reachable from the three
  new engines' malformed-spec paths, and a missing kind-filter in `funcs`/
  `correlate`'s custom-spec attach loops that could otherwise misprocess a
  `syscall:`/`lib:` line meant for another engine. `mod_matches` (the
  precompiled-regex `-I`/`-i`/`-r` matcher) is intentionally NOT retired — kept
  until a future hard-removal (H12) of that mechanism. H12 landed the same day:
  the func-name-regex gap was fixed (a new `resolve_custom_spec_matches_for_path`
  in `common/probe_resolve.c` does real bulk `regexec`-based symbol matching,
  replacing a `-e`/`-F` func-side match that had silently never worked via exact
  `strcmp`), then `-I`/`-i`/`-r` were hard-removed from `funcs`/`correlate` with
  zero net capability loss (verified by an exhaustive semantic audit of every old
  regex-matching code path before removal), and the now-fully-dead `mod_matches`/
  `resolve_targets`/`resolve_targets_for_file` were purged from
  `common/probe_resolve.c`. EPIC H is complete. Tracked in
  `ares-project/TODO.md` EPIC H (H1-H12 done — complete).

### 2026-07-10

- **C9 — `funcs` sockaddr decode.** A `funcs` uprobe on a function taking a
  `struct sockaddr *` (e.g. `-c 'libc.so!connect(F,A,V)'`) previously captured
  that arg only as a NUL-terminated string — garbage for a binary sockaddr.
  Added a new `ARG_SOCKADDR` arg type (`probe_resolve.h`) and DSL marker `A`
  (`probe_resolve.c`'s `parse_custom_probe_spec`, grammar now
  `MOD!FUNC(S,V,F,A)>V`); `struct event` gained a per-arg `sock[NUM_ARGS][28]`
  capture buffer (`funcs.h`); BPF capture is gated by a `sockaddr_capture` rodata
  flag (`funcs.bpf.c`, mirrors the existing `snapshot_enabled` pattern) — off by
  default, zero cost unless a probe spec actually tags a sockaddr arg. The
  loader scans `custom_probe_specs[]` (parsed before `funcs_bpf__load()`, since
  target resolution/`probe_targets[]` only happens after skel load — not what
  the item's naive "scan targets" framing assumed) to decide whether to enable
  it. Decode reuses the already-shared `decode_sockaddr` (no engine-specific
  decoder needed — `funcs_emit.c` already `#include`d `common/decode.h` for
  `render_fd`); `funcs.c` gained the same include for its console renderer.
  Emits a `sock_args` JSON object (mirrors `fd_args`/`string_args`) and prints
  `args[N] ip:port` on console. New `test_funcs_emit.c` case (2 checks: 31 total,
  was 29) + a `test_probe_spec.c` DSL assertion for the `A` marker (added but
  **not run** in this env — `test_probe_spec` needs `libelf-dev`, not installed
  here and no root to `apt install` it; pre-existing gap, same category as the
  `python3+duckdb` note below). **v1 limits:** fixed `SOCK_ADDR_MAX=28` passed as
  `len` — exact for INET/INET6 (fixed offsets), an AF_UNIX path >26 B truncates;
  no `addrlen` captured on the funcs path (unlike syscalls, which reads the next
  syscall arg) so length is always the fixed max. `make test` full suite green
  (all pre-existing checks unaffected — pure addition, existing `S/V/F` specs
  byte-identical). **Pending:** the `sock[]` field grows `struct event`, so the
  checked-in `src/funcs/ares-tracer.skel.h` is stale and needs `bpftool`
  regeneration (unavailable here — same blocker as the file-access/
  ransomware-burst drop-telemetry entry below); on-device confirmation that
  `ares funcs -c 'libc.so!connect(F,A,V)'` renders `ip:port` folds into the
  standing pending-on-device-verification item.

- **MCP richness follow-on: span query tools.** Added `spans` (flat `func_spans`
  filter — `parent_span=N` answers "what's under span N"), `span_tree`
  (recursive-CTE call-tree subtree from a root span, rows tagged with `depth`),
  and `span_syscalls` (flat `span_syscalls` filter, `decoded` flattened to a
  string) query methods + MCP tools over the previously-unexposed
  `func_spans`/`span_syscalls` tables (populated by `load_structured` but only
  consumed internally by the un-wired `correlate_spans()` before this). Pure
  read-only additions — existing tables/methods/tools untouched. New
  `test_spans.py` (17 checks) + `testdata/spans.jsonl` fixture.

- **MCP richness follow-on: `*_summary` ingest.** `load_structured` gained a
  bucket for the five mod-analyzer teardown records (`execve_summary`,
  `prop_read_summary`, `file_access_summary`, `ransomware_burst_summary`,
  `proc_event_summary`) — previously falling into the `skipped` count, same as
  `coverage` did before its fix. Stored as parsed Python dicts on
  `TraceStore._summaries` rather than a DuckDB table (small, bounded records
  whose nested arrays don't map cleanly to `STRUCT[]` inserts), reset on every
  `load`/`load_structured`. One generic `summaries(kind=None, top=50)` query
  method + MCP tool; each record's own nested list (`binaries`/`props`/`paths`/
  `processes`) is capped to `top` entries by `count`. Pure addition — the only
  behavior change is traces containing summary records now report a smaller
  `skipped` count. New `test_summaries.py` (14 checks) +
  `testdata/summaries.jsonl` fixture.

- **MCP richness follow-on: diff/timeline for funcs-span data.** Added
  `diff_calls` (the `diff_traces` analog for funcs data — loads two structured
  traces into throwaway `TraceStore`s and reports `(module,symbol)` call-sites
  and in-span syscalls seen only in `compare`) and `span_timeline` (spans in
  allocation order with a per-span in-span-syscall count, the call-ordering
  view a histogram doesn't give) query methods + MCP tools. Pure read-only
  additions. New `test_diff_timeline.py` (16 checks) + `testdata/spans_b.jsonl`
  fixture (`testdata/spans.jsonl` gained a matching `call` record so the diff
  is meaningful). Closes out the "full `server.py` tool surface for
  `func_spans`/`span_syscalls`/summary records, diff/timeline views" item.

- **`mod file-access`/`mod ransomware-burst` drop-telemetry gap closed.** Both
  analyzers now follow the same pattern as `proc-event`/`execve`/`prop-read`:
  `bpf_drop.bpf.h` included, `bump_dropped()` called at each ring-buffer
  reserve-failure site (`file_access.bpf.c`'s `on_openat`/`on_openat2`;
  `ransomware_burst.bpf.c`'s `record_touch()` re-arm branch — the deliberate
  `bpf_ringbuf_discard` path-gate-reject paths are untouched, not drops), and a
  `*_drops()` accessor (needed adding `common/runtime.h`, previously unincluded
  in these two files) wired into each `ares_analyzer_t.drops` field. Their
  already-emitted `coverage` record's `ring_drops` field goes from always-`0` to
  accurate. `make build/{file_access,ransomware_burst}.bpf.o` compile clean;
  `make test` green (33+ existing checks incl. both classify suites, unaffected).
  **Pending:** userspace `.c` compile needs `bpftool` to regenerate stale
  `*.skel.h` (`dropped` map missing from the checked-in skeletons) — absent in
  this dev env; on-device confirmation that `ring_drops` reports nonzero under
  ring pressure folds into the standing pending-on-device-verification item.

- **CR5 follow-on: MCP `coverage` ingest + tool.** `tools/ares-mcp/trace_store.py`'s
  `load_structured` gained a `coverage` bucket (a flat, nullable `coverage` table,
  one row per engine record, flattening the sparse omitted-when-zero
  `snaps`/`cfi`/`drops`/`returns` JSON) and a `coverage()` query method; `server.py`
  exposes it as an MCP `coverage` tool so a client can check "was this trace clean"
  without grepping raw JSONL. Pure addition — existing `call`/`return`/`func`/
  `syscall+span` buckets untouched; the only behavior change is traces containing
  coverage records now report a smaller `skipped` count, verified against the
  existing `test_unified_ingest.py` fixture (no coverage records in it, assertion
  unaffected). New `test_coverage_ingest.py` + `testdata/coverage.jsonl` fixture
  (19 checks).

- **MCP richness follow-on: call analysis tools.** Added `call_histogram`,
  `call_timing` (count/min/max/avg/p50/p95 of `returns.elapsed_ns`), and
  `calls_where` (module/symbol/pid/tid filtered) query methods + MCP tools over the
  previously-unexposed `calls`/`returns` tables (populated by `load_structured` but
  only consumed internally by `correlate_spans` before this). Pure read-only
  additions, existing tables/methods/tools untouched. New
  `test_call_analysis.py` (25 checks) against the existing `unified.jsonl` fixture.

- **Dev-env note:** `python3 -m venv` failed here (`ensurepip` missing, no root to
  `apt install python3-venv`); worked around via `--without-pip` + bootstrapping pip
  from `get-pip.py`, then normal `pip install -e tools/ares-mcp`. `duckdb`+`mcp` now
  importable via `tools/ares-mcp/.venv` — the long-standing "no python3 duckdb
  module" environment gap (see tiered-audit-fix-plan memory) is resolved for this
  venv, not the bare system `python3`.

### 2026-07-09

- **Engine file-output symmetry with `ares syscalls` (stdout/file asymmetry closed).**
  `syscalls`'s `-o` file was the reference (superset of stdout); `funcs` and `mod`
  had real gaps. `funcs`: CALL/RETURN backtrace frames were addr-only (the earlier
  "funcs JSON backtrace" entry below), no `ppid`/module-relative `offset`, and
  RETURN carried no backtrace at all — console already resolved and printed all of
  it. Fixed by resolving `syms[]` in `funcs.c` (same `sym_resolve` call the console
  already makes) and passing it into the still-symbolizer-free `funcs_emit_call`/
  `funcs_emit_return` (mirrors the `execve.c` pattern); `test_funcs_emit` extended
  (29 checks). `mod`: each analyzer's teardown summary table (exec tallies, RASP
  flags, file-access categories, burst stats, fork/exit counts) printed to stdout
  only. New optional `emit_summary(sink)` hook on `ares_analyzer_t`
  (`src/common/analyzer.h`), called from `mod.c` before the coverage footer; each
  analyzer emits one `{"type":"<name>_summary",...}` record from the same tally
  `print_summary` already reads. Scope: `dump` deliberately excluded (writes binary
  rebuilt `.so` images, not a trace-event stream — no JSON record path to enrich).
  `correlate`'s `decoded[]` array and the syscalls-only monotonic `id` were left
  as-is (enrich-only; no reshape of already-equivalent-but-differently-shaped
  fields). See DOCUMENTATION.md §3.1, §6.6, §7.

- **lib-filter attribution defect fixed (was: sidestepped, not fixed).**
  `lib_ranges` was armed *only* from live `uprobe_mmap` events, so `libc.so`
  (and any other library mapped in the zygote and inherited by the forked app
  via COW) never got a range armed — no mmap fires in the child — and every
  syscall it issued failed the `sysc_issuer_hit` check even though frame-0 is
  reliably `libc!__openat`. Fixed by seeding `lib_ranges` from a one-time
  `/proc/<pid>/maps` scan (`seed_lib_ranges_from_maps`, `src/syscalls/syscalls.c`)
  the moment the target pid is known — attach (`-p`) and just-launched (`-P`,
  now passes `out_pid` to `ares_launch_app`) — before the event loop starts.
  Live mmap arming is unchanged for libraries loaded later; `push_lib_range`
  already dedups by `[start,end)` so overlap with the seed is a no-op. The
  glob/substring match predicate (`lib_name_matches`) is now shared with the
  new seed path via `lib_selector_matches_name` (new `src/syscalls/lib_seed.h`,
  header-only pure predicate, same pattern as `attribution.h`/`snapshot_gate.h`)
  so the two arming paths can't drift. New `tests/test_lib_seed.c` (7 checks).
  Not yet device-verified — folds into the existing pending on-device item.

- **AA3 — `trace`↔engine driver ABI unified via shared header (Tier 7, landed).**
  `trace.c`'s 9 hand-written prototypes and the Makefile's per-engine
  `--keep-global-symbol` lists could drift silently (a signature change
  produced no compile error at the coordinator boundary). New
  `src/common/engine_driver.h` declares the `{setup,run,teardown}` contract for
  all five engines (plus `correlate_attach`, added with GA2 below) once; every
  engine's `.c` and `trace.c` both `#include` it, so a signature change is now a
  compile error. The Makefile's keep-lists moved into per-engine `*_DRIVER`
  variables (`SYSC_DRIVER`/`FUNC_DRIVER`/`LIB_DRIVER`/`CORR_DRIVER`/
  `DUMP_DRIVER`, same `$(foreach)` pattern as the existing `COMMON_API`); a new
  `tests/check_driver_symbols.sh` (wired into `make test`) greps the header and
  the Makefile lists and fails the build if they diverge — belt-and-suspenders
  for the one case the compile-error fix doesn't cover (a stale *extra* keep,
  which is harmless but silent).
- **Phase 3d — coordinator-wide `-p` in `trace` (Tier 7, landed).** `trace`
  previously only launched via `-P`; each standalone engine already supported
  `-p PID[,...]` attach mode. Added a top-level `-p` to `trace_args` (mutually
  exclusive with `-P`), which `trace` injects as `-p <csv>` into each requested
  engine's own built argv and uses to skip the launch entirely — no
  `ares_run_ctx`/`launch.h` change needed, since each engine already fully
  self-arms `target_pids` from its own `-p` parsing when `rc` is zeroed.
- **GA2 — `dump` and `correlate` wired into `trace` (Tier 7, landed).** Completes
  the GA2 major item (`lib` wiring landed earlier, 2026-06-26).
  - **`dump`**: purely additive — `dump_run` already fit the coordinator's
    `run_thread` model (`ares_rb_poll_until` + on-exit rescan), so this was just
    a `--dump` section in `trace_args` and slotting `dump_setup`/`_run`/
    `_teardown` into the existing arm/launch/drain/teardown blocks. `dump`'s
    `argp` requires an explicit `-P`/`-p` (stricter than syscalls/funcs/lib), so
    `-p` attach mode needed the same `-p <csv>` argv injection Phase 3d added,
    extended to `dump` (and later `correlate`) too.
  - **`correlate`**: the real work. `correlate_setup` used to own its `-P`
    launch internally, because uprobe attach needs the launched PID (only known
    post-launch) — this was the one engine that couldn't fit the "setup arms,
    caller launches" contract the other four already followed. Refactored to
    match: `correlate_setup` now honors `rc->pkg` pre-fill like the others and
    arms everything PID-independent (skel open/load, UID install, span kprobe,
    lib-trace kprobes, ring buffer); a new 5th public function,
    `correlate_attach(pid)`, does the post-launch uprobe attach
    (`wait_for_target_mapped` + `attach_uprobes_for_pid`), called by both
    `cmd_correlate` (standalone `-P` mode) and `trace`'s coordinator right after
    their own `ares_launch_app` succeeds. No-op in `-p` attach mode, where PIDs
    are already known at setup time and attached there instead — verified
    byte-for-byte identical call order/behavior in both standalone modes
    against the pre-refactor code (regression audit, load-bearing per the
    coordinator's "setup arms, caller launches" invariant).
  - `dump`'s output is ELF images + an on-exit rescan, not a live stream, so
    combining it with the streaming engines is lifecycle parity, not
    necessarily a useful combined run — documented as such.
- **CR2 — `syscalls` "issued by" attribution + pre-arm window + 32-bit compat
  hook (Tier 6, landed).** Three changes to the same subsystem, all in
  `src/syscalls/`:
  - **Issuer-only attribution** (the core fix). `stack_hits` — any-of-32-frames
    in the target library's range — over-attributed transitively (`targetlib →
    malloc → mmap` counted as a target-lib syscall). Replaced with
    `sysc_issuer_hit` (new `attribution.h`, host-testable like
    `snapshot_gate.h`): a hit requires `stack[0]` (trap PC, frame-pointer
    independent) or `stack[1]` (immediate caller) in range — deeper frames are
    transitive callers, not the issuer. New `tests/test_syscalls_attribution.c`
    (12 checks) asserts the transitive-frame case now misses, plus edge cases
    (n=0/1, half-open range boundary, multi-range, count==0). `COV_DEPTH_CAP`'s
    bump moved to the stack-capture site (it's a general truncation signal
    shared with `funcs`/`correlate`'s span-stack overflow, per
    DOCUMENTATION.md's coverage table — not attribution-specific, so it was
    kept, not deleted, when `stack_hits` was removed).
  - **Pre-arm window** — reduced, not eliminated. Range arming
    (`push_lib_range`) moved from the worker thread (`process_event`) to the
    drain thread (`enqueue_event`), removing the queue-latency hop between an
    mmap event arriving and its range landing in the BPF map. Three comments
    that asserted arming was "race-free" (`syscalls.c` header, `syscalls.bpf.c`
    header + gate) were factually wrong and now describe the real bounded
    window, still counted by `COV_PREARM`/`prearm_drops`.
  - **`do_el0_svc_compat` hook** (32-bit/AArch32 app syscalls, previously
    totally invisible). New BPF program, nr from `regs[7]` (not x8), same
    args/attribution/pre-arm/snapshot-dedup logic as the 64-bit path. Does
    **not** reuse anything keyed on the arm64 syscall-number namespace: no
    `-s`/`-x` allow/denylist, no string/sockaddr capture (`arg_types`/
    `sock_args` are arm64-keyed — applying them to EABI numbers would decode
    against the wrong syscall's metadata, a new bug), no return-value pairing
    (no kretprobe attached to any compat syscall impl). New `compat` flag on
    `struct syscalls_syscall_event`; userspace renders these as
    `compat_syscall_<nr>` (`sysname()`) and skips `arg_count`/`arg_fd_mask`/
    `arg_sock_index`/`flags_decode_arg` (same arm64-keyed reasoning) — args
    shown raw. Attach is non-fatal (`bpf_program__set_autoattach(...,false)` +
    manual `bpf_program__attach`, mirroring the existing `ares_follow_fork`
    pattern) since kernels without `CONFIG_COMPAT` have no
    `do_el0_svc_compat` symbol and the skeleton's blanket `syscalls__attach()`
    fails whole-hog if any autoattach program can't attach. Deliberately
    scoped down (`ponytail:` comment in `syscalls.c`): compat syscalls named
    numerically; add an ARM-EABI `{nr,name}` table (mirrors
    `common/syscall_table.c`) if compat naming matters — vendoring ~400 rows
    was out of proportion for closing the visibility gap.
  - **Docs** (closes Tier 0's remaining CR2 disclosure item too — same
    paragraph). DOCUMENTATION.md §2 rewritten around the issuer-only rule +
    compat hook + pre-arm window; the Raw-vs-CFI paragraph now notes
    `stack[1]` degrades on frame-pointer-omitted targets; the vDSO section now
    states vDSO calls are attribution-invisible (no `svc`), not just a naming
    capability. README's syscalls Limitations bullet and the CFI-unwind limits
    list got the equivalent disclosures.
  - **Verification.** `make test` green including the new
    `test_syscalls_attribution`. Unlike prior tiers, `clang -target bpf`
    **does** work in this dev environment (only `bpftool` is missing) —
    `src/syscalls/syscalls.bpf.c` (all three changes: attribution, pre-arm
    comment/logic move, new compat program) compiled clean end-to-end via
    `make build/syscalls.bpf.o`, a stronger check than prior tiers had for
    BPF-side changes. `syscalls.c` (userspace) still can't be end-to-end
    compiled — `build/syscalls.skel.h` predates this work and regenerating it
    needs `bpftool gen skeleton`, not installed here (no root) — so the
    userspace changes were verified by careful manual type/call-site review
    instead (every `sysname`/`arg_count`/`arg_fd_mask`/`arg_sock_index`/
    `flags_decode_arg` call site was grepped and confirmed gated or updated).
  - **Pending on-device verification** (added to the on-device list above):
    `target→malloc→mmap` no longer attributed while `target→mmap` still is;
    an inline-`svc` hand-asm library attributed via `stack[0]`; a 32-bit app
    surfaces `compat_syscall_*` events; `prearm_drops` lower than the
    pre-change build on a library that syscalls at init; regenerate
    `syscalls.skel.h` on a machine with `bpftool` and confirm `syscalls.c`
    compiles end-to-end against the real (not hand-reviewed) layout.

### 2026-07-08

- **Tier 4 — ART/managed-frame batch (CR4 parity fix, AA9 double-symbolization, SW1
  hardening — fixed).** Three items from the 2026-07-07 graph-informed audit, all
  touching the same managed-frame naming surface, landed together:
  - **CR4 — ShadowFrame parity in the compact managed chain.** `ares_managed_chain`
    (`src/common/symbolize.c`) — the compact `managed[]` fragment shared by both engines
    and cached in the jcache — only ever tried the nterp guess-path, even at an
    `ExecuteSwitchImpl` (switch-interpreter) terminal; the authoritative ShadowFrame walk
    (`art_shadow.c`) was reachable only from the full `cfi_stack` JSON emitter
    (`ares_emit_cfi_stack_json`). Added the missing `ExecuteSwitchImpl` branch calling
    `shadow_frame_chain`, mirroring the JSON path exactly — no reordering across
    terminals (nterp and switch-interp are distinct terminals reading different
    `ManagedStack` fields, so one can't substitute for the other; see the Major CR4 item
    for why a fully-authoritative nterp path is separate, harder future work). Zero
    regression by construction: `shadow_frame_chain` returns 0 on BuildID miss /
    `tls_base==0`, so the nterp branch runs exactly as before whenever shadow doesn't
    apply.
  - **AA9 — double frame symbolization.** `funcs.c`/`syscalls.c` each called
    `ares_emit_cfi_stack_json` then `ares_managed_chain` back-to-back on the same
    snapshot, each re-resolving all `n` frames independently under `g_lock`. Both public
    functions (`src/common/managed_frame.h`) gained an optional pre-resolved `syms`
    array (NULL = resolve internally, preserving existing host-test call shape); both
    call sites now resolve once and share the result. The alloc-churn half of AA9
    (heap `jbuf` floored at 8192 B) was investigated and deferred — see Minor for why.
  - **SW1 — ELF-note parser hardening.** `read_build_id_hex`
    (`src/common/art_buildid.c`) read section-header fields at fixed offsets after a
    `min(shentsize, 64)`-bounded `fread`; a malformed `shentsize < 0x28` would leave
    those fields reading uninitialized `sh[]` bytes. Added a `shentsize < 0x28` guard
    (fails closed — same behavior class as today's other malformed-input paths). Exposed
    (no longer `static`) as a test seam per the `art_shadow.h`-style precedent already in
    this codebase; `test_art_buildid` gained a malformed-shentsize case.
  - **Docs.** Managed-frame (Java) naming labeled experimental/best-effort in
    `DOCUMENTATION.md` and `README.md` — a BuildID miss returns no Java names silently
    and must not read as "app used no Java" (the CR4 strategic ask).
  - Host-verified: `make test` all green, incl. new `test_art_buildid` case;
    `symbolize.c`/`managed_frame.c`/`art_buildid.c`/`art_shadow.c` syntax-checked clean
    (`cc -fsyntax-only`, `symbolize.c` via a throwaway `lzma.h` stub since its one real
    dependency gap — the WSL dev env lacking `liblzma-dev` — is unrelated to the touched
    code, confirmed by grepping for actual `lzma_*` call sites: none exist in the file).
    `funcs.c`/`syscalls.c` call-site edits could not be compiled end-to-end (missing
    `libbpf`/`gelf.h`/generated BPF skeletons, the same pre-existing WSL gap noted in
    prior tiers) — verified instead by type-checking the call sites against the
    now-compiling `symbolize.c` signatures, confirming `sym_resolve` is already visible
    in both files, and a standalone snippet confirming the `const char *arr[N]` →
    `const char *const *` parameter passing used at both call sites is valid C. **Pending
    on-device verification** (added to the on-device list above): confirm ShadowFrame
    names now surface in the compact `managed[]` fragment at an `ExecuteSwitchImpl`
    terminal, and that `nterp_helper` terminals are unchanged.

- **Tier 5 — `correlate` accuracy batch (CR3/`--returns`, decode completion, regex
  targeting, `-P` timing — landed).** Four items from the 2026-07-07 audit, all on the
  `correlate` engine, reusing `funcs`'/`syscalls`' existing mechanisms rather than
  inventing new ones:
  - **CR3 / `--returns`.** `CORR_EV_RETURN` event + `corr_uretprobe_ret`
    (`correlate.bpf.c`), mirroring `funcs.bpf.c`'s `uretprobe_open` line-for-line: fires
    at the real return instruction and authoritatively pops the span
    (`bpf_map_delete_elem`+`span_depth_set`), independent of SP behavior. Opt-in via new
    `-R`/`--returns`; entry-only targets keep the SP-pop best-effort default unchanged
    (see CR3 above for why SP-pop itself isn't touched). `corr_emit_return` emits
    `{"type":"return",...}` with `span`/`entry_addr`/`retval`/`elapsed_ns`. (Event shipped
    2026-07-06 — see below; this batch adds decode/regex/timing around it.)
  - **Decode completion.** `corr_syscall_event` gained `str_present`/`str[]`/`sock_len`/
    `sock[]` (sizes matched to `syscalls.h`); `corr_on_svc` gained the string- and
    sockaddr-capture blocks copied verbatim from `syscalls.bpf.c`. Userspace gained
    `g_fd_args`/`g_str_args`/`g_sock_args` tables + `install_arg_types`/`install_sock_args`
    (copied from `syscalls.c`); `corr_emit_syscall`'s `decoded[]` array now follows the
    same string → fd → sockaddr → flags/enum precedence as `syscalls`' `render_arg`.
    `decode_partial` flipped from 1 to 0 in the coverage report.
  - **Regex (`-I`/`-i`) targeting.** New flags compile into `regex_t mod_re[32]`/
    `func_re[32]` (mirrors `funcs.c`); `attach_uprobes_for_pid` calls the shared
    `resolve_targets_for_file()` per executable mapping alongside the existing
    custom-spec loop, attaching entry (+ `--returns` uretprobe when requested) at each
    resolved offset. Regex-matched functions emit the same unconditional hex args as
    custom specs — no new arg-decode path needed for FUNC events. Return-only regex
    (`-r`) deferred, noted as a follow-up (would open an invisible span with no value
    given `--returns` already covers regex targets).
  - **`-P` attach timing.** Blind `sleep(1)` replaced with `wait_for_target_mapped()`
    — polls `/proc/<pid>/maps` every 10 ms up to a 2 s cap for a spec'd or regex-matched
    library mapped executable, attaching the moment it appears; falls through to
    today's behavior on timeout.
  - Host-verified: `make test` all green, including `test_corr_emit` extended with
    content assertions (decoded path string, `ip:port` sockaddr, rendered fd, decoded
    flags, plus the new return-event shape) — no longer just key-presence checks.
    `correlate.c` syntax-checked clean (`cc -fsyntax-only`) against a scratch copy of
    the stale generated skeleton patched with the new prog/map fields (real skeleton
    regen needs `clang`+`bpftool`, unavailable in this WSL dev env — same pre-existing
    gap noted in prior tiers). `correlate.bpf.c`'s new BPF program and capture blocks
    are copied verbatim from already-BPF-verified sibling code (`funcs.bpf.c`,
    `syscalls.bpf.c`) but could not themselves be verifier-checked here.
  - **Pending on-device verification** (added to the on-device list above): `--returns`
    span-close correctness across a coroutine/async workload vs. entry-only mode;
    `openat`/`connect` decode rendering; `-I`/`-i` resolve+attach with and without
    `-R`; `-P` timing catching an early post-launch call the old `sleep(1)` missed.

### 2026-07-07

- **Tier 3 perf/efficiency batch (AA4, AA5-remainder, AA7, R9 residual, N1, AA6, AA8 —
  fixed; C8 closed as stale).** Seven independent perf items from the graph-informed
  audit, all landed together:
  - **AA4** — `funcs.c`'s `find_target_by_entry_addr` fast path was an O(N) linear
    scan of `probe_targets[]`. Added a fixed 16384-slot open-addressing hash
    (`addr -> probe_target_t*`, `pt_hash_get`/`pt_hash_put`), populated at the same
    two sites that already assign `runtime_entry_addr` (the `/proc/maps`-miss path
    and the low-12-bit fallback). No grow/rehash needed — `probe_targets[]` +
    `retired_targets[]` cap at 4096 each, so the fixed table stays ≤50% loaded even
    at that ceiling. Also caches `retired_targets[]` fallback hits for the first
    time (previously re-scanned every repeat event).
  - **AA5 remainder** — `dynsym_get`/`cfi_get` (`src/common/sym_elf.c`) linear-scanned
    with a `strcmp` per candidate. Added a growable `(path,elf_off) -> index` hash
    (`elfidx_get`/`elfidx_put`, FNV-1a path hash), verified by a single `strcmp` only
    on a hash hit. AA1's `pm_get` hoist was the other half of AA5; this closes it.
  - **AA7** — `syscalls.c`'s `arg_count`/`arg_fd_mask`/`arg_sock_index` were per-event
    linear scans. Added `by_nr[512]` dense arrays (`build_arg_tables()`, called once
    at setup alongside the existing `ares_sysindex_build`), mirroring the R9 pattern.
    Also fixed `json_emit`'s redundant re-scan of `arg_fd_mask` per argument (now
    reuses the already-hoisted `fdm`), and hoisted the same two lookups in
    `render_arg` (found during the audit, not in the original BACKLOG text — its
    signature now takes precomputed `fdm`/`sockidx` from its one caller,
    `handle_syscall`).
  - **R9 residual** — `g_sys[]` (`syscalls.c`) and `syscall_names[]` (`correlate.c`)
    were two separate compilations of the same generated `syscalls_gen.h` data.
    Collapsed into a new shared `src/common/syscall_table.{c,h}` (`ares_syscall_table`/
    `ares_syscall_table_count`), consumed by both engines' `ares_sysindex_build` calls
    and `syscalls.c`'s `sysnr()`. Required Makefile changes: added the new file to
    `COMMON_CSRC`, both new symbols to `COMMON_API`'s `--keep-global-symbol` list,
    `-I$(BUILD)` to `COMMON_CFLAGS`, and an explicit `$(SYSCALLS_TBL)` prerequisite
    on `syscall_table.o` (mirroring `syscalls.o`/`correlate.o`'s existing explicit
    deps, since auto-deps only catch this after a first successful compile).
  - **N1** — `funcs.c`'s STACK-event CFI walk (`cfi_unwind_snapshot`) and managed-chain
    build (`ares_managed_chain`) ran inline on the drain thread; moved into
    `process_call_return` so they run on the worker thread instead, mirroring
    `syscalls.c` exactly. Confirmed via `syscalls.c`'s own `g_cov` comment
    ("mutated only on the worker thread ... no lock needed") that no new locking
    was needed here either — the old `funcs.c` comment's speculation that a lock
    would be required was itself the thing to correct, not a real requirement.
    Worker's scratch buffer enlarged to fit a `struct ares_stack_snapshot`.
  - **AA6** — MCP `load_structured`'s four per-row `con.execute(INSERT...)` loops
    replaced with `con.executemany(...)` (one round-trip per table instead of per
    row), preserving the existing Python-side type-bucketing/skip-counting rather
    than a riskier `read_json`-based rewrite.
  - **AA8** — MCP `wx_scan`'s `add_ivl` re-sorted and rebuilt the entire `ever_w`
    list per writable mapping; replaced with `bisect.bisect_left` + local-window
    merge (only the interval immediately before/after the insertion point).
  - **C8 "duplicate vmlinux.h"** — investigated directly: only one `vmlinux.h`
    exists in ARES's own build graph (repo root); the only other file by that name
    is vendored libbpf's own CI action (`third_party/libbpf/.github/...`),
    unreferenced by ARES's Makefile. Closing as stale rather than inventing a fix
    for a problem that isn't there; reopen with a concrete file:line if the
    original concern resurfaces.

  Host-verified: `make test` green throughout (unaffected — no host test targets
  any of these hot paths directly). Real compiles, not just review, for the pure-
  userspace pieces: `sym_elf.c` and `syscalls.c` (Part A) syntax-check clean via a
  borrowed `lzma.h`/the existing skeleton (0 errors); the R9-residual Makefile
  wiring verified via `make -n`, confirming the exact recipe (`-Ibuild` present,
  correct cross-compiler invoked) and the correct `--keep-global-symbol` additions
  in the dry-run `common.part.o` link line — a real compile needs the aarch64
  cross-toolchain, unavailable in this environment. `funcs.c` (AA4/N1) couldn't be
  compiled (`gelf.h` missing, no root to install `libelf-dev`) — verified by
  careful manual diff review instead. `trace_store.py` (AA6/AA8) syntax-checked
  clean with `python3 -m py_compile`; `add_ivl`'s merge logic additionally verified
  against a standalone hand-worked reproduction (including cases beyond the
  original plan: fully-contained and bridging inserts), matching the old
  full-rebuild's output exactly.

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

### 2026-07-06

- **`correlate --returns` capture-rate coverage field.** CR5's `correlate` record
  now carries `"returns":{"spans":N,"captured":M}` on `--returns` runs (BPF percpu
  counters `COV_SPAN_OPEN` bumped on `span_stack_push` success, `COV_URET_FIRED` on
  return-record emit; read at teardown). Surfaces how many return values were
  captured vs. spans traced without hand-diffing; a gap (`captured < spans` =
  SP-reconcile-backstop closes) flips the record to degraded. Firewall unchanged
  (data-map bumps only). Host-tested (`test_coverage`); device-verified 2026-07-06
  (clean path 15/15 captured; forced gap 723/722, banner + JSON `returns` block correct).

- **`correlate --returns` - opt-in uretprobe for return value + exact exit
  timing.** New `CORR_EV_RETURN` / `struct corr_return_event {span, entry_addr,
  retval, elapsed_ns}` (`src/correlate/correlate.h`), emitted as
  `{"type":"return",...}` (`src/correlate/corr_emit.c`, reuses `TRACE_RETURN`).
  BPF side adds `corr_uretprobe_ret` (`SEC("uretprobe")` in
  `src/correlate/correlate.bpf.c`), attached alongside each entry uprobe only
  when `--returns` is passed; on a real return it authoritatively pops the top
  span frame and reports raw `retval` (x0) + `elapsed_ns` (return ktime minus
  entry ktime) - the pre-existing SP-based `span_stack_reconcile` stays wired
  in as the backstop for a span whose uretprobe never fires. LOUD: this is a
  second detection surface (uretprobe trampoline on the target stack) beyond
  correlate's existing entry `BRK`; disclosed via a one-line stderr notice when
  active. Firewall gate unaffected (`correlate` was already loud;
  `capabilities.c` unchanged). Retval is raw only - no fd/string/errno decode
  (stays parked, see Major). Device-verified 2026-07-06 (well-formed `{"type":"return"}`
  records with raw retval + `elapsed_ns`; authoritative pop + SP-reconcile backstop both exercised).

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
