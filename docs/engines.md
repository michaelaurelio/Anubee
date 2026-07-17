# Engines: which to pick, and how to use each

ANUBEE ships seven subcommands. Six are engines (`syscalls`, `funcs`, `correlate`,
`lib`, `dump`, `trace`); the seventh (`mod`) runs packaged analyzers, see
[`analyzers.md`](analyzers.md). All spec-driven engines (`funcs`, `correlate`,
`syscalls`, `dump`, `mod`) share one probe-spec grammar, see
[`probe-specs.md`](probe-specs.md).

## Pick an engine

| Engine | Sees | Cost |
|---|---|---|
| `syscalls` | Every syscall a target library makes, decoded args + backtraces | **Injectionless** (nothing written into the target, `TracerPid` stays 0) |
| `funcs` | Individual function calls: typed args, return values, timing | **Detectable** (inserts a `BRK` into the target's code) |
| `correlate` | Which syscalls a probed function triggers, tagged with that function's span | **Detectable** (entry uprobe `BRK`), loud by design |
| `lib` | Every native library (`.so`) an app loads | **Injectionless** (kprobe only) |
| `dump` | A rebuilt loadable ELF of a live (possibly decrypted/packed) library | **Injectionless** (kprobe only) |
| `trace` | `syscalls` + `funcs`/`lib` together from one launch (`correlate`/`dump` are standalone-only) | Loud only if `funcs` is enabled |

`syscalls`/`lib` are ideal for stealthy RASP triage (e.g. clean-vs-rooted
diffing); `funcs`/`correlate` are more granular but a RASP can detect the uprobe
instrumentation. They're separate subcommands on purpose. Running `funcs`
against a protected app can tip it off and poison a stealthy `syscalls` capture
run alongside it.

## Attach modes: `-P` vs `-p`

Every engine below takes exactly one of:

- **`-P PACKAGE`**: launch mode (default). Force-stops and relaunches the app,
  capturing from the first thread.
- **`-p PID[,PID...]`**: attach to already-running process(es) instead. No
  launch. Add **`--siblings`** to also trace every process sharing that PID's
  UID, or **`--no-follow-fork`** to stop forked children from being auto-traced
  (on by default).

## Flags shared by every engine below

| Flag | Meaning |
|---|---|
| `-o FILE` | Export structured JSONL to `FILE` (also prints to console; `-q` silences that) |
| `-v` | Verbose debug output |
| `-q` | Suppress per-event console output |
| `-J` | Write JSON Lines (one record per line); default everywhere now, kept for compatibility |
| `-b MB` | Kernel ring buffer size (default 4) |
| `-Q MB` | Userspace worker queue size (default 256) |

(`lib` and `dump` use a smaller, engine-specific set, see their sections.)

---

## `syscalls`: stealthy syscall tracer

```sh
# Syscalls that pass through a specific library:
anubee syscalls -P com.example.app -l librasp.so -o trace.jsonl

# Capture ALL of an app's syscalls (no library filter):
anubee syscalls -P com.example.app -a -o trace.jsonl

# Stack snapshots + CFI-unwind into Java callers (capture-all reaches JNI stacks):
anubee syscalls -P com.example.app -a -s openat --snapshot -o trace.jsonl
```

| Flag | Meaning |
|---|---|
| `-P PACKAGE` / `-p PID[,...]` | Attach target |
| `-l SELECTOR` | Library selector: substring or glob (`e_*`); repeatable, OR'd |
| `-a` | Capture all syscalls (no library filter) |
| `-s LIST` / `-x LIST` | Allowlist / denylist, comma-separated syscall names (mutually exclusive) |
| `-e SPEC` / `-F FILE` | Probe spec: `syscall:[!]NAME` or `lib:[!]PATTERN`, see [`probe-specs.md`](probe-specs.md) |
| `--snapshot` / `--no-snapshot` | Capture stack snapshots for off-device unwinding (default: off) |
| `-A ACTIVITY` | Override launch activity component |

`--snapshot` writes a `<file>.stacks` sidecar (raw snapshot + CFI backtrace
records) alongside `-o <file>`; see [`reading-traces.md`](reading-traces.md).

## `funcs`: function tracer

```sh
# Trace functions from a spec file against a spawned app:
anubee funcs -P com.example.app -F specs/common-file.spec

# Attach to a running PID, bulk-match by regex:
anubee funcs -p 12345 -e 'libfoo.so!/^encrypt/'

# Inline spec with typed args (S=string, V=value, F=fd, A=sockaddr):
anubee funcs -P com.example.app -e 'libc.so!strcmp(S,S)>V'

# Structured JSONL: one record per CALL/RETURN into -o:
anubee funcs -p 12345 -e 'libc.so!open' -o trace.jsonl
```

| Flag | Meaning |
|---|---|
| `-P PACKAGE` / `-p PID[,...]` | Attach target |
| `-e SPEC` / `-F FILE` | `MODULE!FUNC[@OFFSET][(ARGTYPES)][>RETTYPE]`, see [`probe-specs.md`](probe-specs.md) |
| `-c` | Print only the direct caller, suppress the rest of the backtrace |
| `-S` | Resolve and print symbols only, no uprobe attachment |
| `--snapshot` / `--no-snapshot` | Capture stack snapshots for off-device DWARF unwinding (requires `-o`) |
| `-A ACTIVITY` | Override launch activity component |

Output is always JSONL into `-o` (one `{"type":"call",...}` / `{"type":"return",...}`
record per event); console text is a separate, independent channel.

## `correlate`: function→syscall tracer (loud)

Attaches an entry uprobe to each spec'd function plus a span-gated syscall
kprobe: every syscall a probed function issues on its thread is emitted tagged
with that function's `span`. Nested probed functions get a `parent_span` chain.

```sh
# Which syscalls does libc.so!open make, in a launched app:
anubee correlate -P com.example.app -e 'libc.so!open'

# Attach to a running PID, multiple specs (quote specs containing parens):
anubee correlate -p 12345 -e 'libssl.so!SSL_write(S)' -e 'libc.so!open'

# Also capture retval + exact elapsed time per call (adds a uretprobe, louder):
anubee correlate -P com.example.app -e 'libc.so!open' --returns -o corr.jsonl
```

| Flag | Meaning |
|---|---|
| `-P PACKAGE` / `-p PID[,...]` | Attach target |
| `-e SPEC` / `-F FILE` | `MODULE!FUNC[(ARGTYPES)]`, see [`probe-specs.md`](probe-specs.md) |
| `--returns` | Also attach uretprobes: return value + exact span timing (opt-in, adds a second detection surface) |

Up to 64 PIDs and 64 specs per run. `{"type":"func",...}` / `{"type":"syscall",...}`
records join on `span`; `--returns` adds `{"type":"return",...}`.

## `lib`: library-load tracer

Launches an app fresh and lists every native library it loads.

```sh
anubee lib com.example.app                         # Ctrl-C to stop
anubee lib com.example.app com.example.app/.MainActivity   # explicit launcher activity
anubee lib -o libs.jsonl com.example.app            # also write structured JSONL
```

| Flag | Meaning |
|---|---|
| `-P PACKAGE` / `-p PID[,...]` | Attach target |
| `-o FILE` | Structured JSONL output |
| `-v` | Also print `[unlib]` unmap lines (default: `[lib]` only) |
| `-q` | Suppress human-readable `[lib]` console lines |
| `-A ACTIVITY` | Override launch activity component |

Output line: `[lib] pid 22045 /data/app/.../lib/arm64/libfoo.so [0x7a..,0x7b..) off=0x0 inode=12345 ppid=1037`

## `dump`: live-memory library dumper

Launches an app fresh and rebuilds a possibly decrypted/packed native library
out of `/proc/<pid>/mem` into a loadable ELF.

```sh
# Dump every loaded library whose basename matches a glob, on exit:
anubee dump -d /data/local/tmp com.example.app 'libpacked.so'

# Catch a randomized-name library the moment it maps:
anubee dump --on-map -d /data/local/tmp com.example.app 'e_[0-9]*'

# Snapshot an already-running process's currently-mapped modules right away -
# a pure /proc read, no BPF skeleton, no attach, nothing injected into the
# target at all:
anubee dump -p 12345 -d /data/local/tmp --now 'libpacked.so'

# Select by exact load address instead of by name - immune to a library that
# randomizes its on-disk name per run, which defeats -l by construction:
anubee dump -p 12345 -d /data/local/tmp --now --base 0x7281a0000

# Compare a module's live executable memory against its on-disk baseline
# instead of dumping (writes modcmp records, no .so files); --base also
# reaches an APK-embedded library, which -l cannot select at all:
anubee dump -p 12345 --now --check --base 0x7281a0000 -o check.jsonl
```

| Flag | Meaning |
|---|---|
| `-P PACKAGE` / `-p PID[,...]` | Attach target |
| `-A ACTIVITY` | Override launch activity component |
| `-d DIR` | Output directory (default: current dir) |
| `-l PATTERN` | Library basename pattern to dump (glob/substring); repeatable, OR'd |
| `--base ADDR` | Select a module by its exact load base (hex) instead of by name; repeatable, cap 64. OR'd with `-l` |
| `-F FILE` | Spec file; a `lib:` line supplies `PATTERN` when none given positionally |
| `--on-map` | Dump the instant a matching library maps (default: dump on exit, post-decryption) |
| `--now` | Requires `-p`. Rescan the target's already-mapped modules via a pure `/proc` read and exit 0 - no BPF skeleton, attach, or ring buffer at all |
| `--check` | Requires `--now`. Compare each selected module's executable memory against its on-disk baseline instead of dumping; emits `{"type":"modcmp",...}` records, writes no `.so` files |
| `--raw` | Emit the raw phdr-fixed image, skip ELF rebuild |
| `-q` | Suppress progress chatter |

Output filename: `<name>.<pid>.<base>.so`.

`--now` exists because the default (event-driven) triggers only ever learn
which pids to rescan from a library-map event: attaching `-p` to a process
whose libraries are already mapped generates no such event, so dump-on-exit
rescans nothing and, absent `--now`, waits for Ctrl-C indefinitely. `--now` is
also strictly quieter than the (already injectionless) default - it attaches
nothing to the target process at all.

`--check` hashes only `PT_LOAD` segments with the `PF_X` flag - `.data` /
`.got` / `.data.rel.ro` are rewritten by the dynamic linker on every load, so
hashing them would report a difference for every library on the device. Each
`modcmp` record's `state` is one of `match` (identical to disk), `differ` (the
unpacking / self-modification signal), `nofile` (no disk backing), `apk` (an
APK-embedded module, but no stored member starts at the observed offset), or
`unreadable` (a short/failed `/proc/<pid>/mem` read, a bad ELF header, an
unusable phdr table, or a failed allocation - never reported as `differ`, since a partial read hashes
wrong and a false "modified" verdict on a clean library would destroy the
signal's only value).

**APK-embedded libraries:** for an `extractNativeLibs=false` app (the modern
AGP default), every embedded `.so` maps straight out of `base.apk`. `-l`'s
selector only ever sees the raw `/proc/<pid>/maps` path, which for such an app
is `base.apk` for every embedded library - it has no knowledge of the
library's resolved name, so it cannot select one. `--base` is the only
selector that reaches such a module, and the emitted `modcmp` record's
`"module"` field then reads `"base.apk"`, not the library's name.

## `trace`: combined runner (loud if `funcs` is enabled)

Runs `syscalls` + `funcs`/`lib` together from one app launch — the gap standalone
`syscalls`/`funcs` can't cover alone. Independent streams, no cross-engine
correlation (use `correlate` standalone for that). `correlate` and `dump` are
**not** composable into `trace`: `correlate` is itself a funcs+syscalls fusion
that would double-instrument the same targets and needs its own post-launch
uprobe attach; `dump` is a batch engine (rebuilt `.so` files, not a JSONL
stream). Run either standalone alongside `trace` if you need them.

No section markers — every flag routes itself to the engine(s) that
understand it, and its presence enables that engine:

```sh
anubee trace -P com.example.app -o /data/local/tmp/run \
           -a \
           -e 'libc.so!open' -e 'libc.so!/^encrypt/'
```

`-a` is syscalls-only (enables `syscalls`, captures everything); the two `-e`
specs are unprefixed `funcs:` targets (enable `funcs`). Mixing engines needs
no marker — just give each engine's own flags on the same command line.

| Flag | Meaning |
|---|---|
| `-P PACKAGE` / `-p PID[,...]` | Attach target (shared by every engine) |
| `-o PREFIX` | Writes `<prefix>.syscalls.jsonl`, `<prefix>.funcs.jsonl`, `<prefix>.lib.jsonl` |
| `-e SPEC` / `-F FILE` | Probe spec (repeatable); routed by `KIND:` prefix — `syscall:NAME`/`lib:PATTERN` → syscalls, `funcs:MODULE!FUNC`/unprefixed → funcs. A `-F` file may carry both kinds and enable both engines. `mod:` is not a trace engine. |
| `-l PATTERN` | Syscalls library selector, equivalent to `-e 'lib:PATTERN'` |
| `-a` / `-s LIST` / `-x LIST` | Syscalls-only: capture-all / allowlist / denylist; each enables `syscalls` |
| `-S` / `-c` | Funcs-only: resolve-syms mode / caller-only; each enables `funcs` |
| `--snapshot` / `--no-snapshot` | Stack snapshots, broadcast to whichever of syscalls/funcs is enabled |
| `--lib` | Enable library-load tracing (no spec of its own) |
| `-A ACTIVITY` | Override launch activity component |
| `-v` / `-q` / `-b MB` / `-Q MB` | Shared verbosity/buffer flags, broadcast to every enabled engine (`-b`/`-Q`: syscalls+funcs only, `lib` has neither) |

At least one engine must end up enabled — via a unique flag, a routed spec, or
`--lib`. `-P`/`-p`, `-A`, and `-o` can appear anywhere on the command line
(no ordering requirement — there are no sections left to come before).

## Gotchas

- **`funcs`/`correlate` are detectable; `syscalls`/`lib`/`dump` are not.** Don't
  run a detectable engine alongside a stealthy capture you need to stay clean:
  it can tip off the RASP and poison the stealthy run.
- **`-P` and `-p` are mutually exclusive**, one is required.
- **Quote specs containing parentheses** (`'libc.so!open(S)'`), otherwise the
  shell chokes on the `(`.
- **`correlate` caps at 64 PIDs and 64 specs per run.** A warning prints if you
  exceed either; extras are dropped rather than silently ignored.
- **`--returns` on `correlate` and `--snapshot` on `syscalls`/`funcs` are both
  opt-in and louder** than the plain engine: each adds a second detection
  surface (a uretprobe trampoline, or a wider stack capture).
- **`dump`'s `-l`/spec-file `lib:` patterns are substring/glob only.** No
  `/regex/` support, unlike `funcs:`'s module side.
