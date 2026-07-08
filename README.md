# ares

**ares** is an Android RASP (Runtime Application Self-Protection) and malware
analysis tracer. It inspects what an app does at both the **Java and native
layers** by combining two complementary eBPF tracing engines in a single binary:

| Subcommand | Engine | What it sees | Footprint |
|---|---|---|---|
| `ares syscalls` | kprobe on the syscall dispatcher, filtered by which library a syscall came from | every syscall a target library makes, with decoded args + backtraces | **injectionless** — nothing is written into the target; `TracerPid` stays 0 |
| `ares funcs` | uprobe/uretprobe on specific functions (spec-driven), plus process/exec/getprop modules | individual function calls with typed arguments, return values and timing | **detectable** — inserts a `BRK` into the target's code |
| `ares correlate` | entry uprobes (spec-driven) + a span-gated syscall kprobe sharing a per-tid span stack | the syscalls each probed function makes on a live run, each tagged with that function's `span` (function→syscall) | **detectable** — uprobe writes a `BRK`; loud by design |
| `ares dump` | kprobe launch + shared lib_trace probe (like `ares lib`) | dumps matching modules from live memory → a rebuilt loadable ELF (.so) of a possibly-decrypted/packed library | **injectionless** — kprobe only, nothing written into the target |

> **Pick the right engine for the job.** `syscalls` is stealthy and ideal for
> RASP triage (e.g. clean-vs-rooted diffing). `funcs` is more granular but a
> RASP can detect its uprobe instrumentation. They run as **separate
> subcommands** on purpose — see *Detectability* below.

An optional host-side **MCP server** (`tools/ares-mcp`) lets an LLM client
(Claude Code / Claude Desktop) query a captured trace and drive on-device
library dumping.

---

## Prerequisites

**Target device**
- **Rooted** Android device, **arm64 / aarch64** only (ELF64).
- A kernel with **eBPF + BTF** (CO-RE). Most modern Android kernels qualify.
- SELinux typically needs to be **permissive** to load eBPF (note: a RASP can
  treat permissive SELinux as a tamper signal).
- `adb` access; commands run as root (`su -c` on Magisk, or `adb root`).

**To build** (you only need one of these)
- **Easiest:** Docker or Podman. Nothing else — the container carries the whole
  cross-toolchain.
- **Native:** an aarch64 cross-toolchain + clang/llvm/bpftool (see *Building*).

**To download instead of build:** grab the prebuilt static `ares` binary from the
[Releases](../../releases) page — most users never need to build.

---

## Building

### Option A — container (recommended, no host setup)

```sh
git clone --recurse-submodules <repo-url> ares
cd ares
./scripts/build.sh           # builds the image, compiles, leaves build/ares
```

`build.sh` uses Docker, or Podman if Docker is absent (`CONTAINER_RUNTIME=podman`
to force). The static aarch64 binary lands at `build/ares`.

### Option B — native build

```sh
sudo apt install clang llvm bpftool gcc-aarch64-linux-gnu make git
sudo dpkg --add-architecture arm64 && sudo apt update
sudo apt install libelf-dev:arm64 zlib1g-dev:arm64 libzstd-dev:arm64 liblzma-dev:arm64
git submodule update --init --recursive
make                         # -> build/ares
```

> Building on a kernel that differs from the committed `vmlinux.h`? Regenerate it from
> your kernel's BTF — see *Regenerating `vmlinux.h`* in DOCUMENTATION.md.

> The `:arm64` multiarch packages are Debian/Ubuntu-specific and the usual
> source of build pain. If they won't install, use the container build — it
> sidesteps them entirely.

---

## Deploying

```sh
./scripts/deploy.sh          # adb push build/ares + specs to /data/local/tmp
# or: make push
```

---

## Testing

Three automated tiers, each runnable on its own, plus a manual fourth:

```sh
make test            # host unit tests — pure logic, no device, no cross-toolchain
make device-test     # on-device smoke — pushes the binary, asserts each capability
                     #   attaches and emits real output (needs the rooted device)
```

- **`make test`** compiles and runs `tests/` on the host (`cc` + `libelf`); it
  checks the custom probe-spec grammar parser. CI (`.github/workflows/ci.yml`) runs
  this plus the containerized cross-build on every PR.
- **`make device-test`** runs `scripts/device-test.sh [lib|syscalls|all]`. Override
  the target app with `ARES_TEST_PKG=<package>` and the per-capability window with
  `ARES_TEST_TIMEOUT=<secs>` (default 10). It needs a rooted device with kernel BTF.
- **`scripts/burstapp/build.sh install`** (manual, not wired into `make`) builds and
  installs a minimal real app for verifying `mod ransomware-burst` against genuine
  app-UID file activity instead of a synthetic PID — see DOCUMENTATION.md §"Testing
  tiers" for the flow.

---

## Usage

### `ares syscalls` — stealthy syscall tracer

```sh
# Trace syscalls that pass through a specific library (default mode):
ares syscalls -o trace.jsonl com.example.app librasp.so

# Capture ALL of an app's syscalls (no library filter):
ares syscalls -a -o trace.jsonl com.example.app

# Capture stack snapshots + CFI-unwind into Java callers (capture-all reaches JNI stacks):
ares syscalls -a -s openat --snapshot -o trace.jsonl -P com.example.app
# Writes trace.jsonl  (syscall events)
# Writes trace.jsonl.stacks  ({"type":"stack",...} raw snapshot + {"type":"cfi_stack",...} CFI backtrace)
```

Common flags: `-a` all syscalls · `-s/-x list` include/exclude syscalls · `-o file` (`.jsonl` =
streamable JSON Lines) · `-q` quiet · `--snapshot` enable stack snapshots + CFI unwind.

**`--snapshot` and `cfi_stack` records:** When `--snapshot` is used with `-o <file>`
(in either library-filter or capture-all `-a` mode — capture-all is what reaches
JNI-originated stacks), each trapped syscall
captures a frozen register file + up to 32 KB of user-stack bytes. These are written
to `<file>.stacks` as a `{"type":"stack",...}` record. Immediately after, the CFI
unwinder (`cfi_unwind_snapshot`) walks the frozen snapshot across module boundaries
using DWARF `.eh_frame`/`.debug_frame`. A companion `{"type":"cfi_stack","stack_id":N,"cfi_backtrace":[...]}` record follows in the same sidecar, each frame carrying `addr`, `symbol`, and `kind` (`native` | `jni-trampoline` | `managed` | `interp`). The syscall/call records themselves now carry an inline `java_stack` field — a managed/Java call chain (innermost-first, native frames elided) when a managed caller resolves, e.g. `["pkg.Inner.method","pkg.Outer.method"]` (best-effort; AOT frames reliable, nterp frames inherit documented precision limits).

**Status: native unwinding works; the live `art_jni_trampoline` cross is not yet
complete.** Under capture-all the engine now unwinds the full native chain on JNI-originated
stacks (`libc → … → libandroid_runtime`) — snapshots flow under `-a` (W6, done) and the
maps-cache staleness that stopped the walk at frame 0 is fixed (2026-06-29). The trampoline
FDE in `boot.oat` is verified to recover the managed caller. **Two** follow-ups (BACKLOG) gate
a live cross: **W3-window** — the 32 KB snapshot `bpf_probe_read_user` faults to 8 KB at
runtime (299/307 snapshots truncate on-device), so the unwind dies one frame short of the
trampoline; fix is a chunked stack capture. **W5** — JIT-compiled caller frames have no
file-backed CFI; unreachable until W3-window lands.

**Limits of `--snapshot` / CFI unwind:**
- Works only for **compiled-JNI** paths: the Java method must have been compiled ahead-of-time (`.oat`/`.odex`/`.vdex`) so it has a native frame with a DWARF FDE. JIT-compiled callers (W5) and interpreter frames (`ShadowFrame`, tagged `"kind":"interp"`) are not yet crossed/named.
- **Inlining defeats CFI attribution:** an inlined callee has no FDE and cannot be named.
- Cross-thread offloaded syscalls are not attributed (CFI is per-tid, synchronous).

### `ares funcs` — function tracer

```sh
# Trace functions from a spec file against a spawned app:
ares funcs -P com.example.app -F /data/local/tmp/specs/common-file.spec

# Attach to a running PID and trace functions matching a regex in a module:
ares funcs -p 12345 -I libfoo.so -i '^encrypt'

# Inline custom probe spec (S=string arg, V=value, F=fd):
ares funcs -P com.example.app -e 'libc.so!strcmp(S,S)>V'

# Structured JSONL mode: emit one self-describing record per CALL/RETURN event
# into the -o sink (alongside the normal text output):
ares funcs -p 12345 -e 'libc.so!open' -J -o trace.jsonl
# Each line is a JSON object: {"type":"call","pid":...,"symbol":"open",...}
#                          or  {"type":"return","pid":...,"retval":...,"elapsed_ns":...}
```

**`-J` / `--structured`** writes one structured JSONL record per CALL or RETURN
event into the `-o` file alongside the existing text output. The record shape is:

```json
{"type":"call",   "pid":N,"tid":N,"module":"libc.so","symbol":"open",
                  "entry_addr":"0x...","args":["0x..","0x..",..]}
{"type":"return", "pid":N,"tid":N,"module":"libc.so","symbol":"open",
                  "retval":N,"elapsed_ns":N}
```

These records share the same `type` discriminator as `ares syscalls` / `ares lib`
output, making them compatible with the ares-mcp unified schema. Requires `-o
<file>.jsonl` to be set (records go into the same JSONL sink; existing text/legacy
wrapper is preserved).

Common flags: `-p PID` / `-P package` target · `-I module` · `-i func-regex` ·
`-r func-regex` (return-only) · `-e spec` / `-F spec-file` ·
`-o file` (`.jsonl`/`.csv`) · `-J` structured JSONL records (see below).

Probe spec format (see `specs/`): `MODULE!FUNC[(ARGTYPES)]>[RETTYPE]`, e.g.
`libc.so!open(S)>V`.

### `ares correlate` — function→syscall tracer (loud)

Attaches an entry uprobe to each spec'd function and a **span-gated** syscall
kprobe: every syscall a probed function issues on its thread (while the function
is on the stack) is emitted carrying that function's `span` id. Nested probed
functions get a `parent_span` chain. Detectable (uprobe `BRK`), so run it only
when you accept that exposure.

```sh
# Which syscalls does libc.so!open make, in a launched app:
ares correlate -e 'libc.so!open' -P com.example.app

# Attach to a running PID with multiple specs (quote specs containing parens):
ares correlate -p 12345 -e 'libssl.so!SSL_write(S)' -e 'libc.so!open'

# Structured output:
ares correlate -o corr.jsonl -e 'libc.so!open' -P com.example.app
```

Flat JSONL: `{"type":"func","span":N,"parent_span":M,...}` and
`{"type":"syscall","span":N,"syscall":"openat",...}` — join on `span`.
Flags: `-p PID` / `-P package` · `-e SPEC` (repeatable) / `-F spec-file` ·
`-o file.jsonl` · `--returns` (opt-in, see below). **Quote specs with
parentheses** (`'libc.so!open(S)'`) so the shell doesn't choke on the `(`. v1
captures raw syscall args (no decode) and, by default, uses SP-based span close
(no return values). Limits: up to 64 PIDs and 64 specs per run (a warning
prints if you exceed either, rather than silently dropping the extras); `-o`
reports `wrote N event(s)` at exit.

Plain `correlate` (no `--returns`) stays entry-uprobe-only: one BPF program, one
`BRK` per probed call, span close inferred from the stack pointer. Pass
`--returns` to also get the return value and exact call duration:

```sh
# Also capture retval + exact elapsed time for each probed call (LOUD: adds a
# uretprobe trampoline, a second surface beyond the entry BRK):
ares correlate --returns -e 'libc.so!open' -P com.example.app
```

This attaches a second BPF program (a uretprobe) at each spec'd function's
offset, alongside the entry uprobe, and adds
`{"type":"return","span":N,"entry_addr":"0x...","retval":"0x...","elapsed_ns":N}`
records. `retval` is the raw return register (x0) only - no fd/string/errno
decode yet. This is opt-in and strictly louder than plain `correlate`: it is a
second detection surface on top of the entry `BRK`, and `ares` prints a
one-line stderr notice when it is active. If a probed call's uretprobe never
fires (e.g. the thread exits mid-call), the existing SP-based reconcile still
closes that span - no return record for it, but tracking never gets stuck.

### `ares lib` — library-load tracer

Launches an app fresh and lists every native library (`.so`) it loads, from the
process's first thread. Like `syscalls` it gates by app UID installed *before*
launch (injectionless / stealthy — a kprobe on `uprobe_mmap`, nothing written
into the target), so it catches the earliest linker loads and every forked app
process.

```sh
# Trace all libraries an app loads (Ctrl-C to stop):
ares lib com.example.app

# Pass an explicit launcher activity if it can't be auto-resolved:
ares lib com.example.app com.example.app/.MainActivity

# Also write structured JSON Lines for later analysis:
ares lib -o libs.jsonl com.example.app
```

Output line:

```
[lib] pid 22045 /data/app/~~.../lib/arm64/libfoo.so [0x7a..,0x7b..) off=0x0 inode=12345 ppid=1037
```

Common flags: `-o file.jsonl` structured output (`{"type":"lib",...}`) · `-v` also
print `[unlib]` unmap lines (off by default — keeps the stream to `[lib]` only) ·
`-q` quiet. This is the dedicated standalone library-load tracer; to dump a library
out of live memory into a loadable ELF, use `ares dump` (see below).

### `ares dump` — live-memory library dumper

Launches an app fresh (stealthy, like `ares lib`) and rebuilds a possibly
decrypted/packed native library out of `/proc/<pid>/mem` into a loadable ELF.

```sh
# Dump every loaded library whose basename matches a glob, on exit:
ares dump -d /data/local/tmp com.example.app 'libpacked.so'

# Catch a randomized-name library the moment it maps:
ares dump --on-map -d /data/local/tmp com.example.app 'e_[0-9]*'
```

Flags: `--on-map` dump at map time (default: on exit, post-decryption) ·
`--raw` raw phdr-fixed image, skip ELF rebuild · `-q` quiet · output filename is
`<name>.<pid>.<base>.so`.

### MCP server (optional, host-side)

```sh
cd tools/ares-mcp
pip install -e .
ARES_TRACE=/path/to/trace.jsonl ares-mcp        # or configure in your MCP client
```

See `tools/ares-mcp/README.md` for client configuration and the available tools.

---

## Detectability

ares keeps the two engines as **separate subcommands** deliberately:

- `syscalls` is **injectionless**: it hooks the kernel syscall dispatcher, writes
  nothing into the target, and leaves `TracerPid` at 0 — invisible to in-process
  RASP integrity checks.
- `funcs` **writes a `BRK`** into the target's executable pages (how uprobes
  work). A RASP that checksums its own code or inspects function prologues can
  detect this.

**Putting both in one on-disk binary does not make `syscalls` any more
detectable** — the binary sits at `/data/local/tmp`, not inside the target. The
risk is *behavioral*: running `funcs` against a RASP-protected app can tip it off,
which would poison a stealthy `syscalls` capture (e.g. clean-vs-rooted diffing).
Run `funcs` only when you accept that exposure. Both engines also need eBPF
loading privileges (often SELinux permissive), itself a RASP tell.

---

## Limitations

- **arm64 / ELF64 only**; no 32-bit or x86 targets.
- **Rooted device required**; needs eBPF + BTF and (usually) SELinux permissive.
- `syscalls`: string args captured for a built-in syscall set; return values for
  a curated set of syscalls; frame-pointer-based stack walks (omitted frame
  pointers are missed). `syscalls` backtraces name on-disk libraries, AOT app methods (`base.odex`,
  via embedded mini-debug-info), ART JIT methods (`[JIT]!`), and kernel vDSO
  calls (`[vdso]!`). Still shown as file+offset: interpreter/quickened dex frames
  (`base.vdex`, `[anon:dalvik-DEX data]` — planned). `[anon:dalvik-main space]`
  frames are GC-heap addresses surfaced by frame-pointer unwinding, not methods.
- `funcs`: uprobe instrumentation is detectable; spec-driven, so you must know
  which functions to target.
- `ares funcs` emits log-line JSONL by default; pass `-J` to also emit structured
  CALL/RETURN records. MAP/UNMAP/SPAWN/PROC_EXIT/EXECVE/PROP structured records and
  unified MCP ingest are planned (see `DOCUMENTATION.md`).
- Coverage gaps (the 32 KB snapshot cap, an unknown ART build, a blind CFI stop,
  the pre-arm window) used to fail silently. `syscalls`, `funcs`, and
  `correlate` now surface them explicitly in a per-run coverage-health record
  (stderr banner + `{"type":"coverage"}` in the `-o` sink) instead of leaving
  them to be inferred from missing output (see `DOCUMENTATION.md`).

---

## License

See [LICENSE](LICENSE).
