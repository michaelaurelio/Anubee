# ares

**ares** is an Android RASP (Runtime Application Self-Protection) and malware
analysis tracer. It inspects what an app does at both the **Java and native
layers** by combining two complementary eBPF tracing engines in a single binary:

| Subcommand | Engine | What it sees | Footprint |
|---|---|---|---|
| `ares syscalls` | kprobe on the syscall dispatcher, filtered by which library a syscall came from | every syscall a target library makes, with decoded args + backtraces; plus live ELF/library dumping | **injectionless** — nothing is written into the target; `TracerPid` stays 0 |
| `ares funcs` | uprobe/uretprobe on specific functions (spec-driven), plus process/exec/getprop modules | individual function calls with typed arguments, return values and timing | **detectable** — inserts a `BRK` into the target's code |

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

## Usage

### `ares syscalls` — stealthy syscall tracer

```sh
# Trace syscalls that pass through a specific library (default mode):
ares syscalls -o trace.jsonl com.example.app librasp.so

# Capture ALL of an app's syscalls (no library filter):
ares syscalls -a -o trace.jsonl com.example.app

# Just list the native libraries an app loads:
ares syscalls -l com.example.app

# Dump a (possibly decrypted) library from live memory on exit:
ares syscalls -l -D 'libpacked.so' --dump-dir /data/local/tmp com.example.app
```

Common flags: `-a` all syscalls · `-l` list libs only · `-D <glob>` dump
libraries · `-s/-x list` include/exclude syscalls · `-o file` (`.jsonl` =
streamable JSON Lines) · `-q` quiet.

### `ares funcs` — function tracer

```sh
# Trace functions from a spec file against a spawned app:
ares funcs -P com.example.app -F /data/local/tmp/specs/common-file.spec

# Attach to a running PID and trace functions matching a regex in a module:
ares funcs -p 12345 -I libfoo.so -i '^encrypt'

# Inline custom probe spec (S=string arg, V=value, F=fd):
ares funcs -P com.example.app -e 'libc.so!strcmp(S,S)>V'
```

Common flags: `-p PID` / `-P package` target · `-I module` · `-i func-regex` ·
`-r func-regex` (return-only) · `-e spec` / `-F spec-file` · `-m proc-event|execve`
modules · `-o file` (`.jsonl`/`.csv`) · `-D pattern` dump module.

Probe spec format (see `specs/`): `MODULE!FUNC[(ARGTYPES)]>[RETTYPE]`, e.g.
`libc.so!open(S)>V`.

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

Output line (shared with `syscalls -l` / `funcs -L`):

```
[lib] pid 22045 /data/app/~~.../lib/arm64/libfoo.so [0x7a..,0x7b..) off=0x0 inode=12345 ppid=1037
```

Common flags: `-o file.jsonl` structured output (`{"type":"lib",...}`) · `-q`
quiet. This is the dedicated standalone tracer; `ares syscalls -l` keeps the same
listing but is wired to the on-exit memory-dump pipeline (`-D`).

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
  pointers are missed).
- `funcs`: uprobe instrumentation is detectable; spec-driven, so you must know
  which functions to target.
- Today only `ares syscalls` emits **structured** JSONL that the MCP analyzes
  with field-level tools. `ares funcs` emits log-line JSONL; structured funcs
  output + MCP analysis is planned (see `DOCUMENTATION.md`).

---

## License

See [LICENSE](LICENSE).
