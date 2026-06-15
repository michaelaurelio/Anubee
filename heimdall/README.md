# heimdall

An eBPF/CO-RE syscall tracer for a single Android app. By default it is **filtered
by native-library call origin** — a syscall is reported only when the issuing
thread's user backtrace passes through a chosen `.so` (e.g. a RASP / anti-tamper
library) — but with `-a` it captures **all** of the app's syscalls. Inspired by
frida-strace's in-kernel stack-filter design, but standalone and on-device.

For **technical deep-dive** on how everything works, see [DOCUMENTATION.md](DOCUMENTATION.md).

## Quick Start

```sh
# On-device (rooted Android, SELinux permissive):
/data/local/tmp/heimdall <package> <lib>              # library-filtered trace
/data/local/tmp/heimdall -a -o trace.json <package>   # capture-all → JSON
/data/local/tmp/heimdall -l <package>                 # just list loaded libraries
/data/local/tmp/heimdall -l -D 'e_*' <package>        # dump decrypted .so from memory
```

---

## Capture Modes

### Library-Filtered Trace (Default)

```sh
heimdall <package> <lib>
```

Captures **only** syscalls originating from a chosen library. `<lib>` is a substring
of the mapped name, **or a glob** (`* ? []`) over it — use `'e_*'` / `'e_[0-9]*'` to
target a protector payload loaded under a randomized per-run name.

**Why it's fast:** the in-kernel hook skips the stack walk entirely until the library
is mapped, and drops any syscall whose backtrace misses it. Near-zero overhead on
unrelated processes.

**Examples:**
```sh
heimdall com.example.app librasp.so
heimdall com.example.app libtoyguard.so com.example.app.MainActivity  # with activity
heimdall com.example.app 'e_[0-9]*'  # randomized-name payload (glob)
```

### Capture-All Mode

```sh
heimdall -a <package>
```

Captures **every** syscall of the app's UID, from its first one. A firehose — a user
backtrace is taken on *every* syscall — so expect high event volume. Best paired with
`-o trace.json` or `-J` (JSON Lines) output.

If the ring buffer fills, dropped events are counted and reported at exit
(`warning: N event(s) dropped …`) so you know whether the trace is complete.

**Examples:**
```sh
heimdall -a com.example.app
heimdall -a -q -J -o trace.jsonl com.example.app  # quiet, JSON Lines
heimdall -a -s openat,read,close com.example.app  # only these syscalls
heimdall -a -x futex,poll com.example.app         # all except these
```

### Libraries-Only Mode

```sh
heimdall -l <package>
```

Logs each native library (`.so`) as it loads into the app's userspace memory.
**Zero syscall overhead** — only the library-load hook runs, the syscall dispatcher
hook is never attached.

Each line shows the library basename, its executable range, file offset and inode:

```
[lib] pid 12903  libc.so                  [0x7c1d20000, 0x7c1d2f000)  off=0x0  inode=4210
[lib] pid 12903  librasp.so               [0x7b004a000, 0x7b0061000)  off=0x0  inode=8814
```

Pairs with `-o file.json` / `-J` for machine-readable output. Cannot be combined with
`-a`/`-s`/`-x` (there are no syscalls to filter).

---

## Dumping Libraries from Memory (`-D`)

Reconstructs a **loadable `.so` from a library's live process memory**, capturing
in-memory decryption/unpacking. Packers and RASP often ship a native library whose
code is encrypted on disk and only decrypted *in memory* after load.

```sh
# Let the app run long enough for the library to decrypt, then Ctrl-C to dump:
heimdall -l -D libpacked.so --dump-dir /data/local/tmp com.example.app
...
[dump] libpacked.so (pid 12903) -> /data/local/tmp/libpacked.so.12903.7b004a000.so  (212992 bytes)
[dump] wrote 1 module image matching 'libpacked.so' to /data/local/tmp
```

### How It Works

- **Whole-range capture:** reads the entire mapped range page by page, capturing data
  packers stash in gaps *between* segments. Unreadable guard pages are zero-filled.

- **Program-header fixup:** rewrites each program header so the file's layout mirrors
  memory (`p_offset = p_vaddr`), making the file loadable.

- **Relocation un-applying:** restores file-relative values for relative relocations
  the loader applied in memory — both classic `DT_RELA` (`R_AARCH64_RELATIVE`) **and `DT_RELR`**.

- **Section-header reconstruction:** regenerates a full section table from the dynamic
  segment — `.dynsym`, `.dynstr`, `.hash`, `.rela.dyn`, `.rela.plt`, `.relr.dyn`,
  `.init_array`, `.fini_array`, `.dynamic`, `.text`, `.data`, `.shstrtab` — so tools
  that read section headers (incl. IDA/Ghidra) see named sections and the dynamic symbol table.

- **`.dynamic` de-rebasing:** restores pointer entries (`DT_SYMTAB`, `DT_STRTAB`, etc.)
  from absolute to relative offsets, and clears `DT_DEBUG`.

The result loads in IDA/Ghidra with named sections and dynamic symbols intact.

### Randomized Library Names

A protector often loads its payload under a name that changes every run (e.g.
`e_<pid>` / `e_<random>`). Pass a glob to `-D` and it's matched against the mapping
basename — `'e_*'` or `'e_[0-9]*'` catches such a payload regardless of the per-run
suffix. A pattern with no glob characters keeps the original "substring" behavior.

**Fallback:** if the rebuild trips over an unusual packer's dynamic info, `--dump-raw`
writes just the phdr-fixed raw memory image (no section table, no relocation rebuild).

---

## Command-Line Reference

```
usage: heimdall [-o out.json] [-v] [-q] [-a|-l] [-D lib] [-b MB] [-s list|-x list] <package> [lib] [activity]
  -a, --all           capture ALL syscalls of the app (no library filter)
  -l, --libs          only log libraries loaded into the app (no syscalls)
  -D, --dump lib      at exit, dump every loaded library whose name contains <lib>
                      from the app's live memory (captures in-memory decryption)
      --dump-dir dir  directory for dumped .so images (default: current dir)
  -s, --syscall list  only these syscalls (comma-separated names, e.g. openat,read)
  -x, --exclude list  all syscalls except these (comma-separated names)
  -o, --json <file>   export captured syscalls to a JSON file (implies -q)
  -J, --jsonl         write JSON Lines (one record/line; crash-safe, streamable)
  -b, --bufsize MB    ring buffer size in MB (default 4; rounded up to a power of 2)
  -q, --quiet         suppress per-event console output (much faster under load)
  -v, --verbose       also log every executable mapping
```

**Environment variables** (mirror the flags):
`HEIMDALL_JSON`, `HEIMDALL_VERBOSE`, `HEIMDALL_DEBUG`, `HEIMDALL_ALL`, `HEIMDALL_LIBS`,
`HEIMDALL_QUIET`

---

## Output Formats

### Console Output (Default)

Each syscall gets a monotonic **id**. The entry line (`==>`) prints only the syscall's
**real arguments** (per a built-in arm64 arg-count table — no trailing register garbage),
with string (path) args and fd args resolved inline. A `<==` line prints the **return
value** when the call completes (paired by id):

```
==> #42 [12903/12903] openat(AT_FDCWD, "/proc/self/maps", O_RDONLY|O_CLOEXEC)
      #0  libc.so!openat+0x8
      #1  libc.so!fopen+0x54
      #2  librasp.so!scan_maps+0x178
      #3  libc.so!__pthread_start+0x2c
<== #42 openat = 199
==> #43 [12903/12903] read(fd=199 </proc/self/maps>, 0x71db5032c0, 0x400)
      #0  libc.so!read+0x8
      ...
<== #43 read = 1024
```

**Decoded arguments:** flag / enum arguments are decoded (`O_RDONLY|O_CLOEXEC`,
`PROT_READ|PROT_WRITE`, `MAP_PRIVATE|MAP_ANONYMOUS`, `SIGKILL`, …), and the `sockaddr`
of `connect`/`bind`/`sendto` is resolved to the peer address — `connect(fd=42, 142.250.4.100:443)`,
`sendto(fd=45, …, unix:@frida)`.

**Frame resolution:** frames resolve to `lib!function+0xdelta`. Frames with no matching
symbol show `lib+0xvaddr`. Non-ELF executable memory is labelled by region: `[anon]+0x..`
(unnamed JIT/packer), `jit-cache+0x..` (named ART), `0x.. [unmapped]` (not in `/proc/maps`).
Errors decode the errno: `-2 (No such file or directory)`.

### JSON Output (`-o`)

A single JSON array (only valid after clean exit); each element is one syscall:

```json
{
  "id": 42, "pid": 12903, "tid": 12903,
  "syscall_nr": 56, "syscall": "openat", "retval": 199,
  "args": ["0xffffff9c", "0x7c1e3a40", "0x80000", "0x0", "0x0", "0x0"],
  "string_args": { "1": "/proc/self/maps" },
  "fd_args": { "0": "AT_FDCWD" },
  "decoded_args": { "2": "O_RDONLY|O_CLOEXEC" },
  "backtrace": [
    { "frame": 0, "addr": "0x7c1d2a1c", "symbol": "librasp.so!scan_maps+0x178" }
  ]
}
```

For `connect`/`bind`/`sendto` a `"sock_addr"` field carries the decoded peer
(e.g. `"142.250.4.100:443"`, `"[2001:db8::1]:8443"`, `"unix:@frida"`).

### JSON Lines Output (`-J`)

One record per line, flushed ~once a second. Crash-safe: a hard-kill / reboot /
second-Ctrl+C leaves a file that's still valid up to the last second — you lose
at most a few records, not the whole trace.

**File naming convention:** use `.jsonl` extension or pass `-J` to enable. `heimdall-fold.py`
and the MCP layer both accept either format.

### Performance & Throughput

A **drain thread** copies events out of the kernel ring into a large userspace
**worker queue** (default 256 MB), and a **worker thread** does symbolization + JSON
writing. This keeps the kernel ring empty and absorbs bursts in RAM.

Symbolization is **cached** (address→symbol and fd→path), and JSON is written with a
fast in-memory serializer. `-o` implies `-q` (quiet console).

If you see drops on a very heavy target, raise the queue (`-Q 512`) and/or the kernel
ring (`-b 128`); the exit line reports kernel-ring vs queue drops separately.

---

## Post-Processing: Loop Folding

```sh
tools/heimdall-fold.py trace.json                 # text summary
tools/heimdall-fold.py trace.json --json folded.json
# tunables: --min-reps K  --max-period N  --callsite-frames N  --no-nesting
```

Detects **loops in the syscall sequence** and folds them, so a 500-iteration scan reads
as one entry. Runs per-thread, tokenizes by syscall name + call stack, and folds maximal
tandem runs smallest-period-first (discovering nested loops). Original event ids are kept,
so nothing is lost.

**Output:** a `loops` registry (`{id, period, body, occurrences, iterations_total}`)
plus a per-thread `timeline` that replaces each run with `{ "loop": "L4", "iterations": 2, "event_ids": [...] }`.

---

## LLM-Driven Analysis

For LLM-assisted analysis, an **MCP server** exposes the trace to Claude Code / Claude
Desktop as queryable tools (`overview`, `hot_loops`, `files`, `query`, `get_event`,
`distinct_backtraces`, `via`-origin filtering, …).

See `tools/heimdall-mcp/README.md` for setup and tool reference.

---

## Build (Host, Not Device)

CO-RE means the BPF object is compiled once on the host and relocated against the
device kernel's BTF at load time. The loader is cross-compiled into a **static
aarch64** binary you push to the device.

### One-Time Host Dependencies

**Debian/Ubuntu:**
```sh
sudo apt install clang llvm bpftool gcc-aarch64-linux-gnu
sudo dpkg --add-architecture arm64 && sudo apt update
sudo apt install libelf-dev:arm64 zlib1g-dev:arm64 libzstd-dev:arm64
git submodule update --init --recursive      # vendored libbpf
```

**macOS:**
```sh
brew install llvm bpftool
# For cross-compilation to aarch64, use a cross-compile toolchain or Docker
```

### Build & Deploy

```sh
make            # → build/heimdall (static aarch64)
make push       # adb push to /data/local/tmp/heimdall
```

`vmlinux.h` is committed (generated from this device's `vmlinux.btf`). After a kernel
change, re-pull the BTF and run `make regen-vmlinux`.

---

## Run (Rooted Device)

```sh
adb shell
su
setenforce 0    # eBPF on Android usually needs SELinux permissive during testing

# Library-filtered trace:
/data/local/tmp/heimdall com.example.app librasp.so

# Randomized-name payload (glob):
/data/local/tmp/heimdall com.example.app 'e_[0-9]*'

# With specific activity:
/data/local/tmp/heimdall com.example.app libtoyguard.so com.example.app.MainActivity

# Capture everything to JSON Lines (quiet):
/data/local/tmp/heimdall -a -q -J -o /data/local/tmp/trace.jsonl com.example.app

# Only specific syscalls:
/data/local/tmp/heimdall -a -s openat,read,close,newfstatat com.example.app

# List loaded libraries:
/data/local/tmp/heimdall -l com.example.app

# Dump decrypted libraries from memory:
/data/local/tmp/heimdall -l -D libpacked.so --dump-dir /data/local/tmp com.example.app

# Export libraries as JSON:
/data/local/tmp/heimdall -l -o /data/local/tmp/libs.json com.example.app
```

### Back on Host

```sh
adb pull /data/local/tmp/trace.jsonl .
adb pull /data/local/tmp/*.so .
```

---

## Requirements & Limitations

### Requirements

- **Root** access on device
- Kernel with **BTF** (`CONFIG_DEBUG_INFO_BTF=y` — GKI mandates it), **kprobes**, and **uprobes**
- Verify the hook symbols exist: `adb shell su -c 'grep -wE "do_el0_svc|uprobe_mmap|uprobe_munmap" /proc/kallsyms'`
- **Frame pointers required** for stack unwinding
- **SELinux permissive mode** for testing (can detect as anti-tamper exposure)

### Limitations

- **arm64 / ELF64 only** — 32-bit and ARM are not supported
- **Syscall identity is by number, not libc function.** arm64 uses the generic ABI
  (`openat` not `open`, `faccessat` not `access`). Beyond the built-in table shows as `sys_<nr>`.
- **String args:** only args 0–3, capped at 256 bytes, and only for syscalls in the
  built-in table. Non-path string/buffer args (e.g. `write` buffers) show as raw pointers.
- **sockaddr decode:** `connect`/`bind`/`sendto` are captured at entry; `recvfrom`/`accept`
  fill the address at *return*, so those aren't captured (entry-only).
- **Return values** are only for syscalls in the curated kretprobe list (common
  file/proc/memory/process syscalls); others print without a `<==`. Heavily-blocking
  calls (futex/poll/epoll/nanosleep) are omitted to avoid dropped returns.
- **fd resolution** is best-effort via `/proc/<pid>/fd/<n>` at print time;
  a closed descriptor shows as `fd=<n>` without a path.
- **Symbolization** reads `/proc/<pid>/maps` and ELF `.dynsym` (dynamic symbols only);
  `static` functions and stripped libraries show as `lib+0xvaddr`.
- **Libraries mapped from an APK** (at a file offset) are grouped by contiguous run;
  oddly-laid-out APKs may mis-base.
- **Deleted libraries** (showing as `… (deleted)`, a common anti-analysis trick) are
  recovered via `/proc/<pid>/map_files/`.
- **Per-UID:** all processes of the app's UID are traced (main + `:child`).
- **Per-syscall overhead:** a determined RASP could time the tracer's presence.
- **Single-snapshot dumps** can't beat page-level re-encryption; dump timing matters.
- **Not handled:** APS2 packed relocations (`DT_ANDROID_REL[A]`), fully-anonymous blobs with no `vm_file`.

---

## Architecture & Implementation

See [DOCUMENTATION.md](DOCUMENTATION.md) for detailed technical information:

- **How it works:** in-kernel decision logic, stack-origin filtering, argument capture
- **Symbolization:** ELF parsing, frame-pointer unwinding, caching
- **Memory dumps:** phdr rewriting, relocation un-applying, section reconstruction
- **MCP analysis layer:** DuckDB-backed trace analysis, cross-run diffing, anti-tamper detection
- **End-to-end workflows:** triage workflows for RASP reverse-engineering

---

## License

[Your license here — e.g., MIT, Apache 2.0, or internal]
