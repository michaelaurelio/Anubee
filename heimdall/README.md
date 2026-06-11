# heimdall

An eBPF/CO-RE syscall tracer for a single Android app. By default it is **filtered
by native-library call origin** — a syscall is reported only when the issuing
thread's user backtrace passes through a chosen `.so` (e.g. a RASP / anti-tamper
library) — but with `-a` it captures **all** of the app's syscalls. Inspired by
frida-strace's in-kernel stack-filter design, but standalone and on-device.

## Two capture modes

- **Library-filtered (default):** `heimdall <package> <lib>` — only syscalls
  originating from that library. Cheap: the in-kernel hook skips the stack walk
  entirely until the library is mapped, and drops any syscall whose backtrace
  misses it. `<lib>` is a substring of the mapped name, **or a glob** (`* ? []`)
  over it — use `'e_*'` / `'e_[0-9]*'` to target a protector payload loaded under
  a randomized per-run name (same matching the `-D` dump option uses).
- **Capture-all:** `heimdall -a <package>` — every syscall of the app's UID, from
  its first one. A firehose (a user backtrace is taken on *every* syscall), so
  expect high event volume; pair it with `-o trace.json`. If the ring buffer
  fills, dropped events are counted and reported at exit
  (`warning: N event(s) dropped …`) so you know whether the trace is complete.
- **Libraries-only:** `heimdall -l <package>` — log each native library (`.so`) as
  it is loaded into the app's userspace memory, and nothing else. The syscall
  dispatcher hook is **never attached** in this mode, so it has effectively zero
  syscall overhead; only the `uprobe_mmap` hook runs. Each line shows the library
  basename, its executable range, file offset and inode:

  ```
  [lib] pid 12903  libc.so                  [0x7c1d20000, 0x7c1d2f000)  off=0x0  inode=4210
  [lib] pid 12903  librasp.so               [0x7b004a000, 0x7b0061000)  off=0x0  inode=8814
  ```

  Pairs with `-o file.json` / `-J` for a machine-readable list (records carry
  `library`, `pid`, `start`, `end`, `pgoff`, `inode`). Cannot be combined with
  `-a`/`-s`/`-x` (there are no syscalls to filter).

## Dumping a library from memory (`-D`)

Packers and RASP often ship a native library whose code is encrypted on disk and
only decrypted *in memory* after load (sometimes the on-disk `.so` is even
deleted once mapped). `-D, --dump <lib>` reconstructs a loadable `.so` from the
library's **live process memory**, so you get the post-decryption image:

```
# let the app run long enough for the library to decrypt, then Ctrl-C to dump:
heimdall -l -D libpacked.so --dump-dir /data/local/tmp com.example.app
...
[dump] libpacked.so (pid 12903) -> /data/local/tmp/libpacked.so.12903.7b004a000.so  (212992 bytes, 212992 read from memory)
[dump] wrote 1 module image matching 'libpacked.so' to /data/local/tmp
```

How it works: every app process that maps a `.so` is recorded; at exit (Ctrl-C),
for each one we re-read `/proc/<pid>/maps`, find modules whose path contains
`<lib>`, and rebuild each from `/proc/<pid>/mem`. This is the same job as
[SoFixer](https://github.com/F8LEFT/SoFixer), done live against `/proc` rather
than a pre-made dump, and a **superset** of it:

- **Whole-range capture.** Reads the entire `[base, end)` range page by page, so
  data a packer hides in the gaps *between* `PT_LOAD` segments is captured;
  unreadable guard pages are zero-filled rather than aborting the read.
- **Program-header fixup.** Rewrites every phdr so the file mirrors memory
  (`p_offset = p_paddr = p_vaddr`, `p_filesz = p_memsz`), and grows each
  `PT_LOAD` to the next segment so the gaps live inside a loadable segment.
- **Section-header reconstruction.** Regenerates a full section table from the
  dynamic segment — `.dynsym`, `.dynstr`, `.hash`/`.gnu.hash`, `.rela.dyn`,
  `.rela.plt`, `.relr.dyn`, `.init_array`, `.fini_array`, `.dynamic`, `.text`,
  `.data`, `.shstrtab` — so tools that read section headers (incl. older IDA)
  see named sections and the dynamic symbol table.
- **Relocation un-applying.** Restores file-relative values for relative
  relocations the loader applied in memory — both classic `DT_RELA`
  (`R_AARCH64_RELATIVE`) **and `DT_RELR`** (modern Android packed relatives,
  which SoFixer does not handle).
- **`.dynamic` de-rebasing.** Pointer entries (`DT_SYMTAB`/`DT_STRTAB`/… ) the
  linker rewrote to absolute addresses are restored to relative offsets, and
  `DT_DEBUG` is cleared. (SoFixer assumes these are still relative — true on
  bionic, but this also handles a glibc-style rebased dynamic section.)

The result loads in IDA/Ghidra with named sections and dynamic symbols intact.
**Timing matters:** the dump happens when you stop tracing, so let the app run
until the library has actually decrypted itself. `-D` can be combined with any
mode; pair it with `-l` for a lightweight dump-only run (no syscall hook). Only
file-backed, named mappings are dumped — a fully anonymous decrypted blob (no
`vm_file`) has no name to match. Output filenames are
`<basename>.<pid>.<loadbase>.so`.

**Randomized library names.** A protector often loads its payload under a name
that changes every run (e.g. `e_<pid>` / `e_<random>`, frequently `unlink`ed so
it shows as `… (deleted)`). Pass a glob (`* ? []`) to `-D` and it is matched
against the mapping basename — `'e_*'` or `'e_[0-9]*'` catches such a payload
regardless of the per-run suffix. A pattern with no glob characters keeps the
original "substring of the full path" behaviour.

If the rebuild trips over an unusual packer's dynamic info, `--dump-raw` writes
just the phdr-fixed raw memory image (no section table, no relocation rebuild)
as a fallback. **Not handled:** Android APS2 packed relocations
(`DT_ANDROID_REL[A]`) are not un-applied (neither does SoFixer), and 32-bit
(ELF32/ARM) modules — heimdall is aarch64-only.

## Why it's different from a naive strace

Two problems with "launch the app, then start tracing":

1. **Startup gap.** By the time you've found the PID and read its maps, the native
   library has already loaded and run. heimdall resolves the package's **app-UID**
   and installs it into the BPF filter **before** (re)launching the app, so every
   thread is traced from its first syscall. Android assigns the app UID during
   zygote specialization, long before any app/native code runs — nothing is missed.

2. **Racy module tracking.** heimdall builds the process's executable module map
   **purely from `uprobe_mmap` / `uprobe_munmap` kprobe events** — it never reads
   `/proc/<pid>/maps`. The instant the target library's text segment is mapped, its
   range is pushed into the in-kernel filter. A syscall can only originate from the
   library *after* it's mapped, so there is no filter gap.

## How it works

- **Syscall hook:** `kprobe/do_el0_svc` (arm64 64-bit syscall dispatcher). Works
  even when the kernel is built `CONFIG_FTRACE_SYSCALLS=n` (no `raw_syscalls`
  tracepoints). Syscall number is `x8`, args `x0..x5`.
- **Gate:** by UID (`target_uid` map), armed before launch.
- **Filter:** at entry, if the target lib's ranges are known for this process,
  capture the user stack with `bpf_get_stack` and keep the event only if a frame
  lands inside one of those ranges (`lib_ranges`, a per-tgid map).
- **Module map:** `uprobe_mmap`/`uprobe_munmap` events arm the in-kernel library
  filter; backtrace symbolization is handled separately (see *Symbolization*).
- **Return values:** classic **kretprobes** attached to a curated list of
  `__arm64_sys_*` functions (file/proc/memory/process syscalls), gated by a
  per-tid flag set at entry. Per-function kretprobes keep their instance pools
  independent, avoiding the `maxactive` exhaustion a kretprobe on the shared
  `do_el0_svc` dispatcher would hit (every thread blocked in a syscall holds a
  slot). `kretprobe.multi` is intentionally *not* used: it relies on fprobe / the
  ftrace function tracer (`available_filter_functions`), which many Android
  kernels are built without. Best-effort — entry events are captured regardless.

## Build (on your host — not on the device)

CO-RE means the BPF object is compiled once on the host and relocated against the
device kernel's BTF at load time. The loader is cross-compiled into a **static
aarch64** binary you push to the device.

One-time host deps (Debian/Ubuntu):

```sh
sudo apt install clang llvm bpftool gcc-aarch64-linux-gnu
sudo dpkg --add-architecture arm64 && sudo apt update
sudo apt install libelf-dev:arm64 zlib1g-dev:arm64 libzstd-dev:arm64
git submodule update --init --recursive      # vendored libbpf
```

Then:

```sh
make            # -> build/heimdall (static aarch64)
make push       # adb push to /data/local/tmp/heimdall
```

`vmlinux.h` is committed (generated from this device's `vmlinux.btf`). After a
kernel change, re-pull the BTF and run `make regen-vmlinux`.

## Run (rooted device, from `adb shell`)

```sh
adb shell
su
# eBPF on Android usually needs SELinux out of the way during testing:
setenforce 0
/data/local/tmp/heimdall <package> <lib> [activity]
# e.g.
/data/local/tmp/heimdall com.example.app librasp.so
/data/local/tmp/heimdall com.example.app 'e_[0-9]*'   # randomized-name library (glob)
/data/local/tmp/heimdall -o /data/local/tmp/trace.json com.example.app librasp.so
/data/local/tmp/heimdall com.example.app libguard.so com.example.app.MainActivity
/data/local/tmp/heimdall -a -o /data/local/tmp/all.json com.example.app   # capture everything
/data/local/tmp/heimdall -a -s openat,read,close,newfstatat com.example.app   # only these syscalls
/data/local/tmp/heimdall -l com.example.app   # just list libraries loaded into the app
/data/local/tmp/heimdall -l -D libpacked.so --dump-dir /data/local/tmp com.example.app   # dump a decrypted .so from memory
```

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

**Output format.** Default `-o` writes a single JSON array (only valid after a
clean exit). For long/firehose captures prefer **JSON Lines** (`-J`, or just name
the file `.jsonl`): one record per line, flushed ~once a second, so a hard-kill /
reboot / second-Ctrl+C leaves a file that's still valid up to the last second —
you lose at most a few records, not the whole trace. Same per-event cost as the
array form (both stream to a block-buffered file). `heimdall-fold.py` reads either
and tolerates a truncated final line.

`-s`/`-x` restrict **which syscalls** are kept and combine with either mode (the
in-kernel check runs before the stack walk, so excluded syscalls are nearly free
— handy to tame the capture-all firehose).

**Throughput / dropped events.** A **drain thread** copies events out of the
kernel ring into a large userspace **worker queue** (`-Q MB`, default 256), and a
**worker thread** does all symbolization + JSON writing — so the kernel ring stays
empty and bursts are absorbed in RAM. Symbolization is cached (address→symbol and
fd→path), and JSON is written with a fast in-memory serializer. `-o` implies `-q`.
If you still see drops on a very heavy target, raise the queue (`-Q 512`) and/or
the kernel ring (`-b 128`); the exit line reports kernel-ring vs queue drops
separately. (`HEIMDALL_JSON`, `HEIMDALL_VERBOSE`,
`HEIMDALL_DEBUG`, `HEIMDALL_ALL`, `HEIMDALL_LIBS`, `HEIMDALL_QUIET` env vars mirror the flags.)

### Console output

Each syscall gets a monotonic **id**. The entry line (`==>`) prints only the
syscall's **real arguments** (per a built-in arm64 arg-count table — no trailing
register garbage), with string (path) args and fd args resolved inline; a `<==`
line prints the **return value** when the call completes (paired by id):

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

Flag / enum arguments are decoded (`O_RDONLY|O_CLOEXEC`, `PROT_READ|PROT_WRITE`,
`MAP_PRIVATE|MAP_ANONYMOUS`, `PR_GET_DUMPABLE`, `AF_INET`, `SIGKILL`, …), and the
`sockaddr` of `connect`/`bind`/`sendto` is resolved to the peer address —
`connect(fd=42, 142.250.4.100:443)`, `sendto(fd=45, …, unix:@frida)`.

Frames resolve across **all** libraries (target + libc + linker + …) to
`lib!function+0xdelta`. Frames with no matching symbol show `lib+0xvaddr`.
Non-ELF executable memory is labelled by region rather than printed as a bare
address: `[anon]+0x..` (unnamed — JIT/packer/RASP-allocated code), `[anon:..]+0x..`
or `jit-cache+0x..` (named/ART), `0x.. [unmapped]` (not in `/proc/maps` — usually
a broken frame-pointer unwind). Errors decode the errno:
`<== #51 openat = -2 (No such file or directory)`.

### JSON output (`-o`)

A single JSON array; each element is one syscall, emitted when its return
arrives (so `retval` is populated; `null` if the return was never observed):

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
(e.g. `"142.250.4.100:443"`, `"[2001:db8::1]:8443"`, `"unix:@frida"`):

```json
{
  "syscall": "connect", "retval": -115,
  "fd_args": { "0": "fd=42" },
  "sock_addr": "142.250.4.100:443",
  "backtrace": [
    { "frame": 0, "addr": "0x7c1d2a1c", "symbol": "librasp.so!scan_maps+0x178" }
  ]
}
```

### Loop folding (`tools/heimdall-fold.py`)

A standalone post-processor that detects **loops in the syscall sequence** and
folds them, so a 500-iteration scan reads as one entry. It runs **per thread**
(the live stream interleaves threads), tokenizes each syscall by **name + call
stack**, and folds maximal *tandem runs* (a block repeated `k>=2` consecutive
times) smallest-period-first, to a fixpoint — which also discovers **nested**
loops. Original event ids are kept on every loop, so nothing is lost.

```sh
tools/heimdall-fold.py trace.json                 # text summary (hot loops + folded timeline)
tools/heimdall-fold.py trace.json --json folded.json
# tunables: --min-reps K  --max-period N  --callsite-frames N  --no-nesting
```

Output JSON: a `loops` registry (`{id, period, body, occurrences, iterations_total}`,
where a nested body item is `{loop, iterations}`) plus a per-thread `timeline`
that replaces each run with `{ "loop": "L4", "iterations": 2, "event_ids": [...] }`.

### LLM-driven analysis (`tools/heimdall-mcp/`)

For LLM-assisted analysis, an **MCP server** (DuckDB-backed) exposes the trace to
Claude Code / Claude Desktop as queryable tools (`overview`, `hot_loops`,
`files`, `query`, `get_event`, `distinct_backtraces`, `via`-origin filtering, …).
The model retrieves small, pre-aggregated slices on demand instead of ingesting
a multi-million-event trace — see `tools/heimdall-mcp/README.md`.

### How syscalls are identified, and string-arg resolution

The syscall name comes from the **syscall number** in `x8`, mapped through a table
generated from the kernel's `asm-generic` syscall ABI (the same table arm64 uses).
It is not symbol resolution — see the note in *Limitations*. String arguments are
read from the caller's memory at entry with `bpf_probe_read_user_str`, for the
args a built-in per-syscall table marks as `const char *` (paths: `openat`,
`readlinkat`, `newfstatat`, `execve`, `renameat2`, `mount`, …). Only args 0–3 are
resolved.

## Requirements & limitations

- **Root**, and a kernel with BTF (`CONFIG_DEBUG_INFO_BTF=y` — GKI mandates it),
  kprobes, and uprobes. Verify the hook symbols exist:
  `adb shell su -c 'grep -wE "do_el0_svc|uprobe_mmap|uprobe_munmap" /proc/kallsyms'`.
- **Frame pointers required.** `bpf_get_stack` unwinds via frame pointers on arm64;
  if the target lib or the path to the syscall omits them, matching frames may be
  missed (false negatives).
- **Syscall identity is by number, not libc function.** arm64 uses the generic
  ABI, which has only the `*at` variants — there is no `open`/`stat`/`access`
  number, so a libc `open()` shows as `openat`, `access()` as `faccessat`, etc.
  The table is fixed at build time; a number beyond it prints as `sys_<nr>`.
- **String args:** only args 0–3, capped at 256 bytes, and only for syscalls in
  the built-in `const char *` table. Non-path string/buffer args (e.g. `write`
  buffers) are shown as raw pointers.
- **sockaddr decode:** `connect`/`bind`/`sendto` resolve the peer to
  `ip:port` / `[ip6]:port` / `unix:/path` / `unix:@abstract`. `recvfrom`/`accept`
  fill the address at *return*, so those aren't captured (entry-only).
- **Return values** are paired to entries by tid (syscalls are serialized per
  thread) and only for syscalls in the curated kretprobe list (see *How it
  works*); others print without a `<==`. The JSON record is emitted when the
  return arrives, so a syscall still blocked when you stop tracing — or one not in
  the list — is flushed with `"retval": null`. Heavily-blocking calls
  (futex/poll/epoll/nanosleep) are omitted to avoid dropped returns.
- **fd resolution** is best-effort via `readlink(/proc/<pid>/fd/<n>)` at print
  time; a descriptor closed by then shows as `fd=<n>` without a path. `AT_FDCWD`
  is shown by name. Covers the common fd/`*at`-dirfd syscalls.
- **64-bit only.** Compat (32-bit) syscalls go through `do_el0_svc_compat`, not hooked.
- **Symbolization reads `/proc/<pid>/maps`** (lazily, cached, display-only) plus
  each ELF's `.dynsym` — this is how zygote-inherited libraries (libc, libart, the
  linker) get resolved, since no mmap event ever fired for them. The in-kernel
  *filter* stays purely event-driven. Notes:
  - Only `.dynsym` (exported/dynamic symbols) is read. `static` functions and
    libraries stripped of section headers fall back to `lib+0xvaddr`.
  - Libraries mapped directly out of an APK (`base.apk` with a file offset) are
    grouped by contiguous run; oddly-laid-out APKs may mis-base. Plain `.so`
    files are exact.
  - A library the target **deleted from disk after mapping** (`... (deleted)`,
    a common anti-analysis trick) is recovered through
    `/proc/<pid>/map_files/<start>-<end>`, so its `.dynsym` still resolves.
  - A symbol is only attributed if the address lies within `[st_value, +st_size)`;
    otherwise the frame shows `lib+0xvaddr` rather than mislabelling it with the
    nearest exported symbol. Unexported/`static` functions therefore show `+off`.
- **Per-UID.** All processes of the app's UID are traced (main + `:child`), keyed
  by tgid so ranges don't collide.
