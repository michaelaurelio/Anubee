# heimdall

An eBPF/CO-RE syscall tracer for a single Android app, **filtered by native-library
call origin**: a syscall is reported only when the issuing thread's user backtrace
passes through a chosen `.so` (e.g. a RASP / anti-tamper library). Inspired by
frida-strace's in-kernel stack-filter design, but standalone and on-device.

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
/data/local/tmp/heimdall <package> <lib-substring> [activity]
# e.g.
/data/local/tmp/heimdall com.example.app librasp.so
/data/local/tmp/heimdall -o /data/local/tmp/trace.json com.example.app librasp.so
/data/local/tmp/heimdall com.example.app libtoyguard.so com.example.app.MainActivity
```

```
usage: heimdall [-o out.json] [-v] <package> <lib-substring> [activity]
  -o, --json <file>   export captured syscalls to a JSON file
  -v, --verbose       also log every executable mapping
```

(`HEIMDALL_JSON`, `HEIMDALL_VERBOSE`, `HEIMDALL_DEBUG` env vars mirror the flags.)

### Console output

Each syscall gets a monotonic **id**. The entry line (`==>`) prints only the
syscall's **real arguments** (per a built-in arm64 arg-count table — no trailing
register garbage), with string (path) args and fd args resolved inline; a `<==`
line prints the **return value** when the call completes (paired by id):

```
==> #42 [12903/12903] openat(AT_FDCWD, "/proc/self/maps", 0x80000)
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
  "backtrace": [
    { "frame": 0, "addr": "0x7c1d2a1c", "symbol": "librasp.so!scan_maps+0x178" }
  ]
}
```

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
  buffers, `connect` sockaddrs) are shown as raw pointers.
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
