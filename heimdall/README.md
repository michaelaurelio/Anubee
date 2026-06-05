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
- **Module map:** `uprobe_mmap`/`uprobe_munmap` emit map/unmap events for executable
  file mappings; the loader maintains ranges and symbolizes frames as
  `basename+0x<offset-from-load-base>`.

Entry-only (number + args + stack). A kretprobe on `do_el0_svc` is exhausted by
system-wide syscall traffic, so return values aren't captured.

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

Each captured syscall gets a monotonic **id**; string (path) arguments are
resolved inline:

```
==> #42 [12903/12903] openat(0xffffff9c, "/proc/self/maps", 0x80000)
      #0  libc.so!openat+0x8
      #1  libc.so!fopen+0x54
      #2  librasp.so!scan_maps+0x178
      #3  librasp.so!init_protection+0x44
      #4  libc.so!__pthread_start+0x2c
```

Frames resolve across **all** libraries (target + libc + linker + …) to
`lib!function+0xdelta`, so you can see a custom native function calling into
libc. Frames with no matching symbol show `lib+0xvaddr`; frames in anonymous/JIT
regions show the raw address.

### JSON output (`-o`)

A single JSON array; each element is one syscall:

```json
{
  "id": 42, "pid": 12903, "tid": 12903,
  "syscall_nr": 56, "syscall": "openat",
  "args": ["0xffffff9c", "0x7c1e3a40", "0x80000", "0x0", "0x0", "0x0"],
  "string_args": { "1": "/data/app/.../lib/arm64/librasp.so" },
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
- **Per-UID.** All processes of the app's UID are traced (main + `:child`), keyed
  by tgid so ranges don't collide.
