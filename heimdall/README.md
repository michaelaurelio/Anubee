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
/data/local/tmp/heimdall com.example.app libtoyguard.so com.example.app.MainActivity
```

Output: `==>` entry lines (syscall name + raw args) followed by the symbolized
backtrace. Set `HEIMDALL_VERBOSE=1` to also dump every executable mapping, or
`HEIMDALL_DEBUG=1` for libbpf debug logging.

## Requirements & limitations

- **Root**, and a kernel with BTF (`CONFIG_DEBUG_INFO_BTF=y` — GKI mandates it),
  kprobes, and uprobes. Verify the hook symbols exist:
  `adb shell su -c 'grep -wE "do_el0_svc|uprobe_mmap|uprobe_munmap" /proc/kallsyms'`.
- **Frame pointers required.** `bpf_get_stack` unwinds via frame pointers on arm64;
  if the target lib or the path to the syscall omits them, matching frames may be
  missed (false negatives).
- **64-bit only.** Compat (32-bit) syscalls go through `do_el0_svc_compat`, not hooked.
- **Zygote-inherited libraries** (libc, libart, the linker — mapped before tracing
  started) show as raw `0x...` addresses in backtraces; we intentionally don't fall
  back to `/proc/<pid>/maps`. The target library and everything the app loads after
  launch symbolize normally.
- **Per-UID.** All processes of the app's UID are traced (main + `:child`), keyed
  by tgid so ranges don't collide.
