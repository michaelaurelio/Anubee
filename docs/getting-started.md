# Getting started

## Prerequisites

**Target device**
- Rooted Android device, **arm64/aarch64** only.
- Kernel: **Android 12+ / GKI 5.10 or newer** (needs BTF + BPF ring buffer). Tested on Android 15 / 6.6.
- SELinux typically needs to be **permissive** to load eBPF.
- `adb` access; commands run as root (`su -c` on Magisk, or `adb root`).

**To build** (pick one)
- Docker or Podman: the container carries the whole cross-toolchain.
- A native aarch64 cross-toolchain + clang/llvm/bpftool.

**Or skip building:** grab the prebuilt static `anubee` binary from the
[Releases](../../../releases) page.

## Build

```sh
# Container build (recommended, no host setup):
git clone --recurse-submodules <repo-url> anubee
cd anubee
./scripts/build.sh           # -> build/anubee (static aarch64 binary)
```

```sh
# Native build:
sudo apt install clang llvm bpftool gcc-aarch64-linux-gnu make git
sudo dpkg --add-architecture arm64 && sudo apt update
sudo apt install libelf-dev:arm64 zlib1g-dev:arm64 libzstd-dev:arm64 liblzma-dev:arm64
git submodule update --init --recursive
make                          # -> build/anubee
```

`scripts/build.sh` uses Docker, or Podman if Docker is absent
(`CONTAINER_RUNTIME=podman` to force). If your device's kernel BTF differs from
the committed `vmlinux.h`, see *Regenerating `vmlinux.h`* in `../DOCUMENTATION.md`.

## Deploy

```sh
./scripts/deploy.sh          # adb push build/anubee + specs to /data/local/tmp
# or: make push
```

## Run your first trace

```sh
# Stealthy: every syscall com.example.app's librasp.so makes:
adb shell "su -c '/data/local/tmp/anubee syscalls -P com.example.app -l librasp.so \
                   -o /data/local/tmp/trace.jsonl'"
adb pull /data/local/tmp/trace.jsonl
```

That's the injectionless engine, safe to start with. For the full engine
picture (which one to use when, and every flag) see [`engines.md`](engines.md).

## Gotchas

- No `adb`/root access, or a non-arm64 device: `anubee` won't run at all.
- SELinux `enforcing` commonly blocks eBPF loading; a RASP can itself treat
  permissive mode as a tamper signal, so weigh that before flipping it.
- A kernel with mismatched BTF vs. the committed `vmlinux.h` fails to load.
  Regenerate `vmlinux.h` from your device's own kernel (see `../DOCUMENTATION.md`)
  rather than assuming the prebuilt one always matches.
