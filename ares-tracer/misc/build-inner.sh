#!/usr/bin/env bash
# Runs inside the cross-compile container. ares-tracer/ is mounted at /workspace.
set -euo pipefail

SRC_DIR=/workspace/src
LIBBPF_SRC=/workspace/vendor/libbpf/src
LIBBPF_UAPI=/workspace/vendor/libbpf/include/uapi
LIBBPF_DIST=/workspace/vendor/libbpf/dist-android
VMLINUX_DIR=/workspace/include

cd "$SRC_DIR"

echo "[1/3] Building libbpf.a for aarch64..."
make -C "$LIBBPF_SRC" \
    CC=aarch64-linux-gnu-gcc \
    BUILD_STATIC_ONLY=1 \
    OBJDIR=build-android \
    DESTDIR=../dist-android \
    install

echo "[2/3] Compiling BPF kernel side + generating skeleton..."

# Collect clang's own system include dirs — needed for --target=bpf builds
# to find headers like asm/types.h that live outside the standard search path.
CLANG_SYS_INC=$(clang -v -E - </dev/null 2>&1 | \
    sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

clang -g -O2 \
    --target=bpf \
    -D__TARGET_ARCH_arm64 \
    -I"$LIBBPF_DIST/usr/include" \
    -I"$LIBBPF_UAPI" \
    -I"$VMLINUX_DIR" \
    $CLANG_SYS_INC \
    -c ares-tracer.bpf.c -o ares-tracer.tmp.bpf.o

bpftool gen object ares-tracer.bpf.o ares-tracer.tmp.bpf.o
bpftool gen skeleton ares-tracer.bpf.o name ares_tracer_bpf > ares-tracer.skel.h

echo "[3/3] Compiling userspace binary for aarch64..."
aarch64-linux-gnu-gcc -g -Wall \
    -I. \
    -I"$LIBBPF_DIST/usr/include" \
    -I"$LIBBPF_UAPI" \
    ares-tracer.c \
    modules/proc_event.c \
    modules/execve.c \
    modules/prop_read.c \
    "$LIBBPF_DIST/usr/lib64/libbpf.a" \
    -lelf -lz \
    -static \
    -o ares-tracer-aarch64

echo ""
echo "Done. Binary: $SRC_DIR/ares-tracer-aarch64"
echo "  $(ls -lh "$SRC_DIR/ares-tracer-aarch64")"

echo ""
echo "[4/4] Building prelude-check diagnostic tool..."
aarch64-linux-gnu-gcc -g -Wall -O1 -fno-inline \
    /workspace/tools/prelude-check.c \
    -static-pie \
    -o /workspace/bin/prelude-check-aarch64
echo "  $(ls -lh /workspace/bin/prelude-check-aarch64)"
