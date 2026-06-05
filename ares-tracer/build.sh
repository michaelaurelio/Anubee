#!/usr/bin/env bash
# Cross-compile ares-tracer for aarch64 (Android).
set -euo pipefail

ARES_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$ARES_DIR/.." && pwd)"
SRC_DIR="$ARES_DIR/src"
BIN_DIR="$ARES_DIR/bin"
IMAGE="ebpf-cross-arm64-ares"

echo "=== Building Docker cross-compile image ==="
docker build -t "$IMAGE" \
    -f "$ARES_DIR/docker/Dockerfile.cross-arm64" \
    "$ARES_DIR/docker"

mkdir -p "$BIN_DIR"

echo ""
echo "=== Cross-compiling ares-tracer for aarch64 ==="
docker run --rm \
    -v "$WORKSPACE:/workspace" \
    "$IMAGE" \
    bash /workspace/ares-tracer/docker/build-inner.sh

mv "$SRC_DIR/ares-tracer-aarch64" "$BIN_DIR/ares-tracer-aarch64"

rm -f \
    "$SRC_DIR/ares-tracer.skel.h" \
    "$SRC_DIR/ares-tracer.bpf.o" \
    "$SRC_DIR/ares-tracer.tmp.bpf.o"

echo ""
echo "=== Done ==="
ls -lh "$BIN_DIR/ares-tracer-aarch64"
