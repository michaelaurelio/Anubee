#!/usr/bin/env bash
# Build ares-tracer arm64 binaries.
# Usage:
#   ./build.sh                   (build all: ares-tracer, open-tracer, resolver)
#   ./build.sh ares-tracer
#   ./build.sh open-tracer
#   ./build.sh resolver
set -euo pipefail

ARES_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$ARES_DIR/.." && pwd)"
SRC_DIR="$ARES_DIR/src"
BIN_DIR="$ARES_DIR/bin"
IMAGE="ebpf-cross-arm64"

ALL_BPF_TARGETS=(ares-tracer open-tracer)
ALL_NOBPF_TARGETS=(resolver)

BPF_TARGETS=()
NOBPF_TARGETS=()

if [ -n "${1:-}" ]; then
    case "$1" in
        ares-tracer|open-tracer)
            BPF_TARGETS=("$1") ;;
        resolver)
            NOBPF_TARGETS=("$1") ;;
        *)
            echo "Unknown target: $1" >&2
            echo "Valid targets: ares-tracer, open-tracer, resolver" >&2
            exit 1 ;;
    esac
else
    BPF_TARGETS=("${ALL_BPF_TARGETS[@]}")
    NOBPF_TARGETS=("${ALL_NOBPF_TARGETS[@]}")
fi

echo "=== Building Docker cross-compile image ==="
docker build -t "$IMAGE" \
    -f "$WORKSPACE/docker/Dockerfile.cross-arm64" \
    "$WORKSPACE/docker"

mkdir -p "$BIN_DIR"

build_target() {
    local target="$1"
    local no_bpf="$2"

    echo ""
    echo "=== Cross-compiling $target for aarch64 ==="
    docker run --rm \
        -v "$WORKSPACE:/workspace" \
        -e "TARGET=$target" \
        -e "SRC_DIR=/workspace/ares-tracer/src" \
        -e "NO_BPF=$no_bpf" \
        "$IMAGE" \
        bash /workspace/docker/build-inner.sh

    mv "$SRC_DIR/${target}-aarch64" "$BIN_DIR/${target}-aarch64"
    echo "Moved   → bin/${target}-aarch64"

    # Clean up BPF build artifacts left in src/
    rm -f \
        "$SRC_DIR/${target}.skel.h" \
        "$SRC_DIR/${target}.bpf.o" \
        "$SRC_DIR/${target}.tmp.bpf.o"
}

for t in "${BPF_TARGETS[@]+"${BPF_TARGETS[@]}"}"; do
    build_target "$t" 0
done

for t in "${NOBPF_TARGETS[@]+"${NOBPF_TARGETS[@]}"}"; do
    build_target "$t" 1
done

echo ""
echo "=== Done. bin/ ==="
ls -lh "$BIN_DIR/"*-aarch64 2>/dev/null

echo ""
echo "Deploy:"
for t in "${BPF_TARGETS[@]+"${BPF_TARGETS[@]}"}" "${NOBPF_TARGETS[@]+"${NOBPF_TARGETS[@]}"}"; do
    echo "  adb push $BIN_DIR/${t}-aarch64 /data/local/tmp/${t}"
    echo "  adb shell chmod +x /data/local/tmp/${t}"
    echo "  adb shell 'su -c /data/local/tmp/${t}'"
done
