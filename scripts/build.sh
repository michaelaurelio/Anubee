#!/usr/bin/env bash
# Build ares (static aarch64) inside a container — the only host requirement is
# Docker or Podman. The container runs the project Makefile against the mounted
# source tree, so the binary appears at build/ares on the host.
#
# Extra args are forwarded to make, e.g.:  ./scripts/build.sh clean
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="ares-cross-arm64"

RUNTIME="${CONTAINER_RUNTIME:-}"
if [ -z "$RUNTIME" ]; then
    if command -v docker >/dev/null 2>&1; then RUNTIME=docker
    elif command -v podman >/dev/null 2>&1; then RUNTIME=podman
    else echo "need docker or podman (set CONTAINER_RUNTIME)" >&2; exit 1
    fi
fi

echo "=== ensuring vendored libbpf submodule ==="
if [ -d "$ROOT/.git" ]; then
    git -C "$ROOT" submodule update --init --recursive
elif [ ! -f "$ROOT/third_party/libbpf/src/libbpf.c" ]; then
    echo "third_party/libbpf is empty and this is not a git checkout." >&2
    echo "Clone with --recurse-submodules, or populate third_party/libbpf." >&2
    exit 1
fi

# Build artifacts are toolchain-specific (glibc symbol versions, libbpf.a, BPF
# objects). If the Dockerfile changed since the last build, clean build/ so we
# never link objects produced by a different image — e.g. a glibc-version
# mismatch surfaces as undefined `__isoc23_*` references at the final link.
# The stamp lives at the repo root (not in build/) so it is host-writable even
# though container-produced artifacts in build/ are root-owned; the clean runs
# IN the container (as root) so it can actually remove those root-owned files.
STAMP="$ROOT/.ares-image-stamp"
DOCKERFILE_HASH="$(sha1sum "$ROOT/misc/Dockerfile" | awk '{print $1}')"
NEEDS_CLEAN=0
if [ -f "$STAMP" ] && [ "$(cat "$STAMP" 2>/dev/null)" != "$DOCKERFILE_HASH" ]; then
    NEEDS_CLEAN=1
fi

echo "=== building cross-compile image ($RUNTIME) ==="
"$RUNTIME" build -t "$IMAGE" -f "$ROOT/misc/Dockerfile" "$ROOT/misc"

if [ "$NEEDS_CLEAN" = 1 ]; then
    echo "=== Dockerfile changed since last build — cleaning stale build/ ==="
    "$RUNTIME" run --rm -v "$ROOT:/workspace" "$IMAGE" clean
fi

echo "=== compiling ares (static aarch64) ==="
"$RUNTIME" run --rm -v "$ROOT:/workspace" "$IMAGE" "$@"

# Record the toolchain identity for the stale-artifact guard above.
echo "$DOCKERFILE_HASH" > "$STAMP"

echo "=== done ==="
ls -lh "$ROOT/build/ares" 2>/dev/null || true
