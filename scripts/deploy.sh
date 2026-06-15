#!/usr/bin/env bash
# Push the ares binary (and probe specs) to a connected rooted Android device.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="$ROOT/build/ares"
DEVICE_PATH="/data/local/tmp/ares"
SPECS_DIR="$ROOT/specs"
DEVICE_SPECS="/data/local/tmp/specs"

if [ ! -f "$BINARY" ]; then
    echo "binary not found: $BINARY" >&2
    echo "run ./scripts/build.sh first" >&2
    exit 1
fi

echo "=== pushing ares ==="
adb push "$BINARY" "$DEVICE_PATH"
adb shell chmod 755 "$DEVICE_PATH"

if [ -d "$SPECS_DIR" ] && [ -n "$(ls -A "$SPECS_DIR" 2>/dev/null)" ]; then
    echo "=== pushing specs ==="
    adb shell mkdir -p "$DEVICE_SPECS"
    adb push "$SPECS_DIR"/. "$DEVICE_SPECS"
fi

echo "Done."
echo "  syscalls: adb shell 'su -c \"$DEVICE_PATH syscalls <package> <lib>\"'"
echo "  funcs:    adb shell 'su -c \"$DEVICE_PATH funcs -P <package> -F $DEVICE_SPECS/common-file.spec\"'"
