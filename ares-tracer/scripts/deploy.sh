#!/usr/bin/env bash
# Push ares-tracer to a connected Android device via adb.
set -euo pipefail

ARES_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="$ARES_DIR/bin/ares-tracer-aarch64"
DEVICE_PATH="/data/local/tmp/ares-tracer"
SPECS_DIR="$ARES_DIR/specs"
DEVICE_SPECS_PATH="/data/local/tmp/specs"

if [ ! -f "$BINARY" ]; then
    echo "Binary not found: $BINARY" >&2
    echo "Run ./build.sh first." >&2
    exit 1
fi

echo "=== Pushing ares-tracer to device ==="
adb push "$BINARY" "$DEVICE_PATH"
adb shell chmod +x "$DEVICE_PATH"

if [ -d "$SPECS_DIR" ] && [ -n "$(ls -A "$SPECS_DIR")" ]; then
    echo "=== Pushing specs to device ==="
    adb shell mkdir -p "$DEVICE_SPECS_PATH"
    adb push "$SPECS_DIR"/. "$DEVICE_SPECS_PATH"
fi

echo "Done. Run with: adb shell 'su -c $DEVICE_PATH'"
echo "Specs at: $DEVICE_SPECS_PATH"
