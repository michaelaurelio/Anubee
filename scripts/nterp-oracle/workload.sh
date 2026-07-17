#!/usr/bin/env bash
# Deterministic detector workload for the nterp precision oracle.
# Installs the unobfuscated APK (once), launches, drives every detector tab.
set -euo pipefail
PKG="${ANUBEE_TEST_PKG:-${PKG:-icu.nullptr.applistdetector}}"
APK_FILE="${APK_PATH:-$(cat "$(dirname "$0")/../../anubee-nterp-oracle/apk-path.txt" 2>/dev/null || true)}"

if ! adb shell pm list packages | grep -q "package:$PKG"; then
  [ -n "$APK_FILE" ] || { echo "no APK; run ../anubee-nterp-oracle/build.sh" >&2; exit 1; }
  adb install -r -g "$APK_FILE"
fi

adb shell am force-stop "$PKG"
adb shell am start -S -n "$PKG/.MainActivity" >/dev/null
sleep 3
# ApplistDetector runs its detectors per tab; cycle tabs deterministically.
for _ in 1 2 3 4; do
  adb shell input keyevent KEYCODE_TAB
  adb shell input keyevent KEYCODE_ENTER
  sleep 2
done
echo "workload done: $PKG"
