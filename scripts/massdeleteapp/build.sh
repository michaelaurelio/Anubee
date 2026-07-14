#!/usr/bin/env bash
# Builds and (optionally) installs dev.ares.massdeleteapp — a minimal, code-free
# APK used to trigger mod massdelete-detect through a *real installed app*
# instead of a synthetic PID or a real file manager.
#
# WHY a dedicated app instead of an existing file manager: modern file
# managers (verified: Files by Google, and Android's scoped-storage Trash
# convention generally) delete via MediaStore's IS_TRASHED column, a Binder
# call fulfilled by the system MediaProvider process — the real rename()
# happens under MediaProvider's UID, not the file manager's, so a UID-gated
# trace of the file manager sees nothing. See BACKLOG.md.
#
# WHY no classes.dex: this repo's toolchain has aapt2/zipalign/apksigner but
# no dex compiler (Debian/Kali's "dx" package is an unrelated tool — IBM/
# OpenDX — not Android's dexer). android:hasCode="false" plus referencing the
# stock on-device android.app.Activity by name (not a subclass we'd have to
# compile) sidesteps needing one entirely. The app does nothing on launch;
# the actual file touches are driven separately, as the app's own UID, via
# `su <uid> -c scripts/ares_massdelete_gen` (root gives us arbitrary-UID exec, no
# run-as/debuggable dance needed) — see scripts/device-test.sh for the flow.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/build/massdeleteapp"
PKG="dev.ares.massdeleteapp"
FRAMEWORK_RES="/usr/share/android-framework-res/framework-res.apk"
KEYSTORE="$OUT/keystore.jks"
MODE="${1:-build}" # build | install

fail() { echo "FAIL: $*" >&2; exit 1; }

for tool in aapt2 zipalign apksigner keytool; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool not found (see README prereqs)"
done
[ -f "$FRAMEWORK_RES" ] || fail "framework-res.apk not found at $FRAMEWORK_RES (apt install android-framework-res)"

mkdir -p "$OUT"

echo "=== linking (no dex — hasCode=false) ==="
aapt2 link -o "$OUT/unsigned.apk" \
    -I "$FRAMEWORK_RES" \
    --manifest "$ROOT/scripts/massdeleteapp/AndroidManifest.xml" \
    --min-sdk-version 24 --target-sdk-version 36

echo "=== zipalign ==="
zipalign -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"

# Throwaway self-signed key, regenerated once per build/ (gitignored) — same
# spirit as Android's own debug.keystore, not meant to sign anything shipped.
if [ ! -f "$KEYSTORE" ]; then
    echo "=== generating throwaway signing key ==="
    keytool -genkeypair -v -keystore "$KEYSTORE" -alias massdeleteapp \
        -keyalg RSA -keysize 2048 -validity 3650 \
        -storepass changeit -keypass changeit \
        -dname "CN=ares test, OU=ares, O=ares, L=NA, S=NA, C=US" >/dev/null
fi

echo "=== signing ==="
apksigner sign --ks "$KEYSTORE" --ks-pass pass:changeit --key-pass pass:changeit \
    --out "$OUT/signed.apk" "$OUT/aligned.apk"
apksigner verify "$OUT/signed.apk" || fail "signature verification failed"

echo "built $OUT/signed.apk"

[ "$MODE" = "install" ] || exit 0

echo "=== installing ==="
adb install -r "$OUT/signed.apk" || fail "adb install failed"
adb shell "su -c 'appops set $PKG MANAGE_EXTERNAL_STORAGE allow'" >/dev/null 2>&1 \
    || fail "appops grant failed (root?)"
uid="$(adb shell "su -c 'stat -c %u /data/data/$PKG'" 2>/dev/null | tr -d '\r')"
[ -n "$uid" ] || fail "could not resolve installed UID for $PKG"
echo "installed $PKG — uid $uid, MANAGE_EXTERNAL_STORAGE granted"
echo "trigger with: su -c 'su $uid -c /data/local/tmp/ares_massdelete_gen <target-dir>'"
