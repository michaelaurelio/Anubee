#!/usr/bin/env bash
# Builds and (optionally) installs dev.anubee.moddemoapp -- a demo app used
# to trigger `anubee mod massdelete-detect`/`exfil-detect` through a *real
# installed app*'s own code, launched the normal way
# (`anubee mod -P dev.anubee.moddemoapp -m ...`). Replaces the old
# scripts/massdeleteapp/ (a code-free APK paired with an externally
# su-exec'd trigger binary): this app performs both bursts itself, on
# launch, via standard Android Java APIs -- see DemoActivity.java's header
# for the safety constraints and docs/analyzers.md for the full demo flow.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$ROOT/scripts/moddemoapp"
OUT="$ROOT/build/moddemoapp"
PKG="dev.anubee.moddemoapp"
FRAMEWORK_RES="/usr/share/android-framework-res/framework-res.apk"
ANDROID_JAR="/usr/lib/android-sdk/platforms/android-36/android.jar"
KEYSTORE="$SRC/demo.keystore"
MODE="${1:-build}" # build | install

fail() { echo "FAIL: $*" >&2; exit 1; }

for tool in javac d8 aapt2 zipalign apksigner keytool zip; do
    command -v "$tool" >/dev/null 2>&1 \
        || fail "$tool not found (apt install google-android-build-tools-36.0.0-installer)"
done
[ -f "$FRAMEWORK_RES" ] || fail "framework-res.apk not found at $FRAMEWORK_RES (apt install android-framework-res)"
[ -f "$ANDROID_JAR" ] || fail "android.jar not found at $ANDROID_JAR (apt install google-android-platform-36-installer)"

mkdir -p "$OUT/classes" "$OUT/dex"

echo "=== javac ==="
javac --release 8 -classpath "$ANDROID_JAR" -d "$OUT/classes" \
    "$SRC/src/dev/anubee/moddemoapp/DemoActivity.java" \
    "$SRC/src/dev/anubee/moddemoapp/DemoService.java"

echo "=== d8 (dex) ==="
d8 --min-api 24 --output "$OUT/dex" "$OUT/classes/dev/anubee/moddemoapp/"*.class

echo "=== aapt2 link ==="
aapt2 link -o "$OUT/unsigned.apk" \
    -I "$FRAMEWORK_RES" \
    --manifest "$SRC/AndroidManifest.xml" \
    --min-sdk-version 24 --target-sdk-version 36

# aapt2 link only packages resources/manifest -- splice the dex in directly
# (no Gradle/apkbuilder in this toolchain to do it for us).
cp "$OUT/dex/classes.dex" "$OUT/classes.dex"
(cd "$OUT" && zip -q -j unsigned.apk classes.dex)

echo "=== zipalign ==="
zipalign -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"

# Persistent keystore (unlike massdeleteapp's regenerate-if-missing one):
# this app's built .apk is committed to git, so re-running this script after
# a future source edit needs to reproduce a signature-compatible APK, not a
# fresh throwaway key testers would have to uninstall over. Still a
# throwaway self-signed key with no security value beyond satisfying
# Android's "must be signed" requirement.
if [ ! -f "$KEYSTORE" ]; then
    echo "=== generating persistent throwaway signing key ==="
    keytool -genkeypair -v -keystore "$KEYSTORE" -alias moddemoapp \
        -keyalg RSA -keysize 2048 -validity 3650 \
        -storepass changeit -keypass changeit \
        -dname "CN=anubee mod demo, OU=anubee, O=anubee, L=NA, S=NA, C=US" >/dev/null
fi

echo "=== signing ==="
apksigner sign --ks "$KEYSTORE" --ks-pass pass:changeit --key-pass pass:changeit \
    --out "$OUT/signed.apk" "$OUT/aligned.apk"
apksigner verify "$OUT/signed.apk" || fail "signature verification failed"

cp "$OUT/signed.apk" "$SRC/anubee-moddemoapp.apk"
echo "built $SRC/anubee-moddemoapp.apk"

[ "$MODE" = "install" ] || exit 0

echo "=== installing ==="
adb install -r "$SRC/anubee-moddemoapp.apk" || fail "adb install failed"
adb shell "su -c 'appops set $PKG MANAGE_EXTERNAL_STORAGE allow'" >/dev/null 2>&1 \
    || fail "appops grant failed (root?)"
echo "installed $PKG, MANAGE_EXTERNAL_STORAGE granted"
echo "trigger with: anubee mod -P $PKG -m massdelete-detect -m exfil-detect -o <file>"
