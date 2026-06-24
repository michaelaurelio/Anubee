#!/bin/sh
# Regenerate tests/fixtures/sample.dex from Sample.java. Requires javac + d8
# (Android SDK cmdline-tools). d8 8.9.27 was used to produce the committed file.
# The committed sample.dex is canonical; this script documents provenance and
# lets you re-derive the method offsets that tests/test_dex.c hardcodes.
set -e
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
javac --release 8 -d "$dir" "$dir/Sample.java"
d8 --min-api 21 --output "$dir" "$dir/com/ares/Sample.class"
mv "$dir/classes.dex" "$dir/sample.dex"
rm -rf "$dir/com"
echo "wrote $dir/sample.dex"
echo "--- method insns offsets (code_off marker is the [xxxxxx]; insns = code_off+16) ---"
dexdump -d "$dir/sample.dex" | grep -E "Class descriptor|name +:|insns size"
