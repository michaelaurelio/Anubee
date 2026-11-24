#!/bin/sh
# Regenerate tests/fixtures/binder_stub.dex and binder_stub.jar (the dex
# stored uncompressed as classes.dex, like /system/framework/*.jar) from
# binder_stub/IFoo.java. Requires javac + d8 + zip. The committed files are
# canonical; this documents provenance.
set -e
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d)
javac --release 8 -d "$tmp" "$dir/binder_stub/IFoo.java"
d8 --min-api 21 --output "$tmp" $(find "$tmp" -name '*.class')
cp "$tmp/classes.dex" "$dir/binder_stub.dex"
(cd "$tmp" && printf 'x' > README && zip -q -0 binder_stub.jar README classes.dex)
cp "$tmp/binder_stub.jar" "$dir/binder_stub.jar"
# Real framework jars start with a deflated META-INF/MANIFEST.MF whose sizes
# follow the data (general-purpose flag 0x08), so the reader must use the
# central directory. Python's zipfile writes data descriptors when the
# output isn't seekable -- the same layout.
python3 - "$tmp/classes.dex" "$tmp/binder_stub_dd.jar" <<'PY'
import sys, zipfile
class Unseekable:
    def __init__(self, f): self.f = f; self.n = 0
    def write(self, b): self.n += len(b); return self.f.write(b)
    def tell(self): return self.n
    def flush(self): self.f.flush()
    def seekable(self): return False
with open(sys.argv[2], "wb") as out:
    with zipfile.ZipFile(Unseekable(out), "w") as z:
        z.writestr(zipfile.ZipInfo("META-INF/MANIFEST.MF", (2008, 1, 1, 0, 0, 0)),
                   "Manifest-Version: 1.0\n", compress_type=zipfile.ZIP_DEFLATED)
        zi = zipfile.ZipInfo("classes.dex", (2008, 1, 1, 0, 0, 0))
        z.writestr(zi, open(sys.argv[1], "rb").read(), compress_type=zipfile.ZIP_STORED)
PY
cp "$tmp/binder_stub_dd.jar" "$dir/binder_stub_dd.jar"
rm -rf "$tmp"
echo "wrote $dir/binder_stub.dex $dir/binder_stub.jar $dir/binder_stub_dd.jar"
