
## Running the Frida oracle (Frida 17+)

Frida 17 removed the global `Java` bridge, so `oracle.js` is an ESM source that must be
bundled first (build artifacts stay out of the repo, e.g. in `../ares-nterp-oracle/`):

```
npm install frida-java-bridge
frida-compile scripts/nterp-oracle/oracle.js -o oracle.bundle.js
ARES_TEST_PKG=<pkg> python3 scripts/nterp-oracle/run_oracle.py frida.jsonl   # spawns, drives UI, collects
python3 scripts/nterp-oracle/compare.py --ares-events ares.jsonl --ares-stacks ares.jsonl.stacks --frida frida.jsonl
```

`run_oracle.py` loads `oracle.bundle.js` from the CWD.
