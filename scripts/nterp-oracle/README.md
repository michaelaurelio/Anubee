
## Running the Frida oracle (Frida 17+)

Frida 17 removed the global `Java` bridge, so `oracle.js` is an ESM source that must be
bundled first (build artifacts stay out of the repo, e.g. in `../anubee-nterp-oracle/`):

```
npm install frida-java-bridge
frida-compile scripts/nterp-oracle/oracle.js -o oracle.bundle.js
ANUBEE_TEST_PKG=<pkg> python3 scripts/nterp-oracle/run_oracle.py frida.jsonl   # spawns, drives UI, collects
python3 scripts/nterp-oracle/compare.py --anubee-events anubee.jsonl --anubee-stacks anubee.jsonl.stacks --frida frida.jsonl
```

`run_oracle.py` loads `oracle.bundle.js` from the CWD.
