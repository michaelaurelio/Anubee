# DEX test fixture

`sample.dex` — a standard DEX (`dex\n035`) built from `Sample.java`: class
`com.ares.Sample` with methods `add(II)I`, `greet(String)String`, and the
compiler-generated `<init>`.

Regenerate with `./gen_sample_dex.sh` (needs `javac` + `d8` from the Android SDK
cmdline-tools; d8 8.9.27 produced the committed file). **The committed
`sample.dex` is canonical** — `tests/test_dex.c` hardcodes byte offsets read from
its exact bytes. If you regenerate with a different d8 and the layout shifts,
re-derive the offsets below (`dexdump -d sample.dex`) and update the test.

Method insns byte ranges — `[code_off+16, code_off+16 + insns_size*2)`, where the
`[xxxxxx]` marker in `dexdump -d` is `code_off` and the first instruction sits 16
bytes later:

| method  | insns range     |
|---------|-----------------|
| `add`   | `[0x170, 0x174)`|
| `greet` | `[0x184, 0x1ac)`|
| `<init>`| `[0x1bc, 0x1c4)`|
