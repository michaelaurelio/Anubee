# ARES user guide

ARES is an Android RASP / malware analysis tracer: one static aarch64 binary
(`ares`), seven subcommands, running on a rooted device over `adb`. It watches
what an app does at the syscall, native-function, and library-load level via
eBPF, with no injection required for most engines.

For build/architecture/internals see [`../README.md`](../README.md) and
[`../DOCUMENTATION.md`](../DOCUMENTATION.md). This guide is usage only.

## Pages

| Page | Covers |
|---|---|
| [`getting-started.md`](getting-started.md) | Prerequisites, build, deploy, your first trace |
| [`engines.md`](engines.md) | Which subcommand to pick, and how to use each: `syscalls`, `funcs`, `correlate`, `lib`, `dump`, `trace` |
| [`probe-specs.md`](probe-specs.md) | The `[KIND:]TARGET[(ARGTYPES)][>RETTYPE]` grammar shared by `funcs`/`correlate`/`syscalls`/`dump`/`mod` |
| [`analyzers.md`](analyzers.md) | `ares mod`: the 9 built-in analyzers, what each detects, how to run them |
| [`reading-traces.md`](reading-traces.md) | Output formats: JSONL record types, the `.stacks` sidecar, the coverage record |
| [`mcp.md`](mcp.md) | Querying a trace (or driving a live device) from Claude via the `ares-mcp` server |

## Pick an engine

| Need | Use | Detectable? |
|---|---|---|
| Every syscall a library makes, stealthily | `syscalls` | No (injectionless) |
| Specific function calls with typed args/return values | `funcs` | Yes (uprobe `BRK`) |
| Which syscalls a specific function triggers | `correlate` | Yes (uprobe `BRK`) |
| What native libraries an app loads | `lib` | No (injectionless) |
| A decrypted/packed library pulled off live memory | `dump` | No (injectionless) |
| `syscalls` + `funcs` together, one launch | `trace` | Yes (if `--funcs`/`--correlate` used) |
| A packaged detection built for one behavior (ransomware, exfil, a11y abuse, ...) | `mod` | Depends on analyzer |

Details and full flag reference for each: [`engines.md`](engines.md).
