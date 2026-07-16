# ARES: Android RASP and Malware Analysis Tracer for Security Researchers

<p align="center" width="100">

<img src="assets/banner.png" alt="ARES banner" width="800">

</p>

---

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv2-blue.svg"></a>
  <a href="#"><img src="https://img.shields.io/badge/Platform-arm64%20%7C%20aarch64-lightgrey"></a>
  <a href="#"><img src="https://img.shields.io/badge/Built%20With-eBPF-orange"></a>
  <a href="#"><img src="https://img.shields.io/badge/Focus-Android%20RASP%20%2F%20Malware%20Analysis-red"></a>
</p>

<p align="justify">ARES inspects what an app does at both the Java and native
layers, using eBPF, by combining several tracing engines in one static
binary (<code>ares</code>). It's built for reverse engineers and malware analysts who
need to see past a target's own tamper checks, the kind enforced by RASP
(Runtime Application Self-Protection) layers or built into malware itself.
An optional host-side MCP server (<code>tools/ares-mcp</code>) lets an LLM client
(Claude Code / Claude Desktop) query a captured trace and drive on-device
library dumping.</p>

---

## Table of Contents

- [ARES: Android RASP and Malware Analysis Tracer for Security Researchers](#ares-android-rasp-and-malware-analysis-tracer-for-security-researchers)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Motivation](#motivation)
  - [Capabilities](#capabilities)
  - [Quick start](#quick-start)
  - [Demo](#demo)
  - [Designed to Pair With ARES](#designed-to-pair-with-ares)
  - [Documentation](#documentation)
  - [Detectability](#detectability)
  - [Testing](#testing)
  - [Limitations](#limitations)
  - [License](#license)
  - [Authors](#authors)

---

## Features

- Dual-layer tracing: captures Java and native (C/C++) behavior from one
  static binary, using eBPF.
- Zero-instrumentation syscall tracing: the `syscalls` engine hooks the
  kernel dispatcher only, writing nothing into the target process.
- Live memory dump: pulls a decrypted or packed native library straight
  out of a running process and rebuilds it into a loadable ELF.
- Built-in detection modules: ready-made `mod` analyzers for common
  malicious behavior, including fileless code execution, screen-capture
  abuse, and unauthorized system-property reads.
- Build-gated detectability guarantee: every quiet engine is verified at
  compile time (`make check-firewall`) to load zero instrumentation into the
  target.
- Coverage-health reporting: every engine reports its own known gaps
  explicitly at teardown instead of failing silently, so a partial trace is
  never mistaken for a complete one.
- LLM-assisted trace analysis: an optional MCP server lets Claude Code or
  Claude Desktop query a captured trace directly.

---

## Motivation

<p align="justify">Security researchers and malware analysts studying an Android app that
resists tampering, or one that is outright malicious, keep coming back to the
same question: what is this code actually doing, at both the Java and native
layers, without tipping the app off that it's being watched? Most Android
tracing tooling forces analysts into a binary choice between depth (hooking
functions, which a target's own integrity checks can detect) and stealth
(kernel-only tracing, which sees less). ARES refuses that tradeoff: it packs
both approaches into one static binary, kept as separate subcommands on
purpose, so choosing depth over stealth is a decision you make per run, not a
limitation of the tool.</p>

---

## Capabilities

| Subcommand | What it sees | Footprint |
|---|---|---|
| `ares syscalls` | Every syscall a target library makes, decoded args + backtraces | Injectionless (nothing written into the target, `TracerPid` stays 0) |
| `ares funcs` | Individual function calls: typed args, return values, timing | Detectable (inserts a `BRK` into the target's code) |
| `ares correlate` | Which syscalls a probed function triggers, tagged with that function's span | Detectable (entry uprobe `BRK`), loud by design |
| `ares lib` | Every native library (`.so`) an app loads | Injectionless (kprobe only) |
| `ares dump` | A rebuilt loadable ELF of a live (possibly decrypted/packed) library | Injectionless (kprobe only) |
| `ares trace` | `syscalls` + `funcs`/`lib` together from one launch (`correlate`/`dump` are standalone-only) | Loud only if `funcs` is enabled |
| `ares mod` | A packaged detection built for one behavior (mass-deletion, exfil, accessibility abuse, ...) | Depends on analyzer |

> **Pick the right engine for the job.** `syscalls` is stealthy and ideal for
> RASP triage (e.g. clean-vs-rooted diffing). `funcs` is more granular, but
> detectable.

---

## Quick start

Needs a rooted arm64/aarch64 Android device with an eBPF + BTF kernel.
Native build and first-trace walkthrough:
[`docs/getting-started.md`](docs/getting-started.md).

```sh
# Grab the prebuilt binary from Releases, or build it (container, no host setup):
git clone --recurse-submodules <repo-url> ares
cd ares
./scripts/build.sh            # -> build/ares

./scripts/deploy.sh           # adb push build/ares + specs to /data/local/tmp

# First trace: every syscall com.example.app's librasp.so makes
adb shell "su -c '/data/local/tmp/ares syscalls -P com.example.app -l librasp.so \
                   -o /data/local/tmp/trace.jsonl'"
```

The [Releases](../../releases) page has the prebuilt static binary. Most
users never need to build.

---

## Demo

Coming soon.

---

## Designed to Pair With ARES

ARES captures the trace. It isn't built to be the whole workflow by itself:
two companion projects complete it.

[ARES-Desktop](https://github.com/michaelaurelio/ARES-Desktop) is the
intended way to read a trace. A raw capture is millions of syscalls and bare
addresses, unreadable by hand. Load it into ARES-Desktop instead, and follow
the exact chain from Java method to native function to system call, down to
the address you would open in a disassembler. It can also drive `ares`
directly against a connected device.

[ARES-Detector](https://github.com/michaelaurelio/ARES-Detector) is the
intended way to test ARES itself. It's an open-source reference RASP, built
to run real anti-tamper checks and turn its screen red the instant any tool,
including ARES's own loud engines, writes into its memory. Point a "quiet"
capability at it, and the absence of a red screen is the proof.

---

## Documentation

- [`docs/getting-started.md`](docs/getting-started.md): prerequisites, build, deploy
- [`docs/engines.md`](docs/engines.md): which subcommand to pick, full flag reference
- [`docs/probe-specs.md`](docs/probe-specs.md): the probe-spec grammar shared by every engine
- [`docs/analyzers.md`](docs/analyzers.md): `ares mod`'s built-in analyzers
- [`docs/reading-traces.md`](docs/reading-traces.md): output formats, the coverage record
- [`docs/mcp.md`](docs/mcp.md): querying a trace (or driving a live device) from Claude
- [`DOCUMENTATION.md`](DOCUMENTATION.md): architecture and internals

---

## Detectability

ARES keeps its stealthy and detectable engines as separate subcommands
deliberately:

- `syscalls` is injectionless: it hooks the kernel syscall dispatcher,
  writes nothing into the target, and leaves `TracerPid` at 0, invisible to
  in-process RASP integrity checks.
- `funcs`/`correlate` write a `BRK` into the target's executable pages
  (how uprobes work). A RASP that checksums its own code or inspects function
  prologues can detect this.

Putting every engine in one on-disk binary does not make `syscalls` any more
detectable: the binary sits at `/data/local/tmp`, not inside the target. The
risk is *behavioral*. Running `funcs` or `correlate` against a RASP-protected
app can tip it off, which would poison a stealthy `syscalls` capture running
alongside it. Run a detectable engine only when you accept that exposure.
Every engine also needs eBPF loading privileges (often SELinux permissive),
itself a RASP tell.

---

## Testing

Two automated tiers, each runnable on its own, plus a manual third:

```sh
make test           # host unit tests: pure logic, no device, no cross-toolchain
make device-test     # on-device smoke: pushes the binary, asserts each capability
                     #   attaches and emits real output (needs the rooted device)
```

- `make test` compiles and runs `tests/` on the host (`cc` + `libelf`). It
  checks the custom probe-spec grammar parser. CI (`.github/workflows/ci.yml`)
  runs this plus the containerized cross-build on every PR.
- `make device-test` runs `scripts/device-test.sh [lib|syscalls|all]`. Override
  the target app with `ARES_TEST_PKG=<package>` and the per-capability window
  with `ARES_TEST_TIMEOUT=<secs>` (default 10). It needs a rooted device with
  kernel BTF.
- `scripts/massdeleteapp/build.sh install` (manual, not wired into `make`) builds a
  minimal real app for verifying `mod massdelete-detect` against genuine
  app-UID file activity instead of a synthetic PID. Full two-terminal
  procedure: [`docs/analyzers.md`](docs/analyzers.md).

---

## Limitations

- arm64 / ELF64 only, no x86 targets. `syscalls` has a best-effort exception
  for 32-bit/AArch32 app code.
- Rooted device required. Needs eBPF + BTF and (usually) SELinux permissive.
- `syscalls` attribution is an "issued by" heuristic, not full-stack
  presence, with a few known blind spots: vDSO calls, and a brief pre-arm
  window right after a library maps.
- `funcs` and `correlate` write into the target and are detectable by
  design. `dump`'s trigger modes and module-selection flags have some sharp
  edges around already-running processes and APK-embedded libraries.
- Trace coverage isn't always complete. Known gaps include snapshot
  truncation, an unrecognized ART build, and blind CFI-unwind stops.

---

## License

See [LICENSE](LICENSE).

---

## Authors

- [michaelaurelio](https://github.com/michaelaurelio)
- [chronopad](https://github.com/chronopad)
- [Ringoshiroku](https://github.com/Ringoshiroku)
