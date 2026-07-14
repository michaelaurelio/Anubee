# ARES

ARES is an Android RASP (Runtime Application Self-Protection) and malware
analysis tracer. It inspects what an app does at both the **Java and native
layers**, using eBPF, by combining several tracing engines in one static
binary (`ares`). An optional host-side **MCP server** (`tools/ares-mcp`) lets
an LLM client (Claude Code / Claude Desktop) query a captured trace and drive
on-device library dumping.

| Subcommand | What it sees | Footprint |
|---|---|---|
| `ares syscalls` | Every syscall a target library makes, decoded args + backtraces | **Injectionless** (nothing written into the target, `TracerPid` stays 0) |
| `ares funcs` | Individual function calls: typed args, return values, timing | **Detectable** (inserts a `BRK` into the target's code) |
| `ares correlate` | Which syscalls a probed function triggers, tagged with that function's span | **Detectable** (entry uprobe `BRK`), loud by design |
| `ares lib` | Every native library (`.so`) an app loads | **Injectionless** (kprobe only) |
| `ares dump` | A rebuilt loadable ELF of a live (possibly decrypted/packed) library | **Injectionless** (kprobe only) |
| `ares trace` | `syscalls` + `funcs`/`correlate`/`lib`/`dump` together from one launch | Loud only if `--funcs`/`--correlate` is included |
| `ares mod` | A packaged detection built for one behavior (ransomware, exfil, a11y abuse, ...) | Depends on analyzer |

> **Pick the right engine for the job.** `syscalls` is stealthy and ideal for
> RASP triage (e.g. clean-vs-rooted diffing). `funcs` is more granular, but a
> RASP can detect its uprobe instrumentation. They run as **separate
> subcommands** on purpose, see *Detectability* below.

---

## Quick start

Needs a rooted **arm64/aarch64** Android device with an eBPF + BTF kernel.
Full prerequisites, native build, and first-trace walkthrough:
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

The [Releases](../../releases) page has the prebuilt static binary; most users
never need to build.

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

- `syscalls` is **injectionless**: it hooks the kernel syscall dispatcher,
  writes nothing into the target, and leaves `TracerPid` at 0, invisible to
  in-process RASP integrity checks.
- `funcs`/`correlate` **write a `BRK`** into the target's executable pages
  (how uprobes work). A RASP that checksums its own code or inspects function
  prologues can detect this.

Putting every engine in one on-disk binary does not make `syscalls` any more
detectable: the binary sits at `/data/local/tmp`, not inside the target. The
risk is *behavioral*. Running `funcs` or `correlate` against a RASP-protected
app can tip it off, which would poison a stealthy `syscalls` capture running
alongside it (e.g. clean-vs-rooted diffing). Run a detectable engine only when
you accept that exposure. Every engine also needs eBPF loading privileges
(often SELinux permissive), itself a RASP tell.

---

## Testing

Two automated tiers, each runnable on its own, plus a manual third:

```sh
make test           # host unit tests: pure logic, no device, no cross-toolchain
make device-test     # on-device smoke: pushes the binary, asserts each capability
                     #   attaches and emits real output (needs the rooted device)
```

- `make test` compiles and runs `tests/` on the host (`cc` + `libelf`); it
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

- **arm64 / ELF64 only**; no x86 targets. `syscalls` has a best-effort
  exception: a second, optional hook (`do_el0_svc_compat`) covers
  32-bit/AArch32 app syscalls too (entry-only, numeric names, see below);
  every other engine remains arm64/ELF64-only.
- **Rooted device required**; needs eBPF + BTF and (usually) SELinux
  permissive.
- `syscalls`: attribution is an **"issued by" heuristic**, not "library
  present on the stack": a syscall is attributed to the target library only if
  the trap-PC frame or its immediate caller lands in the library's range, not
  any frame on the full walked stack (a target library calling into libc,
  which then syscalls, is correctly *not* attributed to the target). This
  depends on the target's frame pointers for the immediate-caller check; a
  `-fomit-frame-pointer`/hand-asm target degrades to trap-PC-only
  attribution. vDSO calls issue no `svc` and are invisible to `syscalls`
  regardless. A bounded pre-arm window exists between a library being mapped
  and its range being armed in-kernel (syscalls issued in that window are
  dropped, not mis-attributed). 32-bit/AArch32 app syscalls are covered
  best-effort, with numeric names (`compat_syscall_<nr>`) rather than a full
  EABI name table. String args captured for a built-in syscall set (64-bit
  only); return values for a curated set of syscalls (64-bit only).
  `syscalls` backtraces name on-disk libraries, AOT app methods (`base.odex`,
  via embedded mini-debug-info), ART JIT methods (`[JIT]!`), and kernel vDSO
  calls (`[vdso]!`). Still shown as file+offset: interpreter/quickened dex
  frames (`base.vdex`, `[anon:dalvik-DEX data]`; support planned).
  `[anon:dalvik-main space]` frames are GC-heap addresses surfaced by
  frame-pointer unwinding, not methods.
- `funcs`: uprobe instrumentation is detectable; spec-driven, so you must know
  which functions to target.
- `ares funcs` output is always JSONL; `-J`/`--jsonl` is accepted for
  compatibility but is a no-op. MAP/UNMAP/SPAWN/PROC_EXIT/EXECVE/PROP
  structured records and unified MCP ingest are planned (see
  `DOCUMENTATION.md`).
- Coverage gaps (the 32 KB snapshot cap, an unknown ART build, a blind CFI
  stop, the pre-arm window) used to fail silently. `syscalls`, `funcs`, and
  `correlate` now surface them explicitly in a per-run coverage-health record
  (stderr banner + `{"type":"coverage"}` in the `-o` sink) instead of leaving
  them to be inferred from missing output (see `DOCUMENTATION.md`).

---

## License

See [LICENSE](LICENSE).
