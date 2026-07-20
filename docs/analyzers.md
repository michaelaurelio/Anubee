# `anubee mod`: analyzers

`anubee mod <name>` runs a detection package built for one behavior: a
lightweight, standalone BPF object, instead of a general-purpose tracer
you'd have to hand-build with `funcs`/`correlate` specs.

```sh
anubee mod --list                                        # list available analyzers
anubee mod massdelete-detect -P com.example.app -o out.jsonl
anubee mod execve -p 12345                                # attach to a running PID
anubee mod file-access -m file-access -m execve -P com.example.app   # run several at once
```

| Flag | Meaning |
|---|---|
| `-P PACKAGE` / `-p PID[,...]` | Attach target |
| `-A ACTIVITY` | Override launch activity component |
| `-m NAME` | Analyzer to run; repeat `-m` to run several concurrently (or pass `NAME` positionally) |
| `-o FILE` | Export structured JSONL to `FILE` |
| `-v` | Verbose output (e.g. `execve`: full backtrace frames) |
| `-q` | Suppress per-event console output |
| `-F FILE` | Spec file; a `mod:NAME` line supplies the analyzer name when none given positionally |
| `-l` / `--list` | List available analyzers and exit |

## Analyzers

| Name | Detects | Loud? |
|---|---|---|
| `proc-event` | Process fork/exit | Stealthy |
| `execve` | `execve`/`execveat` calls, with full argv + call stack | Stealthy |
| `prop-read` | Android `__system_property_*` reads (anti-emulator/root checks) | **Loud** (libc uprobe) |
| `file-access` | Sensitive file opens: external storage, credential-shaped filenames, foreign app private dirs | Stealthy |
| `massdelete-detect` | Rapid rename+delete bursts on external storage (20 touches / 10s, mostly-distinct files) | Stealthy |
| `exfil-detect` | A sensitive file read followed by a network byte-volume burst (512 KiB / 30s) | Stealthy |
| `accessibility-detect` | A burst of outbound Binder calls to `system_server` (50 / 5s) from an app with a granted Accessibility Service | Stealthy |
| `fileless-detect` | An anonymous executable memory mapping that isn't ART's own JIT cache: fileless native code execution | Stealthy |
| `screencapture-detect` | An active `MediaProjection` screen-capture session (polls `dumpsys`, 1s interval) | Stealthy |

`prop-read` is the only analyzer that writes a `BRK` into the target; every
other analyzer is a kprobe/tracepoint. Each run also prints (and, with `-o`,
writes) an end-of-run summary record, see [`reading-traces.md`](reading-traces.md).

## Testing massdelete-detect/exfil-detect against a real app (manual)

The burst analyzers key off genuine app-UID file/network activity.
`scripts/moddemoapp/anubee-moddemoapp.apk` is a small, safe demo app
(source in the same directory) that performs both behaviors itself, on
launch — no companion trigger process needed:

```sh
adb install scripts/moddemoapp/anubee-moddemoapp.apk
adb shell "su -c 'appops set dev.anubee.moddemoapp MANAGE_EXTERNAL_STORAGE allow'"
adb shell "su -c '/data/local/tmp/anubee mod -P dev.anubee.moddemoapp -m massdelete-detect -m exfil-detect -o /data/local/tmp/moddemo.jsonl'"
```

`anubee`'s own launcher starts the app; both analyzers' alert lines should
appear from that one run. Rebuild from source with
`scripts/moddemoapp/build.sh install` (needs `d8`, see the script header).

## Gotchas

- **`massdelete-detect`/`exfil-detect` need `MANAGE_EXTERNAL_STORAGE`** ("All files
  access") on the target app. Scoped storage (Android 11+) otherwise blocks the
  signal outright. `massdelete-detect` surfaces whether the app holds it.
- **Deletes via MediaStore's trash API are invisible** to `massdelete-detect`.
  The real `renameat` runs under MediaProvider's UID, not the app's.
- **`accessibility-detect`/`screencapture-detect` false-positive on legitimate tools.**
  Screen-share/remote-support apps and legitimate accessibility services trip
  the same signal as abuse.
