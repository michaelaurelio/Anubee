# `ares mod`: analyzers

`ares mod <name>` runs a detection package built for one behavior: a
lightweight, standalone BPF object, instead of a general-purpose tracer
you'd have to hand-build with `funcs`/`correlate` specs.

```sh
ares mod --list                                        # list available analyzers
ares mod massdelete-detect -P com.example.app -o out.jsonl
ares mod execve -p 12345                                # attach to a running PID
ares mod file-access -m file-access -m execve -P com.example.app   # run several at once
```

| Flag | Meaning |
|---|---|
| `-P PACKAGE` / `-p PID[,...]` | Attach target |
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
| `mediaproj-abuse` | An active `MediaProjection` screen-capture session (polls `dumpsys`, 1s interval) | Stealthy |

`prop-read` is the only analyzer that writes a `BRK` into the target; every
other analyzer is a kprobe/tracepoint. Each run also prints (and, with `-o`,
writes) an end-of-run summary record, see [`reading-traces.md`](reading-traces.md).

## Testing `massdelete-detect`/`exfil-detect` against a real app (manual)

The burst analyzers key off genuine app-UID file activity. `scripts/massdeleteapp/build.sh install`
builds and installs a minimal trigger app for this; it needs **two terminals**:

**Terminal A** (leave it running: it blocks with no output until Terminal B kills it, that's expected):
```sh
adb shell "su -c '/data/local/tmp/ares mod massdelete-detect -P dev.ares.massdeleteapp -o /data/local/tmp/burst.jsonl'"
```

**Terminal B:**
```sh
# 1. build + install (prints the assigned UID)
scripts/massdeleteapp/build.sh install

# 2. push the trigger binary
adb push build/ares_massdelete_gen /data/local/tmp/ares_massdelete_gen
adb shell chmod 755 /data/local/tmp/ares_massdelete_gen

# 3. find the PID Terminal A is running as (NOT the UID from step 1)
adb shell "su -c 'ps -ef | grep \"ares mod\" | grep -v grep'"

# 4. trigger the burst AS the app's own UID
adb shell "su -c 'mkdir -p /sdcard/Download/burst_test'"
adb shell "su -c 'su <UID> -c \"/data/local/tmp/ares_massdelete_gen /sdcard/Download/burst_test\"'"

# 5. stop Terminal A by PID (Ctrl-C doesn't reliably reach a non-pty adb shell)
adb shell "su -c 'kill -INT <PID>'"

# 6. read the result
adb shell "su -c 'cat /data/local/tmp/burst.jsonl'"
```

## Gotchas

- **The UID (step 1 above) and the PID (step 3) are not interchangeable.** The
  UID is who runs the trigger, the PID is what you kill.
- **`massdelete-detect`/`exfil-detect` need `MANAGE_EXTERNAL_STORAGE`** ("All files
  access") on the target app. Scoped storage (Android 11+) otherwise blocks the
  signal outright. `massdelete-detect` surfaces whether the app holds it.
- **Deletes via MediaStore's trash API are invisible** to `massdelete-detect`.
  The real `renameat` runs under MediaProvider's UID, not the app's.
- **`accessibility-detect`/`mediaproj-abuse` false-positive on legitimate tools.**
  Screen-share/remote-support apps and legitimate accessibility services trip
  the same signal as abuse.
