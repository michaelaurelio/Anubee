# `anubee mod`: analyzers

`anubee mod <name>` runs a detection package built for one behavior: a
lightweight, standalone BPF object, instead of a general-purpose tracer
you'd have to hand-build with `funcs`/`correlate` specs.

```sh
anubee mod --list                                        # list available analyzers
anubee mod massdelete-detect -P com.example.app -o out.jsonl
anubee mod execve -p 12345                                # attach to a running PID
anubee mod -m file-access -m execve -P com.example.app   # run several at once
anubee mod triage -P com.example.app -o out.jsonl         # every stealthy analyzer at once
anubee mod triage -P com.example.app --no-launch          # wait for the app to start by itself
```

**Start with `triage` on an unknown sample.** It runs every stealthy analyzer
into one JSONL (zero writes into the target), so the first run shows which
behaviors are present; then rerun the relevant analyzers alone with `-v`.
Use `--no-launch` when the sample has no launcher icon, starts from a
receiver (boot, SMS, alarm, push), or you want to start it by hand.

| Flag | Meaning |
|---|---|
| `-P PACKAGE` / `-p PID[,...]` | Attach target |
| `-A ACTIVITY` | Override launch activity component |
| `--no-launch` | With `-P`: trace the package's UID without force-stopping or launching it; the app is caught whenever it starts |
| `-m NAME` | Analyzer to run; repeat `-m` to run several concurrently (or pass `NAME` positionally). `triage` = every stealthy analyzer. A name given twice runs once |
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
| `accessibility-detect` | What the app's own Accessibility Service does, by category: reading other apps' screens (`screen_read`), clicking / entering text (`action`), injecting gestures, global back/home actions, screenshots, keyboard switching. One alert per category | Stealthy |
| `fileless-detect` | Executable memory without a file: an anonymous executable mapping, memory made executable after being written (unpackers), or code run from a memfd -- ART's own JIT regions excluded by name; a copy of each region saved | Stealthy |
| `dexload-detect` | A DEX/APK/JAR/ELF payload written to a file, mapped (loaded) and deleted, with a saved copy + SHA-256: droppers, `DexClassLoader`, native second stages | Stealthy |
| `screencapture-detect` | How far a screen-capture attempt got: capture service declared (`fgs_declared`, even if the user declines the prompt), capture started (`projection_start`), screen mirrored into the app (`virtual_display`) | Stealthy |
| `binder-api` | Which Binder interfaces/methods the app calls (`IActivityManager.getRunningAppProcesses`, `IPackageManager.getInstalledPackages`...), named from the device's own framework jars; every ContentProvider call with its URI (`QUERY content://sms/inbox`) or `CALL` target (`settings GET_secure android_id`) | Stealthy |
| `perm-watch` | Baseline + every change of the package's granted permissions, app-op modes, Accessibility / notification-listener / device-admin enablement, roles (default SMS, dialer, home...), and installed-ness (polls shell tools, 2s) | Stealthy |

`prop-read` is the only analyzer that writes a `BRK` into the target; every
other analyzer is a kprobe/tracepoint (or, for `perm-watch`, shell polling
from anubee's own process). Each run also prints (and, with `-o`,
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
  Screen-share/remote-support apps and legitimate accessibility services
  (TalkBack, password managers, automation apps) make the same calls as abuse.
  `accessibility-detect` says what the service did (read the screen, clicked,
  took a screenshot), not why. Its grant check (`granted`) is made once at
  attach; enable-after-start shows up in `perm-watch`.
- **`exfil-detect` counts only sends to a non-loopback IPv4/IPv6 peer.** The
  fd is resolved to its kernel socket at send time, so AF_UNIX (logd, netd)
  never counts, connections opened before the analyzer attached are seen,
  and `dest` is the socket the bytes went to.
- **`binder-api` logs the first call of each method, then counts.** Every
  call is counted; only the first per (process, interface, method) is printed
  and written, except ContentProvider calls (each URI/`CALL` printed once,
  all written). Native-only interfaces (`ISurfaceComposer`, `media.c2.*`) and
  app-private AIDL show as `#<code>`, unnamed. A URI marshalled as separate
  scheme/authority/path parts isn't decoded (not seen on Android 16). It is
  per-process and synchronous: it shows what the app *asked for*, not the
  reply.
- **`perm-watch` sees state, not the request.** It records that a permission
  or app-op *changed* (2s resolution), not which dialog or `appops`/Settings
  call changed it. A grant that is made and reverted within one poll is
  missed. With `-p` on a process that isn't an app (no package name), it is
  inactive and its coverage record says so.
- **`exfil-detect`'s `sample_path`/`sensitive_paths` are correlational, not
  proof of transfer.** They list sensitive-classified files the process
  opened within a few seconds of the network burst (`EXFIL_RECENT_NS`) —
  plausible candidates for what triggered the alert, not confirmed evidence
  of what was actually sent. Syscall-level tracing can't see which file's
  bytes ended up in which network write; proving that would require
  inspecting buffer contents (uprobes), which this analyzer deliberately
  doesn't do to stay stealthy.
