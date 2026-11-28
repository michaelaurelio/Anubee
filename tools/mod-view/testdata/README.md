# mod-view test fixture

A synthetic `anubee mod` run modelled on a real banking-trojan lab run.
Package `com.example.sample`, suspected C2 `203.0.113.5:3434`. Times below are
seconds after T0 (the first record). The fixture is shared ground truth for the
view's tests; the Python findings view must give `expected-findings.json` too
(`tools/anubee-mcp/test_mod_findings.py`).

Files: `sample-run.jsonl` (records), `sample-run.marks` (lab marks, same clock),
`profile.json` (version-1 noise profile), `expected-findings.json` (Python's
output on the three, minus first-seen times). `degraded.jsonl` is `sample-run.jsonl` with the
`file-access` coverage record set to `clean:false` (the degraded-coverage case).

| When | Records |
|---|---|
| +0 | perm baseline snapshot (installed + three permissions), `binder_api` `attachApplication` (the one noise call, in `profile.json`) at +1.0 |
| +2.4 | `file_access` in the app's own dir (not behaviour, skipped) |
| +2.5 | `dexload_detect` `drop` then `load` of `/data/data/com.example.sample/app_x7k2/payload/0.bin`, same `ino` 38531; `load.saved` has a sha256 and `size` 777276 bytes (also in `dexload_detect_summary`) |
| +2.9 / +3.0 | `binder_api` `IAlarmManager.set`, `IActivityManager.setServiceForeground` |
| +3.1 ... +250 | 16 `net` open/close pairs to `203.0.113.5:3434` (`host_source` `http`); opens at 3.1, 49.7, 53.4, 58.9, 66.2, 79.8, 95.1, 112.6, 131.0, 140.2, then 150, 170, 190, 210, 230, 250 (last six 20 s apart); each close follows its open by 14 ms |
| +48.3 | `perm_change` `SYSTEM_ALERT_WINDOW` default -> allow |
| +48.4 ... +246.4 | 12 `proc_exit` signal 9, 18 s apart; each followed 1.4 s later by an `IAlarmManager.set` from a new pid (13 `set` records in all) |
| +50.9 | `perm_change`: nine runtime permissions granted, accessibility service granted |
| +51.2 / +54.6 | `accessibility_detect` `global_action` / `screen_read` |
| end | 12 clean `coverage` records (no timestamps), `net_summary` (16 connections), `dexload_detect_summary`, `binder_api_summary` (alarm `set` 28 across 12 pids), `accessibility_detect_summary` (global_action 20, screen_read 18), `proc_event_summary` (12 signal exits) |

`sample-run.marks`: `launch` +0; `grant-begin:overlay` +48.2, `grant-end:overlay`
+48.4 (around the +48.3 change); `grant-begin:all` +50.8, `grant-end:all` +51.0
(around +50.9); `stop` +265.
