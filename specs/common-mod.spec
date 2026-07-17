# Analyzer catalog for `anubee mod`. mod:-only. `anubee mod` runs every mod:
# line concurrently (cap 16), so this file is directly runnable:
#   anubee mod -P com.example.app -F specs/common-mod.spec
# Trim to a subset for a focused run, or pass -m NAME instead of -F.
# Full grammar: docs/probe-specs.md. Analyzer list: `anubee mod --list`.
#
# NOTE: unlike funcs:/syscall:/lib:, a mod: line has no trailing-comment or
# inline-annotation support (the loader only strips whole-line '#' comments,
# and mod: copies everything after the prefix verbatim as the analyzer
# name) — keep description comments on their own line above each entry.

# process fork/exit events
mod:proc-event
# execve calls with full argv + call stack
mod:execve
# system property reads (_get/_find/_foreach)
mod:prop-read
# sensitive file opens (storage, creds, foreign app dirs)
mod:file-access
# rename/unlink bursts on external storage (ransomware signal)
mod:massdelete-detect
# network byte-volume burst following a sensitive file read (exfil)
mod:exfil-detect
# Binder-transaction bursts to system_server via granted Accessibility Service
mod:accessibility-detect
# anonymous executable mappings with no ART JIT tag (fileless native code)
mod:fileless-detect
# active MediaProjection screen-capture session
mod:screencapture-detect
