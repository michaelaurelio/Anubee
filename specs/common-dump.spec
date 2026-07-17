# Library selectors for `anubee dump` (rebuild a mapped .so from live memory)
# and for `syscalls`' -F library scoping. lib:-only. Full grammar:
# docs/probe-specs.md.
#   anubee dump -P com.example.app -F specs/common-dump.spec -o out/
#
# rasp-checks.spec (ARES-Detector/sim/) already has its own lib:libsentinel.so
# line for that project's own use; this file is the generic starting point.

lib:libsentinel.so

# App-private native libs (packers/droppers often unpack outside the APK's
# own lib/ dir) — trim or replace with your target's actual library name(s):
# lib:libapp*.so
