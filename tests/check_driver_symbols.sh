#!/bin/sh
# AA3: fail if src/common/engine_driver.h and the Makefile's *_DRIVER keep-lists
# drift. The header is the declared contract; the Makefile's --keep-global-symbol
# lists must keep exactly those symbols linkable for the `trace` coordinator.
# ponytail: text grep, not a C parser — the contract is 3 fixed suffixes per engine.
set -eu
root=$(dirname "$0")/..

# Symbols the header declares, from two shapes:
#  1. ANUBEE_ENGINE_DRIVER(e) invocations -> e_setup/e_run/e_teardown.
#     (excludes the macro's own #define line, which also matches the pattern)
#  2. Standalone prototypes at column 0, e.g. "int correlate_attach(pid_t pid);"
#     (the macro's own body lines are indented, so this doesn't double-count them)
hdr_engines=$(grep -v '^#define' "$root/src/common/engine_driver.h" \
              | grep -oE 'ANUBEE_ENGINE_DRIVER\([a-z]+\)' \
              | sed -E 's/ANUBEE_ENGINE_DRIVER\(([a-z]+)\)/\1/')
hdr_macro_syms=$(for e in $hdr_engines; do printf '%s_setup\n%s_run\n%s_teardown\n' "$e" "$e" "$e"; done)
hdr_standalone_syms=$(grep -E '^(int|void)[[:space:]]' "$root/src/common/engine_driver.h" \
              | sed -E 's/^(int|void)[[:space:]]+\**([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\(.*/\2/')
hdr_syms=$(printf '%s\n%s\n' "$hdr_macro_syms" "$hdr_standalone_syms" | sort -u)

# Symbols kept global by the Makefile's *_DRIVER variables.
mk_syms=$(grep -E '^[A-Z_]+_DRIVER[[:space:]]*:=' "$root/Makefile" \
          | sed -E 's/^[A-Z_]+_DRIVER[[:space:]]*:=[[:space:]]*//' \
          | tr ' ' '\n' | sort -u)

hdr_f=$(mktemp) mk_f=$(mktemp)
trap 'rm -f "$hdr_f" "$mk_f"' EXIT
echo "$hdr_syms" >"$hdr_f"
echo "$mk_syms"  >"$mk_f"

missing=$(comm -23 "$hdr_f" "$mk_f")
extra=$(comm -13 "$hdr_f" "$mk_f")

if [ -n "$missing" ] || [ -n "$extra" ]; then
    echo "driver-symbol drift between engine_driver.h and Makefile *_DRIVER lists:"
    [ -n "$missing" ] && echo "  in header, missing from Makefile: $missing"
    [ -n "$extra" ]   && echo "  in Makefile, missing from header: $extra"
    exit 1
fi
echo "driver-symbol cross-check ok ($(echo "$hdr_syms" | wc -l) symbols)"
