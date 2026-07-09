#!/bin/sh
# AA3: fail if src/common/engine_driver.h and the Makefile's *_DRIVER keep-lists
# drift. The header is the declared contract; the Makefile's --keep-global-symbol
# lists must keep exactly those symbols linkable for the `trace` coordinator.
# ponytail: text grep, not a C parser — the contract is 3 fixed suffixes per engine.
set -eu
root=$(dirname "$0")/..

# Symbols the header declares: ARES_ENGINE_DRIVER(e) expands to e_setup/e_run/e_teardown.
# (excludes the macro's own #define line, which also matches the pattern)
hdr_engines=$(grep -v '^#define' "$root/src/common/engine_driver.h" \
              | grep -oE 'ARES_ENGINE_DRIVER\([a-z]+\)' \
              | sed -E 's/ARES_ENGINE_DRIVER\(([a-z]+)\)/\1/')
hdr_syms=$(for e in $hdr_engines; do printf '%s_setup\n%s_run\n%s_teardown\n' "$e" "$e" "$e"; done | sort -u)

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
