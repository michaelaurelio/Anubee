#!/bin/sh
# Fail if a parser calls argp_error() directly. Every engine parses with
# ARGP_NO_EXIT, where argp_error() only prints and returns, so the run would
# carry on with bad arguments. Use ANUBEE_ARGP_FAIL (engine_args.h) in parser
# callbacks, or return the error_t from the validate_* helpers.
# mod.c is exempt: it parses with flags 0, so argp_error exits there.
set -eu
root=$(dirname "$0")/..
bad=$(grep -rn 'argp_error(' "$root/src" \
      | grep -v 'src/common/engine_args.h' \
      | grep -v 'src/common/target_validate.c' \
      | grep -v 'src/modules/mod.c' \
      | grep -vE ':[0-9]+:[[:space:]]*(//|\*|/\*)' || true)
if [ -n "$bad" ]; then
    echo "bare argp_error() in a parser (use ANUBEE_ARGP_FAIL):" >&2
    echo "$bad" >&2
    exit 1
fi
echo "argp error check: ok"
