#!/usr/bin/env bash
set -euo pipefail
# BLD1 guard: editing a header that defines a BPF/userspace-shared struct must
# invalidate BOTH the BPF object and the userspace reader, and relink ares.
# `make -q <t>` exits 0 if t is up to date, non-zero if it needs rebuilding.
cd "$(dirname "$0")/.."
make >/dev/null                       # ensure the tree is up to date first
HDR=src/common/stack_snapshot.h       # struct shared by BPF (.bpf.h) + userspace
touch "$HDR"
EXPECT=(build/funcs.bpf.o build/syscalls.bpf.o \
        build/common/symbolize.o build/common/stack_snapshot.o build/ares)
fail=0
for t in "${EXPECT[@]}"; do
  if make -q "$t" 2>/dev/null; then
    echo "STALE-DEP BUG: $t not invalidated by touching $HDR" >&2; fail=1
  fi
done
make >/dev/null                       # restore the tree
exit $fail
