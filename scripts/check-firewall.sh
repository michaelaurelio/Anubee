#!/usr/bin/env bash
# CR1 detectability-firewall gate. Proves, off the compiled capabilities.c
# table (via build/capdump), that quiet BPF objects carry no uprobe/uretprobe
# program section and loud ones do (Check A), and that only loud-owned engine
# objects reference bpf_program__attach_uprobe (Check B, Task 3). See
# docs/superpowers/specs/2026-07-05-firewall-gate-design.md.
set -euo pipefail
cd "$(dirname "$0")/.."

OBJDUMP="${LLVM_OBJDUMP:-llvm-objdump}"
NM="${LLVM_NM:-llvm-nm}"
# Fail loudly if the LLVM tools are missing. A not-found objdump/nm otherwise
# emits empty output that masquerades as a breach (a loud object reported as
# having "no uprobe section") - a misleading verdict is worse than a clear
# tooling error. Set LLVM_OBJDUMP / LLVM_NM to override the tool names.
for _t in "$OBJDUMP" "$NM"; do
  command -v "$_t" >/dev/null 2>&1 || {
    echo "check-firewall: required tool '$_t' not found on PATH" \
         "(install LLVM or set LLVM_OBJDUMP / LLVM_NM)" >&2
    exit 2
  }
done
BUILD=build
fail=0
breach() { echo "FIREWALL BREACH: $*" >&2; fail=1; }

# capability name -> its own .bpf.o basename, or SKIP for composite/no-object.
map_bpf_obj() {
  case "$1" in
    syscalls)       echo syscalls.bpf.o ;;
    funcs)          echo funcs.bpf.o ;;
    lib)            echo lib.bpf.o ;;
    dump)           echo dump.bpf.o ;;
    correlate)      echo correlate.bpf.o ;;
    trace)          echo SKIP ;;   # composite: reuses funcs+syscalls, owns none
    mod:proc-event) echo proc_event.bpf.o ;;
    mod:execve)     echo execve.bpf.o ;;
    mod:prop-read)  echo prop_read.bpf.o ;;
    mod:file-access)echo file_access.bpf.o ;;
    mod:massdelete-detect) echo massdelete_detect.bpf.o ;;
    mod:exfil-detect) echo exfil_detect.bpf.o ;;
    mod:a11y-abuse) echo a11y_abuse.bpf.o ;;
    mod:fileless-exec) echo fileless_exec.bpf.o ;;
    mod:mediaproj-abuse) echo mediaproj_abuse.bpf.o ;;
    *)              echo UNMAPPED ;;
  esac
}

# Program-section names in an object, prefix-anchored to real uprobe/usdt
# sections. Excludes kprobe/uprobe_mmap (starts "kprobe") and .reluprobe reloc
# (starts "."). usdt is included because a USDT probe is uprobe-backed and
# writes into target userspace memory (loud), even though its section is
# named "usdt/..." rather than "uprobe...".
uprobe_sections() {
  "$OBJDUMP" -h "$1" | awk '$2 ~ /^uprobe/ || $2 ~ /^uretprobe/ || $2 ~ /^usdt/ { print $2 }'
}

check_sections() {  # args: <name> <loud 0|1>
  local name="$1" loud="$2" obj sec
  obj="$(map_bpf_obj "$name")"
  [ "$obj" = SKIP ] && return 0
  if [ "$obj" = UNMAPPED ]; then
    breach "unmapped capability $name (add it to map_bpf_obj)"; return 0
  fi
  local path="$BUILD/$obj"
  [ -f "$path" ] || { breach "missing object $path for $name (run make)"; return 0; }
  sec="$(uprobe_sections "$path" | head -1 || true)"
  if [ "$loud" = 0 ] && [ -n "$sec" ]; then
    breach "quiet object $obj carries uprobe section '$sec'"
  elif [ "$loud" = 1 ] && [ -z "$sec" ]; then
    breach "loud object $obj has no uprobe/uretprobe section"
  fi
}

run_check_a() {
  while IFS=$'\t' read -r name loud; do
    [ -n "$name" ] && check_sections "$name" "$loud"
  done < <("$BUILD/capdump")
}

# Map a built object path to its owning capability name (matching capdump rows),
# or "shared" for src/common + the mod dispatcher (must never attach a uprobe).
owner_of() {
  case "$1" in
    $BUILD/common/*)            echo shared ;;
    $BUILD/funcs/*)             echo funcs ;;
    $BUILD/syscalls/*)          echo syscalls ;;
    $BUILD/lib/*)               echo lib ;;
    $BUILD/dump/*)              echo dump ;;
    $BUILD/correlate/*)         echo correlate ;;
    $BUILD/trace/*)             echo trace ;;
    $BUILD/modules/execve.o)    echo mod:execve ;;
    $BUILD/modules/prop_read.o) echo mod:prop-read ;;
    $BUILD/modules/proc_event.o) echo mod:proc-event ;;
    $BUILD/modules/file_access.o) echo mod:file-access ;;
    $BUILD/modules/massdelete_detect.o) echo mod:massdelete-detect ;;
    $BUILD/modules/exfil_detect.o) echo mod:exfil-detect ;;
    $BUILD/modules/a11y_abuse.o) echo mod:a11y-abuse ;;
    $BUILD/modules/fileless_exec.o) echo mod:fileless-exec ;;
    $BUILD/modules/mediaproj_abuse.o) echo mod:mediaproj-abuse ;;
    $BUILD/modules/*)           echo shared ;;   # mod.o / mod_emit.o dispatcher
    $BUILD/main.o)              echo shared ;;
    *)                          echo shared ;;
  esac
}

# True (0) if the capability name is loud per capdump.
# capdump is an executable that emits the rows (see run_check_a); it must be
# run, not read as a data file.
is_loud() {
  awk -F'\t' -v n="$1" '$1==n {print $2}' <("$BUILD/capdump") | grep -q '^1$'
}

check_attach_whitelist() {
  local o owner
  # Enumerate ARES-owned objects only (exclude vendored libbpf, BPF objs, and
  # .part.o aggregates which duplicate their members' refs).
  while IFS= read -r o; do
    "$NM" --undefined-only "$o" 2>/dev/null | grep -qE 'bpf_program__attach_(uprobe|usdt)' || continue
    owner="$(owner_of "$o")"
    if [ "$owner" = shared ] || ! is_loud "$owner"; then
      breach "quiet/shared object $o references bpf_program__attach_uprobe/usdt (owner: $owner)"
    fi
  done < <(find "$BUILD" -name '*.o' \
             ! -name '*.bpf.o' ! -name '*.part.o' ! -path "$BUILD/libbpf/*")
}

main() {
  make >/dev/null
  make capdump >/dev/null
  run_check_a
  check_attach_whitelist
  if [ "$fail" -ne 0 ]; then
    echo "check-firewall: FAILED" >&2; exit 1
  fi
  echo "check-firewall: OK (sections + attach-whitelist)"
}

# Prove the gate detects violations. Builds a uprobe-bearing section into a
# copy of a quiet .bpf.c, and an attach ref into a copy of a quiet .c, in a temp
# dir, and asserts each check flags it. Never touches the real build/ or source.
selftest() {
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local clang="${BPF_CLANG:-clang}"
  local ok=0
  local arm_a_skipped=0

  # A: uprobe section injected into a quiet BPF object.
  cat > "$tmp/q.bpf.c" <<'EOF'
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
char _license[] SEC("license") = "GPL";
SEC("uprobe/probe_selftest")
int selftest_probe(void *ctx) { return 0; }
EOF
  if "$clang" -target bpf -g -O2 -I"$BUILD/libbpf/include" -I. -Isrc -c "$tmp/q.bpf.c" -o "$tmp/q.bpf.o" 2>"$tmp/berr"; then
    if [ -n "$(uprobe_sections "$tmp/q.bpf.o")" ]; then ok=$((ok+1));
    else echo "SELFTEST FAIL: uprobe section not detected in injected object" >&2; fi
  else
    echo "SELFTEST SKIP: could not compile BPF probe stub (need clang+vmlinux.h):" >&2
    cat "$tmp/berr" >&2; ok=$((ok+1)); arm_a_skipped=1   # do not fail CI on toolchain gap; Check A still runs live
  fi

  # B: attach_uprobe reference injected into a quiet .c object.
  cat > "$tmp/q.c" <<'EOF'
int bpf_program__attach_uprobe(void);
int quiet_selftest(void) { return bpf_program__attach_uprobe(); }
EOF
  "${HOST_CC:-cc}" -c "$tmp/q.c" -o "$tmp/q.o"
  if "$NM" --undefined-only "$tmp/q.o" | grep -q 'bpf_program__attach_uprobe'; then
    ok=$((ok+1))
  else
    echo "SELFTEST FAIL: attach_uprobe ref not detected in injected object" >&2
  fi

  # C: CR1 gap - A/B only prove the section/symbol primitives work
  # (uprobe_sections, an nm grep). Drive the actual gate routing main() uses
  # (check_sections / check_attach_whitelist, via map_bpf_obj / owner_of /
  # is_loud) against a throwaway build tree: BUILD is overridden only inside a
  # subshell, so this never touches the real build/ or source, and any
  # breach() call's fail=1 dies with the subshell instead of leaking out.
  local arm_c_skipped=0
  mkdir -p "$tmp/fakebuild/syscalls"

  # C1: check_sections should flag a quiet capability (syscalls, loud=0)
  # whose object carries a uprobe section. Reuses arm A's compiled object;
  # skip (not fail) under the same toolchain-absence condition as arm A.
  if [ "$arm_a_skipped" -eq 0 ]; then
    cp "$tmp/q.bpf.o" "$tmp/fakebuild/syscalls.bpf.o"
    if ( BUILD="$tmp/fakebuild"; check_sections syscalls 0 ) 2>&1 | grep -q 'FIREWALL BREACH'; then
      ok=$((ok+1))
    else
      echo "SELFTEST FAIL: check_sections routing missed the injected uprobe section" >&2
    fi
  else
    ok=$((ok+1)); arm_c_skipped=1
  fi

  # C2: check_attach_whitelist should flag a quiet-owned object referencing
  # bpf_program__attach_uprobe. Only needs cc (arm B's q.o) plus the real,
  # already-built capdump symlinked in - the loudness table itself isn't
  # faked, only the injected artifact's location.
  if [ -x "$BUILD/capdump" ]; then
    cp "$tmp/q.o" "$tmp/fakebuild/syscalls/fake.o"
    ln -sf "$(cd "$BUILD" && pwd)/capdump" "$tmp/fakebuild/capdump"
    if ( BUILD="$tmp/fakebuild"; check_attach_whitelist ) 2>&1 | grep -q 'FIREWALL BREACH'; then
      ok=$((ok+1))
    else
      echo "SELFTEST FAIL: check_attach_whitelist routing missed the injected attach ref" >&2
    fi
  else
    echo "SELFTEST SKIP: build/capdump not built (run 'make capdump' first) - C2 skipped" >&2
    ok=$((ok+1))
  fi

  if [ "$ok" -eq 4 ]; then
    if [ "$arm_a_skipped" -eq 1 ] || [ "$arm_c_skipped" -eq 1 ]; then
      echo "check-firewall: selftest OK (BPF-toolchain-dependent arms SKIPPED - only symbol/routing arms exercised)"
    else
      echo "check-firewall: selftest OK"
    fi
    return 0
  fi
  echo "check-firewall: selftest FAILED" >&2; return 1
}

if [ "${1:-}" = "--selftest" ]; then selftest; else main "$@"; fi
