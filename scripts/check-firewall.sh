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
    *)              echo UNMAPPED ;;
  esac
}

# Program-section names in an object, prefix-anchored to real uprobe sections.
# Excludes kprobe/uprobe_mmap (starts "kprobe") and .reluprobe reloc (starts ".").
uprobe_sections() {
  "$OBJDUMP" -h "$1" | awk '$2 ~ /^uprobe/ || $2 ~ /^uretprobe/ { print $2 }'
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
    "$NM" --undefined-only "$o" 2>/dev/null | grep -q 'bpf_program__attach_uprobe' || continue
    owner="$(owner_of "$o")"
    if [ "$owner" = shared ] || ! is_loud "$owner"; then
      breach "quiet/shared object $o references bpf_program__attach_uprobe (owner: $owner)"
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

main "$@"
