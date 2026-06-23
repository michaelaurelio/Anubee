#!/usr/bin/env bash
# Device acceptance smoke test for ares — the device tier of the testing flow.
# Pushes the freshly-built build/ares to the attached rooted device and asserts
# each capability still ATTACHES and emits REAL tracer output (not just help
# text). Exits 0 on pass, non-zero on fail, so it drops into CI / `make` / loops.
#
# Usage:
#   scripts/device-test.sh [lib|syscalls|all]      # default: all
#
# Env overrides:
#   ARES_TEST_PKG=<package>    target app   (default: com.android.deskclock)
#   ARES_TEST_TIMEOUT=<secs>   per-run window (default: 10)
#
# WHY each ares run gets its OWN `su -c`: chaining `am force-stop ...; ares ...`
# inside a single `su -c` runs ares under an intermediate shell in a reduced
# context and the BPF load fails with -EPERM. A direct `su -c "<ares ...>"`
# execs the binary in the root domain with the caps eBPF needs. Keep them split.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="$ROOT/build/ares"
DEVICE_PATH="/data/local/tmp/ares"
PKG="${ARES_TEST_PKG:-com.android.deskclock}"
TIMEOUT="${ARES_TEST_TIMEOUT:-10}"
WHAT="${1:-all}"

fail() { echo "FAIL: $*" >&2; exit 1; }
info() { echo "  $*"; }

# ares runs in its OWN su -c (see header). Host expands the vars; the single
# quotes reach the device shell so `su -c '<one string>'` execs the binary.
# ares stops on SIGINT (its "Ctrl-C") but IGNORES SIGTERM, so plain `timeout`
# (TERM) hangs waiting on it — send INT, with a SIGKILL backstop after 3s.
ares()      { adb shell "su -c 'timeout -s INT -k 3 $TIMEOUT $DEVICE_PATH $*'" 2>&1; }
forcestop() { adb shell "su -c 'am force-stop $PKG'" >/dev/null 2>&1; }
# A run orphaned by an adb disconnect keeps holding the binary -> ETXTBSY on the
# next push/exec. Clear any lingering ares before we push.
kill_ares() { adb shell "su -c 'pkill -INT -f $DEVICE_PATH; sleep 1; pkill -KILL -f $DEVICE_PATH'" >/dev/null 2>&1 || true; }

# --- preflight ------------------------------------------------------------
[ -f "$BINARY" ] || fail "no build/ares — run ./scripts/build.sh first"
adb get-state >/dev/null 2>&1 || fail "no device via adb (check 'adb devices')"
[ "$(adb shell "su -c 'id -u'" 2>/dev/null | tr -d '\r')" = "0" ] \
    || fail "device root unavailable (su -c) — ares needs root for eBPF"
adb shell "su -c 'ls /sys/kernel/btf/vmlinux'" >/dev/null 2>&1 \
    || fail "kernel BTF missing (/sys/kernel/btf/vmlinux) — CO-RE eBPF can't load"
adb shell "pm path $PKG" >/dev/null 2>&1 \
    || fail "test package not installed: $PKG (set ARES_TEST_PKG)"

# --- push fresh binary (skip when the device copy already matches) ---------
# adb push over a flaky USB link can stall for minutes; skipping an identical
# re-push keeps the smoke test fast and resilient.
host_sum="$(md5sum "$BINARY" | awk '{print $1}')"
dev_sum="$(adb shell "md5sum $DEVICE_PATH 2>/dev/null" | awk '{print $1}' | tr -d '\r')"
if [ "$host_sum" = "$dev_sum" ]; then
    echo "=== on-device binary up to date (md5 ${host_sum%${host_sum#????????????}}), skipping push ==="
else
    echo "=== pushing $(basename "$BINARY") -> $DEVICE_PATH ==="
    kill_ares
    adb push "$BINARY" "$DEVICE_PATH" >/dev/null || fail "adb push failed"
    adb shell "chmod 755 $DEVICE_PATH"
fi

# --- capability checks ----------------------------------------------------
# lib: stealthy mmap-kprobe. Deterministic — every app maps bionic libc.so.
test_lib() {
    echo "=== lib (stealthy mmap-kprobe) ==="
    forcestop
    # here-strings (not echo|grep): grep -q exits on first match and would
    # SIGPIPE the writer, which `set -o pipefail` then reports as failure.
    local out; out="$(ares "lib $PKG")"
    grep -q '^\[lib\]' <<<"$out" \
        || { tail -5 <<<"$out" >&2; fail "lib: no [lib] lines (BPF/attach broken?)"; }
    grep -q 'bionic/libc.so' <<<"$out" \
        || fail "lib: libc.so not resolved ([lib] emitter / maps resolver broken?)"
    info "lib OK — $(grep -c '^\[lib\]' <<<"$out") [lib] lines, libc.so resolved"
}

# syscalls: kprobe. Assert on the attach banner, not on events (event timing is
# app-dependent and flaky in a short window; attach proves BPF load + CO-RE).
test_syscalls() {
    echo "=== syscalls (kprobe) ==="
    forcestop
    local out; out="$(ares "syscalls -a -s openat $PKG")"
    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "syscalls: BPF load failed (root/SELinux/own-su-c?)"
    fi
    # The attach banner OR real syscall events (==> call / <== return) both prove
    # the BPF object loaded + attached. Accept either: a flaky adb stream can drop
    # the early banner even when tracing clearly worked.
    if grep -qE 'probes attached to|(==>|<==) #[0-9]' <<<"$out"; then
        info "syscalls OK — attached / events flowing"
    else
        tail -5 <<<"$out" >&2; fail "syscalls: no attach banner or events captured"
    fi
}

# syscalls JIT symbolization: assert that when a JIT-compiled frame appears in a
# backtrace it renders as [JIT]!<method> rather than a bare cache-region offset.
# JIT presence is app/timing-dependent, so a miss is a SKIP, not a failure.
test_syscalls_jit() {
    echo "=== syscalls JIT symbolization ([JIT]! frames) ==="
    forcestop
    local out; out="$(ares "syscalls -a -s openat $PKG")"
    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "syscalls-jit: BPF load failed"
    fi
    if grep -q '\[anon_shmem:dalvik-jit-code-cache\]+0x' <<<"$out"; then
        tail -5 <<<"$out" >&2
        fail "syscalls-jit: cache region still shows bare offset (trigger not broadened?)"
    fi
    if grep -q '\[JIT\]!' <<<"$out"; then
        info "syscalls-jit OK — $(grep -c '\[JIT\]!' <<<"$out") [JIT]! frame(s) resolved"
    else
        echo "  SKIP: no JIT frames in this window (app/timing-dependent) — path not exercised"
    fi
}

# funcs --structured: uprobe with structured JSONL output (-J). Needs at least
# one probed symbol to fire; use libc.so!open as a stable target. Asserts that
# the structured record shape ("type":"call") reaches the output file.
test_funcs_structured() {
    echo "=== funcs --structured (uprobe + JSONL schema) ==="
    forcestop
    local pid; pid="$(adb shell "su -c 'pidof $PKG'" 2>/dev/null | tr -d '\r')"
    if [ -z "$pid" ]; then
        adb shell "su -c 'am start -W $(adb shell pm dump $PKG 2>/dev/null | grep -o "Activity [^ ]*" | head -1 | awk "{print \$2}")'" >/dev/null 2>&1 || true
        sleep 1
        pid="$(adb shell "su -c 'pidof $PKG'" 2>/dev/null | tr -d '\r')"
    fi
    [ -n "$pid" ] || { echo "  SKIP: could not get pid for $PKG (funcs --structured)"; return; }
    local out_file="/data/local/tmp/ares_funcs_structured_test.jsonl"
    adb shell "su -c 'rm -f $out_file'" >/dev/null 2>&1 || true
    ares "funcs -p $pid -e 'libc.so!open' -J -o $out_file" >/dev/null 2>&1 || true
    local content; content="$(adb shell "su -c 'cat $out_file 2>/dev/null'" 2>/dev/null | tr -d '\r')"
    grep -q '"type":"call"' <<<"$content" \
        || { echo "  out: $content" >&2; fail "funcs --structured: no {\"type\":\"call\"} record in $out_file"; }
    adb shell "su -c 'rm -f $out_file'" >/dev/null 2>&1 || true
    info "funcs --structured OK — structured call record found"
}

case "$WHAT" in
    lib)               test_lib ;;
    syscalls)          test_syscalls ;;
    syscalls-jit)      test_syscalls_jit ;;
    funcs-structured)  test_funcs_structured ;;
    all)               test_lib; test_syscalls; test_syscalls_jit; test_funcs_structured ;;
    *)        fail "unknown target '$WHAT' (expected: lib | syscalls | syscalls-jit | funcs-structured | all)" ;;
esac

forcestop
kill_ares
echo "PASS: ares device smoke ($WHAT) on $PKG"
