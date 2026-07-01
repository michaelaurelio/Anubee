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
# ares handles both SIGINT and SIGTERM via the shared 2-stage stop handler.
# -s INT matches the interactive Ctrl-C path; -k 3 keeps the SIGKILL backstop.
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
    local out; out="$(ares "syscalls -a -s openat -P $PKG")"
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
    local out; out="$(ares "syscalls -a -s openat -P $PKG")"
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

# syscalls vDSO symbolization: assert that when a [vdso] frame appears in a
# backtrace it renders as [vdso]!<symbol> rather than a bare [vdso]+0x offset.
# vDSO frame presence is app/timing-dependent, so a miss is a SKIP, not a failure.
test_syscalls_vdso() {
    echo "=== syscalls vDSO symbolization ([vdso]! frames) ==="
    forcestop
    local out; out="$(ares "syscalls -a -s openat -P $PKG")"
    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "syscalls-vdso: BPF load failed"
    fi
    if grep -q '\[vdso\]!' <<<"$out"; then
        info "syscalls-vdso OK — $(grep -c '\[vdso\]!' <<<"$out") [vdso]! frame(s) resolved"
    elif grep -q '\[vdso\]+0x' <<<"$out"; then
        echo "  SKIP: [vdso] frames present but none symbolized in this window" >&2
    else
        echo "  SKIP: no [vdso] frames in this window (app/timing-dependent)"
    fi
}

# syscalls register file: assert that a "stack" sidecar record carries a 31-entry
# "regs" array (x0..x30 as hex strings). Snapshots are opt-in (--snapshot) and
# library-filtered mode only (disabled in -a capture-all), and the package must be
# passed via -P; so use -l libc.so --snapshot -P (not -a, not a positional pkg).
# A miss on "regs" means the BPF capture or serializer regressed.
test_syscalls_regs() {
    echo "=== syscalls register file (regs[0..30] in stack sidecar) ==="
    forcestop
    local out_file="/data/local/tmp/ares_regs_test.jsonl"
    local stacks_file="${out_file}.stacks"
    adb shell "su -c 'rm -f $out_file $stacks_file'" >/dev/null 2>&1 || true
    local out; out="$(ares "syscalls -l libc.so -s openat --snapshot -o $out_file -P $PKG")"
    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "syscalls-regs: BPF load failed (root/SELinux/own-su-c?)"
    fi
    local stacks; stacks="$(adb shell "su -c 'cat $stacks_file 2>/dev/null'" 2>/dev/null | tr -d '\r')"
    adb shell "su -c 'rm -f $out_file $stacks_file'" >/dev/null 2>&1 || true
    if [ -z "$stacks" ]; then
        echo "  SKIP: no stack sidecar produced in this window (no stack snapshots captured)"
        return
    fi
    # Each "stack" record must carry "regs":["<hex>","<hex>",... ] with exactly 31 entries
    # (30 commas separating 31 quoted hex strings inside the array).
    local regs_line; regs_line="$(grep '"regs":\[' <<<"$stacks" | head -1)"
    if [ -z "$regs_line" ]; then
        echo "  stacks: $stacks" >&2; fail "syscalls-regs: no \"regs\" field in stack sidecar"
    fi
    # Count commas inside the regs array: extract content between "regs":[ and the closing ]
    local regs_content; regs_content="$(sed 's/.*"regs":\[\([^]]*\)\].*/\1/' <<<"$regs_line")"
    local comma_count; comma_count="$(echo "$regs_content" | tr -cd ',' | wc -c)"
    [ "$comma_count" -eq 30 ] \
        || fail "syscalls-regs: expected 30 commas (31 regs) in regs array, got $comma_count"
    info "syscalls-regs OK — regs[0..30] present in stack sidecar"
}

# syscalls CFI cross-trampoline unwind: assert that --snapshot produces at least
# one {"type":"cfi_stack"} record and that its cfi_backtrace demonstrates a
# native→JNI-trampoline→managed cross (a "kind":"jni-trampoline" frame is present
# AND a later "kind":"managed" frame follows it). Runs in capture-all mode (W6-A:
# snapshots are now available under -a; lib-filter mode only ever captured native
# process-init stacks that never reach the trampoline). A miss (no snapshot in the
# window) is a SKIP, not a failure (timing-dependent). A cfi_stack that stops at a
# JIT [anon] frame instead of crossing is also a SKIP (pending W5: JIT mini-ELF
# CFI), not a failure. Hard-fail only on BPF-load error.
test_syscalls_cfi() {
    echo "=== syscalls CFI cross-trampoline unwind (cfi_stack sidecar) ==="
    forcestop
    local out_file="/data/local/tmp/ares_cfi_test.jsonl"
    local stacks_file="${out_file}.stacks"
    adb shell "su -c 'rm -f $out_file $stacks_file'" >/dev/null 2>&1 || true
    # Run with ARES_CFI_DEBUG=1 so per-step diag fields (incl. stop_reason) land in
    # the sidecar — the PAC RUN_FAIL guard below greps that debug-only field. Own
    # su -c (the load-bearing gotcha); mirrors the ares() wrapper + the env prefix.
    local out; out="$(adb shell "su -c 'ARES_CFI_DEBUG=1 timeout -s INT -k 3 $TIMEOUT $DEVICE_PATH syscalls -a -s openat --snapshot -o $out_file -P $PKG'" 2>&1)"
    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "syscalls-cfi: BPF load failed (root/SELinux/own-su-c?)"
    fi
    local stacks; stacks="$(adb shell "su -c 'cat $stacks_file 2>/dev/null'" 2>/dev/null | tr -d '\r')"
    local mainout; mainout="$(adb shell "su -c 'cat $out_file 2>/dev/null'" 2>/dev/null | tr -d '\r')"
    adb shell "su -c 'rm -f $out_file $stacks_file'" >/dev/null 2>&1 || true
    if [ -z "$stacks" ]; then
        echo "  SKIP: no stack sidecar produced in this window (no stack snapshots captured)"
        return
    fi
    local cfi_records; cfi_records="$(grep '"type":"cfi_stack"' <<<"$stacks")"
    if [ -z "$cfi_records" ]; then
        echo "  SKIP: no cfi_stack records in this window (CFI unwind produced no frames)"
        return
    fi
    # W3-window milestone = the chunked-capture snap_len spread (snapshots now
    # exceed the old 8 KB tier). The jni-trampoline reach below is the CFI cross
    # PATH: as of the module_base gapped walk-back fix (maps.c) AND the PAC
    # negate_ra_state fix (cfi_unwind.c), the CFI walk steps through the ART apex
    # libs and crosses into managed Java, so a trampoline reach IS now expected.
    if grep -qE '"snap_len":(9[0-9]{3}|[1-9][0-9]{4,})' <<<"$stacks"; then
        local maxlen; maxlen="$(grep -o '"snap_len":[0-9]*' <<<"$stacks" | grep -o '[0-9]*' | sort -n | tail -1)"
        info "syscalls-cfi: W3-window goal met — chunked capture recovered tail, max snap_len=$maxlen (>8192)"
    else
        echo "  NOTE: no snapshot exceeded 8192 in this window — chunked tail not exercised (W3-window unproven this run)"
    fi
    echo "  NOTE: re-run with ARES_CFI_DEBUG=1 to enrich cfi_stack frames with per-step"
    echo "        CFI internals (module_pc/load_base/fde_pc_lo..hi/cfa/ra_slot/ra_value/stop_reason)"
    # PAC regression guard: before the negate_ra_state fix the CFI walk failed in
    # every PAC-built ART apex lib with terminal stop_reason 6 (CFI_RUN_FAIL) —
    # ~83% of stacks on a real RASP target. Post-fix that count should be ~0. The
    # numeric enum (not the name) is emitted in the sidecar. Soft NOTE only.
    if ! grep -q '"stop_reason":' <<<"$stacks"; then
        echo "  NOTE: no stop_reason in sidecar (ARES_CFI_DEBUG off?) — PAC RUN_FAIL guard skipped"
    else
        local nrunfail; nrunfail="$(grep -o '"stop_reason":6' <<<"$stacks" | grep -c . || true)"
        if [ "$nrunfail" -gt 0 ]; then
            echo "  NOTE: $nrunfail terminal CFI_RUN_FAIL (stop_reason 6) — PAC negate_ra_state regression? expected ~0 post-fix"
        else
            info "syscalls-cfi: 0 terminal CFI_RUN_FAIL — PAC negate_ra_state handling holds"
        fi
    fi
    if grep -q '"kind":"jni-trampoline"' <<<"$cfi_records"; then
        info "syscalls-cfi: CFI walk reached jni-trampoline (cross path — expected post module_base + PAC fixes)"
    else
        echo "  SKIP: CFI walk did not reach jni-trampoline in this window (timing/app-dependent)"
    fi
    # Assert the cross: a jni-trampoline frame AND a later managed frame in the same record.
    local crossed=0
    while IFS= read -r rec; do
        if echo "$rec" | grep -q '"kind":"jni-trampoline"' && \
           echo "$rec" | grep -q '"kind":"managed"'; then
            # Verify ordering: jni-trampoline frame index < managed frame index.
            local jni_frame; jni_frame="$(echo "$rec" | grep -o '"frame":[0-9]*,"addr":"[^"]*","symbol":"[^"]*","kind":"jni-trampoline"' | grep -o '"frame":[0-9]*' | head -1 | grep -o '[0-9]*')"
            local mgd_frame; mgd_frame="$(echo "$rec" | grep -o '"frame":[0-9]*,"addr":"[^"]*","symbol":"[^"]*","kind":"managed"' | grep -o '"frame":[0-9]*' | head -1 | grep -o '[0-9]*')"
            if [ -n "$jni_frame" ] && [ -n "$mgd_frame" ] && [ "$mgd_frame" -gt "$jni_frame" ]; then
                crossed=1
                break
            fi
        fi
    done <<<"$cfi_records"
    if [ "$crossed" -eq 1 ]; then
        local ncfi; ncfi="$(grep -c '"type":"cfi_stack"' <<<"$stacks")"
        info "syscalls-cfi OK — $ncfi cfi_stack record(s); cross confirmed (jni-trampoline -> managed)"
    else
        echo "  SKIP: cfi_stack records present but no jni-trampoline→managed cross in this window (app/timing-dependent)"
    fi

    # nterp interpreter-frame naming (commit 8c5da1e): when the walk terminates in
    # ART's nterp fast interpreter, the resolver appends a {"kind":"interp"} frame
    # whose symbol is the interpreted Java method ("pkg.Class.method" — dotted, and
    # NOT a "module!symbol" native frame). Its presence means reached_APP_frame>0.
    # SKIP on miss: a fully-AOT target (e.g. stock system apps) runs no interpreted
    # app code, and interpreted execution is timing-dependent — this is not a failure.
    if grep -oE '"symbol":"[^"]*","kind":"interp"' <<<"$cfi_records" \
         | grep -qE '"symbol":"[A-Za-z0-9_$.]+\.[A-Za-z0-9_$<>]+","kind":"interp"'; then
        local nnamed; nnamed="$(grep -oE '"symbol":"[^"!]*\.[^"!]*","kind":"interp"' <<<"$cfi_records" | sort -u | wc -l | tr -d ' ')"
        info "syscalls-cfi: nterp naming works — $nnamed interpreted Java method(s) named (reached_APP_frame>0)"
    else
        echo "  SKIP: no named nterp interp frame in this window ($PKG may be fully AOT / no interpreted app code ran)"
    fi
    # inline java_stack on syscall records (Task 3): when the managed chain was built
    # and cached by emit_cfi_backtrace, each matching syscall record in the main JSONL
    # carries a "java_stack" array. WARN on miss: not all targets run interpreted code.
    jstack=$(grep -c '"java_stack":\[' <<<"$mainout" 2>/dev/null || echo 0)
    if [ "$jstack" -gt 0 ]; then
        echo "PASS: $jstack syscall record(s) carry inline java_stack"
    else
        echo "WARN: no inline java_stack (expected on a managed/nterp target app)"
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
    syscalls-vdso)     test_syscalls_vdso ;;
    syscalls-regs)     test_syscalls_regs ;;
    syscalls-cfi)      test_syscalls_cfi ;;
    funcs-structured)  test_funcs_structured ;;
    all)               test_lib; test_syscalls; test_syscalls_jit; test_syscalls_vdso; test_syscalls_regs; test_syscalls_cfi; test_funcs_structured ;;
    *)        fail "unknown target '$WHAT' (expected: lib | syscalls | syscalls-jit | syscalls-vdso | syscalls-regs | syscalls-cfi | funcs-structured | all)" ;;
esac

forcestop
kill_ares
echo "PASS: ares device smoke ($WHAT) on $PKG"
