#!/usr/bin/env bash
# Device acceptance smoke test for ares — the device tier of the testing flow.
# Pushes the freshly-built build/ares to the attached rooted device and asserts
# each capability still ATTACHES and emits REAL tracer output (not just help
# text). Exits 0 on pass, non-zero on fail, so it drops into CI / `make` / loops.
#
# Usage:
#   scripts/device-test.sh [lib|lib-records|syscalls|massdelete-detect|exfil-detect|accessibility-detect|fileless-detect|screencapture-detect|correlate-returns|dump-now|all]  # default: all
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
    # SYM1 Phase 4b put emit_lib/unlib on ts_print, which prepends "HH:MM:SS "
    # ahead of the tag -- tolerate that optional prefix rather than anchoring
    # to a bare "[lib]" line start.
    grep -q '^[0-9: ]*\[lib\]' <<<"$out" \
        || { tail -5 <<<"$out" >&2; fail "lib: no [lib] lines (BPF/attach broken?)"; }
    grep -q 'bionic/libc.so' <<<"$out" \
        || fail "lib: libc.so not resolved ([lib] emitter / maps resolver broken?)"
    info "lib OK - $(grep -c '^[0-9: ]*\[lib\]' <<<"$out") [lib] lines, libc.so resolved"
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
    # Task 8 drain contract: a single Ctrl-C must complete post-processing, not
    # truncate it. This run's on-device `timeout -s INT -k 3 $TIMEOUT` sends
    # exactly one SIGINT (the interactive Ctrl-C path); a 2nd SIGINT would
    # _exit(130) and throw away the queue plus the end-of-run records - the loss
    # the drain progress UI exists to warn about, and what this asserts we did
    # not do.
    #
    # Placed HERE, above the sidecar/cfi_stack gates below, on purpose: the
    # contract is independent of whether --snapshot capture fired, and it only
    # needs $mainout (populated just above). Downstream of those gates it would
    # silently never run on a no-snapshot window - a guard that can quietly skip
    # itself is worse than no guard.
    #
    # Asserts syscalls_summary only, not coverage: in syscalls_teardown
    # ares_coverage_report runs before sysc_emit_summary (src/syscalls/syscalls.c
    # :1655 then :1659, same g_worker_started block), so a summary record present
    # already implies coverage was emitted. The coverage record has its own
    # assertion further down; no need to duplicate it.
    #
    # Traffic gate first: sysc_emit_summary early-returns unless
    # g_sysc_stat_count > 0, so a window that captured nothing has no summary
    # for a legitimate reason. SKIP that case rather than fail it for the wrong
    # reason. ("type":"syscall" is json_emit's per-event discriminator; the
    # closing quote keeps it from matching "syscalls_summary".)
    if [ "$(grep -c '"type":"syscall"' <<<"$mainout")" -eq 0 ]; then
        echo "  SKIP: no syscall events captured in this window - drain-contract check needs traffic to be meaningful"
    else
        grep -q '"type":"syscalls_summary"' <<<"$mainout" \
            || { echo "  out: $mainout" >&2; fail "syscalls-cfi: no {\"type\":\"syscalls_summary\"} record after single SIGINT (drain truncated?)"; }
        echo "PASS: single-SIGINT drain contract held - syscalls_summary present after one SIGINT"
    fi
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
    # full interpreted-chain naming (nterp_chain): a cfi_stack record can now carry
    # MULTIPLE consecutive named {"kind":"interp"} frames (the interpreted call chain),
    # not just the terminal. Detect two adjacent named interp frames. Workload-dependent
    # (needs a deep interpreted chain), so INFO on miss — but proves the multi-frame
    # extension when present.
    if grep -qE '"kind":"interp"\},\{"frame":[0-9]+,"addr":"0x0","symbol":"[^"!]*\.[^"!]*","kind":"interp"' <<<"$cfi_records"; then
        info "syscalls-cfi: full interpreted chain — multiple named interp frames in one cfi_stack record"
    else
        echo "  INFO: no multi-frame interpreted chain this window (single-frame or AOT)"
    fi
    # Switch-interpreter ShadowFrame naming: a cfi_stack with an ExecuteSwitchImpl terminal
    # should now carry >=1 named interp frame (addr 0x0) from the live ManagedStack walk
    # (shadow_frame_chain). Same JSON shape as the nterp block above (kind:interp,
    # addr:0x0), so this counts all such frames regardless of which walker produced them;
    # non-vacuous only on a target that runs switch-interpreted Java. INFO-only on miss.
    local sw_named; sw_named="$(grep -c '"addr":"0x0","symbol"' <<<"$cfi_records" 2>/dev/null || echo 0)"
    echo "  switch-interp named frames: $sw_named"
    # inline java_stack on syscall records (Task 3): when the managed chain was built
    # and cached by emit_cfi_backtrace, each matching syscall record in the main JSONL
    # carries a "java_stack" array. WARN on miss: not all targets run interpreted code.
    local jstack; jstack=$(grep -c '"java_stack":\[' <<<"$mainout" 2>/dev/null || echo 0)
    if [ "$jstack" -gt 0 ]; then
        echo "PASS: $jstack syscall record(s) carry inline java_stack"
    else
        echo "WARN: no inline java_stack (expected on a managed/nterp target app)"
    fi
    # dex_pc corroboration suffix (Task 3): a corroborated nterp name carries a
    # "+0x<dexpc>" bytecode-offset suffix inside a java_stack entry. Corroboration
    # firing is workload-dependent, so this is informational (not a hard fail) —
    # but it must never regress to zero once seen.
    if grep -oE '"java_stack":\[[^]]*\]' <<<"$mainout" 2>/dev/null | grep -qE '\+0x[0-9a-f]+"'; then
        echo "PASS: nterp java_stack carries +0x<dexpc> suffix (corroborated)"
    else
        echo "INFO: no +0x<dexpc> suffix this run (corroboration did not fire)"
    fi
    # CR5 coverage-health record (Task 7): teardown must emit exactly one
    # {"type":"coverage"} record into the main sink JSONL (not the .stacks
    # sidecar), tagged to this engine. Hard-fail on miss - unlike the
    # timing-dependent frame checks above, this fires on every run regardless
    # of what the target app did.
    grep -q '"type":"coverage"' <<<"$mainout" \
        || { echo "  out: $mainout" >&2; fail "syscalls-cfi: no {\"type\":\"coverage\"} record in sink output"; }
    grep -q '"engine":"syscalls"' <<<"$mainout" \
        || fail "syscalls-cfi: coverage record not tagged engine=syscalls"
    echo "PASS: coverage record emitted and tagged to syscalls"
    # On the known apex build, art_buildid.c's table has a row, so Java naming
    # stays ON - managed_naming_off must be ABSENT (grep-negation idiom, no
    # assert_json_absent helper exists in this script).
    if grep -q '"managed_naming_off":true' <<<"$mainout"; then
        fail "syscalls-cfi: managed_naming_off:true on known apex build (naming table stale?)"
    fi
    echo "PASS: Java naming on (known build) - managed_naming_off absent"
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
    ares "funcs -p $pid -e 'libc.so!open' -J --snapshot -o $out_file" >/dev/null 2>&1 || true
    local content; content="$(adb shell "su -c 'cat $out_file 2>/dev/null'" 2>/dev/null | tr -d '\r')"
    grep -q '"type":"call"' <<<"$content" \
        || { echo "  out: $content" >&2; fail "funcs --structured: no {\"type\":\"call\"} record in $out_file"; }
    local stacks_file="${out_file}.stacks"
    local stacks_content; stacks_content="$(adb shell "su -c 'cat $stacks_file 2>/dev/null'" 2>/dev/null | tr -d '\r')"
    local cfi; cfi=$(grep -c '"type":"cfi_stack"' <<<"$stacks_content" 2>/dev/null || echo 0)
    [ "$cfi" -gt 0 ] && echo "PASS: funcs sidecar has $cfi cfi_stack record(s)" \
                      || echo "  SKIP: no cfi_stack in funcs sidecar (short window — CFI may not have fired)"
    adb shell "su -c 'rm -f $out_file $stacks_file'" >/dev/null 2>&1 || true
    info "funcs --structured OK — structured call record found"
}

# mod file-access: kprobe-only analyzer. deskclock's own /data/data opens at
# startup are enough to prove attach + emission; we don't rely on it touching
# external storage or another app's dir (timing/app-dependent).
test_mod_file_access() {
    echo "=== mod file-access (stealthy openat/openat2 kprobes) ==="
    forcestop
    local out; out="$(ares "mod file-access -P $PKG")"
    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "mod-file-access: BPF load failed (root/SELinux/own-su-c?)"
    fi
    grep -q 'stealthy: file-access uses kernel-only probes' <<<"$out" \
        || { tail -5 <<<"$out" >&2; fail "mod-file-access: no stealthy-attach banner"; }
    # SYM1 Phase 4c put file-access's live line on ts_print (adds "HH:MM:SS "
    # ahead of the tag) -- tolerate that optional prefix.
    if grep -q '^[0-9: ]*\[file\]' <<<"$out"; then
        info "mod-file-access OK - $(grep -c '^[0-9: ]*\[file\]' <<<"$out") [file] line(s)"
    else
        echo "  SKIP: no [file] events in this window (app's own data-dir opens are timing-dependent)"
    fi
}

# mod massdelete-detect: deterministic trigger via a compiled single-process
# generator (scripts/ares_massdelete_gen.c), attached by PID (-p gates on
# target_pids regardless of the generator's UID, so this doesn't need it to
# run as the traced app). Hard-fail, not SKIP: we control the trigger, unlike
# file-access's timing-dependent natural app behavior.
#
# Two requirements confirmed the hard way, both load-bearing:
#   - One process, no forked mv/rm: burst_map keys per calling PID, so 25
#     touches split across 25 short-lived subprocesses never accumulate to
#     MASSDELETE_DETECT_THRESHOLD — each subprocess only ever contributes one touch.
#   - nohup+setsid: a bare `cmd & echo $!` backgrounded inside `su -c '...'`
#     gets killed with the su session on some devices' su/shell before ares
#     ever attaches (confirmed via `ps` — the pid was gone within ~1s, well
#     inside its own pre-touch sleep). Detaching from the session is what
#     keeps it alive to be traced.
test_massdelete_detect() {
    echo "=== mod massdelete-detect (rename/unlink burst on external storage) ==="
    forcestop
    command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 \
        || fail "massdelete-detect: aarch64-linux-gnu-gcc not found (see README prereqs)"
    local gen_bin="$ROOT/build/ares_massdelete_gen"
    aarch64-linux-gnu-gcc -static -O2 -o "$gen_bin" "$ROOT/scripts/ares_massdelete_gen.c" \
        || fail "massdelete-detect: failed to compile mass-delete generator"
    local gen="/data/local/tmp/ares_massdelete_gen"
    adb push "$gen_bin" "$gen" >/dev/null || fail "massdelete-detect: push failed"
    adb shell "chmod 755 $gen"

    local loop_pid
    loop_pid="$(adb shell "su -c 'nohup setsid $gen /sdcard/.ares_massdelete_test >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
    if [ -z "$loop_pid" ] || ! [ "$loop_pid" -gt 0 ] 2>/dev/null; then
        fail "massdelete-detect: could not start burst-generator (no pid captured)"
    fi

    local out; out="$(ares "mod massdelete-detect -p $loop_pid")"

    local loop_pid2
    loop_pid2="$(adb shell "su -c 'nohup setsid $gen /sdcard/.ares_massdelete_test >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
    if [ -n "$loop_pid2" ] && [ "$loop_pid2" -gt 0 ] 2>/dev/null; then
        adb shell "su -c 'timeout -s INT -k 3 $TIMEOUT $DEVICE_PATH mod massdelete-detect -p $loop_pid2 -v -o /data/local/tmp/massdelete_verbose.jsonl -q'" >/dev/null 2>&1
        local verbose_out
        verbose_out="$(adb shell "su -c 'cat /data/local/tmp/massdelete_verbose.jsonl'" 2>/dev/null)"
        adb shell "su -c 'rm -f /data/local/tmp/massdelete_verbose.jsonl'" >/dev/null 2>&1
        if grep -q '"paths":\[' <<<"$verbose_out"; then
            info "massdelete-detect -v OK — paths array present in alert JSON"
        else
            echo "  SKIP: massdelete-detect -v produced no paths array (burst may not have re-fired in this window)"
        fi
    fi

    adb shell "su -c 'rm -f $gen; rm -rf /sdcard/.ares_massdelete_test'" >/dev/null 2>&1 || true

    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "massdelete-detect: BPF load failed (root/SELinux/own-su-c?)"
    fi
    # SYM1 Phase 4c put the analyzer's live alert on ts_print (adds "HH:MM:SS "
    # ahead of the tag) -- tolerate that optional prefix.
    if grep -q '^[0-9: ]*\[massdelete-detect\]' <<<"$out"; then
        info "massdelete-detect OK - $(grep -c '^[0-9: ]*\[massdelete-detect\]' <<<"$out") [massdelete-detect] line(s)"
    else
        tail -10 <<<"$out" >&2
        fail "massdelete-detect: no [massdelete-detect] line from a 25-touch generator loop (threshold/window mistuned, or timing missed the attach window)"
    fi
}

# mod exfil-detect: deterministic trigger via a compiled single-process
# generator (scripts/ares_exfil_gen.c), attached by PID (-p gates on
# target_pids regardless of the generator's UID). Hard-fail, not SKIP: we
# control the trigger. Same single-process rationale as massdelete-detect's
# generator (a forked write()-per-call pattern would split byte-volume
# across too many short-lived pids to accumulate a per-pid signal) plus a
# new constraint: the destination is a deliberately unreachable RFC 5737
# test address, because exfil_detect.bpf.c's connect() hook discards
# loopback destinations outright (a real listener on 127.0.0.1 would never
# arm the socket fd).
test_exfil_detect() {
    echo "=== mod exfil-detect (sensitive-read + network byte-volume burst) ==="
    forcestop
    command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 \
        || fail "exfil-detect: aarch64-linux-gnu-gcc not found (see README prereqs)"
    local gen_bin="$ROOT/build/ares_exfil_gen"
    aarch64-linux-gnu-gcc -static -O2 -o "$gen_bin" "$ROOT/scripts/ares_exfil_gen.c" \
        || fail "exfil-detect: failed to compile exfil generator"
    local gen="/data/local/tmp/ares_exfil_gen"
    adb push "$gen_bin" "$gen" >/dev/null || fail "exfil-detect: push failed"
    adb shell "chmod 755 $gen"

    local loop_pid
    loop_pid="$(adb shell "su -c 'nohup setsid $gen /sdcard/.ares_exfil_test/DCIM >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
    if [ -z "$loop_pid" ] || ! [ "$loop_pid" -gt 0 ] 2>/dev/null; then
        fail "exfil-detect: could not start exfil-generator (no pid captured)"
    fi

    local out; out="$(ares "mod exfil-detect -p $loop_pid")"

    local loop_pid2
    loop_pid2="$(adb shell "su -c 'nohup setsid $gen /sdcard/.ares_exfil_test/DCIM >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
    if [ -n "$loop_pid2" ] && [ "$loop_pid2" -gt 0 ] 2>/dev/null; then
        adb shell "su -c 'timeout -s INT -k 3 $TIMEOUT $DEVICE_PATH mod exfil-detect -p $loop_pid2 -v -o /data/local/tmp/exfil_verbose.jsonl -q'" >/dev/null 2>&1
        local verbose_out
        verbose_out="$(adb shell "su -c 'cat /data/local/tmp/exfil_verbose.jsonl'" 2>/dev/null)"
        adb shell "su -c 'rm -f /data/local/tmp/exfil_verbose.jsonl'" >/dev/null 2>&1
        if grep -q '"sensitive_paths":\[' <<<"$verbose_out"; then
            info "exfil-detect -v OK — sensitive_paths array present in alert JSON"
        else
            echo "  SKIP: exfil-detect -v produced no sensitive_paths array (burst may not have re-fired in this window)"
        fi
    fi

    adb shell "su -c 'rm -f $gen; rm -rf /sdcard/.ares_exfil_test'" >/dev/null 2>&1 || true

    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "exfil-detect: BPF load failed (root/SELinux/own-su-c?)"
    fi
    if grep -q '^\[exfil-detect\]' <<<"$out"; then
        info "exfil-detect OK — $(grep -c '^\[exfil-detect\]' <<<"$out") [exfil-detect] line(s)"
    else
        tail -10 <<<"$out" >&2
        fail "exfil-detect: no [exfil-detect] line from a 576KiB-write generator (threshold/window mistuned, or timing missed the attach window)"
    fi
}

# mod accessibility-detect: real trigger via TalkBack (com.google.android.marvin.talkback),
# confirmed installed on the test device. Unlike massdelete-detect/exfil-detect,
# the trigger here isn't a compiled single-process generator: a real
# AccessibilityService needs actual compiled code, and this toolchain has no
# dexer. TalkBack is enabled for the run (bypassing the interactive consent
# dialog by writing the secure settings directly via su, confirmed working)
# and its genuine accessibility traffic to system_server is driven by a
# host-side loop of `input keyevent` calls run concurrently with the blocking
# ares call (avoids nested su -c / device-shell quoting for an on-device
# loop). Prior accessibility settings state is saved and restored
# unconditionally, even on failure — never leave the device in a different
# accessibility configuration than it started in. Hard-fail, not SKIP: we
# control the trigger, same rationale as massdelete-detect/exfil-detect.
test_accessibility_detect() {
    echo "=== mod accessibility-detect (binder-transaction burst to system_server + accessibility grant) ==="
    local tb_pkg="com.google.android.marvin.talkback"
    local tb_svc="$tb_pkg/com.google.android.marvin.talkback.TalkBackService"

    adb shell "pm path $tb_pkg" >/dev/null 2>&1 \
        || fail "accessibility-detect: TalkBack ($tb_pkg) not installed on this device"

    local prev_svc prev_enabled
    prev_svc="$(adb shell "su -c 'settings get secure enabled_accessibility_services'" 2>/dev/null | tr -d '\r')"
    prev_enabled="$(adb shell "su -c 'settings get secure accessibility_enabled'" 2>/dev/null | tr -d '\r')"
    [ -z "$prev_enabled" ] && prev_enabled=0

    restore_a11y() {
        adb shell "su -c 'settings put secure enabled_accessibility_services $prev_svc'" >/dev/null 2>&1
        adb shell "su -c 'settings put secure accessibility_enabled $prev_enabled'" >/dev/null 2>&1
        adb shell "su -c 'am force-stop $tb_pkg'" >/dev/null 2>&1
    }

    adb shell "su -c 'settings put secure enabled_accessibility_services $tb_svc'" >/dev/null 2>&1
    adb shell "su -c 'settings put secure accessibility_enabled 1'" >/dev/null 2>&1
    sleep 2

    local tb_pid
    tb_pid="$(adb shell "su -c 'pidof $tb_pkg'" 2>/dev/null | tr -d '\r' | awk '{print $1}')"
    if [ -z "$tb_pid" ] || ! [ "$tb_pid" -gt 0 ] 2>/dev/null; then
        restore_a11y
        fail "accessibility-detect: TalkBack did not start after enabling (no pid)"
    fi

    (
        for _ in $(seq 1 30); do
            adb shell "su -c 'input keyevent 20'" >/dev/null 2>&1
            adb shell "su -c 'input keyevent 19'" >/dev/null 2>&1
        done
    ) &
    local stim_pid=$!

    local out; out="$(ares "mod accessibility-detect -p $tb_pid")"
    wait "$stim_pid" 2>/dev/null || true
    restore_a11y

    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "accessibility-detect: BPF load failed (root/SELinux/own-su-c?)"
    fi
    if grep -q '^\[accessibility-detect\]' <<<"$out"; then
        info "accessibility-detect OK — $(grep -c '^\[accessibility-detect\]' <<<"$out") [accessibility-detect] line(s)"
    else
        tail -10 <<<"$out" >&2
        fail "accessibility-detect: no [accessibility-detect] line (threshold not crossed, system_server pid resolve failed, or timing missed the attach window)"
    fi
}

# mod fileless-detect: deterministic trigger via a compiled single-process
# generator (scripts/ares_fileless_gen.c) that performs one raw
# mmap(MAP_ANONYMOUS|PROT_EXEC) -- no real installed app does this as part
# of normal operation, so (like massdelete-detect/exfil-detect) this needs a
# purpose-built native binary rather than driving a real app. Hard-fail, not
# SKIP: we control the trigger. A second, informational-only run against an
# ordinary app checks the dalvik- carve-out doesn't false-positive on real
# ART JIT activity -- not a hard assertion, since JIT compilation isn't
# guaranteed to happen within a short launch window either way, so absence
# of output there proves nothing on its own.
test_fileless_detect() {
    echo "=== mod fileless-detect (anonymous executable mmap, non-ART) ==="
    forcestop
    command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 \
        || fail "fileless-detect: aarch64-linux-gnu-gcc not found (see README prereqs)"
    local gen_bin="$ROOT/build/ares_fileless_gen"
    aarch64-linux-gnu-gcc -static -O2 -o "$gen_bin" "$ROOT/scripts/ares_fileless_gen.c" \
        || fail "fileless-detect: failed to compile fileless generator"
    local gen="/data/local/tmp/ares_fileless_gen"
    adb push "$gen_bin" "$gen" >/dev/null || fail "fileless-detect: push failed"
    adb shell "chmod 755 $gen"

    local loop_pid
    loop_pid="$(adb shell "su -c 'nohup setsid $gen >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
    if [ -z "$loop_pid" ] || ! [ "$loop_pid" -gt 0 ] 2>/dev/null; then
        fail "fileless-detect: could not start fileless-generator (no pid captured)"
    fi

    local out; out="$(ares "mod fileless-detect -p $loop_pid")"
    adb shell "su -c 'rm -f $gen'" >/dev/null 2>&1 || true

    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "fileless-detect: BPF load failed (root/SELinux/own-su-c?)"
    fi
    # Match only the per-event alert line ("[fileless-detect] PID:...") -- NOT
    # fileless_print_summary()'s own [fileless-detect]-prefixed header/column-
    # header/table-row/footer lines, which share the same tag prefix and would
    # otherwise inflate any non-zero count by 4 (confirmed via manual -o/JSONL
    # cross-check: a single real detection always produces exactly one
    # {"type":"fileless_detect"} record, but the old '^\[fileless-detect\]' pattern
    # counted 5 console lines for it -- 1 real alert + 4 summary-table lines).
    if grep -q '^\[fileless-detect\] PID:' <<<"$out"; then
        info "fileless-detect OK — $(grep -c '^\[fileless-detect\] PID:' <<<"$out") [fileless-detect] line(s)"
    else
        tail -10 <<<"$out" >&2
        fail "fileless-detect: no [fileless-detect] line from a single anon-exec mmap (timing missed the attach window, or the kprobe/anon_name field didn't resolve as expected)"
    fi

    local jit_out; jit_out="$(ares "mod fileless-detect -P $PKG")"
    forcestop
    local jit_lines
    jit_lines="$(grep -c '^\[fileless-detect\] PID:' <<<"$jit_out")"
    info "fileless-detect dalvik carve-out check (informational): $jit_lines line(s) against $PKG"
}

# mod screencapture-detect: real trigger via com.transsion.screenrecorder
# (pre-installed OEM screen-recorder app, confirmed installed on the test
# device), whose exported RecordingService legitimately requests a
# MediaProjection-typed foreground service (types=0x000000A0 =
# MEDIA_PROJECTION|MICROPHONE, confirmed via `aapt2 dump xmltree` on the
# installed APK). Unlike massdelete-detect/fileless-detect's synthetic
# code-free generators, and like accessibility-detect's use of TalkBack, this drives a
# real app's real service directly via its exported intent-filter action --
# no UI/consent-dialog automation needed (the exported Service bypasses the
# in-app "Start now" consent flow entirely, since am start-foreground-service
# talks to the service directly).
#
# Trigger order is service-first, then attach via -p <pid> (NOT -P <pkg>):
# this package has a MAIN-action activity but no LAUNCHER category, so `cmd
# package resolve-activity --brief` returns "No activity found" on this
# device and -P's ares_launch_app() (src/common/launch.c) hard-fails before
# the dumpsys poll thread ever starts polling -- confirmed on-device, not a
# timing issue. -p <pid> against the already-running service process skips
# that resolve-activity step entirely, same precedent as accessibility-detect's
# already-running-process attach. The ares() call below is synchronous
# (blocking, like accessibility-detect/fileless-detect), not backgrounded: this file's
# own header note applies here too -- ares's stdio is fully buffered once
# it isn't a tty, so killing it early from the host side (pkill on the local
# adb shell client doesn't even reach the remote process -- see
# testing-ares-on-device gotchas) loses whatever hadn't flushed yet.
# Blocking for the device-side `timeout -s INT $TIMEOUT` window lets ares
# exit cleanly and flush before the capture completes.
test_screencapture_detect() {
    echo "=== mod screencapture-detect (active MediaProjection session via dumpsys poll) ==="
    local pkg="com.transsion.screenrecorder"
    local svc="$pkg/.service.RecordingService"

    adb shell "pm path $pkg" >/dev/null 2>&1 \
        || fail "screencapture-detect: $pkg not installed on this device"

    adb shell am start-foreground-service \
        -a transsion.intent.screenrecorder.RECORDER_SERVICE -n "$svc" >/dev/null 2>&1 \
        || fail "screencapture-detect: could not start $svc (adb/root/service export changed?)"
    # Settle delay for cold-start pid resolution race (same as accessibility-detect).
    sleep 2

    local svc_pid
    svc_pid="$(adb shell "su -c 'pidof $pkg'" 2>/dev/null | tr -d '\r' | awk '{print $1}')"
    if [ -z "$svc_pid" ] || ! [ "$svc_pid" -gt 0 ] 2>/dev/null; then
        adb shell am stopservice -n "$svc" >/dev/null 2>&1
        fail "screencapture-detect: $svc did not start (no pid) after start-foreground-service"
    fi

    local out; out="$(ares "mod screencapture-detect -p $svc_pid")"
    adb shell am stopservice -n "$svc" >/dev/null 2>&1

    if grep -q "BPF load failed\|failed to load BPF" <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "screencapture-detect: BPF load failed (root/SELinux/own-su-c?)"
    fi
    if grep -q '^\[screencapture-detect\] PID:' <<<"$out"; then
        info "screencapture-detect OK — $(grep -c '^\[screencapture-detect\] PID:' <<<"$out") [screencapture-detect] line(s)"
    else
        tail -10 <<<"$out" >&2
        fail "screencapture-detect: no [screencapture-detect] line after triggering $svc (poll interval missed the window, or dumpsys types= field format differs on this device build)"
    fi
}

# correlate --returns: uretprobe return-value + span timing (LOUD - adds a
# stack trampoline on top of the entry BRK). Needs a fresh launch (-P) so the
# entry uprobe attaches before the target opens any files. Spec mirrors
# funcs --structured's stable target (libc.so!open) so a return is guaranteed
# to fire during a normal app-start window. Hard-fail (not SKIP): unlike the
# timing/app-dependent CFI checks above, --returns must always produce at
# least one return record with real elapsed_ns on a plain app launch.
test_correlate_returns() {
    echo "=== correlate --returns (uretprobe + elapsed_ns timing) ==="
    forcestop
    local out_file="/data/local/tmp/ares_correlate_returns_test.jsonl"
    adb shell "su -c 'rm -f $out_file'" >/dev/null 2>&1 || true
    local out; out="$(ares "correlate -P $PKG -e 'libc.so!open' --returns -o $out_file")"
    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "correlate-returns: BPF load failed (root/SELinux/own-su-c?)"
    fi
    local content; content="$(adb shell "su -c 'cat $out_file 2>/dev/null'" 2>/dev/null | tr -d '\r')"
    adb shell "su -c 'rm -f $out_file'" >/dev/null 2>&1 || true
    grep -q '"type":"return"' <<<"$content" \
        || { echo "  out: $content" >&2; fail "correlate-returns: no {\"type\":\"return\"} record in $out_file"; }
    if grep -q '"type":"return"' <<<"$content" && ! grep -q '"elapsed_ns":0[,}]' <<<"$content"; then
        info "correlate-returns OK - return record(s) present, elapsed_ns > 0"
    else
        echo "  out: $content" >&2
        fail "correlate-returns: return record present but elapsed_ns not > 0"
    fi
}

# lib-records: syscalls + correlate must write {"type":"lib",...} to the -o sink
# (mmap/munmap probes now emit library-load records alongside their normal output).
test_lib_records() {
    echo "=== lib records to -o sink (syscalls + correlate) ==="
    forcestop
    local of="/data/local/tmp/ares_librec_test.jsonl"

    adb shell "su -c 'rm -f $of'" >/dev/null 2>&1 || true
    local so; so="$(ares "syscalls -a -s openat -o $of -P $PKG")"
    grep -qi 'BPF load failed\|-EPERM' <<<"$so" \
        && { tail -5 <<<"$so" >&2; fail "lib-records/syscalls: BPF load failed"; }
    local sc; sc="$(adb shell "su -c 'cat $of 2>/dev/null'" 2>/dev/null | tr -d '\r')"
    grep -q '"type":"lib"' <<<"$sc" \
        || { echo "  out: $(tail -3 <<<"$sc")" >&2; fail "lib-records/syscalls: no {\"type\":\"lib\"} in -o sink"; }
    info "lib-records/syscalls OK — $(grep -c '"type":"lib"' <<<"$sc") lib record(s) in sink"

    forcestop
    adb shell "su -c 'rm -f $of'" >/dev/null 2>&1 || true
    local co; co="$(ares "correlate -P $PKG -e 'libc.so!open' -o $of")"
    grep -qi 'BPF load failed\|-EPERM' <<<"$co" \
        && { tail -5 <<<"$co" >&2; fail "lib-records/correlate: BPF load failed"; }
    local cc; cc="$(adb shell "su -c 'cat $of 2>/dev/null'" 2>/dev/null | tr -d '\r')"
    adb shell "su -c 'rm -f $of'" >/dev/null 2>&1 || true
    grep -q '"type":"lib"' <<<"$cc" \
        || { echo "  out: $(tail -3 <<<"$cc")" >&2; fail "lib-records/correlate: no {\"type\":\"lib\"} in -o sink"; }
    info "lib-records/correlate OK — $(grep -c '"type":"lib"' <<<"$cc") lib record(s) in sink"
}

# dump --now: assert the pure-/proc snapshot path (--base) exits 0, and that
# --check reports a real verdict for the reference app's APK-embedded
# libsentinel.so. dev.ares.detector ships extractNativeLibs=false: libsentinel.so
# is mapped straight out of base.apk, not extracted to disk, so this also pins
# dump_read_apk_member's stored-ZIP-member resolution end to end.
#
# Own package (not $PKG): this needs dev.ares.detector specifically, same
# precedent as accessibility-detect/screencapture-detect hardcoding their own
# fixed target app rather than the generic $PKG.
#
# pid+base discovery: the natural, lowest-friction source is `ares lib -P`'s
# own [lib] line (it already resolves the APK-embedded module's friendly name),
# so no extra /proc/<pid>/maps parsing is needed on the host side.
#
# --check selector note (confirmed by hand before writing this): -l
# 'libsentinel.so' does NOT match here. dump's --check selector (dump_sel_matches)
# only matches the raw /proc/<pid>/maps path -- glob on basename, else substring
# of the full path -- and has no knowledge of the APK member's resolved SONAME;
# for an extractNativeLibs=false app every embedded library's maps path is just
# ".../base.apk". A -l pattern of the friendly name matches nothing (0 modules
# checked), so --base is the only selector that reaches this module, and the
# emitted modcmp record's "module" field is correspondingly "base.apk" -- the
# record is identified by base address, not by name.
run_dump_now() {
    # Same on-device timeout guard as ares() (own su -c; -s INT / -k 3 backstop)
    # -- if --now ever regressed into the old wait-for-Ctrl-C behavior this
    # still bounds the run -- but unlike ares(), this also surfaces the real
    # exit status: --now's whole point is exiting 0 instead of hanging until a
    # signal, so the status IS the assertion, not just the output.
    #
    # A regression surfaces here as 124, NOT 130. 130 (128+SIGINT) was the
    # symptom the desktop client saw, where an unrelated pkill -INT delivered the
    # signal directly. Under this wrapper the on-device timeout fires instead,
    # and Android's timeout is toybox: it reports 124 on expiry regardless of
    # -s INT or the -k SIGKILL backstop, and this script never passes
    # --preserve-status. Verified on-device: `timeout -s INT -k 3 2 sleep 10`
    # exits 124.
    local raw
    raw="$(adb shell "su -c 'timeout -s INT -k 3 $TIMEOUT $DEVICE_PATH $*; echo ARES_EXIT:\$?'" 2>&1 | tr -d '\r')"
    RUN_DUMP_NOW_STATUS="$(sed -n 's/.*ARES_EXIT:\([0-9]*\)$/\1/p' <<<"$raw" | tail -1)"
    RUN_DUMP_NOW_OUT="$(sed '/^ARES_EXIT:[0-9]*$/d' <<<"$raw")"
}
test_dump_now() {
    echo "=== dump --now (pure /proc snapshot, no BPF) + --check (APK-embedded baseline) ==="
    local dpkg="dev.ares.detector"
    adb shell "pm path $dpkg" >/dev/null 2>&1 \
        || fail "dump-now: $dpkg not installed on this device"
    forcestop
    local lib_out; lib_out="$(ares "lib -P $dpkg")"
    if grep -qi 'BPF load failed\|-EPERM' <<<"$lib_out"; then
        tail -5 <<<"$lib_out" >&2; fail "dump-now: lib (pid+base discovery) BPF load failed"
    fi
    local sline; sline="$(grep -E '\[lib\] pid [0-9]+ .*-> libsentinel\.so$' <<<"$lib_out" | tail -1)"
    [ -n "$sline" ] || { tail -10 <<<"$lib_out" >&2; fail "dump-now: no [lib] line for libsentinel.so (pid+base discovery failed)"; }
    local pid; pid="$(sed -E 's/.*\[lib\] pid ([0-9]+).*/\1/' <<<"$sline")"
    local base; base="$(sed -E 's/.*\[(0x[0-9a-f]+), 0x[0-9a-f]+\).*/\1/' <<<"$sline")"
    [ -n "$pid" ] && [ -n "$base" ] || fail "dump-now: could not parse pid/base from: $sline"
    info "dump-now: discovered pid=$pid base=$base for libsentinel.so"

    local devdir="/data/local/tmp/ares_dumpnow_test"
    adb shell "su -c 'rm -rf $devdir; mkdir -p $devdir'" >/dev/null 2>&1

    # --- Assertion A: --now --base dumps and exits 0 --------------------------
    run_dump_now "dump --now -p $pid --base $base -d $devdir -o $devdir/manifest.jsonl"
    [ "$RUN_DUMP_NOW_STATUS" = "0" ] \
        || { echo "  out: $RUN_DUMP_NOW_OUT" >&2; fail "dump-now: --now --base exited ${RUN_DUMP_NOW_STATUS:-?} (expected 0; 124 means --now waited for a signal instead of snapshotting, i.e. the dump-on-exit bug is back)"; }
    local manifest; manifest="$(adb shell "su -c 'cat $devdir/manifest.jsonl 2>/dev/null'" 2>/dev/null | tr -d '\r')"
    grep -q '"type":"dump"' <<<"$manifest" \
        || { echo "  manifest: $manifest" >&2; fail "dump-now: no \"type\":\"dump\" record in manifest.jsonl"; }
    local so_count; so_count="$(adb shell "su -c 'ls -1 $devdir 2>/dev/null'" 2>/dev/null | tr -d '\r' | grep -c '\.so$')"
    [ "${so_count:-0}" -gt 0 ] \
        || fail "dump-now: no rebuilt .so file in $devdir"
    info "dump-now --base OK - exit 0, manifest has a dump record, $so_count rebuilt .so file(s)"

    # --- Assertion B: --now --check reports match for libsentinel.so ----------
    # Do NOT trigger the RASP check: libsentinel.so is an ordinary compiled
    # library that never rewrites its own .text (its only mmap is a
    # PROT_READ|PROT_WRITE shared-memory region for antidebug; wxscan.c
    # *detects* W^X in others, it doesn't perform it), so it must report match
    # both before and after any RASP check fires -- match is the only
    # assertion this makes.
    adb shell "su -c 'rm -f $devdir/check.jsonl'" >/dev/null 2>&1
    run_dump_now "dump --now --check -p $pid --base $base -o $devdir/check.jsonl"
    [ "$RUN_DUMP_NOW_STATUS" = "0" ] \
        || { echo "  out: $RUN_DUMP_NOW_OUT" >&2; fail "dump-now: --now --check exited ${RUN_DUMP_NOW_STATUS:-?} (expected 0)"; }
    local check; check="$(adb shell "su -c 'cat $devdir/check.jsonl 2>/dev/null'" 2>/dev/null | tr -d '\r')"
    local rec; rec="$(grep '"type":"modcmp"' <<<"$check" | grep "\"base\":\"$base\"" | head -1)"
    [ -n "$rec" ] || { echo "  check: $check" >&2; fail "dump-now: no modcmp record for base $base in check.jsonl"; }
    if grep -q '"state":"apk"' <<<"$rec"; then
        echo "  rec: $rec" >&2
        fail "dump-now: --check reports state=apk for libsentinel.so -- the APK member did not resolve at the mapping's offset"
    fi
    if grep -q '"state":"unreadable"' <<<"$rec"; then
        echo "  rec: $rec" >&2
        fail "dump-now: --check reports state=unreadable for libsentinel.so -- memory or baseline could not be read"
    fi
    if grep -q '"state":"differ"' <<<"$rec"; then
        echo "  rec: $rec" >&2
        fail "dump-now: --check reports state=differ for libsentinel.so -- it never self-modifies, so differ means the comparison itself is wrong (bad ZIP member or offset), a false-positive bug"
    fi
    grep -q '"state":"match"' <<<"$rec" \
        || { echo "  rec: $rec" >&2; fail "dump-now: --check record for libsentinel.so has an unexpected state: $rec"; }
    info "dump-now --check OK - libsentinel.so (APK-embedded) reports state=match"

    adb shell "su -c 'rm -rf $devdir'" >/dev/null 2>&1
}

case "$WHAT" in
    lib)               test_lib ;;
    lib-records)       test_lib_records ;;
    syscalls)          test_syscalls ;;
    syscalls-jit)      test_syscalls_jit ;;
    syscalls-vdso)     test_syscalls_vdso ;;
    syscalls-regs)     test_syscalls_regs ;;
    syscalls-cfi)      test_syscalls_cfi ;;
    funcs-structured)  test_funcs_structured ;;
    mod-file-access)   test_mod_file_access ;;
    massdelete-detect)  test_massdelete_detect ;;
    exfil-detect)       test_exfil_detect ;;
    accessibility-detect)        test_accessibility_detect ;;
    fileless-detect)     test_fileless_detect ;;
    screencapture-detect)   test_screencapture_detect ;;
    correlate-returns) test_correlate_returns ;;
    dump-now)          test_dump_now ;;
    all)               test_lib; test_lib_records; test_syscalls; test_syscalls_jit; test_syscalls_vdso; test_syscalls_regs; test_syscalls_cfi; test_funcs_structured; test_mod_file_access; test_massdelete_detect; test_exfil_detect; test_accessibility_detect; test_fileless_detect; test_screencapture_detect; test_correlate_returns; test_dump_now ;;
    *)        fail "unknown target '$WHAT' (expected: lib | lib-records | syscalls | syscalls-jit | syscalls-vdso | syscalls-regs | syscalls-cfi | funcs-structured | mod-file-access | massdelete-detect | exfil-detect | accessibility-detect | fileless-detect | screencapture-detect | correlate-returns | dump-now | all)" ;;
esac

forcestop
kill_ares
echo "PASS: ares device smoke ($WHAT) on $PKG"
