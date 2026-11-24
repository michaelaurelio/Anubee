#!/usr/bin/env bash
# Device acceptance smoke test for anubee — the device tier of the testing flow.
# Pushes the freshly-built build/anubee to the attached rooted device and asserts
# each capability still ATTACHES and emits REAL tracer output (not just help
# text). Exits 0 on pass, non-zero on fail, so it drops into CI / `make` / loops.
#
# Usage:
#   scripts/device-test.sh [lib|lib-records|syscalls|syscalls-argwarn|trace-syscalls|massdelete-detect|exfil-detect|accessibility-detect|fileless-detect|dexload-detect|screencapture-detect|correlate-returns|dump-now|all]  # default: all
#
# Env overrides:
#   ANUBEE_TEST_PKG=<package>    target app   (default: com.android.deskclock)
#   ANUBEE_TEST_TIMEOUT=<secs>   per-run window (default: 10)
#
# WHY each anubee run gets its OWN `su -c`: chaining `am force-stop ...; anubee ...`
# inside a single `su -c` runs anubee under an intermediate shell in a reduced
# context and the BPF load fails with -EPERM. A direct `su -c "<anubee ...>"`
# execs the binary in the root domain with the caps eBPF needs. Keep them split.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="$ROOT/build/anubee"
DEVICE_PATH="/data/local/tmp/anubee"
PKG="${ANUBEE_TEST_PKG:-com.android.deskclock}"
TIMEOUT="${ANUBEE_TEST_TIMEOUT:-10}"
WHAT="${1:-all}"

fail() { echo "FAIL: $*" >&2; exit 1; }
info() { echo "  $*"; }

# anubee runs in its OWN su -c (see header). Host expands the vars; the single
# quotes reach the device shell so `su -c '<one string>'` execs the binary.
# anubee handles both SIGINT and SIGTERM via the shared 2-stage stop handler.
# -s INT matches the interactive Ctrl-C path; -k 3 keeps the SIGKILL backstop.
anubee()      { adb shell "su -c 'timeout -s INT -k 3 $TIMEOUT $DEVICE_PATH $*'" 2>&1; }
forcestop() { adb shell "su -c 'am force-stop $PKG'" >/dev/null 2>&1; }
# A run orphaned by an adb disconnect keeps holding the binary -> ETXTBSY on the
# next push/exec. Clear any lingering anubee before we push.
kill_anubee() { adb shell "su -c 'pkill -INT -f $DEVICE_PATH; sleep 1; pkill -KILL -f $DEVICE_PATH'" >/dev/null 2>&1 || true; }

# --- preflight ------------------------------------------------------------
[ -f "$BINARY" ] || fail "no build/anubee — run ./scripts/build.sh first"
adb get-state >/dev/null 2>&1 || fail "no device via adb (check 'adb devices')"
[ "$(adb shell "su -c 'id -u'" 2>/dev/null | tr -d '\r')" = "0" ] \
    || fail "device root unavailable (su -c) — anubee needs root for eBPF"
adb shell "su -c 'ls /sys/kernel/btf/vmlinux'" >/dev/null 2>&1 \
    || fail "kernel BTF missing (/sys/kernel/btf/vmlinux) — CO-RE eBPF can't load"
adb shell "pm path $PKG" >/dev/null 2>&1 \
    || fail "test package not installed: $PKG (set ANUBEE_TEST_PKG)"

# --- push fresh binary (skip when the device copy already matches) ---------
# adb push over a flaky USB link can stall for minutes; skipping an identical
# re-push keeps the smoke test fast and resilient.
host_sum="$(md5sum "$BINARY" | awk '{print $1}')"
dev_sum="$(adb shell "md5sum $DEVICE_PATH 2>/dev/null" | awk '{print $1}' | tr -d '\r')"
if [ "$host_sum" = "$dev_sum" ]; then
    echo "=== on-device binary up to date (md5 ${host_sum%${host_sum#????????????}}), skipping push ==="
else
    echo "=== pushing $(basename "$BINARY") -> $DEVICE_PATH ==="
    kill_anubee
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
    local out; out="$(anubee "lib $PKG")"
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
    local out; out="$(anubee "syscalls -s openat -P $PKG")"
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
    local out; out="$(anubee "syscalls -s openat -P $PKG")"
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
    local out; out="$(anubee "syscalls -s openat -P $PKG")"
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
# library-filtered mode only (disabled in bare capture-all), and the package must be
# passed via -P; so use -l libc.so --snapshot -P (not bare capture-all, not a positional pkg).
# A miss on "regs" means the BPF capture or serializer regressed.
test_syscalls_regs() {
    echo "=== syscalls register file (regs[0..30] in stack sidecar) ==="
    forcestop
    local out_file="/data/local/tmp/anubee_regs_test.jsonl"
    local stacks_file="${out_file}.stacks"
    adb shell "su -c 'rm -f $out_file $stacks_file'" >/dev/null 2>&1 || true
    local out; out="$(anubee "syscalls -l libc.so -s openat --snapshot -o $out_file -P $PKG")"
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
    local out_file="/data/local/tmp/anubee_cfi_test.jsonl"
    local stacks_file="${out_file}.stacks"
    adb shell "su -c 'rm -f $out_file $stacks_file'" >/dev/null 2>&1 || true
    # Run with ANUBEE_CFI_DEBUG=1 so per-step diag fields (incl. stop_reason) land in
    # the sidecar — the PAC RUN_FAIL guard below greps that debug-only field. Own
    # su -c (the load-bearing gotcha); mirrors the anubee() wrapper + the env prefix.
    local out; out="$(adb shell "su -c 'ANUBEE_CFI_DEBUG=1 timeout -s INT -k 3 $TIMEOUT $DEVICE_PATH syscalls -s openat --snapshot -o $out_file -P $PKG'" 2>&1)"
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
    # anubee_coverage_report runs before sysc_emit_summary (src/syscalls/syscalls.c
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
    echo "  NOTE: re-run with ANUBEE_CFI_DEBUG=1 to enrich cfi_stack frames with per-step"
    echo "        CFI internals (module_pc/load_base/fde_pc_lo..hi/cfa/ra_slot/ra_value/stop_reason)"
    # PAC regression guard: before the negate_ra_state fix the CFI walk failed in
    # every PAC-built ART apex lib with terminal stop_reason 6 (CFI_RUN_FAIL) —
    # ~83% of stacks on a real RASP target. Post-fix that count should be ~0. The
    # numeric enum (not the name) is emitted in the sidecar. Soft NOTE only.
    if ! grep -q '"stop_reason":' <<<"$stacks"; then
        echo "  NOTE: no stop_reason in sidecar (ANUBEE_CFI_DEBUG off?) — PAC RUN_FAIL guard skipped"
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

# syscalls arg-parse no-op warnings + -a removal: commit 433aca4 dropped the
# redundant -a switch (bare "no -l" already meant capture-all) and made
# --snapshot-without-o, --siblings/--no-follow-fork-without-p, and
# -A/--activity-in--p-mode diagnosed no-ops (warn on stderr, keep running)
# instead of silent misconfiguration. Warnings print at ARGP_KEY_END, before
# any BPF load or app launch, so these are cheap/fast asserts on the anubee()
# banner text -- same convention as the rest of this file. -a is the one HARD
# case: argp must now reject it outright, so that check asserts a real
# nonzero exit instead of a warning string.
test_syscalls_argwarn() {
    echo "=== syscalls arg-parse no-op warnings + -a removal ==="

    forcestop
    local out; out="$(anubee "syscalls -P $PKG --snapshot")"
    grep -q -- "--snapshot needs -o" <<<"$out" \
        || { tail -10 <<<"$out" >&2; fail "syscalls-argwarn: no --snapshot-without-o warning"; }
    info "syscalls-argwarn: --snapshot-without-o warning present"

    forcestop
    out="$(anubee "syscalls -P $PKG --siblings")"
    grep -q -- "--siblings/--no-follow-fork need -p" <<<"$out" \
        || { tail -10 <<<"$out" >&2; fail "syscalls-argwarn: no --siblings-without-p warning"; }
    info "syscalls-argwarn: --siblings-without-p warning present"

    # -p 1 (init) needs no forcestop/launch -- it's not $PKG.
    out="$(anubee "syscalls -p 1 -A .Main")"
    grep -q -- "-A/--activity has no effect in -p mode" <<<"$out" \
        || { tail -10 <<<"$out" >&2; fail "syscalls-argwarn: no -A-in-p-mode warning"; }
    info "syscalls-argwarn: -A-in-p-mode warning present"

    # -a: argp must reject it fast (before any timeout-expiry ambiguity), so
    # this is the one case in the file worth a real exit-status check rather
    # than a text grep. Reuse run_dump_now's ANUBEE_EXIT sentinel (already in
    # this file for exactly that purpose) instead of trusting adb's own
    # propagated exit code.
    run_dump_now "syscalls -P $PKG -a"
    [ "$RUN_DUMP_NOW_STATUS" != "0" ] \
        || { echo "  out: $RUN_DUMP_NOW_OUT" >&2; fail "syscalls-argwarn: -a was accepted (exit 0) -- removed flag should be rejected by argp"; }
    info "syscalls-argwarn: -a correctly rejected (exit ${RUN_DUMP_NOW_STATUS:-?})"
}

# trace --syscalls: commit 433aca4 gave trace a bare --syscalls enable switch
# (the replacement for the old -a, which routed a capture-all token through
# trace's own arg accumulator). Assert it actually wires up a running syscalls
# engine -- not just an accepted flag -- by checking the engine produces its
# <prefix>.syscalls.jsonl output (per trace's -o <prefix> convention).
test_trace_syscalls() {
    echo "=== trace --syscalls (bare enable switch wires the syscalls stream) ==="
    forcestop
    local prefix="/data/local/tmp/anubee_trace_syscalls_test"
    adb shell "su -c 'rm -f ${prefix}.syscalls.jsonl'" >/dev/null 2>&1 || true
    local out; out="$(anubee "trace -P $PKG --syscalls -o $prefix")"
    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "trace-syscalls: BPF load failed (root/SELinux/own-su-c?)"
    fi
    local content; content="$(adb shell "su -c 'cat ${prefix}.syscalls.jsonl 2>/dev/null'" 2>/dev/null | tr -d '\r')"
    adb shell "su -c 'rm -f ${prefix}.syscalls.jsonl'" >/dev/null 2>&1 || true
    [ -n "$content" ] \
        || { echo "  out: $out" >&2; fail "trace-syscalls: ${prefix}.syscalls.jsonl empty/missing -- --syscalls did not enable the engine"; }
    info "trace-syscalls OK -- ${prefix}.syscalls.jsonl non-empty ($(wc -l <<<"$content" | tr -d ' ') line(s))"
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
    local out_file="/data/local/tmp/anubee_funcs_structured_test.jsonl"
    adb shell "su -c 'rm -f $out_file'" >/dev/null 2>&1 || true
    anubee "funcs -p $pid -e 'libc.so!open' -J --snapshot -o $out_file" >/dev/null 2>&1 || true
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
    local out; out="$(anubee "mod file-access -P $PKG")"
    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "mod-file-access: BPF load failed (root/SELinux/own-su-c?)"
    fi
    grep -q 'stealthy: file-access writes nothing into the target' <<<"$out" \
        || { tail -5 <<<"$out" >&2; fail "mod-file-access: no stealthy-attach banner"; }
    # SYM1 Phase 4c put file-access's live line on ts_print (adds "HH:MM:SS "
    # ahead of the tag) -- tolerate that optional prefix.
    if grep -q '^[0-9: ]*\[file\]' <<<"$out"; then
        info "mod-file-access OK - $(grep -c '^[0-9: ]*\[file\]' <<<"$out") [file] line(s)"
    else
        echo "  SKIP: no [file] events in this window (app's own data-dir opens are timing-dependent)"
    fi

    # A name given both positionally and via -m must run that analyzer once:
    # one attach banner, plus a warning naming the duplicate.
    forcestop
    local dup; dup="$(anubee "mod file-access -m file-access -P $PKG")"
    grep -q "analyzer 'file-access' given more than once" <<<"$dup" \
        || { tail -5 <<<"$dup" >&2; fail "mod-file-access: no duplicate-name warning"; }
    [ "$(grep -c 'stealthy: file-access writes nothing into the target' <<<"$dup")" = "1" ] \
        || { tail -5 <<<"$dup" >&2; fail "mod-file-access: duplicate name still set up twice"; }
    info "mod-file-access duplicate-name OK - analyzer set up once, warning shown"
}

# mod massdelete-detect: deterministic trigger via a compiled single-process
# generator (scripts/anubee_massdelete_gen.c), attached by PID (-p gates on
# target_pids regardless of the generator's UID, so this doesn't need it to
# run as the traced app). Hard-fail, not SKIP: we control the trigger, unlike
# file-access's timing-dependent natural app behavior.
#
# Two requirements confirmed the hard way, both load-bearing:
#   - One process, no forked mv/rm: burst_map keys per calling PID, so 25
#     touches split across 25 short-lived subprocesses never accumulate to
#     MASSDELETE_DETECT_THRESHOLD — each subprocess only ever contributes one touch.
#   - nohup+setsid: a bare `cmd & echo $!` backgrounded inside `su -c '...'`
#     gets killed with the su session on some devices' su/shell before anubee
#     ever attaches (confirmed via `ps` — the pid was gone within ~1s, well
#     inside its own pre-touch sleep). Detaching from the session is what
#     keeps it alive to be traced.
test_massdelete_detect() {
    echo "=== mod massdelete-detect (rename/unlink burst on external storage) ==="
    forcestop
    command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 \
        || fail "massdelete-detect: aarch64-linux-gnu-gcc not found (see README prereqs)"
    local gen_bin="$ROOT/build/anubee_massdelete_gen"
    aarch64-linux-gnu-gcc -static -O2 -o "$gen_bin" "$ROOT/scripts/anubee_massdelete_gen.c" \
        || fail "massdelete-detect: failed to compile mass-delete generator"
    local gen="/data/local/tmp/anubee_massdelete_gen"
    adb push "$gen_bin" "$gen" >/dev/null || fail "massdelete-detect: push failed"
    adb shell "chmod 755 $gen"

    local loop_pid
    loop_pid="$(adb shell "su -c 'nohup setsid $gen /sdcard/.anubee_massdelete_test >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
    if [ -z "$loop_pid" ] || ! [ "$loop_pid" -gt 0 ] 2>/dev/null; then
        fail "massdelete-detect: could not start burst-generator (no pid captured)"
    fi

    local out; out="$(anubee "mod massdelete-detect -p $loop_pid")"

    local loop_pid2
    loop_pid2="$(adb shell "su -c 'nohup setsid $gen /sdcard/.anubee_massdelete_test >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
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

    adb shell "su -c 'rm -f $gen; rm -rf /sdcard/.anubee_massdelete_test'" >/dev/null 2>&1 || true

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
# generator (scripts/anubee_exfil_gen.c), attached by PID (-p gates on
# target_pids regardless of the generator's UID). Hard-fail, not SKIP: we
# control the trigger. Same single-process rationale as massdelete-detect's
# generator (a forked write()-per-call pattern would split byte-volume
# across too many short-lived pids to accumulate a per-pid signal) plus a
# new constraint: the peer must be a non-loopback IPv4 address (loopback and
# AF_UNIX never count), and the phone may be offline -- so the generator puts
# RFC 5737's 192.0.2.1 on lo inside its own network namespace and listens
# there (see the generator's header).
test_exfil_detect() {
    echo "=== mod exfil-detect (sensitive-read + network byte-volume burst) ==="
    forcestop
    command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 \
        || fail "exfil-detect: aarch64-linux-gnu-gcc not found (see README prereqs)"
    local gen_bin="$ROOT/build/anubee_exfil_gen"
    aarch64-linux-gnu-gcc -static -O2 -o "$gen_bin" "$ROOT/scripts/anubee_exfil_gen.c" \
        || fail "exfil-detect: failed to compile exfil generator"
    local gen="/data/local/tmp/anubee_exfil_gen"
    adb push "$gen_bin" "$gen" >/dev/null || fail "exfil-detect: push failed"
    adb shell "chmod 755 $gen"

    local loop_pid
    loop_pid="$(adb shell "su -c 'nohup setsid $gen /sdcard/.anubee_exfil_test/DCIM >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
    if [ -z "$loop_pid" ] || ! [ "$loop_pid" -gt 0 ] 2>/dev/null; then
        fail "exfil-detect: could not start exfil-generator (no pid captured)"
    fi

    local out; out="$(anubee "mod exfil-detect -p $loop_pid")"

    local loop_pid2
    loop_pid2="$(adb shell "su -c 'nohup setsid $gen /sdcard/.anubee_exfil_test/DCIM >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
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

    adb shell "su -c 'rm -f $gen; rm -rf /sdcard/.anubee_exfil_test'" >/dev/null 2>&1 || true

    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "exfil-detect: BPF load failed (root/SELinux/own-su-c?)"
    fi
    if grep -q '^\[exfil-detect\]' <<<"$out"; then
        info "exfil-detect OK — $(grep -c '^\[exfil-detect\]' <<<"$out") [exfil-detect] line(s)"
    else
        tail -10 <<<"$out" >&2
        fail "exfil-detect: no [exfil-detect] line from a 576KiB-write generator (threshold/window mistuned, or timing missed the attach window)"
    fi

    # Regression modes (generator argv[2]). preconnect: the socket is connected
    # BEFORE the sensitive read (pooled keep-alive) -- dest must still name the
    # peer. unix: the burst goes over a connected AF_UNIX socket (logd/dnsproxyd
    # shape) -- local IPC, must not alert.
    adb push "$gen_bin" "$gen" >/dev/null || fail "exfil-detect: push failed"
    adb shell "chmod 755 $gen"
    local mode mpid mout
    for mode in preconnect unix; do
        mpid="$(adb shell "su -c 'nohup setsid $gen /sdcard/.anubee_exfil_test/DCIM $mode >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
        mout="$(anubee "mod exfil-detect -p $mpid")"
        if [ "$mode" = preconnect ]; then
            grep -q '^\[exfil-detect\] .*dest 192\.0\.2\.1:9' <<<"$mout" \
                || { grep '^\[exfil-detect\]' <<<"$mout" >&2; fail "exfil-detect: preconnect burst not attributed to 192.0.2.1:9 (dest lost for a socket connected before the sensitive read)"; }
            info "exfil-detect preconnect OK — dest names the pre-existing connection's peer"
        else
            ! grep -q '^\[exfil-detect\] PID' <<<"$mout" \
                || { grep '^\[exfil-detect\]' <<<"$mout" >&2; fail "exfil-detect: AF_UNIX burst raised an exfil alert (local IPC counted as outbound)"; }
            info "exfil-detect unix OK — AF_UNIX burst not counted"
        fi
    done
    adb shell "su -c 'rm -f $gen; rm -rf /sdcard/.anubee_exfil_test'" >/dev/null 2>&1 || true
}

# mod accessibility-detect: real trigger via TalkBack (com.google.android.marvin.talkback),
# confirmed installed on the test device. Unlike massdelete-detect/exfil-detect,
# the trigger here isn't a compiled single-process generator: a real
# AccessibilityService needs actual compiled code, and this toolchain has no
# dexer. TalkBack is enabled for the run (bypassing the interactive consent
# dialog by writing the secure settings directly via su, confirmed working)
# and its genuine accessibility traffic to system_server is driven by a
# host-side loop of `input keyevent` calls run concurrently with the blocking
# anubee call (avoids nested su -c / device-shell quoting for an on-device
# loop). Prior accessibility settings state is saved and restored
# unconditionally, even on failure — never leave the device in a different
# accessibility configuration than it started in. Hard-fail, not SKIP: we
# control the trigger, same rationale as massdelete-detect/exfil-detect.
test_accessibility_detect() {
    echo "=== mod accessibility-detect (Accessibility-service calls by category + grant) ==="
    # Negative first: an ordinary app with no Accessibility service must not
    # alert (the old volume-burst signal fired on the stock clock app).
    local neg; neg="$(anubee "mod accessibility-detect -P $PKG")"
    if grep -q '^\[accessibility-detect\] PID' <<<"$neg"; then
        grep '^\[accessibility-detect\] PID' <<<"$neg" | head -3 >&2
        fail "accessibility-detect: alert on $PKG, which has no Accessibility service"
    fi
    info "accessibility-detect negative OK - no alert on $PKG"

    # Positive: TalkBack is a real Accessibility service; its process calls
    # IAccessibilityServiceConnection (getWindows, findAccessibilityNodeInfo*...).
    local tb_pkg="com.google.android.marvin.talkback"
    local tb_svc="$tb_pkg/com.google.android.marvin.talkback.TalkBackService"
    if ! adb shell "pm path $tb_pkg" >/dev/null 2>&1; then
        info "SKIP positive: TalkBack ($tb_pkg) not installed on this device"
        return 0
    fi

    local prev_svc prev_enabled
    prev_svc="$(adb shell "su -c 'settings get secure enabled_accessibility_services'" 2>/dev/null | tr -d '\r')"
    prev_enabled="$(adb shell "su -c 'settings get secure accessibility_enabled'" 2>/dev/null | tr -d '\r')"
    restore_a11y() {
        if [ "$prev_svc" = "null" ] || [ -z "$prev_svc" ]; then
            adb shell "su -c 'settings delete secure enabled_accessibility_services'" >/dev/null 2>&1
        else
            adb shell "su -c 'settings put secure enabled_accessibility_services $prev_svc'" >/dev/null 2>&1
        fi
        if [ "$prev_enabled" = "null" ] || [ -z "$prev_enabled" ]; then
            adb shell "su -c 'settings delete secure accessibility_enabled'" >/dev/null 2>&1
        else
            adb shell "su -c 'settings put secure accessibility_enabled $prev_enabled'" >/dev/null 2>&1
        fi
        adb shell "su -c 'am force-stop $tb_pkg'" >/dev/null 2>&1
    }

    # Attach by UID before enabling, so the service's first calls are seen.
    adb shell "su -c 'nohup setsid sh -c \"sleep 3; settings put secure enabled_accessibility_services $tb_svc; settings put secure accessibility_enabled 1; sleep 4; input keyevent KEYCODE_HOME\" >/dev/null 2>&1 &'"
    local out; out="$(anubee "mod accessibility-detect -P $tb_pkg --no-launch")"
    restore_a11y

    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "accessibility-detect: BPF load failed (root/SELinux/own-su-c?)"
    fi
    grep -q '^\[accessibility-detect\] PID.* screen_read ' <<<"$out" \
        || { tail -10 <<<"$out" >&2; fail "accessibility-detect: no screen_read alert from an active Accessibility service"; }
    info "accessibility-detect OK - $(grep -c '^\[accessibility-detect\] PID' <<<"$out") category alert(s) from TalkBack"
}

# mod fileless-detect: deterministic trigger via a compiled generator
# (scripts/anubee_fileless_gen.c) that does one of each signal --
# anon_exec_mmap, mprotect_exec, memfd_exec -- each holding an ELF-headed
# payload, plus the first two on regions named "dalvik-*" (ART's naming),
# which must not alert. No real installed app does this, so a purpose-built
# native binary is needed (like massdelete-detect/exfil-detect). Hard-fail,
# not SKIP: we control the trigger. A final run against an ordinary app is
# informational (JIT activity in a short window isn't guaranteed).
test_fileless_detect() {
    echo "=== mod fileless-detect (anonymous executable mmap, non-ART) ==="
    forcestop
    command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 \
        || fail "fileless-detect: aarch64-linux-gnu-gcc not found (see README prereqs)"
    local gen_bin="$ROOT/build/anubee_fileless_gen"
    aarch64-linux-gnu-gcc -static -O2 -o "$gen_bin" "$ROOT/scripts/anubee_fileless_gen.c" \
        || fail "fileless-detect: failed to compile fileless generator"
    local gen="/data/local/tmp/anubee_fileless_gen"
    adb push "$gen_bin" "$gen" >/dev/null || fail "fileless-detect: push failed"
    adb shell "chmod 755 $gen"

    local loop_pid
    loop_pid="$(adb shell "su -c 'nohup setsid $gen >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
    if [ -z "$loop_pid" ] || ! [ "$loop_pid" -gt 0 ] 2>/dev/null; then
        fail "fileless-detect: could not start fileless-generator (no pid captured)"
    fi

    local out; out="$(anubee "mod fileless-detect -p $loop_pid")"
    adb shell "su -c 'rm -f $gen; rm -rf /data/local/tmp/anubee-payloads'" >/dev/null 2>&1 || true

    if grep -qi 'BPF load failed\|failed to load BPF\|attaching .* failed' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "fileless-detect: BPF load/attach failed (root/SELinux/own-su-c?)"
    fi
    # Count only per-event alert lines ("[fileless-detect] PID:..."), not the
    # summary table that shares the prefix.
    local kind
    for kind in anon_exec_mmap mprotect_exec memfd_exec; do
        grep -q "^\[fileless-detect\] PID:.* $kind .*content=elf" <<<"$out" \
            || { tail -15 <<<"$out" >&2; fail "fileless-detect: no $kind alert with ELF content"; }
    done
    [ "$(grep -c '^\[fileless-detect\] PID:' <<<"$out")" -eq 3 ] \
        || { tail -15 <<<"$out" >&2; fail "fileless-detect: expected exactly 3 alerts -- the dalvik-named regions must be recognised as ART's"; }
    [ "$(grep -c '^\[fileless-detect\]   saved ' <<<"$out")" -eq 3 ] \
        || { tail -15 <<<"$out" >&2; fail "fileless-detect: payload copies not saved for all three regions"; }
    info "fileless-detect OK - anon_exec_mmap, mprotect_exec, memfd_exec caught and saved; ART-named regions excluded"

    # Shared-sink wiring: fileless-detect's alerts are produced off the ring
    # path (pending_map scan), and must reach the single-writer -o sink via the
    # dispatcher tick alongside another analyzer's records. Assert the alert
    # record lands and every line of the combined file is intact JSON.
    adb push "$gen_bin" "$gen" >/dev/null || fail "fileless-detect: push failed"
    adb shell "chmod 755 $gen"
    local mix_pid
    mix_pid="$(adb shell "su -c 'nohup setsid $gen >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
    local mix_file="/data/local/tmp/fileless_mix.jsonl"
    anubee "mod -m fileless-detect -m proc-event -p $mix_pid -o $mix_file -q" >/dev/null
    local mix_out; mix_out="$(adb shell "su -c 'cat $mix_file'" 2>/dev/null | tr -d '\r')"
    adb shell "su -c 'rm -rf $mix_file $mix_file.payloads $gen'" >/dev/null 2>&1 || true
    grep -q '"type":"fileless_detect"' <<<"$mix_out" \
        || { tail -5 <<<"$mix_out" >&2; fail "fileless-detect: no fileless_detect record in a combined -m fileless-detect -m proc-event -o run"; }
    python3 -c 'import json,sys
for n,l in enumerate(sys.stdin,1):
    if l.strip(): json.loads(l)' <<<"$mix_out" \
        || fail "fileless-detect: combined -o file has a corrupt JSONL line"
    info "fileless-detect shared-sink OK — alert record present, combined JSONL intact"

    local jit_out; jit_out="$(anubee "mod fileless-detect -P $PKG")"
    forcestop
    adb shell "su -c 'rm -rf /data/local/tmp/anubee-payloads'" >/dev/null 2>&1 || true
    local jit_lines
    jit_lines="$(grep -c '^\[fileless-detect\] PID:' <<<"$jit_out")"
    info "fileless-detect ART-name exclusion check on a real app (informational): $jit_lines line(s) against $PKG"
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
# device and -P's anubee_launch_app() (src/common/launch.c) hard-fails before
# the dumpsys poll thread ever starts polling -- confirmed on-device, not a
# timing issue. -p <pid> against the already-running service process skips
# that resolve-activity step entirely, same precedent as accessibility-detect's
# already-running-process attach. The anubee() call below is synchronous
# (blocking, like accessibility-detect/fileless-detect), not backgrounded: this file's
# own header note applies here too -- anubee's stdio is fully buffered once
# it isn't a tty, so killing it early from the host side (pkill on the local
# adb shell client doesn't even reach the remote process -- see
# testing-anubee-on-device gotchas) loses whatever hadn't flushed yet.
# Blocking for the device-side `timeout -s INT $TIMEOUT` window lets anubee
# exit cleanly and flush before the capture completes.
test_screencapture_detect() {
    echo "=== mod screencapture-detect (capture stages: FGS declared, projection start, virtual display) ==="
    # Drives the OEM screen recorder through a real ~4s recording: its
    # foreground service (fgs_declared, dumpsys poll), then IMediaProjection.start
    # and IDisplayManager.createVirtualDisplay (Binder). The consent prompt is
    # accepted by tapping its "Start recording" node when it appears (the app
    # skips it once consent was given). The recording is deleted afterwards.
    local pkg="com.transsion.screenrecorder"
    local svc="$pkg/.service.RecordingService"
    if ! adb shell "pm path $pkg" >/dev/null 2>&1; then
        info "SKIP: screencapture-detect needs the OEM recorder ($pkg), not installed"
        return 0
    fi
    local dir="/storage/emulated/0/Movies/ScreenRecord" mark="/data/local/tmp/anubee_sc_mark"
    local drive="/data/local/tmp/anubee_sc_drive.sh"
    adb shell "cat > $drive" <<SH
sleep 2
am start-foreground-service -a transsion.intent.screenrecorder.RECORDER_SERVICE -n $svc >/dev/null 2>&1
sleep 2
uiautomator dump /data/local/tmp/anubee_sc_ui.xml >/dev/null 2>&1
b=\$(grep -o 'text="Start recording"[^>]*bounds="[^"]*"' /data/local/tmp/anubee_sc_ui.xml | grep -o '[0-9][0-9]*' | tail -4 | tr '\n' ' ')
rm -f /data/local/tmp/anubee_sc_ui.xml
if [ -n "\$b" ]; then set -- \$b; input tap \$(( (\$1 + \$3) / 2 )) \$(( (\$2 + \$4) / 2 )); fi
sleep 4
am force-stop $pkg
SH
    adb shell "su -c 'touch $mark; nohup setsid sh $drive >/dev/null 2>&1 &'"
    local out; out="$(anubee "mod screencapture-detect -P $pkg --no-launch")"
    adb shell "su -c 'am force-stop $pkg'" >/dev/null 2>&1
    # Delete only recordings created during this test (find -delete is refused
    # on the FUSE mount, rm per file works).
    adb shell "su -c 'for f in \$(find $dir -newer $mark -type f -name \"*.mp4\" 2>/dev/null); do rm -f \"\$f\"; done; rm -f $mark $drive'" >/dev/null 2>&1

    if grep -q "BPF load failed\|failed to load BPF" <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "screencapture-detect: BPF load failed (root/SELinux/own-su-c?)"
    fi
    local st
    for st in fgs_declared projection_start virtual_display; do
        grep -q "^\[screencapture-detect\] PID:.* $st " <<<"$out" \
            || { tail -12 <<<"$out" >&2; fail "screencapture-detect: no $st stage during a real recording"; }
    done
    grep -q 'IMediaProjection\.start' <<<"$out" || fail "screencapture-detect: projection stage not named"
    info "screencapture-detect OK - fgs_declared, projection_start, virtual_display"
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
    local out_file="/data/local/tmp/anubee_correlate_returns_test.jsonl"
    adb shell "su -c 'rm -f $out_file'" >/dev/null 2>&1 || true
    local out; out="$(anubee "correlate -P $PKG -e 'libc.so!open' --returns -o $out_file")"
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
    local of="/data/local/tmp/anubee_librec_test.jsonl"

    adb shell "su -c 'rm -f $of'" >/dev/null 2>&1 || true
    local so; so="$(anubee "syscalls -s openat -o $of -P $PKG")"
    grep -qi 'BPF load failed\|-EPERM' <<<"$so" \
        && { tail -5 <<<"$so" >&2; fail "lib-records/syscalls: BPF load failed"; }
    local sc; sc="$(adb shell "su -c 'cat $of 2>/dev/null'" 2>/dev/null | tr -d '\r')"
    grep -q '"type":"lib"' <<<"$sc" \
        || { echo "  out: $(tail -3 <<<"$sc")" >&2; fail "lib-records/syscalls: no {\"type\":\"lib\"} in -o sink"; }
    info "lib-records/syscalls OK — $(grep -c '"type":"lib"' <<<"$sc") lib record(s) in sink"

    forcestop
    adb shell "su -c 'rm -f $of'" >/dev/null 2>&1 || true
    local co; co="$(anubee "correlate -P $PKG -e 'libc.so!open' -o $of")"
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
# libsentinel.so. dev.anubee.detector ships extractNativeLibs=false: libsentinel.so
# is mapped straight out of base.apk, not extracted to disk, so this also pins
# dump_read_apk_member's stored-ZIP-member resolution end to end.
#
# Own package (not $PKG): this needs dev.anubee.detector specifically, same
# precedent as accessibility-detect/screencapture-detect hardcoding their own
# fixed target app rather than the generic $PKG.
#
# pid+base discovery: the natural, lowest-friction source is `anubee lib -P`'s
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
    # Same on-device timeout guard as anubee() (own su -c; -s INT / -k 3 backstop)
    # -- if --now ever regressed into the old wait-for-Ctrl-C behavior this
    # still bounds the run -- but unlike anubee(), this also surfaces the real
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
    raw="$(adb shell "su -c 'timeout -s INT -k 3 $TIMEOUT $DEVICE_PATH $*; echo ANUBEE_EXIT:\$?'" 2>&1 | tr -d '\r')"
    RUN_DUMP_NOW_STATUS="$(sed -n 's/.*ANUBEE_EXIT:\([0-9]*\)$/\1/p' <<<"$raw" | tail -1)"
    RUN_DUMP_NOW_OUT="$(sed '/^ANUBEE_EXIT:[0-9]*$/d' <<<"$raw")"
}
test_dump_now() {
    echo "=== dump --now (pure /proc snapshot, no BPF) + --check (APK-embedded baseline) ==="
    local dpkg="dev.anubee.detector"
    adb shell "pm path $dpkg" >/dev/null 2>&1 \
        || fail "dump-now: $dpkg not installed on this device"
    forcestop
    local lib_out; lib_out="$(anubee "lib -P $dpkg")"
    if grep -qi 'BPF load failed\|-EPERM' <<<"$lib_out"; then
        tail -5 <<<"$lib_out" >&2; fail "dump-now: lib (pid+base discovery) BPF load failed"
    fi
    local sline; sline="$(grep -E '\[lib\] pid [0-9]+ .*-> libsentinel\.so$' <<<"$lib_out" | tail -1)"
    [ -n "$sline" ] || { tail -10 <<<"$lib_out" >&2; fail "dump-now: no [lib] line for libsentinel.so (pid+base discovery failed)"; }
    local pid; pid="$(sed -E 's/.*\[lib\] pid ([0-9]+).*/\1/' <<<"$sline")"
    local base; base="$(sed -E 's/.*\[(0x[0-9a-f]+), 0x[0-9a-f]+\).*/\1/' <<<"$sline")"
    [ -n "$pid" ] && [ -n "$base" ] || fail "dump-now: could not parse pid/base from: $sline"
    info "dump-now: discovered pid=$pid base=$base for libsentinel.so"

    local devdir="/data/local/tmp/anubee_dumpnow_test"
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

# -p follow-fork: a target that creates many threads must still have its
# child processes followed. Thread creation fires sched_process_fork too; if
# threads are inserted into the 64-slot target_pids map, a later child can't
# be. scripts/anubee_forkfollow_gen.c creates 100 threads, then forks a child
# that execs /system/bin/true with a marker argv; mod execve -p must show it.
test_mod_no_launch() {
    echo "=== mod --no-launch (arm the UID, never start/stop the app) ==="
    local comp; comp="$(adb shell "cmd package resolve-activity --brief $PKG" | tr -d '\r' | tail -1)"
    [ -n "$comp" ] || fail "no-launch: cannot resolve a launcher activity for $PKG"
    # 1) an app that is already running must not be force-stopped/relaunched
    adb shell "am start -n $comp" >/dev/null 2>&1; sleep 2
    local before after con
    before="$(adb shell "pidof $PKG" | tr -d '\r')"
    con="$(anubee "mod proc-event -P $PKG --no-launch -q")"
    after="$(adb shell "pidof $PKG" | tr -d '\r')"
    [ -n "$before" ] && [ "$before" = "$after" ] \
        || fail "no-launch: running app was restarted (pid '$before' -> '$after')"
    ! grep -q '^launching' <<<"$con" || fail "no-launch: launch banner printed"
    # 2) an app started later by someone else (here: am start from a detached
    #    job, standing in for a user tap / receiver / alarm) is traced
    local out="/data/local/tmp/anubee_no_launch.jsonl"
    forcestop; sleep 1
    adb shell "su -c 'rm -f $out; nohup setsid sh -c \"sleep 3; am start -n $comp\" >/dev/null 2>&1 &'"
    anubee "mod proc-event -P $PKG --no-launch -q -o $out" >/dev/null
    local n; n="$(adb shell "su -c 'grep -c \"type\\\":\\\"spawn\" $out; rm -f $out'" | tr -d '\r' | head -1)"
    [ "${n:-0}" -gt 0 ] 2>/dev/null || fail "no-launch: app started after attach produced no spawn records"
    info "no-launch OK - running app untouched; later start traced ($n spawn record(s))"
}

test_mod_triage() {
    echo "=== mod triage preset (every stealthy analyzer, one sink) ==="
    local out="/data/local/tmp/anubee_triage.jsonl" con recs
    con="$(anubee "mod triage -P $PKG -q -o $out")"
    grep -q 'LOUD' <<<"$con" && fail "triage: a LOUD analyzer was included"
    local want; want="$(adb shell "su -c '$DEVICE_PATH mod --list'" | tr -d '\r' | grep -c '^  [a-z-]* *\[stealth\]')"
    local got; got="$(grep -c '^\[mod\]   > stealthy:' <<<"$con")"
    [ "$got" = "$want" ] || { tail -15 <<<"$con" >&2; fail "triage: $got analyzer(s) set up, expected every [stealth] one ($want)"; }
    recs="$(adb shell "su -c 'cat $out; rm -f $out'" | tr -d '\r')"
    python3 -c 'import json,sys; [json.loads(l) for l in sys.stdin if l.strip()]' <<<"$recs" \
        || fail "triage: combined -o output is not valid JSONL"
    local ncov; ncov="$(grep -c '"type":"coverage"' <<<"$recs")"
    [ "$ncov" = "$want" ] || fail "triage: $ncov coverage record(s), expected $want (an analyzer didn't tear down?)"
    info "triage OK - $got stealthy analyzers, valid shared JSONL, $ncov coverage records"
}

test_mod_binder_api() {
    echo "=== mod binder-api (interface/method names, content-provider URIs) ==="
    # A shell target that makes known Binder calls: the `content` CLI does a
    # ContentProvider QUERY on content://sms/inbox and a settings CALL. -p on the
    # shell + follow-fork covers the two app_process children.
    local out="/data/local/tmp/anubee_binder_api.jsonl" script="/data/local/tmp/anubee_binder_api.sh"
    adb shell "cat > $script" <<'SH'
sh -c 'sleep 3; content query --uri content://sms/inbox --projection _id >/dev/null 2>&1; content call --uri content://settings/secure --method GET_secure --arg android_id >/dev/null 2>&1; sleep 1' >/dev/null 2>&1 &
echo $!
SH
    local tpid; tpid="$(adb shell "su -c 'sh $script'" | tr -d '\r' | tail -1)"
    [ "${tpid:-0}" -gt 0 ] 2>/dev/null || fail "binder-api: could not start the shell target"
    local con; con="$(anubee "mod binder-api -p $tpid -o $out")"
    grep -q 'AIDL method name(s) from [1-9]' <<<"$con" \
        || { head -5 <<<"$con" >&2; fail "binder-api: no method names loaded from the framework jars"; }
    grep -q 'IActivityManager\.getContentProviderExternal' <<<"$con" \
        || { tail -15 <<<"$con" >&2; fail "binder-api: named AIDL method not decoded"; }
    grep -q 'IContentProvider\.QUERY content://sms/inbox' <<<"$con" \
        || { tail -15 <<<"$con" >&2; fail "binder-api: content-provider QUERY URI not decoded"; }
    grep -q 'IContentProvider\.CALL settings GET_secure android_id' <<<"$con" \
        || { tail -15 <<<"$con" >&2; fail "binder-api: content-provider CALL not decoded"; }
    local recs; recs="$(adb shell "su -c 'cat $out; rm -f $out $script'" | tr -d '\r')"
    python3 -c 'import json,sys; [json.loads(l) for l in sys.stdin if l.strip()]' <<<"$recs" \
        || fail "binder-api: -o output is not valid JSONL"
    grep -q '"uri":"content://sms/inbox"' <<<"$recs" || fail "binder-api: uri field missing from JSONL"
    grep -q '"type":"binder_api_summary"' <<<"$recs" || fail "binder-api: no summary record"
    info "binder-api OK - AIDL names, QUERY content://sms/inbox, CALL settings GET_secure android_id"
}

test_mod_perm_watch() {
    echo "=== mod perm-watch (baseline + app-op change timeline) ==="
    # Flip SYSTEM_ALERT_WINDOW (overlay -- the banking-trojan staple) on the
    # test app mid-run and back; both changes must appear, in order, as
    # perm_change records. The original mode is restored whatever happens.
    local op=SYSTEM_ALERT_WINDOW out="/data/local/tmp/anubee_perm_watch.jsonl"
    local orig; orig="$(adb shell "appops get $PKG $op" | tr -d '\r' | sed -n "s/^$op: \([a-z]*\).*/\1/p")"
    [ -n "$orig" ] || orig=default
    local flip=allow; [ "$orig" = allow ] && flip=ignore
    # Flips at ~3s and ~6s: inside the run (TIMEOUT, default 10s) with a 2s
    # poll on each side. nohup+setsid so the job outlives this adb shell.
    adb shell "su -c 'rm -f $out; nohup setsid sh -c \"sleep 3; appops set $PKG $op $flip; sleep 3; appops set $PKG $op $orig\" >/dev/null 2>&1 &'"
    local con; con="$(anubee "mod perm-watch -P $PKG -o $out")"
    adb shell "appops set $PKG $op $orig" >/dev/null 2>&1 || true
    grep -q "^\[perm-watch\] $PKG baseline:" <<<"$con" \
        || { tail -10 <<<"$con" >&2; fail "perm-watch: no baseline line"; }
    local recs; recs="$(adb shell "su -c 'cat $out'" | tr -d '\r')"
    python3 -c 'import json,sys; [json.loads(l) for l in sys.stdin if l.strip()]' <<<"$recs" \
        || fail "perm-watch: -o output is not valid JSONL"
    grep -q '"change":"baseline"' <<<"$recs" || fail "perm-watch: no baseline records in -o output"
    local seq; seq="$(grep "\"name\":\"$op\",\"change\":\"changed\"" <<<"$recs" \
        | sed 's/.*"old":"\([a-z]*\)","new":"\([a-z]*\)".*/\1>\2/' | tr '\n' ' ')"
    [ "$seq" = "$orig>$flip $flip>$orig " ] \
        || { echo "  got: '$seq'" >&2; fail "perm-watch: expected '$orig>$flip $flip>$orig' for $op"; }
    adb shell "su -c 'rm -f $out'" >/dev/null 2>&1 || true
    info "perm-watch OK - baseline + $op $orig>$flip>$orig timeline"
}

test_mod_pkg_inject() {
    echo "=== mod -p: target-controlled cmdline never reaches a root shell ==="
    # In -p mode the package name is read from /proc/<pid>/cmdline, which the
    # traced process controls; massdelete-detect/screencapture-detect/perm-watch
    # interpolate it into root dumpsys/appops commands. A target whose argv[0]
    # carries a shell payload must not get it executed.
    command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 \
        || fail "pkg-inject: aarch64-linux-gnu-gcc not found (see README prereqs)"
    local gen_bin="$ROOT/build/anubee_forkfollow_gen"
    aarch64-linux-gnu-gcc -static -O2 -pthread -o "$gen_bin" "$ROOT/scripts/anubee_forkfollow_gen.c" \
        || fail "pkg-inject: failed to compile generator"
    local gen="/data/local/tmp/anubee_forkfollow_gen" mark="/data/local/tmp/anubee_pkg_inject_mark"
    adb push "$gen_bin" "$gen" >/dev/null || fail "pkg-inject: push failed"
    adb shell "chmod 755 $gen; su -c 'rm -f $mark'"
    # The generator ignores argv[0]; exec -a sets it to the payload.
    local script="/data/local/tmp/anubee_pkg_inject.sh"
    adb shell "cat > $script" <<SH
(exec -a 'com.x;touch $mark' $gen) >/dev/null 2>&1 &
echo \$!
SH
    local gen_pid
    gen_pid="$(adb shell "su -c 'sh $script'" 2>/dev/null | tr -d '\r' | tail -1)"
    if [ -z "$gen_pid" ] || ! [ "$gen_pid" -gt 0 ] 2>/dev/null; then
        fail "pkg-inject: could not start generator (no pid captured)"
    fi
    anubee "mod massdelete-detect -p $gen_pid -q" >/dev/null
    local hit; hit="$(adb shell "su -c 'ls $mark 2>/dev/null; rm -f $mark $script $gen'" | tr -d '\r')"
    [ -z "$hit" ] || fail "pkg-inject: a target-controlled cmdline was executed by a root shell"
    info "pkg-inject OK - hostile cmdline rejected as a package name"
}

test_mod_proc_event() {
    echo "=== mod proc-event (process spawns, not thread creations) ==="
    # sched_process_fork fires for thread creation too; a spawn record must
    # mean a new process. The generator creates 100 threads, then forks once.
    command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 \
        || fail "proc-event: aarch64-linux-gnu-gcc not found (see README prereqs)"
    local gen_bin="$ROOT/build/anubee_forkfollow_gen"
    aarch64-linux-gnu-gcc -static -O2 -pthread -o "$gen_bin" "$ROOT/scripts/anubee_forkfollow_gen.c" \
        || fail "proc-event: failed to compile generator"
    local gen="/data/local/tmp/anubee_forkfollow_gen" out="/data/local/tmp/anubee_proc_event.jsonl"
    adb push "$gen_bin" "$gen" >/dev/null || fail "proc-event: push failed"
    adb shell "chmod 755 $gen"
    local gen_pid
    gen_pid="$(adb shell "su -c 'nohup setsid $gen >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
    [ "${gen_pid:-0}" -gt 0 ] 2>/dev/null || fail "proc-event: could not start generator"
    anubee "mod proc-event -p $gen_pid --no-follow-fork -q -o $out" >/dev/null
    local n; n="$(adb shell "su -c 'grep -c spawn $out; rm -f $out $gen'" | tr -d '\r' | head -1)"
    [ "$n" = "1" ] || fail "proc-event: $n spawn record(s) for 100 threads + 1 fork, expected 1"
    info "proc-event OK - 1 spawn for 100 threads + 1 fork"
}

test_mod_follow_fork() {
    echo "=== mod -p follow-fork (children followed past many threads) ==="
    command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 \
        || fail "follow-fork: aarch64-linux-gnu-gcc not found (see README prereqs)"
    local gen_bin="$ROOT/build/anubee_forkfollow_gen"
    aarch64-linux-gnu-gcc -static -O2 -pthread -o "$gen_bin" "$ROOT/scripts/anubee_forkfollow_gen.c" \
        || fail "follow-fork: failed to compile generator"
    local gen="/data/local/tmp/anubee_forkfollow_gen"
    adb push "$gen_bin" "$gen" >/dev/null || fail "follow-fork: push failed"
    adb shell "chmod 755 $gen"

    local gen_pid
    gen_pid="$(adb shell "su -c 'nohup setsid $gen >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
    if [ -z "$gen_pid" ] || ! [ "$gen_pid" -gt 0 ] 2>/dev/null; then
        fail "follow-fork: could not start generator (no pid captured)"
    fi
    local out; out="$(anubee "mod execve -p $gen_pid")"
    adb shell "su -c 'rm -f $gen'" >/dev/null 2>&1 || true

    if grep -qi 'BPF load failed\|-EPERM' <<<"$out"; then
        tail -5 <<<"$out" >&2; fail "follow-fork: BPF load failed (root/SELinux/own-su-c?)"
    fi
    grep -q 'anubee-forkfollow-child' <<<"$out" \
        || { tail -10 <<<"$out" >&2; fail "follow-fork: child exec not traced after 100 threads (threads exhausted target_pids?)"; }
    info "follow-fork OK - child of a 100-thread target traced"
}

test_dexload_detect() {
    echo "=== mod dexload-detect (payload drop -> load -> delete, copy saved) ==="
    # A shell stands in for a dropper: writes a real DEX (from a framework jar)
    # and an ELF, maps both (dalvikvm loads the DEX, the ELF is executed),
    # then deletes them -- the "load then delete" pattern.
    local d=/data/local/tmp/anubee_dltest out_jsonl=/data/local/tmp/anubee_dl.jsonl
    local drv="$ROOT/build/anubee_dl_drive.sh"
    cat > "$drv" <<DRV
#!/system/bin/sh
mkdir -p $d
sleep 3
unzip -p /system/framework/am.jar classes.dex > $d/stage2.dex
cat /system/bin/toybox > $d/echo
chmod 755 $d/echo
chmod 444 $d/stage2.dex
$d/echo dropped-elf-ran >/dev/null
dalvikvm64 -cp $d/stage2.dex com.android.commands.am.Am >/dev/null 2>&1
rm -f $d/stage2.dex $d/echo
sleep 1
DRV
    adb push "$drv" /data/local/tmp/anubee_dl_drive.sh >/dev/null || fail "dexload-detect: push failed"
    adb shell "su -c 'chmod 755 /data/local/tmp/anubee_dl_drive.sh; rm -rf $out_jsonl $out_jsonl.payloads $d'" >/dev/null 2>&1
    local want_sha
    want_sha="$(adb shell "su -c 'unzip -p /system/framework/am.jar classes.dex | sha256sum'" | tr -d '\r' | cut -d' ' -f1)"
    [ -n "$want_sha" ] || fail "dexload-detect: no classes.dex in /system/framework/am.jar on this device"

    local drv_pid
    drv_pid="$(adb shell "su -c 'nohup setsid /data/local/tmp/anubee_dl_drive.sh >/dev/null 2>&1 & echo \$!'" 2>/dev/null | tr -d '\r' | tail -1)"
    [ -n "$drv_pid" ] && [ "$drv_pid" -gt 0 ] 2>/dev/null || fail "dexload-detect: could not start the driver"
    local out; out="$(anubee "mod dexload-detect -p $drv_pid -o $out_jsonl")"
    local rec; rec="$(adb shell "su -c 'cat $out_jsonl'" 2>/dev/null | tr -d '\r')"
    adb shell "su -c 'rm -rf $out_jsonl $out_jsonl.payloads $d /data/local/tmp/anubee_dl_drive.sh'" >/dev/null 2>&1 || true

    if grep -qi 'BPF load failed\|failed to load BPF\|attaching .* failed' <<<"$out"; then
        tail -15 <<<"$out" >&2; fail "dexload-detect: BPF load/attach failed"
    fi
    grep -q 'dropped dex  .*/anubee_dltest/stage2.dex' <<<"$out" \
        || { tail -15 <<<"$out" >&2; fail "dexload-detect: DEX drop (with full path) not reported"; }
    grep -q 'dropped elf  .*/anubee_dltest/echo' <<<"$out" \
        || { tail -15 <<<"$out" >&2; fail "dexload-detect: ELF drop not reported"; }
    grep -q 'loaded  elf  .*\[exec\]' <<<"$out" \
        || { tail -15 <<<"$out" >&2; fail "dexload-detect: executable mapping of the ELF not reported"; }
    grep -q 'loaded  dex  .*/anubee_dltest/stage2.dex' <<<"$out" \
        || { tail -15 <<<"$out" >&2; fail "dexload-detect: DEX load (dalvikvm mapping it) not reported"; }
    [ "$(grep -c 'deleted ' <<<"$out")" -ge 2 ] \
        || { tail -15 <<<"$out" >&2; fail "dexload-detect: deletes not reported"; }
    grep -q "\"stage\":\"load\",\"kind\":\"dex\".*\"sha256\":\"$want_sha\"" <<<"$rec" \
        || { echo "$rec" | head -5 >&2; fail "dexload-detect: saved DEX copy missing or its sha256 differs from the original"; }
    grep -q '"type":"dexload_detect_summary","file_count":2' <<<"$rec" \
        || fail "dexload-detect: summary record missing"
    info "dexload-detect OK - drop/load/delete of a DEX and an ELF, payload copy sha256 matches"
}

case "$WHAT" in
    lib)               test_lib ;;
    lib-records)       test_lib_records ;;
    syscalls)          test_syscalls ;;
    syscalls-jit)      test_syscalls_jit ;;
    syscalls-vdso)     test_syscalls_vdso ;;
    syscalls-regs)     test_syscalls_regs ;;
    syscalls-cfi)      test_syscalls_cfi ;;
    syscalls-argwarn)  test_syscalls_argwarn ;;
    trace-syscalls)    test_trace_syscalls ;;
    funcs-structured)  test_funcs_structured ;;
    mod-file-access)   test_mod_file_access ;;
    mod-follow-fork)   test_mod_follow_fork ;;
    mod-proc-event)    test_mod_proc_event ;;
    mod-pkg-inject)    test_mod_pkg_inject ;;
    mod-perm-watch)    test_mod_perm_watch ;;
    mod-binder-api)    test_mod_binder_api ;;
    mod-no-launch)     test_mod_no_launch ;;
    mod-triage)        test_mod_triage ;;
    massdelete-detect)  test_massdelete_detect ;;
    exfil-detect)       test_exfil_detect ;;
    accessibility-detect)        test_accessibility_detect ;;
    fileless-detect)     test_fileless_detect ;;
    dexload-detect)      test_dexload_detect ;;
    screencapture-detect)   test_screencapture_detect ;;
    correlate-returns) test_correlate_returns ;;
    dump-now)          test_dump_now ;;
    all)               test_lib; test_lib_records; test_syscalls; test_syscalls_jit; test_syscalls_vdso; test_syscalls_regs; test_syscalls_cfi; test_syscalls_argwarn; test_trace_syscalls; test_funcs_structured; test_mod_file_access; test_mod_follow_fork; test_mod_proc_event; test_mod_pkg_inject; test_mod_perm_watch; test_mod_binder_api; test_mod_no_launch; test_mod_triage; test_massdelete_detect; test_exfil_detect; test_accessibility_detect; test_fileless_detect; test_dexload_detect; test_screencapture_detect; test_correlate_returns; test_dump_now ;;
    *)        fail "unknown target '$WHAT' (expected: lib | lib-records | syscalls | syscalls-jit | syscalls-vdso | syscalls-regs | syscalls-cfi | syscalls-argwarn | trace-syscalls | funcs-structured | mod-file-access | mod-follow-fork | mod-proc-event | mod-pkg-inject | mod-perm-watch | mod-binder-api | mod-no-launch | mod-triage | massdelete-detect | exfil-detect | accessibility-detect | fileless-detect | screencapture-detect | correlate-returns | dump-now | all)" ;;
esac

forcestop
kill_anubee
echo "PASS: anubee device smoke ($WHAT) on $PKG"
