#ifndef ANUBEE_SYSCALLS_SNAPSHOT_GATE_H
#define ANUBEE_SYSCALLS_SNAPSHOT_GATE_H

// Pure decision predicates for the syscalls stack-snapshot gate. Kept in a
// header of static-inline functions (no .c, no BPF skeleton dependency) so the
// logic is host-testable by tests/test_snapshot_gate.c while still inlining into
// syscalls_setup.

// Snapshots are enabled iff the user asked for them (--snapshot) AND there is a
// JSON output file to write the <out>.stacks sidecar to. NOTE: intentionally no
// capture_all term — W6-A decouples snapshot capture from library-filter mode so
// JNI-originated (capture-all) stacks can be snapshotted and CFI-unwound.
static inline int sysc_want_snapshots(int want_snap, int has_json)
{
    return want_snap && has_json;
}

// The firehose guard: capture-all with no syscall allow/deny filter ships a
// snapshot per distinct stack across ALL syscalls. Warn (caller proceeds) so the
// user can bound it with -s/-x. syscall_mode: 0=off, 1=allowlist, 2=denylist.
static inline int sysc_snapshot_firehose_warn(int want_snap, int capture_all,
                                              int syscall_mode)
{
    return want_snap && capture_all && syscall_mode == 0;
}

#endif // ANUBEE_SYSCALLS_SNAPSHOT_GATE_H
