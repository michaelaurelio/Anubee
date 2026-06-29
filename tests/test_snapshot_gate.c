// Host unit test for the syscalls snapshot-gate predicates (W6-A decouple).
#include <stdio.h>
#include "syscalls/snapshot_gate.h"

static int failures;
#define CHECK(cond) do { \
    if (cond) { printf("  ok: %s\n", #cond); } \
    else { printf("  FAIL: %s\n", #cond); failures++; } \
} while (0)

int main(void)
{
    // want_snapshots: enabled iff --snapshot AND json output, regardless of -a.
    CHECK(sysc_want_snapshots(1, 1) == 1);   // --snapshot + -o
    CHECK(sysc_want_snapshots(1, 0) == 0);   // --snapshot, no -o
    CHECK(sysc_want_snapshots(0, 1) == 0);   // -o, no --snapshot
    CHECK(sysc_want_snapshots(0, 0) == 0);

    // The decouple: capture-all no longer disables snapshots. want_snapshots
    // takes no capture_all argument, so -a + --snapshot + -o is enabled.
    CHECK(sysc_want_snapshots(1, 1) == 1);   // (same call, documents intent)

    // firehose warn: only for -a + --snapshot + NO syscall filter (mode 0).
    CHECK(sysc_snapshot_firehose_warn(1, 1, 0) == 1);  // -a --snapshot, no filter
    CHECK(sysc_snapshot_firehose_warn(1, 1, 1) == 0);  // -a --snapshot -s (allowlist)
    CHECK(sysc_snapshot_firehose_warn(1, 1, 2) == 0);  // -a --snapshot -x (denylist)
    CHECK(sysc_snapshot_firehose_warn(1, 0, 0) == 0);  // lib-filter, no firehose
    CHECK(sysc_snapshot_firehose_warn(0, 1, 0) == 0);  // no --snapshot, no warn

    if (failures) { printf("FAILED: %d check(s)\n", failures); return 1; }
    printf("test_snapshot_gate: all checks passed\n");
    return 0;
}
