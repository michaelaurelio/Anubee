// Host unit test for src/common/syscall_index.h (pure logic, no BPF).
#include "common/syscall_index.h"
#include <stdio.h>
#include <string.h>

static int failures;

static void check(int cond, const char *msg) {
    if (!cond) { printf("FAIL: %s\n", msg); failures++; }
}

// Reference linear scan the index must agree with.
static const char *ref_name(const struct ares_sysent *t, size_t n, long nr) {
    for (size_t i = 0; i < n; i++) if (t[i].nr == nr) return t[i].name;
    return NULL;
}

int main(void) {
    // Deliberate mix: low nrs, gaps, and one nr >= cap (cold fallback path).
    static const struct ares_sysent tbl[] = {
        { 0,   "read"  },
        { 1,   "write" },
        { 56,  "openat"},
        { 63,  "close" },
        { ARES_SYS_NR_CAP + 7, "high_cold" },
    };
    const size_t n = sizeof(tbl) / sizeof(tbl[0]);

    struct ares_sysindex ix;
    ares_sysindex_build(&ix, tbl, n);

    // Every table entry resolves, and matches the reference scan.
    for (size_t i = 0; i < n; i++) {
        const char *got = ares_sysindex_name(&ix, tbl[i].nr);
        const char *ref = ref_name(tbl, n, tbl[i].nr);
        check(got != NULL && ref != NULL && strcmp(got, ref) == 0,
              "table entry resolves to reference name");
    }

    // Hot-path spot check.
    check(strcmp(ares_sysindex_name(&ix, 56), "openat") == 0, "hot-path openat");
    // Cold-path (nr >= cap) still resolves via the retained linear fallback.
    check(strcmp(ares_sysindex_name(&ix, ARES_SYS_NR_CAP + 7), "high_cold") == 0,
          "cold-path nr >= cap");
    // Unknown nrs return NULL (both below cap and negative).
    check(ares_sysindex_name(&ix, 999) == NULL, "unknown low nr -> NULL");
    check(ares_sysindex_name(&ix, -1) == NULL, "negative nr -> NULL");

    // Idempotency: rebuilding yields identical lookups.
    ares_sysindex_build(&ix, tbl, n);
    check(strcmp(ares_sysindex_name(&ix, 1), "write") == 0, "idempotent rebuild");

    printf(failures ? "%d check(s) FAILED\n" : "all checks passed\n", failures);
    return failures ? 1 : 0;
}
