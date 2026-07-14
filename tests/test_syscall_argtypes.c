// Host unit test for the syscall arity table (common/syscall_argc.h) that
// src/common/syscall_argtypes.c's arg_count() serves and both syscalls.c and
// correlate.c now bound their per-event arg loop with — so a leftover x0..x5
// register value past a syscall's real argument count stops printing as if
// it were an argument. syscall_argtypes.c itself isn't host-buildable (it
// pulls in <bpf/bpf.h> for install_arg_types/install_sock_args, unavailable
// without the cross-built libbpf — same reason no existing test links it);
// this test instead loads the shared data table directly and re-implements
// arg_count()'s trivial linear-scan-with-fallback (identical shape to the
// already-proven arg_fd_mask/arg_sock_index in the same file) to check what
// actually moved: the table entries themselves.
#include <stdio.h>
#include <sys/syscall.h>

struct entry { long nr; int count; };
static const struct entry g_arg_counts[] = {
#include "common/syscall_argc.h"
};
static const int g_count = (int)(sizeof(g_arg_counts) / sizeof(g_arg_counts[0]));

static int lookup(long nr) {
    for (int i = 0; i < g_count; i++)
        if (g_arg_counts[i].nr == nr) return g_arg_counts[i].count;
    return 6;
}

static int failures;

static void check(int cond, const char *msg) {
    if (!cond) { printf("FAIL: %s\n", msg); failures++; }
}

int main(void) {
    check(g_count > 0, "table is non-empty after the move to common/");
#ifdef __NR_read
    check(lookup(__NR_read) == 3, "read has 3 args");
#endif
#ifdef __NR_openat
    check(lookup(__NR_openat) == 4, "openat has 4 args");
#endif
#ifdef __NR_close
    check(lookup(__NR_close) == 1, "close has 1 arg");
#endif
    check(lookup(99999) == 6, "unknown syscall falls back to 6");

    if (failures) { printf("%d failure(s)\n", failures); return 1; }
    printf("all checks passed\n");
    return 0;
}
