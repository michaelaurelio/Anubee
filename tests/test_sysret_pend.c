// SPDX-License-Identifier: GPL-2.0
// Host unit tests for sysret_pend: pairing a syscall's entry event with its
// return value (from a kretprobe), keyed by thread id.
#include <stdio.h>
#include <string.h>
#include "modules/sysret_pend.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

struct ev { unsigned tid; char path[16]; };

static struct { struct ev ev; long long ret; int known; } out[16];
static int nout;

static void emit(void *ctx, const void *ev, size_t len, long long ret, int known)
{
    (void)ctx;
    if (nout < 16 && len == sizeof(struct ev)) {
        memcpy(&out[nout].ev, ev, len);
        out[nout].ret = ret;
        out[nout].known = known;
    }
    nout++;
}

static struct ev mk(unsigned tid, const char *p)
{
    struct ev e = { .tid = tid };
    snprintf(e.path, sizeof e.path, "%s", p);
    return e;
}

int main(void)
{
    struct sysret_pend *p = sysret_pend_new(2, sizeof(struct ev));
    CHECK(p != NULL, "table allocates");

    // entry is held until its result arrives, then emitted with the result
    struct ev a = mk(100, "/a");
    sysret_pend_entry(p, 100, &a, sizeof a, emit, NULL);
    CHECK(nout == 0, "entry is held, not emitted");
    CHECK(sysret_pend_count(p) == 1, "one pending");
    CHECK(sysret_pend_result(p, 100, -2, emit, NULL) == 1, "result matches the pending tid");
    CHECK(nout == 1 && out[0].known && out[0].ret == -2 && strcmp(out[0].ev.path, "/a") == 0,
          "entry emitted with its return value");
    CHECK(sysret_pend_count(p) == 0, "nothing pending after the result");

    // a result for a tid with nothing pending is ignored
    CHECK(sysret_pend_result(p, 999, 0, emit, NULL) == 0, "unmatched result ignored");
    CHECK(nout == 1, "unmatched result emits nothing");

    // results pair by tid, not by arrival order
    nout = 0;
    struct ev b = mk(200, "/b"), c = mk(300, "/c");
    sysret_pend_entry(p, 200, &b, sizeof b, emit, NULL);
    sysret_pend_entry(p, 300, &c, sizeof c, emit, NULL);
    sysret_pend_result(p, 300, 5, emit, NULL);
    sysret_pend_result(p, 200, 3, emit, NULL);
    CHECK(nout == 2 && strcmp(out[0].ev.path, "/c") == 0 && out[0].ret == 5
          && strcmp(out[1].ev.path, "/b") == 0 && out[1].ret == 3, "pairing is by tid");

    // a second entry on the same tid (result lost) flushes the first as unknown
    nout = 0;
    struct ev d1 = mk(400, "/d1"), d2 = mk(400, "/d2");
    sysret_pend_entry(p, 400, &d1, sizeof d1, emit, NULL);
    sysret_pend_entry(p, 400, &d2, sizeof d2, emit, NULL);
    CHECK(nout == 1 && !out[0].known && strcmp(out[0].ev.path, "/d1") == 0,
          "older entry on the same tid is flushed with result unknown");
    sysret_pend_result(p, 400, 0, emit, NULL);
    CHECK(nout == 2 && out[1].known && strcmp(out[1].ev.path, "/d2") == 0, "newer entry gets the result");

    // table full: the new entry is emitted at once, result unknown (never dropped)
    nout = 0;
    struct ev e1 = mk(501, "/e1"), e2 = mk(502, "/e2"), e3 = mk(503, "/e3");
    sysret_pend_entry(p, 501, &e1, sizeof e1, emit, NULL);
    sysret_pend_entry(p, 502, &e2, sizeof e2, emit, NULL);
    sysret_pend_entry(p, 503, &e3, sizeof e3, emit, NULL);
    CHECK(nout == 1 && !out[0].known && strcmp(out[0].ev.path, "/e3") == 0,
          "entry that doesn't fit is emitted immediately, result unknown");

    // flush emits everything still pending, result unknown
    sysret_pend_flush(p, emit, NULL);
    CHECK(nout == 3 && !out[1].known && !out[2].known, "flush emits the rest as unknown");
    CHECK(sysret_pend_count(p) == 0, "nothing pending after flush");

    // an event bigger than the slot is emitted at once rather than truncated
    nout = 0;
    struct sysret_pend *small = sysret_pend_new(4, 4);
    struct ev big = mk(600, "/big");
    sysret_pend_entry(small, 600, &big, sizeof big, emit, NULL);
    CHECK(nout == 1 && !out[0].known && strcmp(out[0].ev.path, "/big") == 0, "oversized event emitted whole");
    sysret_pend_free(small);

    sysret_pend_free(p);
    printf("test_sysret_pend: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
