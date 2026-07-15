// SPDX-License-Identifier: GPL-2.0
// Host unit test for dump's maps walker, driven against /proc/self/maps.
//
// The walker owns the selection, the per-base dedup and the covered-range skip
// that BOTH the dump and check paths depend on. It parses no ELF - the callbacks
// do - so it is host-portable even though rebuild.c's dumping is aarch64-only.
//
// Before this test dump_pid_modules had no coverage at all; the extraction it
// guards rewired a working, shipped function.
#include "dump/rebuild.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++;                            \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); }      \
} while (0)

#define MAXREC 64
struct rec {
    unsigned long long base[MAXREC];
    char               path[MAXREC][256];
    int                n;
    unsigned long long claim_end;   // if set, every cb claims this much coverage
    int                fail_all;    // if set, every cb reports failure
};

static int rec_cb(int pid, int memfd, unsigned long long base, const char *path,
                  unsigned long long file_off, void *ctx, unsigned long long *covered_end)
{
    (void)pid;
    (void)file_off;
    struct rec *r = (struct rec *)ctx;
    CHECK(memfd >= 0, "callback gets an open memfd");
    if (r->n < MAXREC) {
        r->base[r->n] = base;
        snprintf(r->path[r->n], sizeof(r->path[0]), "%s", path);
        r->n++;
    }
    if (r->claim_end)
        *covered_end = base + r->claim_end;
    return r->fail_all ? -1 : 0;
}

int main(void)
{
    int self = (int)getpid();

    // --- a pattern selector finds this process's own libc ---
    const char *pats[] = { "libc" };
    struct dump_sel sel = { .pats = pats, .npat = 1 };
    struct rec r = { 0 };
    int got = dump_walk_pid_modules(self, &sel, rec_cb, &r);
    CHECK(got >= 1, "walker finds at least one libc mapping in self");
    CHECK(r.n == got, "return value equals successful callback count");
    for (int i = 0; i < r.n; i++)
        CHECK(strstr(r.path[i], "libc") != NULL, "every reported path matched the selector");

    // --- each distinct module is reported exactly once (base dedup) ---
    // libc has several PT_LOAD segments; without the dedup the walker would call
    // back once per segment line in /proc/self/maps.
    for (int i = 0; i < r.n; i++)
        for (int k = i + 1; k < r.n; k++)
            CHECK(r.base[i] != r.base[k], "no base reported twice");

    // --- a base selector re-finds exactly that module, and nothing else ---
    if (r.n > 0) {
        unsigned long long want = r.base[0];
        struct dump_sel bsel = { .bases = &want, .nbase = 1 };
        struct rec r2 = { 0 };
        int got2 = dump_walk_pid_modules(self, &bsel, rec_cb, &r2);
        CHECK(got2 == 1, "exact-base selector reports exactly one module");
        CHECK(r2.n == 1 && r2.base[0] == want, "and it is the requested base");
    }

    // --- a callback reporting failure is not counted as a success ---
    struct rec rf = { .fail_all = 1 };
    int gotf = dump_walk_pid_modules(self, &sel, rec_cb, &rf);
    CHECK(gotf == 0, "failing callbacks count zero successes");
    CHECK(rf.n >= 1, "but the walker still visited the modules");

    // --- the covered-range skip suppresses candidates inside a claimed range ---
    // This needs >= 2 DISTINCT bases to mean anything. With a single matching
    // module (libc's segments share one load base) the done_bases dedup alone
    // explains "one callback", and this check would pass even against a walker
    // with the coverage skip deleted. Select every file-backed mapping instead -
    // "/" is a substring of any real path - so several distinct bases are live.
    const char *anypat[] = { "/" };
    struct dump_sel broad = { .pats = anypat, .npat = 1 };
    struct rec rb = { 0 };
    dump_walk_pid_modules(self, &broad, rec_cb, &rb);
    CHECK(rb.n >= 2, "the broad selector really does see several distinct modules");

    // Maps are address-sorted ascending, so the first module claiming half the
    // address space covers every later candidate. Their bases are all distinct,
    // so done_bases cannot suppress them - only the coverage-range skip can.
    struct rec rc = { .claim_end = ~0ULL / 2 };
    dump_walk_pid_modules(self, &broad, rec_cb, &rc);
    CHECK(rc.n == 1, "a module covering everything suppresses later candidates");

    // --- an empty selector matches nothing, and a dead pid returns -1 ---
    struct dump_sel none = { 0 };
    struct rec r3 = { 0 };
    CHECK(dump_walk_pid_modules(self, &none, rec_cb, &r3) == 0, "empty selector -> 0");
    CHECK(r3.n == 0, "empty selector never invokes the callback");
    struct rec r4 = { 0 };
    CHECK(dump_walk_pid_modules(999999, &sel, rec_cb, &r4) == -1, "unreadable pid -> -1");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
