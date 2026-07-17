// SPDX-License-Identifier: GPL-2.0
// Host unit tests for src/common/evqueue.c (no BPF, no device required).
#include "common/evqueue.h"
#include <stdio.h>
#include <string.h>

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

static void mark_done(struct anubee_evq *q)
{
    pthread_mutex_lock(&q->m);
    q->done = 1;
    pthread_cond_signal(&q->cv);
    pthread_mutex_unlock(&q->m);
}

int main(void)
{
    struct anubee_evq q;
    unsigned char out[256];
    size_t alen;

    // basic push/pop roundtrip
    CHECK(anubee_evq_init(&q, 1024) == 0, "init");
    unsigned char data[] = {1, 2, 3, 4, 5};
    CHECK(anubee_evq_push(&q, data, 5) == 0, "push ok");
    CHECK(anubee_evq_pop(&q, out, sizeof(out), &alen) == 1, "pop returns 1");
    CHECK(alen == 5, "pop len");
    CHECK(memcmp(out, data, 5) == 0, "pop content");
    CHECK(q.dropped == 0, "no drops");
    anubee_evq_destroy(&q);

    // full queue -> drop counter increments
    CHECK(anubee_evq_init(&q, 20) == 0, "init small");  // room for one 8-byte rec (4+8=12)
    unsigned char big[8] = {0xAB};
    CHECK(anubee_evq_push(&q, big, 8) == 0, "push1 ok");
    CHECK(anubee_evq_push(&q, big, 8) == -1, "push2 dropped");
    CHECK(q.dropped == 1, "dropped==1");
    CHECK(anubee_evq_pop(&q, out, sizeof(out), &alen) == 1, "pop after drop");
    CHECK(alen == 8, "alen==8");
    anubee_evq_destroy(&q);

    // GA4: an oversized record (> outcap) is dropped whole, not partially consumed,
    // so the next record stays correctly framed.
    CHECK(anubee_evq_init(&q, 256) == 0, "init5");
    unsigned char wide[40]; memset(wide, 0xCD, sizeof wide);
    CHECK(anubee_evq_push(&q, wide, 40) == 0, "push wide");
    CHECK(anubee_evq_push(&q, data, 5) == 0, "push narrow after wide");
    CHECK(anubee_evq_pop(&q, out, 16, &alen) == 1, "pop skips oversized -> next");
    CHECK(alen == 5, "got the narrow record, not a 16B truncation");
    CHECK(memcmp(out, data, 5) == 0, "framing intact after drop");
    CHECK(q.dropped == 1, "oversized counted as dropped");
    anubee_evq_destroy(&q);

    // done+empty -> pop returns 0 immediately
    CHECK(anubee_evq_init(&q, 256) == 0, "init3");
    mark_done(&q);
    CHECK(anubee_evq_pop(&q, out, sizeof(out), &alen) == 0, "done+empty->0");
    anubee_evq_destroy(&q);

    // done+data -> pop drains data first, then returns 0
    CHECK(anubee_evq_init(&q, 256) == 0, "init4");
    CHECK(anubee_evq_push(&q, data, 5) == 0, "push4");
    mark_done(&q);
    CHECK(anubee_evq_pop(&q, out, sizeof(out), &alen) == 1, "done+data->1");
    CHECK(alen == 5, "alen4==5");
    CHECK(anubee_evq_pop(&q, out, sizeof(out), &alen) == 0, "empty+done->0");
    anubee_evq_destroy(&q);

    // --- pushed/popped accounting (drain progress denominator) ---
    {
        struct anubee_evq q;
        CHECK(anubee_evq_init(&q, 4096) == 0, "counters: init ok");
        CHECK(q.pushed == 0 && q.popped == 0, "counters: zero at init");

        CHECK(anubee_evq_push(&q, "hello", 5) == 0, "counters: push ok");
        CHECK(q.pushed == 1, "counters: push increments pushed");
        CHECK(q.popped == 0, "counters: push leaves popped alone");

        char out[64];
        size_t sz = 0;
        q.done = 1;
        CHECK(anubee_evq_pop(&q, out, sizeof out, &sz) == 1, "counters: pop ok");
        CHECK(sz == 5, "counters: pop size");
        CHECK(q.pushed == 1 && q.popped == 1, "counters: pop increments popped");
        CHECK(q.used == 0, "counters: drained");
        anubee_evq_destroy(&q);
    }

    // --- oversized record: consumes bytes + counts as dropped, never popped ---
    // Pins the intentional divergence the progress bar relies on: bytes advance
    // while the record count does not, because the record was never delivered.
    {
        struct anubee_evq q;
        CHECK(anubee_evq_init(&q, 4096) == 0, "oversized: init ok");
        char big[1000];
        memset(big, 'x', sizeof big);
        CHECK(anubee_evq_push(&q, big, sizeof big) == 0, "oversized: push ok");
        CHECK(q.pushed == 1, "oversized: pushed counted");

        char small[16];
        size_t sz = 0;
        q.done = 1;
        CHECK(anubee_evq_pop(&q, small, sizeof small, &sz) == 0,
              "oversized: pop reports done+empty after draining it");
        CHECK(q.dropped == 1, "oversized: counted as dropped");
        CHECK(q.popped == 0, "oversized: NOT counted as popped");
        CHECK(q.used == 0, "oversized: bytes still consumed");
        anubee_evq_destroy(&q);
    }

    // --- counters survive ring wrap ---
    {
        struct anubee_evq q;
        CHECK(anubee_evq_init(&q, 128) == 0, "wrap: init ok");
        char rec[16];
        memset(rec, 'z', sizeof rec);
        char out[64];
        size_t sz = 0;
        for (int i = 0; i < 50; i++) {
            CHECK(anubee_evq_push(&q, rec, sizeof rec) == 0, "wrap: push ok");
            CHECK(anubee_evq_pop(&q, out, sizeof out, &sz) == 1, "wrap: pop ok");
        }
        CHECK(q.pushed == 50 && q.popped == 50, "wrap: counters exact after wrap");
        CHECK(q.used == 0, "wrap: empty");
        anubee_evq_destroy(&q);
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
