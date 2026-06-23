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

static void mark_done(struct ares_evq *q)
{
    pthread_mutex_lock(&q->m);
    q->done = 1;
    pthread_cond_signal(&q->cv);
    pthread_mutex_unlock(&q->m);
}

int main(void)
{
    struct ares_evq q;
    unsigned char out[256];
    size_t alen;

    // basic push/pop roundtrip
    CHECK(ares_evq_init(&q, 1024) == 0, "init");
    unsigned char data[] = {1, 2, 3, 4, 5};
    CHECK(ares_evq_push(&q, data, 5) == 0, "push ok");
    CHECK(ares_evq_pop(&q, out, sizeof(out), &alen) == 1, "pop returns 1");
    CHECK(alen == 5, "pop len");
    CHECK(memcmp(out, data, 5) == 0, "pop content");
    CHECK(q.dropped == 0, "no drops");
    ares_evq_destroy(&q);

    // full queue -> drop counter increments
    CHECK(ares_evq_init(&q, 20) == 0, "init small");  // room for one 8-byte rec (4+8=12)
    unsigned char big[8] = {0xAB};
    CHECK(ares_evq_push(&q, big, 8) == 0, "push1 ok");
    CHECK(ares_evq_push(&q, big, 8) == -1, "push2 dropped");
    CHECK(q.dropped == 1, "dropped==1");
    CHECK(ares_evq_pop(&q, out, sizeof(out), &alen) == 1, "pop after drop");
    CHECK(alen == 8, "alen==8");
    ares_evq_destroy(&q);

    // done+empty -> pop returns 0 immediately
    CHECK(ares_evq_init(&q, 256) == 0, "init3");
    mark_done(&q);
    CHECK(ares_evq_pop(&q, out, sizeof(out), &alen) == 0, "done+empty->0");
    ares_evq_destroy(&q);

    // done+data -> pop drains data first, then returns 0
    CHECK(ares_evq_init(&q, 256) == 0, "init4");
    CHECK(ares_evq_push(&q, data, 5) == 0, "push4");
    mark_done(&q);
    CHECK(ares_evq_pop(&q, out, sizeof(out), &alen) == 1, "done+data->1");
    CHECK(alen == 5, "alen4==5");
    CHECK(ares_evq_pop(&q, out, sizeof(out), &alen) == 0, "empty+done->0");
    ares_evq_destroy(&q);

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
