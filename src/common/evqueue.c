// SPDX-License-Identifier: GPL-2.0
#include "common/evqueue.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static void q_in(struct ares_evq *q, const void *src, size_t n)
{
    size_t f = q->cap - q->head;
    if (f > n) f = n;
    memcpy(q->buf + q->head, src, f);
    if (n > f) memcpy(q->buf, (const unsigned char *)src + f, n - f);
    q->head = (q->head + n) % q->cap;
    q->used += n;
}

static void q_out(struct ares_evq *q, void *dst, size_t n)
{
    size_t f = q->cap - q->tail;
    if (f > n) f = n;
    memcpy(dst, q->buf + q->tail, f);
    if (n > f) memcpy((unsigned char *)dst + f, q->buf, n - f);
    q->tail = (q->tail + n) % q->cap;
    q->used -= n;
}

int ares_evq_init(struct ares_evq *q, size_t cap)
{
    q->buf = malloc(cap);
    if (!q->buf) return -1;
    q->cap = cap; q->head = q->tail = q->used = 0;
    q->done = 0; q->dropped = 0;
    pthread_mutex_init(&q->m, NULL);
    pthread_cond_init(&q->cv, NULL);
    return 0;
}

int ares_evq_push(struct ares_evq *q, const void *rec, size_t len)
{
    uint32_t s = (uint32_t)len;
    size_t total = 4 + len;
    int ret;
    pthread_mutex_lock(&q->m);
    if (q->cap - q->used < total) {
        q->dropped++;
        ret = -1;
    } else {
        q_in(q, &s, 4);
        q_in(q, rec, len);
        pthread_cond_signal(&q->cv);
        ret = 0;
    }
    pthread_mutex_unlock(&q->m);
    return ret;
}

int ares_evq_pop(struct ares_evq *q, void *out, size_t outcap, size_t *actual_len)
{
    pthread_mutex_lock(&q->m);
    while (q->used == 0 && !q->done)
        pthread_cond_wait(&q->cv, &q->m);
    if (q->used == 0 && q->done) {
        pthread_mutex_unlock(&q->m);
        return 0;
    }
    uint32_t sz;
    q_out(q, &sz, 4);
    size_t n = sz;
    if (n > outcap) n = outcap;    // safety clamp — records are always bounded
    q_out(q, out, n);
    pthread_mutex_unlock(&q->m);
    *actual_len = n;
    return 1;
}

void ares_evq_destroy(struct ares_evq *q)
{
    free(q->buf);
    q->buf = NULL;
    pthread_mutex_destroy(&q->m);
    pthread_cond_destroy(&q->cv);
}
