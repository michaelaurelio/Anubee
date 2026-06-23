// SPDX-License-Identifier: GPL-2.0
// SPSC byte-queue for decoupled drain: producer (ring callback) writes, one
// consumer (worker thread) reads. [4-byte len][payload] framing.
#ifndef __ARES_COMMON_EVQUEUE_H
#define __ARES_COMMON_EVQUEUE_H

#include <stddef.h>
#include <pthread.h>

// ponytail: SPSC — single producer (ring cb) + single consumer (worker).
// No MPMC machinery; callers ensure the contract.
struct ares_evq {
    unsigned char  *buf;
    size_t          cap, head, tail, used;
    pthread_mutex_t m;
    pthread_cond_t  cv;
    int             done;
    unsigned long long dropped; // events discarded (queue full)
};

// Allocate the ring (cap bytes). Returns 0 on success, -1 on malloc failure.
int  ares_evq_init(struct ares_evq *q, size_t cap);

// Frame [4-byte len][payload] and push. Thread-safe (locks internally).
// Returns 0 on success; -1 and increments q->dropped if queue is full.
int  ares_evq_push(struct ares_evq *q, const void *rec, size_t len);

// Block until a record is available or the queue is done+empty.
// Pops one record into out (clamped to outcap); sets *actual_len.
// Returns 1 if a record was popped, 0 if done+empty (worker should exit).
int  ares_evq_pop(struct ares_evq *q, void *out, size_t outcap, size_t *actual_len);

// Free the ring buffer and destroy the mutex/cond. Call after joining the consumer.
void ares_evq_destroy(struct ares_evq *q);

#endif /* __ARES_COMMON_EVQUEUE_H */
