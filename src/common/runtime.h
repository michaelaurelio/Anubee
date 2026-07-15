// SPDX-License-Identifier: GPL-2.0
// Shared engine-runtime helpers: signal handling, drop accounting, ring sizing.
//
// BPF-dependent helpers (ares_libbpf_quiet, ares_drops_read) are declared as
// static inline and only activated when <bpf/libbpf.h> has been included before
// this header — so runtime.h stays host-testable without libbpf.
#ifndef __ARES_COMMON_RUNTIME_H
#define __ARES_COMMON_RUNTIME_H

#include <signal.h>
#include <stdarg.h>

// Install SIGINT + SIGTERM → 2-stage stop: 1st signal sets *flag, 2nd _exit(130).
// Call once from cmd_* (not from setup/run, so the trace coordinator can install
// its own handler and let both engines share a single stop flag).
void ares_install_stop_handler(volatile sig_atomic_t *flag);

// Mark a post-processing drain as in flight. While set, a 2nd SIGINT/SIGTERM
// writes a one-line loss warning to stderr before _exit(130), so an impatient
// Ctrl-C states its own cost instead of silently discarding the queue.
//
// Set when the drain starts and cleared when it finishes - deliberately NOT
// gated on the progress UI's 300ms timer, so a fast double-tap still warns.
void ares_drain_set_active(int on);

// Teardown drop report to stderr. Always prints something so "no message" never
// means "didn't check":
//   zero:       "no events dropped"
//   ring only:  "N event(s) dropped (ring buffer full) — trace incomplete"
//   both:       "N event(s) dropped (K kernel ring, Q queue) — trace incomplete"
void ares_drops_report(unsigned long long kdrops, unsigned long long qdrops);

// Round v up to the next power of two (v == 0 → 1). BPF ring maps require
// power-of-two sizes.
unsigned long ares_round_pow2(unsigned long v);

// BPF-dependent helpers — activated when <bpf/libbpf.h> was included first.
// Defined as static inline so runtime.c has no libbpf dependency.
#ifdef __LIBBPF_LIBBPF_H
#include <bpf/bpf.h>
#include <linux/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

// ARES_DEBUG-gated libbpf print callback. Pass to libbpf_set_print().
// ponytail: trivial 4-line helper; static inline avoids a cross-compilation-unit
// reference from each engine into common.part.o just for a gated vfprintf.
static inline int ares_libbpf_quiet(enum libbpf_print_level lvl,
                                     const char *fmt, va_list ap)
{
    if (lvl == LIBBPF_DEBUG && !getenv("ARES_DEBUG"))
        return 0;
    return vfprintf(stderr, fmt, ap);
}

// Poll rb until *stop is set. Benign EINTR is ignored; any other poll error ends the
// loop and is returned (<0). tick (if non-NULL) is called once per poll return — used
// for periodic status work that self-throttles via its own counter.
// ponytail: one loop for all engines; 200ms bounds Ctrl-C latency and epoll wakes
// immediately on data so the timeout never delays draining.
static inline int ares_rb_poll_until_cb(struct ring_buffer *rb,
                                        volatile sig_atomic_t *stop,
                                        void (*tick)(void *), void *ctx)
{
	int err = 0;
	while (!*stop) {
		err = ring_buffer__poll(rb, 200);
		if (err < 0 && err != -EINTR)
			break;
		err = 0;
		if (tick)
			tick(ctx);
	}
	return err;
}

static inline void ares_rb_poll_until(struct ring_buffer *rb,
                                      volatile sig_atomic_t *stop)
{
	(void)ares_rb_poll_until_cb(rb, stop, NULL, NULL);
}

// Drain N independent ring buffers from one thread until *stop. Non-blocking
// consume across all rbs; sleep 100ms only when a full pass drained nothing, so
// a steady event stream never sleeps. Single writer => callers share one sink
// with no locking.
// ponytail: 100ms idle ceiling bounds Ctrl-C latency; swap to a merged epoll over
// ring_buffer__epoll_fd() if sub-100ms first-event latency ever matters.
static inline void ares_rb_poll_multi(struct ring_buffer **rbs, int n,
                                      volatile sig_atomic_t *stop)
{
	while (!*stop) {
		int total = 0;
		for (int i = 0; i < n; i++) {
			int c = ring_buffer__consume(rbs[i]);   // non-blocking
			if (c > 0) total += c;
		}
		if (total == 0) {
			struct timespec ts = { 0, 100 * 1000 * 1000 };
			nanosleep(&ts, NULL);                    // wakes early on SIGINT (EINTR)
		}
	}
}

// Sum per-CPU dropped-event counters from a BPF PERCPU_ARRAY at key 0.
static inline unsigned long long ares_drops_read(int map_fd)
{
    int ncpu = libbpf_num_possible_cpus();
    if (ncpu < 1) ncpu = 1;
    __u64 *vals = calloc((size_t)ncpu, sizeof(__u64));
    if (!vals) return 0;
    __u32 k = 0;
    unsigned long long total = 0;
    if (bpf_map_lookup_elem(map_fd, &k, vals) == 0)
        for (int i = 0; i < ncpu; i++)
            total += vals[i];
    free(vals);
    return total;
}
#endif /* __LIBBPF_LIBBPF_H */

#endif /* __ARES_COMMON_RUNTIME_H */
