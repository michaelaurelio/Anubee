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
