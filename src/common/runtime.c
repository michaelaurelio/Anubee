// SPDX-License-Identifier: GPL-2.0
// Shared engine-runtime helpers (pure POSIX — no libbpf dependency).
// BPF-dependent helpers live as static inline in runtime.h.
#include "common/runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Shared state for the 2-stage stop handler. Written once before any signals.
static volatile sig_atomic_t *g_stop_flag;
static volatile sig_atomic_t  g_stop_count;

static void runtime_sig_handler(int sig)
{
    (void)sig;
    if (g_stop_flag)
        *g_stop_flag = 1;
    if (++g_stop_count > 1)
        _exit(130);
}

void ares_install_stop_handler(volatile sig_atomic_t *flag)
{
    g_stop_flag  = flag;
    g_stop_count = 0;
    signal(SIGINT,  runtime_sig_handler);
    signal(SIGTERM, runtime_sig_handler);
}

void ares_drops_report(unsigned long long kdrops, unsigned long long qdrops)
{
    unsigned long long total = kdrops + qdrops;
    if (!total) {
        fprintf(stderr, "no events dropped\n");
        return;
    }
    if (!qdrops)
        fprintf(stderr, "%llu event(s) dropped (ring buffer full)"
                " — trace incomplete\n", total);
    else
        fprintf(stderr, "%llu event(s) dropped (%llu kernel ring, %llu queue)"
                " — trace incomplete\n", total, kdrops, qdrops);
}

unsigned long ares_round_pow2(unsigned long v)
{
    if (!v) return 1;
    unsigned long p = 1;
    while (p < v)
        p <<= 1;
    return p;
}
