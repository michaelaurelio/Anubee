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
static volatile sig_atomic_t  g_drain_active;

void ares_drain_set_active(int on)
{
    g_drain_active = on;
}

// Async-signal-safe by construction: static storage, emitted with write(2).
// Never fprintf from here - the signal can land on the worker thread while it
// holds stderr's FILE lock, and taking stdio locks in a handler can deadlock
// the one path that must always work. Same reason there is no formatted
// backlog count: snprintf in a handler is the same class of mistake.
// The leading \n steps off the drain progress bar instead of overwriting it.
static const char ABORT_MSG[] =
    "\nares: aborting post-processing - queued events and the coverage and\n"
    "summary records are LOST. Output files may end on an incomplete line.\n";

static void runtime_sig_handler(int sig)
{
    (void)sig;
    if (g_stop_flag)
        *g_stop_flag = 1;
    if (++g_stop_count > 1) {
        if (g_drain_active)
            (void)!write(STDERR_FILENO, ABORT_MSG, sizeof(ABORT_MSG) - 1);
        _exit(130);
    }
}

void ares_install_stop_handler(volatile sig_atomic_t *flag)
{
    g_stop_flag    = flag;
    g_stop_count   = 0;
    g_drain_active = 0;
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
