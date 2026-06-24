// SPDX-License-Identifier: GPL-2.0
#ifndef __ARES_TRACER_PRIV_H
#define __ARES_TRACER_PRIV_H

#include <stdbool.h>
#include <stddef.h>
#include <signal.h>
#include <sys/types.h>
#include <linux/types.h>

// Globals defined in ares-tracer.c, shared with modules
extern bool verbose;
extern bool caller_only;
extern bool resolve_syms;

// Engine driver, split into three phases so the uprobe engine runs standalone
// (cmd_funcs) or under the `trace` coordinator alongside the kprobe engine from
// a single app launch. funcs_setup arms probes + UID but does NOT launch; the
// caller owns the launch. On failure funcs_setup cleans up and returns nonzero.
struct ares_run_ctx;   // common/launch.h
int  funcs_setup(int argc, char **argv, const struct ares_run_ctx *rc);
int  funcs_run(volatile sig_atomic_t *stop);
void funcs_teardown(void);

// Functions defined in ares-tracer.c, shared with modules
void out_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void err_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ts_print(const char *fmt, ...)  __attribute__((format(printf, 1, 2)));
#include "common/symbolize.h"   // sym_resolve / sym_flush_pid (shared call-stack resolver)

// Structured-record builders defined in funcs_emit.c (pure, no libbpf deps).
// Called from ares-tracer.c when --structured mode is active.
struct jbuf;   // common/emit.h
struct event;  // ares-tracer.h
#include "common/probe_resolve.h"
void funcs_emit_call(struct jbuf *j, const struct event *e, const char *module, const char *symbol, const probe_target_t *target);
void funcs_emit_return(struct jbuf *j, const struct event *e, const char *module, const char *symbol, const probe_target_t *target);

#endif /* __ARES_TRACER_PRIV_H */
