// SPDX-License-Identifier: GPL-2.0
#ifndef __FUNCS_PRIV_H
#define __FUNCS_PRIV_H

#include <stdbool.h>
#include <stddef.h>
#include <signal.h>
#include <sys/types.h>
#include <linux/types.h>

// Globals defined in funcs.c, shared with modules
extern bool verbose;
extern bool caller_only;
extern bool resolve_syms;

// Engine driver, split into three phases so the uprobe engine runs standalone
// (cmd_funcs) or under the `trace` coordinator alongside the kprobe engine from
// a single app launch. funcs_setup arms probes + UID but does NOT launch; the
// caller owns the launch. On failure funcs_setup cleans up and returns nonzero.
// Declared in common/engine_driver.h (AA3) so trace.c and this definition can't drift.
#include "common/engine_driver.h"

// Functions defined in funcs.c, shared with modules
void out_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void err_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ts_print(const char *fmt, ...)  __attribute__((format(printf, 1, 2)));
#include "common/symbolize.h"   // sym_resolve / sym_flush_pid (shared call-stack resolver)

// Structured-record builders defined in funcs_emit.c (pure, no libbpf deps).
// Called from funcs.c when --structured mode is active.
struct jbuf;   // common/emit.h
struct event;  // funcs.h
#include "common/probe_resolve.h"
// syms: frame-parallel resolved symbol strings for e->call_stack (caller-resolved
// via sym_resolve, same as it already does for the console); NULL entry or NULL
// array omits the per-frame "symbol" field. Keeps this pair symbolizer-free.
void funcs_emit_call(struct jbuf *j, const struct event *e, const char *module, const char *symbol, const probe_target_t *target, const char *java_stack, const char *const *syms);
void funcs_emit_return(struct jbuf *j, const struct event *e, const char *module, const char *symbol, const probe_target_t *target, const char *const *syms);

#endif /* __FUNCS_PRIV_H */
