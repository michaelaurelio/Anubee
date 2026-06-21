// SPDX-License-Identifier: GPL-2.0
#ifndef __ARES_TRACER_PRIV_H
#define __ARES_TRACER_PRIV_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <linux/types.h>

// Globals defined in ares-tracer.c, shared with modules
extern bool verbose;
extern bool caller_only;
extern bool resolve_syms;

// Functions defined in ares-tracer.c, shared with modules
void out_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void err_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ts_print(const char *fmt, ...)  __attribute__((format(printf, 1, 2)));
int  lookup_caller(pid_t pid, __u64 addr,
                   char *mod_out, size_t mod_sz, unsigned long *off_out);

// Structured-record builders defined in funcs_emit.c (pure, no libbpf deps).
// Called from ares-tracer.c when --structured mode is active.
struct jbuf;   // common/emit.h
struct event;  // ares-tracer.h
void funcs_emit_call(struct jbuf *j, const struct event *e, const char *module, const char *symbol);
void funcs_emit_return(struct jbuf *j, const struct event *e, const char *module, const char *symbol);

#endif /* __ARES_TRACER_PRIV_H */
