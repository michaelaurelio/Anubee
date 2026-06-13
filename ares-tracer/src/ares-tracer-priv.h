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
extern bool list_libs;
extern bool resolve_syms;

// Functions defined in ares-tracer.c, shared with modules
void out_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void err_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ts_print(const char *fmt, ...)  __attribute__((format(printf, 1, 2)));
int  lookup_caller(pid_t pid, __u64 addr,
                   char *mod_out, size_t mod_sz, unsigned long *off_out);

#endif /* __ARES_TRACER_PRIV_H */
