// SPDX-License-Identifier: GPL-2.0
// Shared event schema for the `ares correlate` engine. Included by both the BPF
// object (after vmlinux.h) and the userspace loader (after libbpf headers), so it
// must not pull in its own <linux/types.h> (would clash with vmlinux.h).
#ifndef __ARES_CORRELATE_H
#define __ARES_CORRELATE_H

#define CORR_NUM_ARGS 8      // saved function-entry args
#define CORR_SYS_ARGS 6      // aarch64 syscall args x0..x5

enum corr_event_type {
    CORR_EV_FUNC    = 1,     // a probed function was entered (span opened)
    CORR_EV_SYSCALL = 2,     // a syscall issued while inside a probed function
    CORR_EV_RETURN  = 3,     // a probed function returned (span closed)
    CORR_EV_MAP     = 4,     // an executable library was mapped (shared lib_trace)
    CORR_EV_UNMAP   = 5,     // an executable range was unmapped (shared lib_trace)
};

#include "common/trace_schema.h"
#include "common/lib_trace.h"   // struct lib_map_event / lib_unmap_event + emitters

// A probed-function entry. `span` is this frame's id; `parent_span` links to the
// enclosing probed frame (0 = outermost).
struct corr_func_event {
    struct trace_event_header h;
    __u64 span;
    __u64 parent_span;
    __u64 entry_addr;
    __u64 args[CORR_NUM_ARGS];
};

// A syscall attributed to the innermost open span on its thread.
struct corr_syscall_event {
    struct trace_event_header h;
    __u64 span;
    __u64 nr;
    __u64 args[CORR_SYS_ARGS];
};

// A probed-function return. `span` is the closing frame's id, so a consumer joins
// it to the CORR_EV_FUNC that opened the span and every CORR_EV_SYSCALL tagged with
// it. `retval` is the raw x0 at return (no decode); `elapsed_ns` is the exact span
// duration (return ktime - entry ktime).
struct corr_return_event {
    struct trace_event_header h;
    __u64 span;
    __u64 entry_addr;
    __u64 retval;
    __u64 elapsed_ns;
};

struct jbuf;  /* common/emit.h */
void corr_emit_func(struct jbuf *j, const struct corr_func_event *e);
void corr_emit_syscall(struct jbuf *j, const struct corr_syscall_event *e,
                       const char *syscall_name);
void corr_emit_return(struct jbuf *j, const struct corr_return_event *e);

#endif /* __ARES_CORRELATE_H */
