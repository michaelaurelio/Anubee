// SPDX-License-Identifier: GPL-2.0
// Shared event schema for the `ares correlate` engine. Included by both the BPF
// object (after vmlinux.h) and the userspace loader (after libbpf headers), so it
// must not pull in its own <linux/types.h> (would clash with vmlinux.h).
#ifndef __ARES_CORRELATE_H
#define __ARES_CORRELATE_H

#define CORR_NUM_ARGS 8      // saved function-entry args
#define CORR_SYS_ARGS 6      // aarch64 syscall args x0..x5

// String/sockaddr capture sizing — matches syscalls.h so the two engines'
// BPF-side capture logic (copied verbatim) sees identical bounds.
#define CORR_STR_SLOTS 4
#define CORR_STR_MAX   256
#define CORR_SOCK_MAX  64

enum corr_event_type {
    CORR_EV_FUNC        = 1, // a probed function was entered (span opened)
    CORR_EV_SYSCALL     = 2, // a syscall issued while inside a probed function
    CORR_EV_FUNC_RETURN = 3, // a --returns-probed function returned (span closed)
};

#include "common/trace_schema.h"

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
    __u32 str_present;                       // bit i set => str[i] is valid
    char  str[CORR_STR_SLOTS][CORR_STR_MAX]; // string value of args[i]
    __u32 sock_len;                          // bytes valid in sock[], 0 = none
    __u8  sock[CORR_SOCK_MAX];               // raw sockaddr (connect/bind/sendto)
};

// A --returns-probed function's return (authoritative span close).
struct corr_func_return_event {
    struct trace_event_header h;
    __u64 span;
    __u64 entry_addr;
    __u64 retval;
    __u64 elapsed_ns;
};

struct jbuf;  /* common/emit.h */
void corr_emit_func(struct jbuf *j, const struct corr_func_event *e);
void corr_emit_syscall(struct jbuf *j, const struct corr_syscall_event *e,
                       const char *syscall_name, unsigned fdmask, int sockidx);
void corr_emit_func_return(struct jbuf *j, const struct corr_func_return_event *e);

#endif /* __ARES_CORRELATE_H */
