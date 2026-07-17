// SPDX-License-Identifier: GPL-2.0
#ifndef __ANUBEE_COMMON_SYSCALL_ARGTYPES_H
#define __ANUBEE_COMMON_SYSCALL_ARGTYPES_H

#include <stddef.h>

// Shared syscall arg-decode tables + install/lookup helpers (EPIC I2),
// extracted from byte-identical copies previously duplicated in
// src/correlate/correlate.c and src/syscalls/syscalls.c.
//
// syscalls.c layers its own dense by-nr cache (ARG_TBL_CAP/g_fdmask_by_nr/
// g_sockidx_by_nr/build_arg_tables) on top of arg_fd_mask()/arg_sock_index()
// for its higher per-event volume - that fast path stays syscalls-local, NOT
// here. arg_fd_mask()/arg_sock_index() below are the plain linear-scan forms
// correlate.c uses directly, and that syscalls.c's own build_arg_tables()
// falls back to past ARG_TBL_CAP - see syscalls.c's own arg_fd_mask/
// arg_sock_index for that cache wrapper, unchanged and not moved here.

struct anubee_arg_mask_entry { long nr; unsigned char mask; };
struct anubee_arg_sock_entry { long nr; int arg; };
struct anubee_arg_count_entry { long nr; int count; };

// Which arg holds a sockaddr* (connect/bind at arg1, sendto at arg4).
// Exported (not static) so syscalls.c's build_arg_tables() can scatter this
// into its own dense g_sockidx_by_nr[] cache; a _count sibling is needed
// because an extern array of unknown bound is an incomplete type - a caller
// in another translation unit can't sizeof() it directly.
extern const struct anubee_arg_sock_entry g_sock_args[];
extern const size_t g_sock_args_count;

// Which args are a file descriptor (or *at dirfd) per syscall - bit i =>
// args[i] is an fd. Same cross-TU visibility reason as g_sock_args above.
extern const struct anubee_arg_mask_entry g_fd_args[];
extern const size_t g_fd_args_count;

// Mirror the string/fd/sockaddr tables into their BPF maps. Must run before
// the traced app is launched.
void install_arg_types(int fd);
void install_sock_args(int fd);

// Plain linear-scan lookups - see the file-level comment above for why
// syscalls.c keeps its own dense-cache versions instead of calling these.
unsigned arg_fd_mask(unsigned long long nr);
int arg_sock_index(unsigned long long nr);

// Per-syscall argument count (arm64 ABI), so a printer can show only the real
// arguments instead of leftover register values. Unknown syscalls return 6
// (all of x0..x5). Moved here from src/syscalls/syscalls.c (which kept its
// own copy of the { nr, count } table) so src/correlate/correlate.c's human
// syscall-arg line can bound the same way (anubee correlate output-clarity
// rework) instead of always printing all 6 slots. syscalls.c layers its own
// dense by-nr cache (arg_count_cached(), same reasoning as arg_fd_mask_cached/
// arg_sock_index_cached above) on top of this plain linear-scan form.
extern const struct anubee_arg_count_entry g_arg_counts[];
extern const size_t g_arg_counts_count;
int arg_count(unsigned long long nr);

#endif /* __ANUBEE_COMMON_SYSCALL_ARGTYPES_H */
