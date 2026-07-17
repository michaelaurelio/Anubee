// SPDX-License-Identifier: GPL-2.0
// Shared syscall-name table data (R9 residual): the {nr,name} rows generated
// from the toolchain's <sys/syscall.h> at build time, previously compiled
// separately into both syscalls.c and correlate.c from the same generated
// header (build/syscalls_gen.h). One copy now; both engines link against it.
#ifndef __ANUBEE_COMMON_SYSCALL_TABLE_H
#define __ANUBEE_COMMON_SYSCALL_TABLE_H

#include <stddef.h>
#include "common/syscall_index.h"   // struct anubee_sysent

extern const struct anubee_sysent anubee_syscall_table[];
extern const size_t anubee_syscall_table_count;

#endif /* __ANUBEE_COMMON_SYSCALL_TABLE_H */
