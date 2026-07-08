// SPDX-License-Identifier: GPL-2.0
#include <sys/syscall.h>            // __NR_* for the generated table
#include "common/syscall_table.h"

const struct ares_sysent ares_syscall_table[] = {
#include "syscalls_gen.h"
};
const size_t ares_syscall_table_count =
	sizeof(ares_syscall_table) / sizeof(ares_syscall_table[0]);
