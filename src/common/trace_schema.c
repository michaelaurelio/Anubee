// SPDX-License-Identifier: GPL-2.0
// Userspace half of the shared trace schema: the type->name table. Kept out of
// the header so BPF objects (which include trace_schema.h) never compile it.
#include <linux/types.h>
#include "common/trace_schema.h"

const char *trace_type_name(unsigned type)
{
    switch (type) {
    case TRACE_CALL:      return "call";
    case TRACE_RETURN:    return "return";
    case TRACE_SYSCALL:   return "syscall";
    case TRACE_LIB:       return "lib";
    case TRACE_UNLIB:     return "unlib";
    case TRACE_SPAWN:     return "spawn";
    case TRACE_PROC_EXIT: return "proc_exit";
    case TRACE_EXECVE:    return "execve";
    case TRACE_PROP:      return "prop";
    case TRACE_STACK:     return "stack";
    case TRACE_FUNC:      return "func";
    case TRACE_FILE_ACCESS: return "file_access";
    case TRACE_RANSOMWARE_BURST: return "ransomware_burst";
    case TRACE_DUMP:       return "dump";
    default:              return "unknown";
    }
}
