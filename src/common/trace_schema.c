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
    case TRACE_MAP:       return "map";
    case TRACE_UNMAP:     return "unmap";
    case TRACE_SPAWN:     return "spawn";
    case TRACE_PROC_EXIT: return "proc_exit";
    case TRACE_EXECVE:    return "execve";
    case TRACE_PROP:      return "prop";
    case TRACE_STACK:     return "stack";
    case TRACE_FUNC:      return "func";
    default:              return "unknown";
    }
}
