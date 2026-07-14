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
    case TRACE_MASSDELETE_DETECT: return "massdelete_detect";
    case TRACE_DUMP:       return "dump";
    case TRACE_EXFIL_DETECT: return "exfil_detect";
    case TRACE_A11Y_ABUSE:        return "a11y_abuse";
    case TRACE_FILELESS_EXEC:     return "fileless_exec";
    case TRACE_MEDIAPROJ_ABUSE:   return "mediaproj_abuse";
    default:              return "unknown";
    }
}
