// SPDX-License-Identifier: GPL-2.0
// Pure structured-record builders for ares mod analyzers (no libbpf/skeleton
// deps, so the host test can link them). Built on the shared serializer + schema.
#include <linux/types.h>
#include "common/emit.h"
#include "common/trace_schema.h"
#include "modules/mod_events.h"

void mod_emit_spawn(struct jbuf *j, const struct spawn_event *e)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");      jb_s(j, trace_type_name(TRACE_SPAWN)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");        jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");        jb_u64(j, e->h.tid);
    jb_s(j, ",\"child_pid\":"); jb_u64(j, e->child_pid);
    jb_s(j, ",\"comm\":\"");     jb_esc(j, e->comm); jb_c(j, '"');
    jb_c(j, '}');
}

void mod_emit_proc_exit(struct jbuf *j, const struct proc_exit_event *e)
{
    int sig    = e->exit_code & 0x7f;
    int status = (e->exit_code >> 8) & 0xff;

    jb_c(j, '{');
    jb_s(j, "\"type\":\"");      jb_s(j, trace_type_name(TRACE_PROC_EXIT)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");        jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");        jb_u64(j, e->h.tid);
    jb_s(j, ",\"comm\":\"");     jb_esc(j, e->comm); jb_c(j, '"');
    if (sig)
        { jb_s(j, ",\"signal\":"); jb_u64(j, sig); }
    else
        { jb_s(j, ",\"exit_status\":"); jb_u64(j, status); }
    jb_c(j, '}');
}

// syms: resolved symbol strings for each frame (NULL or syms[i]==NULL/"" → omit symbol field).
// Caller (execve.c) resolves via sym_resolve; passing NULL produces addr-only output.
void mod_emit_execve(struct jbuf *j, const struct execve_event *e, const char *const *syms)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");       jb_s(j, trace_type_name(TRACE_EXECVE)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");         jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");         jb_u64(j, e->h.tid);
    jb_s(j, ",\"comm\":\"");      jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"filename\":\"");  jb_esc(j, e->filename); jb_c(j, '"');
    jb_s(j, ",\"argc\":");        jb_u64(j, e->argc);
    jb_s(j, ",\"argv\":[");
    for (int i = 0; i < (int)e->argc && i < MAX_ARGV_ENTRIES; i++) {
        if (i) jb_c(j, ',');
        jb_c(j, '"'); jb_esc(j, e->argv[i]); jb_c(j, '"');
    }
    jb_c(j, ']');
    jb_s(j, ",\"backtrace\":[");
    for (int i = 0, first = 1; i < (int)e->stack_depth && i < STACK_DEPTH; i++) {
        if (e->call_stack[i] == 0) break;
        if (!first) jb_c(j, ',');
        first = 0;
        jb_s(j, "{\"frame\":");  jb_u64(j, i);
        jb_s(j, ",\"addr\":\""); jb_hex(j, e->call_stack[i]); jb_c(j, '"');
        if (syms && syms[i] && syms[i][0]) {
            jb_s(j, ",\"symbol\":\""); jb_esc(j, syms[i]); jb_c(j, '"');
        }
        jb_c(j, '}');
    }
    jb_c(j, ']');
    jb_c(j, '}');
}

void mod_emit_prop(struct jbuf *j, const struct prop_event *e)
{
    const char *op;
    switch (e->h.type) {
    case MOD_EV_PROP_GET:  op = "get";     break;
    case MOD_EV_PROP_FIND: op = "find";    break;
    case MOD_EV_PROP_SCAN: op = "scan";    break;
    case MOD_EV_PROP_READ: op = "read";    break;
    default:               op = "unknown"; break;
    }
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");    jb_s(j, trace_type_name(TRACE_PROP)); jb_c(j, '"');
    jb_s(j, ",\"op\":\"");     jb_s(j, op); jb_c(j, '"');
    jb_s(j, ",\"pid\":");      jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");      jb_u64(j, e->h.tid);
    jb_s(j, ",\"comm\":\"");   jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"name\":\"");   jb_esc(j, e->name); jb_c(j, '"');
    jb_s(j, ",\"value\":\"");  jb_esc(j, e->value); jb_c(j, '"');
    jb_s(j, ",\"is_ret\":");   jb_u64(j, e->is_ret);
    jb_s(j, ",\"found\":");    jb_u64(j, e->found);
    jb_c(j, '}');
}
