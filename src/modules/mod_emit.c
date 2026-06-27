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
