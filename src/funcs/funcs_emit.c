// SPDX-License-Identifier: GPL-2.0
// Pure structured-record builders for ares funcs (no libbpf/skeleton deps, so
// the host test can link them). Built on the shared serializer + schema.
#include <linux/types.h>
#include "common/emit.h"
#include "common/trace_schema.h"
#include "funcs/ares-tracer.h"

// Structured record builders (opt-in --structured mode). One self-describing
// JSON object per event into j, on the shared schema/serializer so ares-mcp can
// analyze funcs traces with the same field-level tools it uses for syscalls.
void funcs_emit_call(struct jbuf *j, const struct event *e,
                     const char *module, const char *symbol)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");      jb_s(j, trace_type_name(TRACE_CALL)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");        jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");        jb_u64(j, e->h.tid);
    jb_s(j, ",\"module\":\"");   jb_esc(j, module); jb_c(j, '"');
    jb_s(j, ",\"symbol\":\"");   jb_esc(j, symbol); jb_c(j, '"');
    jb_s(j, ",\"entry_addr\":\""); jb_hex(j, e->entry_addr); jb_c(j, '"');
    jb_s(j, ",\"args\":[");
    for (int i = 0; i < NUM_ARGS; i++) {
        if (i) jb_c(j, ',');
        jb_c(j, '"'); jb_hex(j, e->args[i]); jb_c(j, '"');
    }
    jb_s(j, "]}");
}

void funcs_emit_return(struct jbuf *j, const struct event *e,
                       const char *module, const char *symbol)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");      jb_s(j, trace_type_name(TRACE_RETURN)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");        jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");        jb_u64(j, e->h.tid);
    jb_s(j, ",\"module\":\"");   jb_esc(j, module); jb_c(j, '"');
    jb_s(j, ",\"symbol\":\"");   jb_esc(j, symbol); jb_c(j, '"');
    jb_s(j, ",\"retval\":");     jb_i64(j, (long long)e->retval); // retval is ABI-signed; render signed so small negative error codes read naturally
    jb_s(j, ",\"elapsed_ns\":"); jb_u64(j, e->elapsed_ns);
    jb_s(j, "}");
}
