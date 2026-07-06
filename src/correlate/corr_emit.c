// SPDX-License-Identifier: GPL-2.0
// Pure structured-record builders for ares correlate (no libbpf deps, so the
// host test links them). Built on the shared serializer + flag decoder. The
// syscall-name lookup is passed in by the caller (the generated table lives in
// correlate.c), keeping this unit free of syscalls_gen.h.
#include <linux/types.h>
#include "common/emit.h"
#include "common/decode.h"
#include "common/trace_schema.h"
#include "correlate/correlate.h"

static void emit_hex_args(struct jbuf *j, const __u64 *args, int n)
{
    jb_s(j, ",\"args\":[");
    for (int i = 0; i < n; i++) {
        if (i) jb_c(j, ',');
        jb_c(j, '"'); jb_hex(j, args[i]); jb_c(j, '"');
    }
    jb_c(j, ']');
}

void corr_emit_func(struct jbuf *j, const struct corr_func_event *e)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");        jb_s(j, trace_type_name(TRACE_FUNC)); jb_c(j, '"');
    jb_s(j, ",\"span\":");         jb_u64(j, e->span);
    jb_s(j, ",\"parent_span\":");  jb_u64(j, e->parent_span);
    jb_s(j, ",\"pid\":");          jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");          jb_u64(j, e->h.tid);
    jb_s(j, ",\"entry_addr\":\""); jb_hex(j, e->entry_addr); jb_c(j, '"');
    emit_hex_args(j, e->args, CORR_NUM_ARGS);
    jb_c(j, '}');
}

void corr_emit_syscall(struct jbuf *j, const struct corr_syscall_event *e,
                       const char *syscall_name)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");   jb_s(j, trace_type_name(TRACE_SYSCALL)); jb_c(j, '"');
    jb_s(j, ",\"span\":");    jb_u64(j, e->span);
    jb_s(j, ",\"pid\":");     jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");     jb_u64(j, e->h.tid);
    jb_s(j, ",\"nr\":");      jb_u64(j, e->nr);
    jb_s(j, ",\"syscall\":\""); jb_esc(j, syscall_name); jb_c(j, '"');
    emit_hex_args(j, e->args, CORR_SYS_ARGS);
    // Decoded array: human-readable form per arg where a flag decoder applies,
    // empty string otherwise. Parallel to args[] so consumers index by position.
    jb_s(j, ",\"decoded\":[");
    for (int i = 0; i < CORR_SYS_ARGS; i++) {
        if (i) jb_c(j, ',');
        char dec[128];
        if (flags_decode_arg((long)e->nr, i, e->args[i], dec, sizeof(dec)))
            { jb_c(j, '"'); jb_esc(j, dec); jb_c(j, '"'); }
        else
            jb_s(j, "\"\"");
    }
    jb_c(j, ']');
    jb_c(j, '}');
}

void corr_emit_return(struct jbuf *j, const struct corr_return_event *e)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");        jb_s(j, trace_type_name(TRACE_RETURN)); jb_c(j, '"');
    jb_s(j, ",\"span\":");         jb_u64(j, e->span);
    jb_s(j, ",\"pid\":");          jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");          jb_u64(j, e->h.tid);
    jb_s(j, ",\"entry_addr\":\""); jb_hex(j, e->entry_addr); jb_c(j, '"');
    jb_s(j, ",\"retval\":\"");     jb_hex(j, e->retval); jb_c(j, '"');
    jb_s(j, ",\"elapsed_ns\":");   jb_u64(j, e->elapsed_ns);
    jb_c(j, '}');
}
