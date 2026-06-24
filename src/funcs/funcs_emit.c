// SPDX-License-Identifier: GPL-2.0
// Pure structured-record builders for ares funcs (no libbpf/skeleton deps, so
// the host test can link them). Built on the shared serializer + schema.
#include <linux/types.h>
#include <stdbool.h>            // struct event uses bool (exit_event); not transitively guaranteed
#include "common/emit.h"
#include "common/trace_schema.h"
#include "common/decode.h"
#include "common/probe_resolve.h"
#include "funcs/ares-tracer.h"

// Structured record builders (opt-in --structured mode). One self-describing
// JSON object per event into j, on the shared schema/serializer so ares-mcp can
// analyze funcs traces with the same field-level tools it uses for syscalls.
//
// target may be NULL (unresolved entry addr) — all resolved fields are omitted.
void funcs_emit_call(struct jbuf *j, const struct event *e,
                     const char *module, const char *symbol,
                     const probe_target_t *target)
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
    jb_c(j, ']');

    if (target && target->arg_count >= 0) {
        // string_args: BPF-captured string values for ARG_STR args.
        jb_s(j, ",\"string_args\":{");
        for (int i = 0, first = 1; i < target->arg_count && i < NUM_ARGS; i++) {
            if (target->arg_types[i] != ARG_STR || !e->is_str[i]) continue;
            if (!first) jb_c(j, ',');
            first = 0;
            jb_c(j, '"'); jb_u64(j, i); jb_s(j, "\":\""); jb_esc(j, e->strings[i]); jb_c(j, '"');
        }
        jb_c(j, '}');

        // fd_args: FD→path resolved via /proc/<pid>/fd (mirrors syscalls' json_emit).
        jb_s(j, ",\"fd_args\":{");
        for (int i = 0, first = 1; i < target->arg_count && i < NUM_ARGS; i++) {
            if (target->arg_types[i] != ARG_FD) continue;
            char fdbuf[320];
            render_fd((int)e->h.pid, e->args[i], fdbuf, sizeof(fdbuf));
            if (!first) jb_c(j, ',');
            first = 0;
            jb_c(j, '"'); jb_u64(j, i); jb_s(j, "\":\""); jb_esc(j, fdbuf); jb_c(j, '"');
        }
        jb_c(j, '}');
    }

    jb_c(j, '}');
}

void funcs_emit_return(struct jbuf *j, const struct event *e,
                       const char *module, const char *symbol,
                       const probe_target_t *target)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");      jb_s(j, trace_type_name(TRACE_RETURN)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");        jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");        jb_u64(j, e->h.tid);
    jb_s(j, ",\"module\":\"");   jb_esc(j, module); jb_c(j, '"');
    jb_s(j, ",\"symbol\":\"");   jb_esc(j, symbol); jb_c(j, '"');
    jb_s(j, ",\"retval\":");     jb_i64(j, (long long)e->retval); // retval is ABI-signed; render signed so small negative error codes read naturally
    jb_s(j, ",\"elapsed_ns\":"); jb_u64(j, e->elapsed_ns);

    if (target) {
        // retval_str: BPF-captured string return value (strings[0] slot).
        if (target->ret_type == ARG_STR && e->is_str[0]) {
            jb_s(j, ",\"retval_str\":\""); jb_esc(j, e->strings[0]); jb_c(j, '"');
        }
        // out_args: output string args (slot i+1 for ARG_STR arg i — mirrors console "(out)").
        if (target->arg_count >= 0) {
            jb_s(j, ",\"out_args\":{");
            for (int i = 0, first = 1; i < target->arg_count && i < NUM_ARGS - 1; i++) {
                if (target->arg_types[i] != ARG_STR || !e->is_str[i + 1]) continue;
                if (!first) jb_c(j, ',');
                first = 0;
                jb_c(j, '"'); jb_u64(j, i); jb_s(j, "\":\""); jb_esc(j, e->strings[i + 1]); jb_c(j, '"');
            }
            jb_c(j, '}');
        }
    }

    jb_c(j, '}');
}
