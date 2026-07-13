// SPDX-License-Identifier: GPL-2.0
// Pure structured-record builders for ares funcs (no libbpf/skeleton deps, so
// the host test can link them). Built on the shared serializer + schema.
#include <linux/types.h>
#include <stdbool.h>            // struct event uses bool (exit_event); not transitively guaranteed
#include "common/emit.h"
#include "common/trace_schema.h"
#include "common/decode.h"
#include "common/probe_resolve.h"
#include "funcs/funcs.h"

// Structured record builders (opt-in --structured mode). One self-describing
// JSON object per event into j, on the shared schema/serializer so ares-mcp can
// analyze funcs traces with the same field-level tools it uses for syscalls.
//
// target may be NULL (unresolved entry addr) — all resolved fields are omitted.
// syms may be NULL (host tests / no resolver available) — per-frame "symbol" is
// then omitted, same as before this field existed.
void funcs_emit_call(struct jbuf *j, const struct event *e,
                     const char *module, const char *symbol,
                     const probe_target_t *target, const char *java_stack,
                     const char *const *syms)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");      jb_s(j, trace_type_name(TRACE_CALL)); jb_c(j, '"');
    jb_s(j, ",\"id\":");         jb_u64(j, e->span_id); // pairs with the RETURN record; orders the stream (parity with syscalls)
    jb_s(j, ",\"pid\":");        jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");        jb_u64(j, e->h.tid);
    jb_s(j, ",\"ppid\":");       jb_i64(j, e->ppid);
    jb_s(j, ",\"module\":\"");   jb_esc(j, module); jb_c(j, '"');
    jb_s(j, ",\"symbol\":\"");   jb_esc(j, symbol); jb_c(j, '"');
    jb_s(j, ",\"entry_addr\":\""); jb_hex(j, e->entry_addr); jb_c(j, '"');
    jb_s(j, ",\"ktime\":");      jb_u64(j, e->ktime); // EPIC C3: boot-monotonic entry time
    if (target) {
        jb_s(j, ",\"offset\":"); jb_u64(j, target->offset);
    }
    jb_s(j, ",\"args\":[");
    for (int i = 0; i < NUM_ARGS; i++) {
        if (i) jb_c(j, ',');
        jb_c(j, '"'); jb_hex(j, e->args[i]); jb_c(j, '"');
    }
    jb_c(j, ']');
    if (e->stack_id) {
        jb_s(j, ",\"stack_id\":"); jb_u64(j, e->stack_id);
        if (java_stack) { jb_s(j, ",\"java_stack\":"); jb_s(j, java_stack); }
    }

    // symbol per frame comes from the caller-resolved syms[] (funcs.c mirrors the
    // console's sym_resolve loop) — this file stays libbpf/symbolizer-free.
    jb_s(j, ",\"backtrace\":[");
    for (int i = 0, first = 1; i < (int)e->stack_depth && i < STACK_DEPTH; i++) {
        if (e->call_stack[i] == 0) break;
        if (!first) jb_c(j, ',');
        first = 0;
        jb_s(j, "{\"frame\":");    jb_u64(j, i);
        jb_s(j, ",\"addr\":\"");   jb_hex(j, e->call_stack[i]); jb_c(j, '"');
        if (syms && syms[i] && syms[i][0]) {
            jb_s(j, ",\"symbol\":\""); jb_esc(j, syms[i]); jb_c(j, '"');
        }
        jb_c(j, '}');
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

        // sock_args: ARG_SOCKADDR args decoded to ip:port / [ip6]:port / unix:path.
        jb_s(j, ",\"sock_args\":{");
        for (int i = 0, first = 1; i < target->arg_count && i < NUM_ARGS; i++) {
            if (target->arg_types[i] != ARG_SOCKADDR) continue;
            char sbuf[128];
            // ponytail: fixed SOCK_ADDR_MAX len — exact for INET/INET6; an AF_UNIX
            // path >26 B truncates. No addrlen is captured on the funcs path.
            if (!decode_sockaddr(e->sock[i], SOCK_ADDR_MAX, sbuf, sizeof(sbuf))) continue;
            if (!first) jb_c(j, ',');
            first = 0;
            jb_c(j, '"'); jb_u64(j, i); jb_s(j, "\":\""); jb_esc(j, sbuf); jb_c(j, '"');
        }
        jb_c(j, '}');
    }

    jb_c(j, '}');
}

void funcs_emit_return(struct jbuf *j, const struct event *e,
                       const char *module, const char *symbol,
                       const probe_target_t *target, const char *const *syms)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");      jb_s(j, trace_type_name(TRACE_RETURN)); jb_c(j, '"');
    jb_s(j, ",\"id\":");         jb_u64(j, e->span_id); // same id as the matching CALL record
    jb_s(j, ",\"pid\":");        jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");        jb_u64(j, e->h.tid);
    jb_s(j, ",\"module\":\"");   jb_esc(j, module); jb_c(j, '"');
    jb_s(j, ",\"symbol\":\"");   jb_esc(j, symbol); jb_c(j, '"');
    if (target) {
        jb_s(j, ",\"offset\":"); jb_u64(j, target->offset);
    }
    jb_s(j, ",\"retval\":");     jb_i64(j, (long long)e->retval); // retval is ABI-signed; render signed so small negative error codes read naturally
    jb_s(j, ",\"elapsed_ns\":"); jb_u64(j, e->elapsed_ns);
    jb_s(j, ",\"ktime\":");      jb_u64(j, e->ktime); // EPIC C3: boot-monotonic return time

    // backtrace: mirrors the call record's frame builder (console already prints
    // this on return, e.g. "caller: ..." — the file previously had no backtrace).
    jb_s(j, ",\"backtrace\":[");
    for (int i = 0, first = 1; i < (int)e->stack_depth && i < STACK_DEPTH; i++) {
        if (e->call_stack[i] == 0) break;
        if (!first) jb_c(j, ',');
        first = 0;
        jb_s(j, "{\"frame\":");    jb_u64(j, i);
        jb_s(j, ",\"addr\":\"");   jb_hex(j, e->call_stack[i]); jb_c(j, '"');
        if (syms && syms[i] && syms[i][0]) {
            jb_s(j, ",\"symbol\":\""); jb_esc(j, syms[i]); jb_c(j, '"');
        }
        jb_c(j, '}');
    }
    jb_c(j, ']');

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
