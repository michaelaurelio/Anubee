// SPDX-License-Identifier: GPL-2.0
// Pure structured-record builders for anubee correlate (no libbpf deps, so the
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
    jb_s(j, ",\"ktime\":");        jb_u64(j, e->ktime); // EPIC C3: boot-monotonic span-open time
    emit_hex_args(j, e->args, CORR_NUM_ARGS);
    jb_c(j, '}');
}

// SYM1 Phase 2: extracted out of this function's own decode loop so
// correlate.c's stdout rendering can share the exact same precedence instead
// of duplicating it. Behavior unchanged — see declaration comment (correlate.h).
int corr_decode_arg(const struct corr_syscall_event *e, int i,
                    unsigned fdmask, int sockidx, char *dec, unsigned long decsz)
{
    if (i < CORR_STR_SLOTS && (e->str_present & (1u << i))) {
        snprintf(dec, decsz, "%.*s", (int)(decsz - 1), e->str[i]);
        return 1;
    }
    if (fdmask & (1u << i)) {
        render_fd((int)e->h.pid, e->args[i], dec, decsz);
        return 1;
    }
    if (i == sockidx && e->sock_len > 0 &&
        decode_sockaddr(e->sock, e->sock_len, dec, decsz))
        return 1;
    if (flags_decode_arg((long)e->nr, i, e->args[i], dec, decsz))
        return 1;
    return 0;
}

void corr_emit_syscall(struct jbuf *j, const struct corr_syscall_event *e,
                       const char *syscall_name, unsigned fdmask, int sockidx)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");   jb_s(j, trace_type_name(TRACE_SYSCALL)); jb_c(j, '"');
    jb_s(j, ",\"span\":");    jb_u64(j, e->span);
    jb_s(j, ",\"pid\":");     jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");     jb_u64(j, e->h.tid);
    jb_s(j, ",\"ktime\":");   jb_u64(j, e->ktime); // EPIC C3: boot-monotonic issue time
    jb_s(j, ",\"nr\":");      jb_u64(j, e->nr);
    jb_s(j, ",\"syscall\":\""); jb_esc(j, syscall_name); jb_c(j, '"');
    emit_hex_args(j, e->args, CORR_SYS_ARGS);
    // Decoded array: human-readable form per arg — string > fd > sockaddr >
    // flags/enum, empty string if none apply. Parallel to args[] so consumers
    // index by position; empty means "use the raw hex in args[]".
    jb_s(j, ",\"decoded\":[");
    for (int i = 0; i < CORR_SYS_ARGS; i++) {
        if (i) jb_c(j, ',');
        char dec[300];
        if (corr_decode_arg(e, i, fdmask, sockidx, dec, sizeof(dec))) {
            jb_c(j, '"'); jb_esc(j, dec); jb_c(j, '"');
        } else {
            jb_s(j, "\"\"");
        }
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
    jb_s(j, ",\"ktime\":");        jb_u64(j, e->ktime); // EPIC C3: boot-monotonic span-close time
    jb_c(j, '}');
}
