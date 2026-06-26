// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the funcs structured record builders. Pins the exact JSON
// for a known event so the schema is stable for ares-mcp ingest.
#include <linux/types.h>
#include <stdbool.h>
#include "common/emit.h"
#include "common/trace_schema.h"
#include "common/probe_resolve.h"
#include "funcs/ares-tracer.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void funcs_emit_call(struct jbuf *j, const struct event *e, const char *module,
                     const char *symbol, const probe_target_t *target);
void funcs_emit_return(struct jbuf *j, const struct event *e, const char *module,
                       const char *symbol, const probe_target_t *target);

static int checks = 0, failures = 0;
#define CHECK_HAS(j, sub, msg) do {                                  \
    checks++;                                                        \
    char tmp[4096]; int n = (int)(j).len; if (n > 4095) n = 4095;    \
    memcpy(tmp, (j).b, n); tmp[n] = 0;                               \
    if (!strstr(tmp, sub)) { failures++;                            \
        printf("  FAIL: %s\n    in: %s\n", msg, tmp); }              \
} while (0)

int main(void)
{
    struct jbuf j = {0};

    // ---- basic call (no target) --------------------------------------------
    struct event e = {0};
    e.h.type = TRACE_CALL;
    e.h.pid = 1234;
    e.h.tid = 1240;
    e.entry_addr = 0xabc000;
    e.args[0] = 0x10; e.args[1] = 0x20;

    j.len = 0;
    funcs_emit_call(&j, &e, "libc.so", "open", NULL);
    CHECK_HAS(j, "\"type\":\"call\"", "call type");
    CHECK_HAS(j, "\"pid\":1234", "call pid");
    CHECK_HAS(j, "\"tid\":1240", "call tid");
    CHECK_HAS(j, "\"module\":\"libc.so\"", "call module");
    CHECK_HAS(j, "\"symbol\":\"open\"", "call symbol");
    CHECK_HAS(j, "\"entry_addr\":\"0xabc000\"", "call entry_addr");

    // stack_id = 0 → no "stack_id" field in output (quiet when no snapshot)
    j.len = 0;
    e.stack_id = 0;
    funcs_emit_call(&j, &e, "libc.so", "open", NULL);
    { char tmp[4096]; int n = j.len < 4095 ? (int)j.len : 4095; memcpy(tmp, j.b, n); tmp[n]=0;
      checks++;
      if (strstr(tmp, "stack_id")) { failures++; printf("  FAIL: stack_id emitted when zero\n"); }
    }

    // stack_id != 0 → "stack_id" field present
    j.len = 0;
    e.stack_id = 0xdeadbeef1ULL;
    funcs_emit_call(&j, &e, "libc.so", "open", NULL);
    CHECK_HAS(j, "\"stack_id\":", "stack_id emitted when nonzero");

    // ---- call with ARG_STR arg (string_args emitted) -----------------------
    struct event es = {0};
    es.h.type = TRACE_CALL;
    es.h.pid = 1234; es.h.tid = 1240;
    es.entry_addr = 0xabc000;
    es.is_str[0] = 1;
    strncpy(es.strings[0], "/data/local/tmp/x", MAX_STR_LEN - 1);

    probe_target_t tgt_str = {0};
    tgt_str.arg_count = 1;
    tgt_str.arg_types[0] = ARG_STR;
    tgt_str.ret_type = ARG_NONE;

    j.len = 0;
    funcs_emit_call(&j, &es, "libc.so", "open", &tgt_str);
    CHECK_HAS(j, "\"string_args\"", "call string_args key");
    CHECK_HAS(j, "/data/local/tmp/x", "call string_args value");

    // ---- call with ARG_FD arg (fd_args emitted; bogus pid → fd=N fallback) -
    struct event ef = {0};
    ef.h.type = TRACE_CALL;
    ef.h.pid = 9999999; ef.h.tid = 1240;
    ef.args[0] = 5;

    probe_target_t tgt_fd = {0};
    tgt_fd.arg_count = 1;
    tgt_fd.arg_types[0] = ARG_FD;
    tgt_fd.ret_type = ARG_NONE;

    j.len = 0;
    funcs_emit_call(&j, &ef, "libc.so", "read", &tgt_fd);
    CHECK_HAS(j, "\"fd_args\"", "call fd_args key");
    CHECK_HAS(j, "fd=5", "call fd_args value");

    // ---- basic return (no target) ------------------------------------------
    struct event r = {0};
    r.h.type = TRACE_RETURN;
    r.h.pid = 1234; r.h.tid = 1240;
    r.exit_event = true;
    r.retval = 7;
    r.elapsed_ns = 4096;

    j.len = 0;
    funcs_emit_return(&j, &r, "libc.so", "open", NULL);
    CHECK_HAS(j, "\"type\":\"return\"", "return type");
    CHECK_HAS(j, "\"retval\":7", "return retval");
    CHECK_HAS(j, "\"elapsed_ns\":4096", "return elapsed");

    // ---- return with ARG_STR retval (retval_str emitted) -------------------
    struct event rs = {0};
    rs.h.type = TRACE_RETURN;
    rs.h.pid = 1234; rs.h.tid = 1240;
    rs.retval = 0;
    rs.is_str[0] = 1;
    strncpy(rs.strings[0], "hello", MAX_STR_LEN - 1);

    probe_target_t tgt_ret = {0};
    tgt_ret.arg_count = 0;
    tgt_ret.ret_type = ARG_STR;

    j.len = 0;
    funcs_emit_return(&j, &rs, "libc.so", "getprop", &tgt_ret);
    CHECK_HAS(j, "\"retval_str\"", "return retval_str key");
    CHECK_HAS(j, "hello", "return retval_str value");

    free(j.b);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
