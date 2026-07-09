// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the funcs structured record builders. Pins the exact JSON
// for a known event so the schema is stable for ares-mcp ingest.
#include <linux/types.h>
#include <stdbool.h>
#include "common/emit.h"
#include "common/trace_schema.h"
#include "common/probe_resolve.h"
#include "funcs/funcs.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void funcs_emit_call(struct jbuf *j, const struct event *e, const char *module,
                     const char *symbol, const probe_target_t *target,
                     const char *java_stack, const char *const *syms);
void funcs_emit_return(struct jbuf *j, const struct event *e, const char *module,
                       const char *symbol, const probe_target_t *target,
                       const char *const *syms);

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
    funcs_emit_call(&j, &e, "libc.so", "open", NULL, NULL, NULL);
    CHECK_HAS(j, "\"type\":\"call\"", "call type");
    CHECK_HAS(j, "\"pid\":1234", "call pid");
    CHECK_HAS(j, "\"tid\":1240", "call tid");
    CHECK_HAS(j, "\"ppid\":0", "call ppid");
    CHECK_HAS(j, "\"module\":\"libc.so\"", "call module");
    CHECK_HAS(j, "\"symbol\":\"open\"", "call symbol");
    CHECK_HAS(j, "\"entry_addr\":\"0xabc000\"", "call entry_addr");

    // backtrace array emitted from call_stack (always-on, independent of --snapshot);
    // syms=NULL (host tests / no resolver) → per-frame "symbol" omitted, addr-only.
    j.len = 0;
    e.call_stack[0] = 0xdead000ULL;
    e.stack_depth = 1;
    funcs_emit_call(&j, &e, "libc.so", "open", NULL, NULL, NULL);
    CHECK_HAS(j, "\"backtrace\":[", "call backtrace key");
    CHECK_HAS(j, "\"frame\":0",     "call backtrace frame 0");
    CHECK_HAS(j, "dead000",         "call backtrace addr");
    { char tmp[4096]; int n = j.len < 4095 ? (int)j.len : 4095; memcpy(tmp, j.b, n); tmp[n]=0;
      checks++;
      if (strstr(tmp, "\"symbol\":\"") && strstr(tmp, "backtrace")) {
          // symbol key legitimately appears once (the top-level resolved symbol);
          // make sure the backtrace frame itself carries no second "symbol" key.
          const char *bt = strstr(tmp, "\"backtrace\":[");
          if (bt && strstr(bt, "\"symbol\"")) { failures++; printf("  FAIL: frame symbol emitted with syms=NULL\n"); }
      }
    }

    // backtrace WITH resolved syms[] → frame carries "symbol".
    {
        struct jbuf j3 = {0};
        const char *syms[STACK_DEPTH] = {0};
        syms[0] = "libc.so`open";
        probe_target_t tgt_off = {0};
        tgt_off.arg_count = -1;
        tgt_off.offset = 0x1234;
        funcs_emit_call(&j3, &e, "libc.so", "open", &tgt_off, NULL, syms);
        CHECK_HAS(j3, "\"offset\":4660", "call offset (0x1234)");
        char tmp3[4096]; int n3 = j3.len < 4095 ? (int)j3.len : 4095;
        memcpy(tmp3, j3.b, n3); tmp3[n3] = 0;
        checks++;
        if (!strstr(tmp3, "\"backtrace\":[{\"frame\":0,\"addr\":\"0xdead000\",\"symbol\":\"libc.so`open\"")) {
            failures++; printf("  FAIL: backtrace frame symbol\n    in: %s\n", tmp3);
        }
        free(j3.b);
    }

    // stack_id = 0 → no "stack_id" field in output (quiet when no snapshot)
    j.len = 0;
    e.call_stack[0] = 0; e.stack_depth = 0;
    e.stack_id = 0;
    funcs_emit_call(&j, &e, "libc.so", "open", NULL, NULL, NULL);
    { char tmp[4096]; int n = j.len < 4095 ? (int)j.len : 4095; memcpy(tmp, j.b, n); tmp[n]=0;
      checks++;
      if (strstr(tmp, "stack_id")) { failures++; printf("  FAIL: stack_id emitted when zero\n"); }
    }

    // stack_id != 0 → "stack_id" field present
    j.len = 0;
    e.stack_id = 0xdeadbeef1ULL;
    funcs_emit_call(&j, &e, "libc.so", "open", NULL, NULL, NULL);
    CHECK_HAS(j, "\"stack_id\":", "stack_id emitted when nonzero");

    // java_stack present: fragment spliced verbatim.
    {
        struct jbuf j2 = {0};
        funcs_emit_call(&j2, &e, "libfoo.so", "sym", NULL, "[\"pkg.Class.method\"]", NULL);
        CHECK_HAS(j2, "\"java_stack\":[\"pkg.Class.method\"]", "call carries java_stack");
        free(j2.b);
    }
    // java_stack NULL: field omitted.
    {
        struct jbuf j2 = {0};
        funcs_emit_call(&j2, &e, "libfoo.so", "sym", NULL, NULL, NULL);
        { char tmp2[4096]; int n2 = (int)j2.len; if (n2 > 4095) n2 = 4095;
          memcpy(tmp2, j2.b, n2); tmp2[n2] = 0;
          checks++;
          if (strstr(tmp2, "java_stack")) { failures++; printf("  FAIL: no java_stack when NULL\n"); }
        }
        free(j2.b);
    }

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
    funcs_emit_call(&j, &es, "libc.so", "open", &tgt_str, NULL, NULL);
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
    funcs_emit_call(&j, &ef, "libc.so", "read", &tgt_fd, NULL, NULL);
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
    funcs_emit_return(&j, &r, "libc.so", "open", NULL, NULL);
    CHECK_HAS(j, "\"type\":\"return\"", "return type");
    CHECK_HAS(j, "\"retval\":7", "return retval");
    CHECK_HAS(j, "\"elapsed_ns\":4096", "return elapsed");
    { char tmp[4096]; int n = j.len < 4095 ? (int)j.len : 4095; memcpy(tmp, j.b, n); tmp[n]=0;
      checks++;
      if (!strstr(tmp, "\"backtrace\":[]")) { failures++; printf("  FAIL: return backtrace key (empty)\n    in: %s\n", tmp); }
    }

    // ---- return WITH backtrace + resolved syms[] + offset -------------------
    {
        struct jbuf j4 = {0};
        struct event r2 = {0};
        r2.h.type = TRACE_RETURN;
        r2.h.pid = 1234; r2.h.tid = 1240;
        r2.retval = 0;
        r2.call_stack[0] = 0xcafe000ULL;
        r2.stack_depth = 1;
        const char *syms[STACK_DEPTH] = {0};
        syms[0] = "libc.so`open+0x4";
        probe_target_t tgt_roff = {0};
        tgt_roff.offset = 0x99;
        funcs_emit_return(&j4, &r2, "libc.so", "open", &tgt_roff, syms);
        CHECK_HAS(j4, "\"offset\":153", "return offset (0x99)");
        char tmp4[4096]; int n4 = j4.len < 4095 ? (int)j4.len : 4095;
        memcpy(tmp4, j4.b, n4); tmp4[n4] = 0;
        checks++;
        if (!strstr(tmp4, "\"backtrace\":[{\"frame\":0,\"addr\":\"0xcafe000\",\"symbol\":\"libc.so`open+0x4\"")) {
            failures++; printf("  FAIL: return backtrace frame symbol\n    in: %s\n", tmp4);
        }
        free(j4.b);
    }

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
    funcs_emit_return(&j, &rs, "libc.so", "getprop", &tgt_ret, NULL);
    CHECK_HAS(j, "\"retval_str\"", "return retval_str key");
    CHECK_HAS(j, "hello", "return retval_str value");

    free(j.b);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
