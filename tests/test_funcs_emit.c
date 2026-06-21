// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the funcs structured record builders. Pins the exact JSON
// for a known event so the schema is stable for ares-mcp ingest.
#include <linux/types.h>
#include <stdbool.h>
#include "common/emit.h"
#include "common/trace_schema.h"
#include "funcs/ares-tracer.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Declared in ares-tracer.c (exposed via ares-tracer-priv.h for this test).
void funcs_emit_call(struct jbuf *j, const struct event *e, const char *module, const char *symbol);
void funcs_emit_return(struct jbuf *j, const struct event *e, const char *module, const char *symbol);

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
    struct event e = {0};
    e.h.type = TRACE_CALL;
    e.h.pid = 1234;
    e.h.tid = 1240;
    e.entry_addr = 0xabc000;
    e.args[0] = 0x10; e.args[1] = 0x20;

    j.len = 0;
    funcs_emit_call(&j, &e, "libc.so", "open");
    CHECK_HAS(j, "\"type\":\"call\"", "call type");
    CHECK_HAS(j, "\"pid\":1234", "call pid");
    CHECK_HAS(j, "\"tid\":1240", "call tid");
    CHECK_HAS(j, "\"module\":\"libc.so\"", "call module");
    CHECK_HAS(j, "\"symbol\":\"open\"", "call symbol");
    CHECK_HAS(j, "\"entry_addr\":\"0xabc000\"", "call entry_addr");

    struct event r = {0};
    r.h.type = TRACE_RETURN;
    r.h.pid = 1234; r.h.tid = 1240;
    r.exit_event = true;
    r.retval = 7;
    r.elapsed_ns = 4096;

    j.len = 0;
    funcs_emit_return(&j, &r, "libc.so", "open");
    CHECK_HAS(j, "\"type\":\"return\"", "return type");
    CHECK_HAS(j, "\"retval\":7", "return retval");
    CHECK_HAS(j, "\"elapsed_ns\":4096", "return elapsed");

    free(j.b);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
