// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the correlate structured record builders. Pins the JSON
// shape (type discriminator, span linkage, hex args, decoded array).
#include <linux/types.h>
#include "common/emit.h"
#include "common/trace_schema.h"
#include "correlate/correlate.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void corr_emit_func(struct jbuf *j, const struct corr_func_event *e);
void corr_emit_syscall(struct jbuf *j, const struct corr_syscall_event *e, const char *syscall_name);
void corr_emit_return(struct jbuf *j, const struct corr_return_event *e);

static int checks = 0, failures = 0;
#define HAS(j, sub, msg) do {                                        \
    checks++;                                                        \
    char tmp[4096]; int n = (int)(j).len; if (n > 4095) n = 4095;    \
    memcpy(tmp, (j).b, n); tmp[n] = 0;                               \
    if (!strstr(tmp, sub)) { failures++;                            \
        printf("  FAIL: %s\n    in: %s\n", msg, tmp); }              \
} while (0)

int main(void)
{
    struct jbuf j = {0};

    struct corr_func_event f = {0};
    f.h.type = TRACE_FUNC; f.h.pid = 100; f.h.tid = 101;
    f.span = 5; f.parent_span = 0; f.entry_addr = 0xabc;
    f.args[0] = 0x10;
    j.len = 0; corr_emit_func(&j, &f);
    HAS(j, "\"type\":\"func\"", "func type");
    HAS(j, "\"span\":5", "func span");
    HAS(j, "\"parent_span\":0", "func parent");
    HAS(j, "\"pid\":100", "func pid");
    HAS(j, "\"entry_addr\":\"0xabc\"", "func entry hex");
    HAS(j, "\"args\":[\"0x10\"", "func args hex");

    struct corr_syscall_event s = {0};
    s.h.type = TRACE_SYSCALL; s.h.pid = 100; s.h.tid = 101;
    s.span = 5; s.nr = 56 /* openat */; s.args[2] = 0 /* O_RDONLY */;
    j.len = 0; corr_emit_syscall(&j, &s, "openat");
    HAS(j, "\"type\":\"syscall\"", "sys type");
    HAS(j, "\"span\":5", "sys span");
    HAS(j, "\"syscall\":\"openat\"", "sys name");
    HAS(j, "\"nr\":56", "sys nr");
    HAS(j, "\"args\":[", "sys args present");
    HAS(j, "\"decoded\":[", "sys decoded present");

    struct corr_return_event r = {0};
    r.h.type = TRACE_RETURN; r.h.pid = 100; r.h.tid = 101;
    r.span = 5; r.entry_addr = 0xabc; r.retval = 0xdeadbeef; r.elapsed_ns = 4200;
    j.len = 0; corr_emit_return(&j, &r);
    HAS(j, "\"type\":\"return\"", "ret type");
    HAS(j, "\"span\":5", "ret span");
    HAS(j, "\"pid\":100", "ret pid");
    HAS(j, "\"entry_addr\":\"0xabc\"", "ret entry hex");
    HAS(j, "\"retval\":\"0xdeadbeef\"", "ret retval hex");
    HAS(j, "\"elapsed_ns\":4200", "ret elapsed");

    free(j.b);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
