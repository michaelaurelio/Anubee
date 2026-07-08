// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the correlate structured record builders. Pins the JSON
// shape (type discriminator, span linkage, hex args, decoded array) and, for
// the syscall record, the actual decode content (string/fd/sockaddr/flags).
#include <linux/types.h>
#include "common/emit.h"
#include "common/trace_schema.h"
#include "correlate/correlate.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void corr_emit_func(struct jbuf *j, const struct corr_func_event *e);
void corr_emit_syscall(struct jbuf *j, const struct corr_syscall_event *e, const char *syscall_name,
                       unsigned fdmask, int sockidx);
void corr_emit_func_return(struct jbuf *j, const struct corr_func_return_event *e);

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

    struct corr_func_return_event r = {0};
    r.h.type = TRACE_RETURN; r.h.pid = 100; r.h.tid = 101;
    r.span = 5; r.entry_addr = 0xabc; r.retval = 0x1; r.elapsed_ns = 4200;
    j.len = 0; corr_emit_func_return(&j, &r);
    HAS(j, "\"type\":\"return\"", "return type");
    HAS(j, "\"span\":5", "return span");
    HAS(j, "\"entry_addr\":\"0xabc\"", "return entry hex");
    HAS(j, "\"retval\":\"0x1\"", "return retval hex");
    HAS(j, "\"elapsed_ns\":4200", "return elapsed_ns");

    // openat: string arg (path) + flags decode, no fd/sockaddr.
#ifdef __NR_openat
    struct corr_syscall_event s = {0};
    s.h.type = TRACE_SYSCALL; s.h.pid = 100; s.h.tid = 101;
    s.span = 5; s.nr = __NR_openat;
    s.args[2] = 0;  // O_RDONLY
    s.str_present = (1u << 1);
    snprintf(s.str[1], sizeof(s.str[1]), "/data/test");
    j.len = 0; corr_emit_syscall(&j, &s, "openat", 0, -1);
    HAS(j, "\"type\":\"syscall\"", "sys type");
    HAS(j, "\"span\":5", "sys span");
    HAS(j, "\"syscall\":\"openat\"", "sys name");
    HAS(j, "\"args\":[", "sys args present");
    HAS(j, "\"decoded\":[", "sys decoded present");
    HAS(j, "/data/test", "openat decoded path");
    HAS(j, "O_RDONLY", "openat decoded flags");
#endif

    // read: fd arg, rendered via render_fd (falls back to "fd=N" for a pid
    // with no real /proc/<pid>/fd/<n> to resolve).
#ifdef __NR_read
    struct corr_syscall_event sfd = {0};
    sfd.h.type = TRACE_SYSCALL; sfd.h.pid = 100; sfd.h.tid = 101;
    sfd.span = 5; sfd.nr = __NR_read; sfd.args[0] = 3;
    j.len = 0; corr_emit_syscall(&j, &sfd, "read", 1u << 0, -1);
    HAS(j, "fd=3", "read decoded fd");
#endif

    // connect: sockaddr arg decoded to ip:port.
#ifdef __NR_connect
    struct corr_syscall_event sc = {0};
    sc.h.type = TRACE_SYSCALL; sc.h.pid = 100; sc.h.tid = 101;
    sc.span = 5; sc.nr = __NR_connect;
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);
    memcpy(sc.sock, &sin, sizeof(sin));
    sc.sock_len = (__u32)sizeof(sin);
    j.len = 0; corr_emit_syscall(&j, &sc, "connect", 0, 1);
    HAS(j, "127.0.0.1:8080", "connect decoded sockaddr");
#endif

    free(j.b);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
