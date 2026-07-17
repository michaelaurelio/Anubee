// SPDX-License-Identifier: GPL-2.0
// Host smoke test for common/human_out.c (SYM1 Phase 0): pins the exact byte
// layout of out_print/ts_print/human_detail's output — this is the shared
// stdout formatter every engine will render through, so a drift here would
// silently reshape every engine's console output.
#include "common/human_out.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static int checks = 0, failures = 0;
#define CHECK_HAS(buf, sub, msg) do {                                \
    checks++;                                                        \
    if (!strstr(buf, sub)) { failures++;                            \
        printf("  FAIL: %s\n    want: %s\n    in: %s\n", msg, sub, buf); } \
} while (0)

static char *slurp(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, (size_t)sz, f);
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

int main(void)
{
    char tmppath[] = "/tmp/test_human_out_XXXXXX";
    int fd = mkstemp(tmppath);
    if (fd < 0) { perror("mkstemp"); return 1; }
    close(fd);

    FILE *f = freopen(tmppath, "w", stdout);
    if (!f) { perror("freopen"); remove(tmppath); return 1; }

    out_print("plain %d\n", 7);
    ts_print("[event] > [CALL] PID:%d PPID:%d %s!%s @ 0x%lx\n",
              111, 222, "libc.so", "open", 0x1234UL);
    human_detail("event", "args[%d] \"%s\"\n", 0, "/data/local/tmp");
    human_detail("syscall", "decoded: %s\n", "AT_FDCWD");

    fflush(stdout);
    fclose(stdout);

    char *out = slurp(tmppath);
    remove(tmppath);
    if (!out) { fprintf(stderr, "slurp failed\n"); return 1; }

    CHECK_HAS(out, "plain 7\n",                                          "out_print plain line");
    // ts_print prepends a live "HH:MM:SS " — check the fixed suffix only.
    CHECK_HAS(out, "[event] > [CALL] PID:111 PPID:222 libc.so!open @ 0x1234\n", "ts_print event line");
    CHECK_HAS(out, "         [event]   | args[0] \"/data/local/tmp\"\n",   "human_detail default tag");
    CHECK_HAS(out, "         [syscall]   | decoded: AT_FDCWD\n",           "human_detail custom tag");

    free(out);

    // --- sticky progress line ---
    // Default (no bar set) must stay byte-identical: this file pins the exact
    // output of every engine's console, so the sticky-line path must be inert
    // until a bar is actually set.
    {
        char op[] = "/tmp/anubee_ho_out_XXXXXX";
        char ep[] = "/tmp/anubee_ho_err_XXXXXX";
        int ofd = mkstemp(op), efd = mkstemp(ep);
        if (ofd < 0 || efd < 0) { perror("mkstemp"); return 1; }
        close(ofd); close(efd);

        int so = dup(STDOUT_FILENO), se = dup(STDERR_FILENO);
        FILE *of = freopen(op, "w", stdout);
        FILE *ef = freopen(ep, "w", stderr);
        (void)of; (void)ef;

        human_progress_set(NULL);          // inert: nothing set
        out_print("plain\n");

        human_progress_set("BAR1");        // draw
        out_print("event\n");              // clear, print, redraw
        human_progress_set(NULL);          // clear

        fflush(stdout); fflush(stderr);
        dup2(so, STDOUT_FILENO); dup2(se, STDERR_FILENO);
        close(so); close(se);
        clearerr(stdout); clearerr(stderr);

        char *out = slurp(op);
        char *err = slurp(ep);
        if (!out || !err) { fprintf(stderr, "slurp failed\n"); return 1; }

        CHECK_HAS(out, "plain\n", "sticky: stdout keeps plain line");
        CHECK_HAS(out, "event\n", "sticky: stdout keeps event line");
        checks++;
        if (strstr(out, "\033[") || strstr(out, "\r")) {
            failures++;
            printf("  FAIL: sticky: stdout must carry no ANSI/CR\n    got: %s\n", out);
        }
        // stderr: BAR1, then clear+redraw around the event line, then final clear.
        CHECK_HAS(err, "BAR1", "sticky: bar drawn to stderr");
        CHECK_HAS(err, "\r\033[K", "sticky: bar cleared with CR+EL");
        checks++;
        if (strcmp(err, "BAR1\r\033[KBAR1\r\033[K") != 0) {
            failures++;
            printf("  FAIL: sticky: exact stderr sequence\n"
                   "    want: BAR1<CR>ESC[K BAR1<CR>ESC[K\n    got:  %s\n", err);
        }

        free(out); free(err);
        remove(op); remove(ep);
    }

    fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
