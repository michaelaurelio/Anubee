// SPDX-License-Identifier: GPL-2.0
// Host unit tests for src/common/runtime.c (no BPF required).
// Tests: ares_round_pow2, ares_drops_report (3 cases), ares_install_stop_handler.
#include "common/runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

// Capture one ares_drops_report(k, q) call; returns malloc'd NUL-terminated string.
static char *capture_drops_report(unsigned long long k, unsigned long long q)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) return NULL;
    int saved = dup(STDERR_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[1]);
    ares_drops_report(k, q);
    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    char *buf = malloc(512);
    ssize_t n = read(pipefd[0], buf, 511);
    close(pipefd[0]);
    buf[n > 0 ? (size_t)n : 0] = '\0';
    return buf;
}

int main(void)
{
    // --- ares_round_pow2 ---
    CHECK(ares_round_pow2(0) == 1,               "pow2(0)==1");
    CHECK(ares_round_pow2(1) == 1,               "pow2(1)==1");
    CHECK(ares_round_pow2(2) == 2,               "pow2(2)==2");
    CHECK(ares_round_pow2(3) == 4,               "pow2(3)==4");
    CHECK(ares_round_pow2(4) == 4,               "pow2(4)==4");
    CHECK(ares_round_pow2(5) == 8,               "pow2(5)==8");
    CHECK(ares_round_pow2(1024*1024) == 1024*1024UL,   "pow2(1M)==1M");
    CHECK(ares_round_pow2(1024*1024+1) == 2*1024*1024UL, "pow2(1M+1)==2M");

    // --- ares_drops_report ---
    {
        char *s = capture_drops_report(0, 0);
        CHECK(s && strcmp(s, "no events dropped\n") == 0, "drops zero");
        free(s);
    }
    {
        char *s = capture_drops_report(5, 0);
        CHECK(s && strstr(s, "5 event(s) dropped") && strstr(s, "ring buffer full"),
              "drops ring-only");
        free(s);
    }
    {
        char *s = capture_drops_report(3, 2);
        CHECK(s && strstr(s, "5 event(s) dropped") &&
              strstr(s, "3 kernel ring") && strstr(s, "2 queue"),
              "drops both");
        free(s);
    }

    // --- ares_install_stop_handler ---
    {
        static volatile sig_atomic_t flag = 0;
        ares_install_stop_handler(&flag);
        raise(SIGINT);
        CHECK(flag == 1, "stop_handler sets flag on SIGINT");
        signal(SIGINT,  SIG_DFL);   // restore so the process can be killed normally
        signal(SIGTERM, SIG_DFL);
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
