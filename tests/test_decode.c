// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the shared decoders. Covers the pure paths (flag decoding
// and sockaddr parsing); render_fd touches /proc and is exercised on-device.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE          // CLONE_* for the clone-flag regression case
#endif
#include "common/decode.h"

#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                   \
    checks++;                                                   \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); }   \
} while (0)

int main(void)
{
    char out[128];

    // flags_decode_arg returns 1 when a decoder applies. Use __NR_openat from
    // <sys/syscall.h> so the nr matches the host arch's table (the brief's
    // hardcoded 56 is the aarch64 value; on x86_64 openat = 257). arg 2 =
    // open flags, val 0 = O_RDONLY.
    int rc = flags_decode_arg((long)__NR_openat, /*arg=*/2,
                              /*val=*/0 /*O_RDONLY*/, out, sizeof(out));
    CHECK(rc == 1, "openat flags decode applies");
    CHECK(strstr(out, "O_RDONLY") != NULL, "O_RDONLY rendered");

    // decode_sockaddr: build an AF_INET sockaddr for 127.0.0.1:80.
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);
    rc = decode_sockaddr((const unsigned char *)&sin, sizeof(sin), out, sizeof(out));
    CHECK(rc == 1, "sockaddr decodes");
    CHECK(strstr(out, "127.0.0.1") != NULL, "ip rendered");
    CHECK(strstr(out, "80") != NULL, "port rendered");

    // clone() flag decode (arg 0). A modest, fitting flag set renders each piece.
    rc = flags_decode_arg((long)__NR_clone, /*arg=*/0,
                          (unsigned long long)(CLONE_VM | CLONE_FS | SIGCHLD),
                          out, sizeof(out));
    CHECK(rc == 1, "clone flags decode applies");
    CHECK(strstr(out, "CLONE_VM") != NULL, "CLONE_VM rendered");
    CHECK(strstr(out, "CLONE_FS") != NULL, "CLONE_FS rendered");
    CHECK(strstr(out, "SIGCHLD") != NULL, "clone exit-signal rendered");
    CHECK(strlen(out) < sizeof(out), "clone output fits buffer");

    // Regression: dec_clone assembled flags/leftover/exit-signal with an
    // unclamped `pos += snprintf`, which overshoots on truncation and writes the
    // next piece out of bounds. Force truncation with every bit set into a tiny
    // buffer — ASAN traps the OOB on the pre-fix code; the fix keeps it in bounds.
    char small[24];
    rc = flags_decode_arg((long)__NR_clone, /*arg=*/0,
                          0xffffffffULL, small, sizeof(small));
    CHECK(rc == 1, "clone tiny-buffer decode applies");
    CHECK(strlen(small) < sizeof(small), "clone tiny-buffer output NUL-terminated in bounds");

    // socket() type+flags decode (arg 1), same append idiom as dec_clone.
    rc = flags_decode_arg((long)__NR_socket, /*arg=*/1,
                          (unsigned long long)(SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC),
                          out, sizeof(out));
    CHECK(rc == 1, "socket type decode applies");
    CHECK(strstr(out, "SOCK_STREAM") != NULL, "SOCK_STREAM rendered");
    CHECK(strstr(out, "SOCK_NONBLOCK") != NULL, "SOCK_NONBLOCK rendered");
    CHECK(strstr(out, "SOCK_CLOEXEC") != NULL, "SOCK_CLOEXEC rendered");

    // ptrace(): arg 0 is the request and decodes to its PTRACE_* name; the
    // remaining args (pid, addr, data) stay raw.
    rc = flags_decode_arg((long)__NR_ptrace, /*arg=*/0, 0x4206ULL, out, sizeof(out));
    CHECK(rc == 1, "ptrace request decode applies");
    CHECK(strcmp(out, "PTRACE_SEIZE") == 0, "0x4206 -> PTRACE_SEIZE");
    rc = flags_decode_arg((long)__NR_ptrace, 0, 0x4204ULL, out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "PTRACE_GETREGSET") == 0, "0x4204 -> PTRACE_GETREGSET");
    rc = flags_decode_arg((long)__NR_ptrace, 0, 0ULL, out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "PTRACE_TRACEME") == 0, "0 -> PTRACE_TRACEME");
    rc = flags_decode_arg((long)__NR_ptrace, 0, 16ULL, out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "PTRACE_ATTACH") == 0, "16 -> PTRACE_ATTACH");
    rc = flags_decode_arg((long)__NR_ptrace, 0, 0x4200ULL, out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "PTRACE_SETOPTIONS") == 0, "0x4200 -> PTRACE_SETOPTIONS");
    rc = flags_decode_arg((long)__NR_ptrace, 0, 0x9999ULL, out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "0x9999") == 0, "unknown ptrace request falls back to hex");
    for (int a = 1; a <= 3; a++) {
        rc = flags_decode_arg((long)__NR_ptrace, a, 0x4206ULL, out, sizeof(out));
        CHECK(rc == 0, "ptrace args after the request are not decoded");
    }
    {
        char tiny[8];
        rc = flags_decode_arg((long)__NR_ptrace, 0, 0x4206ULL, tiny, sizeof(tiny));
        CHECK(rc == 1 && strlen(tiny) < sizeof(tiny), "ptrace tiny-buffer decode stays in bounds");
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
