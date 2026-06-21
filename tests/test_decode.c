// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the shared decoders. Covers the pure paths (flag decoding
// and sockaddr parsing); render_fd touches /proc and is exercised on-device.
#include "common/decode.h"

#include <stdio.h>
#include <string.h>
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

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
