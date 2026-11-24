// SPDX-License-Identifier: GPL-2.0
// Host unit tests for exfil-detect's "does this destination count as outbound"
// rule (src/modules/exfil_detect_addr.h, shared with exfil_detect.bpf.c).
// Only non-loopback IPv4/IPv6 counts: AF_UNIX (logd's logdw socket, dnsproxyd,
// fwmarkd) and other local families are IPC, not exfiltration.
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "modules/exfil_detect_addr.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                 \
    checks++;                                                  \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

static int v4(const char *ip)
{
    struct in_addr a;
    inet_pton(AF_INET, ip, &a);
    return exfil_addr_is_outbound(AF_INET, (const unsigned char *)&a);
}

static int v6(const char *ip)
{
    struct in6_addr a;
    inet_pton(AF_INET6, ip, &a);
    return exfil_addr_is_outbound(AF_INET6, (const unsigned char *)&a);
}

static int sa_unix(void)
{
    unsigned char sa[28] = {0};
    struct sockaddr_un u = { .sun_family = AF_UNIX };
    strcpy(u.sun_path, "/dev/socket/logdw");
    memcpy(sa, &u, sizeof sa);
    return exfil_sockaddr_is_outbound(sa);
}

static int sa_in(const char *ip)
{
    unsigned char sa[28] = {0};
    struct sockaddr_in s = { .sin_family = AF_INET, .sin_port = htons(443) };
    inet_pton(AF_INET, ip, &s.sin_addr);
    memcpy(sa, &s, sizeof s);
    return exfil_sockaddr_is_outbound(sa);
}

static int sa_in6(const char *ip)
{
    unsigned char sa[28] = {0};
    struct sockaddr_in6 s = { .sin6_family = AF_INET6, .sin6_port = htons(443) };
    inet_pton(AF_INET6, ip, &s.sin6_addr);
    memcpy(sa, &s, sizeof s);
    return exfil_sockaddr_is_outbound(sa);
}

int main(void)
{
    // family + raw address (what the BPF side reads from struct sock)
    CHECK(v4("192.0.2.1") == 1,        "v4 public -> outbound");
    CHECK(v4("127.0.0.1") == 0,        "v4 loopback -> not outbound");
    CHECK(v4("127.53.0.1") == 0,       "v4 127/8 -> not outbound");
    CHECK(v4("0.0.0.0") == 0,          "v4 unspecified (unconnected) -> not outbound");
    CHECK(v6("2001:db8::1") == 1,      "v6 public -> outbound");
    CHECK(v6("::1") == 0,              "v6 loopback -> not outbound");
    CHECK(v6("::") == 0,               "v6 unspecified -> not outbound");
    CHECK(v6("::ffff:127.0.0.1") == 0, "v4-mapped loopback -> not outbound");
    CHECK(v6("::ffff:192.0.2.1") == 1, "v4-mapped public -> outbound");
    CHECK(exfil_addr_is_outbound(AF_UNIX, (const unsigned char *)"x") == 0,
          "AF_UNIX -> not outbound");
    CHECK(exfil_addr_is_outbound(AF_NETLINK, (const unsigned char *)"x") == 0,
          "AF_NETLINK -> not outbound");

    // raw sockaddr bytes (sendto's explicit dest_addr)
    CHECK(sa_unix() == 0,              "sockaddr_un -> not outbound");
    CHECK(sa_in("192.0.2.1") == 1,     "sockaddr_in public -> outbound");
    CHECK(sa_in("127.0.0.1") == 0,     "sockaddr_in loopback -> not outbound");
    CHECK(sa_in6("2001:db8::1") == 1,  "sockaddr_in6 public -> outbound");
    CHECK(sa_in6("::1") == 0,          "sockaddr_in6 loopback -> not outbound");

    printf("test_exfil_detect_addr: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
