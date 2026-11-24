// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the net analyzer's payload parsers: TLS ClientHello
// SNI, HTTP Host, netd dnsproxyd commands and DNS question names, plus
// destination formatting. Fixtures: tests/fixtures/README.md.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "modules/net_parse.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

static size_t slurp(const char *path, unsigned char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}

int main(void)
{
    unsigned char ch[4096], q[512];
    char out[256];
    size_t n = slurp("tests/fixtures/tls_clienthello.bin", ch, sizeof ch);
    CHECK(n == 1687, "ClientHello fixture loaded");

    // ---- TLS SNI ----------------------------------------------------------------
    CHECK(net_tls_sni(ch, n, out, sizeof out) == 1 && strcmp(out, "api.example-c2.net") == 0,
          "SNI from a real ClientHello");
    CHECK(net_tls_sni(ch, 2048 > n ? n : 2048, out, sizeof out) == 1, "SNI within a 2 KiB capture");
    CHECK(net_tls_sni(ch, 200, out, sizeof out) == 0, "capture cut before the SNI -> not found");
    CHECK(net_tls_sni(ch, 5, out, sizeof out) == 0, "record header only");
    unsigned char bad[64];
    memcpy(bad, ch, sizeof bad);
    bad[5] = 2;   // ServerHello, not ClientHello
    CHECK(net_tls_sni(bad, sizeof bad, out, sizeof out) == 0, "not a ClientHello");
    CHECK(net_tls_sni((const unsigned char *)"GET / HTTP/1.1\r\n", 16, out, sizeof out) == 0,
          "plain HTTP is not TLS");
    char tiny[6];
    CHECK(net_tls_sni(ch, n, tiny, sizeof tiny) == 1 && strlen(tiny) == 5, "SNI truncated to the buffer");

    // ---- HTTP Host ----------------------------------------------------------------
    const char *req = "POST /upload HTTP/1.1\r\nUser-Agent: x\r\nhost: c2.example.org:8080\r\n\r\n";
    CHECK(net_http_host((const unsigned char *)req, strlen(req), out, sizeof out) == 1 &&
          strcmp(out, "c2.example.org:8080") == 0, "HTTP Host header, case-insensitive");
    const char *nohost = "GET / HTTP/1.0\r\n\r\n";
    CHECK(net_http_host((const unsigned char *)nohost, strlen(nohost), out, sizeof out) == 0,
          "request without Host");
    CHECK(net_http_host(ch, n, out, sizeof out) == 0, "TLS is not HTTP");

    // ---- DNS question name ---------------------------------------------------------
    size_t qn = slurp("tests/fixtures/dns_query.bin", q, sizeof q);
    CHECK(qn > 12, "DNS fixture loaded");
    CHECK(net_dns_qname(q, qn, out, sizeof out) == 1 && strcmp(out, "api.example-c2.net") == 0,
          "qname from a DNS query");
    CHECK(net_dns_qname(q, 14, out, sizeof out) == 0, "truncated question");
    unsigned char loop[16] = { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12 };
    CHECK(net_dns_qname(loop, sizeof loop, out, sizeof out) == 0, "compression pointer in a query rejected");

    // ---- netd dnsproxyd commands ---------------------------------------------------
    const char *gai = "getaddrinfo api.example-c2.net ^ 1024 0 1 6 0";
    CHECK(net_dnsproxy_host((const unsigned char *)gai, strlen(gai) + 1, out, sizeof out) == 1 &&
          strcmp(out, "api.example-c2.net") == 0, "getaddrinfo command");
    const char *ghbn = "gethostbyname 0 api.example-c2.net 2";
    CHECK(net_dnsproxy_host((const unsigned char *)ghbn, strlen(ghbn) + 1, out, sizeof out) == 1 &&
          strcmp(out, "api.example-c2.net") == 0, "gethostbyname command (netid first)");
    const char *rns = "resnsend 0 0 EjQBAAABAAAAAAAAA2FwaQpleGFtcGxlLWMyA25ldAAAAQAB";
    CHECK(net_dnsproxy_host((const unsigned char *)rns, strlen(rns) + 1, out, sizeof out) == 1 &&
          strcmp(out, "api.example-c2.net") == 0, "resnsend command (base64 DNS query)");
    const char *other = "getnetworkforpid 1234";
    CHECK(net_dnsproxy_host((const unsigned char *)other, strlen(other), out, sizeof out) == 0,
          "other netd command ignored");

    // ---- destination formatting ----------------------------------------------------
    unsigned char v4[16] = { 93, 184, 216, 34 };
    net_fmt_dest(2, v4, 443, out, sizeof out);
    CHECK(strcmp(out, "93.184.216.34:443") == 0, "IPv4 dest");
    unsigned char v6[16] = { 0x20, 0x01, 0x0d, 0xb8, [15] = 1 };
    net_fmt_dest(10, v6, 8443, out, sizeof out);
    CHECK(strcmp(out, "[2001:db8::1]:8443") == 0, "IPv6 dest");
    unsigned char m6[16] = { [10] = 0xff, [11] = 0xff, 10, 0, 0, 7 };
    net_fmt_dest(10, m6, 80, out, sizeof out);
    CHECK(strcmp(out, "10.0.0.7:80") == 0, "v4-mapped IPv6 shown as IPv4");

    printf("test_net_parse: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
