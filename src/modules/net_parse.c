// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "modules/net_parse.h"

static unsigned be16(const unsigned char *p) { return (unsigned)p[0] << 8 | p[1]; }

static void copy_out(char *out, size_t cap, const unsigned char *s, size_t len)
{
    if (!cap) return;
    if (len >= cap) len = cap - 1;
    memcpy(out, s, len);
    out[len] = '\0';
}

int net_tls_sni(const unsigned char *b, size_t n, char *out, size_t cap)
{
    // record: type 22 (handshake), version 3.x, length; handshake: type 1
    if (!b || n < 9 || b[0] != 0x16 || b[1] != 3 || b[5] != 1) return 0;
    size_t p = 9;                        // record hdr (5) + handshake hdr (4)
    p += 2 + 32;                         // client_version + random
    if (p >= n) return 0;
    p += 1 + b[p];                       // session_id
    if (p + 2 > n) return 0;
    p += 2 + be16(b + p);                // cipher_suites
    if (p >= n) return 0;
    p += 1 + b[p];                       // compression_methods
    if (p + 2 > n) return 0;
    size_t ext_end = p + 2 + be16(b + p);
    p += 2;
    while (p + 4 <= n && p + 4 <= ext_end) {
        unsigned type = be16(b + p), len = be16(b + p + 2);
        p += 4;
        if (type == 0) {                 // server_name: list len, entries
            if (p + 2 > n) return 0;
            size_t q = p + 2, list_end = p + 2 + be16(b + p);
            while (q + 3 <= n && q + 3 <= list_end) {
                unsigned nt = b[q], nl = be16(b + q + 1);
                q += 3;
                if (q + nl > n) return 0;
                if (nt == 0 && nl > 0) { copy_out(out, cap, b + q, nl); return 1; }
                q += nl;
            }
            return 0;
        }
        p += len;
    }
    return 0;
}

int net_http_host(const unsigned char *b, size_t n, char *out, size_t cap)
{
    static const char *const methods[] = { "GET ", "POST ", "PUT ", "HEAD ", "DELETE ",
                                           "PATCH ", "OPTIONS ", "CONNECT " };
    if (!b) return 0;
    int is_http = 0;
    for (size_t i = 0; i < sizeof methods / sizeof methods[0]; i++) {
        size_t l = strlen(methods[i]);
        if (n >= l && !memcmp(b, methods[i], l)) { is_http = 1; break; }
    }
    if (!is_http) return 0;
    for (size_t i = 0; i + 7 < n; i++) {
        if (b[i] != '\n') continue;
        const unsigned char *h = b + i + 1;
        size_t rest = n - i - 1;
        if (rest < 5 || strncasecmp((const char *)h, "host:", 5)) continue;
        size_t s = 5;
        while (s < rest && (h[s] == ' ' || h[s] == '\t')) s++;
        size_t e = s;
        while (e < rest && h[e] != '\r' && h[e] != '\n') e++;
        if (e == s) return 0;
        copy_out(out, cap, h + s, e - s);
        return 1;
    }
    return 0;
}

int net_dns_qname(const unsigned char *msg, size_t n, char *out, size_t cap)
{
    if (!msg || n < 13 || be16(msg + 4) == 0 || !cap) return 0;   // QDCOUNT
    size_t p = 12, o = 0;
    while (p < n) {
        unsigned l = msg[p++];
        if (l == 0) {
            if (o == 0) return 0;
            out[o < cap ? o : cap - 1] = '\0';
            return 1;
        }
        if (l & 0xc0) return 0;          // no compression in a query's question
        if (p + l > n) return 0;
        if (o && o < cap - 1) out[o++] = '.';
        for (unsigned i = 0; i < l; i++)
            if (o < cap - 1) out[o++] = (char)msg[p + i];
        p += l;
    }
    return 0;
}

static int b64v(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

// Nth space-separated token (0-based) of the NUL/len-bounded command.
static int token(const unsigned char *b, size_t n, int idx, const unsigned char **s, size_t *len)
{
    size_t i = 0;
    for (int t = 0; ; t++) {
        while (i < n && b[i] == ' ') i++;
        size_t st = i;
        while (i < n && b[i] != ' ' && b[i] != '\0') i++;
        if (i == st) return 0;
        if (t == idx) { *s = b + st; *len = i - st; return 1; }
        if (i >= n || b[i] == '\0') return 0;
    }
}

int net_dnsproxy_host(const unsigned char *b, size_t n, char *out, size_t cap)
{
    const unsigned char *t;
    size_t l;
    if (!b || !token(b, n, 0, &t, &l)) return 0;
    if (l == 11 && !memcmp(t, "getaddrinfo", 11)) {
        if (!token(b, n, 1, &t, &l)) return 0;
        copy_out(out, cap, t, l);
        return 1;
    }
    if (l == 13 && !memcmp(t, "gethostbyname", 13)) {
        if (!token(b, n, 2, &t, &l)) return 0;
        copy_out(out, cap, t, l);
        return 1;
    }
    if (l == 8 && !memcmp(t, "resnsend", 8)) {
        if (!token(b, n, 3, &t, &l)) return 0;
        unsigned char msg[512];
        size_t m = 0;
        unsigned acc = 0;
        int bits = 0;
        for (size_t i = 0; i < l && m < sizeof msg; i++) {
            int v = b64v(t[i]);
            if (v < 0) break;            // '=' padding or junk ends the data
            acc = acc << 6 | (unsigned)v;
            bits += 6;
            if (bits >= 8) { bits -= 8; msg[m++] = (unsigned char)(acc >> bits); }
        }
        return net_dns_qname(msg, m, out, cap);
    }
    return 0;
}

void net_fmt_dest(unsigned family, const unsigned char *addr, unsigned port,
                  char *out, size_t cap)
{
    char a[INET6_ADDRSTRLEN] = "?";
    static const unsigned char mapped[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };
    if (family == 10 && !memcmp(addr, mapped, 12)) {
        inet_ntop(AF_INET, addr + 12, a, sizeof a);
        snprintf(out, cap, "%s:%u", a, port);
    } else if (family == 10) {
        inet_ntop(AF_INET6, addr, a, sizeof a);
        snprintf(out, cap, "[%s]:%u", a, port);
    } else {
        inet_ntop(AF_INET, addr, a, sizeof a);
        snprintf(out, cap, "%s:%u", a, port);
    }
}
