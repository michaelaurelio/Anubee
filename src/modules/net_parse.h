// SPDX-License-Identifier: GPL-2.0
// Pure parsers for the net analyzer (src/modules/net.c): the server name in
// a TLS ClientHello, the Host header of a plaintext HTTP request, the host
// in a netd dnsproxyd command, the question name of a DNS query, and
// destination formatting. Input is target-controlled: every read is bounds
// checked. libc only -- host-testable.
#ifndef __ANUBEE_NET_PARSE_H
#define __ANUBEE_NET_PARSE_H

#include <stddef.h>

// First bytes of a TLS connection -> SNI host_name. 1 = found (out always
// NUL-terminated, truncated to cap), 0 = not a ClientHello or the SNI lies
// beyond the n bytes captured.
int net_tls_sni(const unsigned char *b, size_t n, char *out, size_t cap);

// Plaintext HTTP/1.x request -> Host header value (port kept). 1 = found.
int net_http_host(const unsigned char *b, size_t n, char *out, size_t cap);

// A DNS message -> the first question's name, dotted. 1 = found.
int net_dns_qname(const unsigned char *msg, size_t n, char *out, size_t cap);

// A command an app's libc sends to netd's /dev/socket/dnsproxyd:
//   "getaddrinfo <host> <service> <flags> <family> <socktype> <proto> <netid>"
//   "gethostbyname <netid> <host> <af>"
//   "resnsend <netid> <flags> <base64 DNS query>"
// -> the host being looked up. 1 = found.
int net_dnsproxy_host(const unsigned char *b, size_t n, char *out, size_t cap);

// family 2 (AF_INET: addr[0..3]) or 10 (AF_INET6: addr[0..15]; v4-mapped
// shown as IPv4); port in host order. "a.b.c.d:port" / "[v6]:port".
void net_fmt_dest(unsigned family, const unsigned char *addr, unsigned port,
                  char *out, size_t cap);

#endif /* __ANUBEE_NET_PARSE_H */
