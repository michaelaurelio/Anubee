// SPDX-License-Identifier: GPL-2.0
// Shared JSON serializer — see emit.h. Moved verbatim from the syscalls engine.
#include "common/emit.h"

#include <stdlib.h>   // realloc
#include <string.h>   // memcpy, strlen
#include <stdio.h>    // snprintf

static void jb_need(struct jbuf *j, size_t n)
{
	if (j->len + n <= j->cap)
		return;
	size_t nc = j->cap ? j->cap * 2 : 8192;
	while (nc < j->len + n)
		nc *= 2;
	char *nb = realloc(j->b, nc);
	if (nb) { j->b = nb; j->cap = nc; }
}

static void jb_raw(struct jbuf *j, const char *s, size_t n)
{
	jb_need(j, n);
	if (j->b) { memcpy(j->b + j->len, s, n); j->len += n; }
}

void jb_s(struct jbuf *j, const char *s) { jb_raw(j, s, strlen(s)); }
void jb_c(struct jbuf *j, char c) { jb_need(j, 1); if (j->b) j->b[j->len++] = c; }

void jb_u64(struct jbuf *j, unsigned long long v)
{
	char t[24];
	int n = 0;
	do { t[n++] = '0' + (v % 10); v /= 10; } while (v);
	jb_need(j, n);
	while (n--) jb_c(j, t[n]);
}

void jb_i64(struct jbuf *j, long long v)
{
	if (v < 0) { jb_c(j, '-'); jb_u64(j, (unsigned long long)(-(v + 1)) + 1); }
	else jb_u64(j, (unsigned long long)v);
}

void jb_hex(struct jbuf *j, unsigned long long v)
{
	static const char d[] = "0123456789abcdef";
	char t[16];
	int n = 0;
	do { t[n++] = d[v & 0xf]; v >>= 4; } while (v);
	jb_s(j, "0x");
	jb_need(j, n);
	while (n--) jb_c(j, t[n]);
}

void jb_esc(struct jbuf *j, const char *s)
{
	const char *p = s;
	while (*p) {
		const char *run = p;             // bulk-copy the (common) run of safe chars
		unsigned char c;
		while ((c = (unsigned char)*p) >= 0x20 && c != '"' && c != '\\')
			p++;
		if (p > run)
			jb_raw(j, run, (size_t)(p - run));
		if (!*p)
			break;
		switch (*p) {
		case '"':  jb_s(j, "\\\""); break;
		case '\\': jb_s(j, "\\\\"); break;
		case '\n': jb_s(j, "\\n");  break;
		case '\r': jb_s(j, "\\r");  break;
		case '\t': jb_s(j, "\\t");  break;
		default: { char u[8]; snprintf(u, sizeof(u), "\\u%04x", (unsigned char)*p); jb_s(j, u); }
		}
		p++;
	}
}

// Base64-encode a byte run into the json buffer (for the stack snapshot blob).
void jb_b64(struct jbuf *j, const unsigned char *p, size_t n)
{
	static const char e[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	jb_need(j, (n + 2) / 3 * 4);
	size_t i = 0;
	for (; i + 3 <= n; i += 3) {
		unsigned v = (unsigned)p[i] << 16 | (unsigned)p[i + 1] << 8 | p[i + 2];
		jb_c(j, e[(v >> 18) & 63]); jb_c(j, e[(v >> 12) & 63]);
		jb_c(j, e[(v >> 6) & 63]);  jb_c(j, e[v & 63]);
	}
	if (n - i == 1) {
		unsigned v = (unsigned)p[i] << 16;
		jb_c(j, e[(v >> 18) & 63]); jb_c(j, e[(v >> 12) & 63]);
		jb_s(j, "==");
	} else if (n - i == 2) {
		unsigned v = (unsigned)p[i] << 16 | (unsigned)p[i + 1] << 8;
		jb_c(j, e[(v >> 18) & 63]); jb_c(j, e[(v >> 12) & 63]);
		jb_c(j, e[(v >> 6) & 63]); jb_c(j, '=');
	}
}
