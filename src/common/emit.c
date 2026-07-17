// SPDX-License-Identifier: GPL-2.0
// Shared JSON serializer + output sink — see emit.h.
#include "common/emit.h"

#include <stdlib.h>   // realloc, malloc, free
#include <string.h>   // memcpy, strlen, strerror
#include <stdio.h>    // snprintf, fwrite, fputs, fputc, fflush, fclose, fprintf
#include <errno.h>    // errno, EIO

static void jb_need(struct jbuf *j, size_t n)
{
	if (j->err)
		return;                  // already poisoned — leave the buffer untouched
	if (j->len + n <= j->cap)
		return;
	size_t nc = j->cap ? j->cap * 2 : 8192;
	while (nc < j->len + n)
		nc *= 2;
	char *nb = realloc(j->b, nc);
	if (nb) { j->b = nb; j->cap = nc; }
	else j->err = 1;             // OOM grow failed: poison; the record is dropped at emit
}

// After jb_need, !err guarantees len+n <= cap, so guarding on !err is the
// capacity check — the old `if (j->b)` only checked non-NULL and wrote past cap.
static void jb_raw(struct jbuf *j, const char *s, size_t n)
{
	jb_need(j, n);
	if (j->b && !j->err) { memcpy(j->b + j->len, s, n); j->len += n; }
}

void jb_s(struct jbuf *j, const char *s) { jb_raw(j, s, strlen(s)); }
void jb_c(struct jbuf *j, char c) { jb_need(j, 1); if (j->b && !j->err) j->b[j->len++] = c; }

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
	char t[24];
	int n = snprintf(t, sizeof t, "%lld", v);
	jb_raw(j, t, (size_t)n);
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

// ---------------------------------------------------------------------------
// anubee_sink — shared file-output sink
// ---------------------------------------------------------------------------

#define SINK_BUF_SIZE (8u << 20)           // 8 MB write buffer
#define SINK_FLUSH_DEFAULT 8192u           // flush every N emitted records

int anubee_sink_open(struct anubee_sink *s, const char *path,
                   const char *noun, int jsonl)
{
    s->f = fopen(path, "w");
    if (!s->f)
        return -1;
    {
        char *vbuf = malloc(SINK_BUF_SIZE);
        if (setvbuf(s->f, vbuf, _IOFBF, SINK_BUF_SIZE) != 0) free(vbuf);
    }
    s->path   = path;
    s->noun   = noun;
    s->jsonl  = jsonl;
    s->count  = 0;
    s->since_flush = 0;
    if (!jsonl)
        fputc('[', s->f);
    return 0;
}

void anubee_sink_emit(struct anubee_sink *s)
{
    if (!s->f || !s->jb.b || !s->jb.len)
        return;
    if (s->jb.err) {
        // OOM during record build: drop this record and reset for the next.
        s->jb.err = 0; s->jb.len = 0;
        return;
    }
    if (s->jsonl) {
        fwrite(s->jb.b, 1, s->jb.len, s->f);
        fputc('\n', s->f);
    } else {
        fputs(s->count ? ",\n  " : "\n  ", s->f);
        fwrite(s->jb.b, 1, s->jb.len, s->f);
    }
    if (!s->werr && ferror(s->f)) s->werr = errno ? errno : EIO;
    s->count++;
    s->jb.len = 0;
    if (++s->since_flush >= SINK_FLUSH_DEFAULT) {
        if (fflush(s->f) != 0 && !s->werr) s->werr = errno ? errno : EIO;
        s->since_flush = 0;
    }
}

void anubee_sink_flush(struct anubee_sink *s)
{
    if (s->f && fflush(s->f) != 0 && !s->werr)
        s->werr = errno ? errno : EIO;
}

void anubee_sink_close(struct anubee_sink *s)
{
    if (!s->f)
        return;
    if (!s->jsonl)
        fputs("\n]\n", s->f);
    if (fflush(s->f) != 0 && !s->werr) s->werr = errno ? errno : EIO;
    if (fclose(s->f) != 0 && !s->werr) s->werr = errno ? errno : EIO;
    s->f = NULL;
    free(s->jb.b);
    s->jb.b = NULL; s->jb.len = s->jb.cap = 0;
}

void anubee_sink_report(const struct anubee_sink *s)
{
    if (!s->path || !s->noun)
        return;
    fprintf(stderr, "wrote %llu %s%s to %s\n",
            s->count, s->noun, s->count == 1 ? "" : "s", s->path);
    if (s->werr)
        fprintf(stderr, "WARNING: write error on %s (%s) — output is incomplete\n",
                s->path, strerror(s->werr));
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
