// SPDX-License-Identifier: GPL-2.0
// Shared JSON serializer: a growable in-memory buffer with hand-rolled
// formatting (no per-field fprintf — that locks the FILE and re-parses a format
// string per call). Callers own a struct jbuf, build into it, then flush with a
// single fwrite(j.b, 1, j.len, stream). Lifted from the syscalls engine so all
// engines share one serializer and one escaper.
#ifndef __ARES_EMIT_H
#define __ARES_EMIT_H

#include <stddef.h>

struct jbuf { char *b; size_t len, cap; };

void jb_s(struct jbuf *j, const char *s);                 // append raw string
void jb_c(struct jbuf *j, char c);                        // append one char
void jb_u64(struct jbuf *j, unsigned long long v);        // decimal unsigned
void jb_i64(struct jbuf *j, long long v);                 // decimal signed
void jb_hex(struct jbuf *j, unsigned long long v);        // 0x-prefixed hex
void jb_esc(struct jbuf *j, const char *s);               // JSON-escaped string body
void jb_b64(struct jbuf *j, const unsigned char *p, size_t n);  // base64 blob

#endif /* __ARES_EMIT_H */
