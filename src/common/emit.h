// SPDX-License-Identifier: GPL-2.0
// Shared JSON serializer: a growable in-memory buffer with hand-rolled
// formatting (no per-field fprintf — that locks the FILE and re-parses a format
// string per call). Callers own a struct jbuf, build into it, then flush with a
// single fwrite(j.b, 1, j.len, stream). Lifted from the syscalls engine so all
// engines share one serializer and one escaper.
#ifndef __ARES_EMIT_H
#define __ARES_EMIT_H

#include <stddef.h>
#include <stdio.h>

// err latches on a failed realloc grow: once set, every jb_* write is a no-op
// (so nothing is written past cap) and ares_sink_emit drops the whole record.
struct jbuf { char *b; size_t len, cap; int err; };

// Flush the output sink every N records to limit loss on hard kill.
#define ARES_FLUSH_MASK 0x3fff

void jb_s(struct jbuf *j, const char *s);                 // append raw string
void jb_c(struct jbuf *j, char c);                        // append one char
void jb_u64(struct jbuf *j, unsigned long long v);        // decimal unsigned
void jb_i64(struct jbuf *j, long long v);                 // decimal signed
void jb_hex(struct jbuf *j, unsigned long long v);        // 0x-prefixed hex
void jb_esc(struct jbuf *j, const char *s);               // JSON-escaped string body
void jb_b64(struct jbuf *j, const unsigned char *p, size_t n);  // base64 blob

// Shared output sink: owns FILE*, jbuf, count, flush policy, and framing.
// Default: single-writer, no lock; caller ensures one thread drives it.
// Multi-writer engines (e.g. funcs: drain lib/unlib + worker call/return) MUST
// serialize all jb-build + ares_sink_emit calls under an external mutex.
// ares_sink_flush (fflush only) is safe to call unlocked from any thread.
struct ares_sink {
    FILE               *f;
    struct jbuf         jb;           // engine builds a bare {…} object into jb, then calls emit
    unsigned long long  count;
    const char         *path;         // for the "wrote N" report
    const char         *noun;         // "syscall" / "event"
    int                 jsonl;        // 1 = newline-per-record; 0 = JSON array with commas
    unsigned long       since_flush;
    int                 werr;         // latched errno of first write failure (0 = ok)
};

// Open sink: fopen("w") + 8 MB _IOFBF buffer. Array mode: writes opening '['.
int  ares_sink_open(struct ares_sink *s, const char *path,
                    const char *noun, int jsonl);
// Write jb as the next record (with framing); reset jb.len; periodic flush.
void ares_sink_emit(struct ares_sink *s);
void ares_sink_flush(struct ares_sink *s);
// Array mode: writes "\n]\n". Flushes and fcloses.
void ares_sink_close(struct ares_sink *s);
// Prints "wrote N <noun>(s) to PATH\n" to stderr. Safe to call after close.
void ares_sink_report(const struct ares_sink *s);

#endif /* __ARES_EMIT_H */
