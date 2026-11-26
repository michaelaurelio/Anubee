// SPDX-License-Identifier: GPL-2.0
// Entry-event / return-value pairing by thread id (see sysret_pend.h).
// A small fixed table, linear scan: an app has at most a few dozen threads
// inside a traced syscall at once.
#include <stdlib.h>
#include <string.h>
#include "modules/sysret_pend.h"

struct slot {
    uint32_t tid;
    int      used;
    size_t   len;
    unsigned char *ev;
};

struct sysret_pend {
    unsigned cap;
    size_t   max_ev;
    unsigned count;
    struct slot *slots;
    unsigned char *buf;     // cap * max_ev bytes
};

struct sysret_pend *sysret_pend_new(unsigned cap, size_t max_ev)
{
    struct sysret_pend *p = calloc(1, sizeof *p);
    if (!p) return NULL;
    p->slots = calloc(cap, sizeof *p->slots);
    p->buf   = calloc(cap, max_ev ? max_ev : 1);
    if (!p->slots || !p->buf) { sysret_pend_free(p); return NULL; }
    p->cap = cap;
    p->max_ev = max_ev;
    for (unsigned i = 0; i < cap; i++)
        p->slots[i].ev = p->buf + (size_t)i * max_ev;
    return p;
}

void sysret_pend_free(struct sysret_pend *p)
{
    if (!p) return;
    free(p->slots);
    free(p->buf);
    free(p);
}

static struct slot *find(struct sysret_pend *p, uint32_t tid)
{
    for (unsigned i = 0; i < p->cap; i++)
        if (p->slots[i].used && p->slots[i].tid == tid)
            return &p->slots[i];
    return NULL;
}

static void release(struct sysret_pend *p, struct slot *s, long long ret, int known,
                    sysret_emit_fn emit, void *ctx)
{
    emit(ctx, s->ev, s->len, ret, known);
    s->used = 0;
    p->count--;
}

void sysret_pend_entry(struct sysret_pend *p, uint32_t tid, const void *ev, size_t len,
                       sysret_emit_fn emit, void *ctx)
{
    struct slot *s = find(p, tid);
    if (s)
        release(p, s, 0, 0, emit, ctx);
    if (len > p->max_ev || p->count >= p->cap) {
        emit(ctx, ev, len, 0, 0);
        return;
    }
    for (unsigned i = 0; i < p->cap; i++) {
        if (!p->slots[i].used) {
            s = &p->slots[i];
            break;
        }
    }
    memcpy(s->ev, ev, len);
    s->len  = len;
    s->tid  = tid;
    s->used = 1;
    p->count++;
}

int sysret_pend_result(struct sysret_pend *p, uint32_t tid, long long ret,
                       sysret_emit_fn emit, void *ctx)
{
    struct slot *s = find(p, tid);
    if (!s) return 0;
    release(p, s, ret, 1, emit, ctx);
    return 1;
}

void sysret_pend_flush(struct sysret_pend *p, sysret_emit_fn emit, void *ctx)
{
    for (unsigned i = 0; i < p->cap; i++)
        if (p->slots[i].used)
            release(p, &p->slots[i], 0, 0, emit, ctx);
}

unsigned sysret_pend_count(const struct sysret_pend *p)
{
    return p->count;
}

// The errnos open/exec actually return; numbers are the Linux generic ones
// (arm64 and x86-64 agree), so host tests and the device print the same names.
const char *sys_errno_name(long long ret)
{
    static const struct { int no; const char *name; } t[] = {
        { 1, "EPERM" }, { 2, "ENOENT" }, { 4, "EINTR" }, { 5, "EIO" }, { 7, "E2BIG" },
        { 8, "ENOEXEC" }, { 9, "EBADF" }, { 12, "ENOMEM" }, { 13, "EACCES" }, { 14, "EFAULT" },
        { 16, "EBUSY" }, { 17, "EEXIST" }, { 20, "ENOTDIR" }, { 21, "EISDIR" }, { 22, "EINVAL" },
        { 23, "ENFILE" }, { 24, "EMFILE" }, { 26, "ETXTBSY" }, { 28, "ENOSPC" }, { 30, "EROFS" },
        { 36, "ENAMETOOLONG" }, { 40, "ELOOP" }, { 95, "EOPNOTSUPP" },
    };
    if (ret >= 0) return NULL;
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
        if (t[i].no == -ret) return t[i].name;
    return NULL;
}
