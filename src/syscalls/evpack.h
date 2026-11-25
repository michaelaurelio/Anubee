/* evpack.h
 *
 * Compact queue format for the syscalls engine.
 *
 * The kernel ring records are fixed size (the BPF reservation cannot vary), but
 * the userspace queue behind `-Q` only needs the bytes a consumer reads. This
 * header packs a syscall record down to its valid prefix, stack words, present
 * strings, sockaddr bytes and compat flag, and trims a stack snapshot to the
 * valid part of snap[]. Records are rebuilt on the worker side, so consumers
 * never see the packed layout.
 *
 * Packed syscall record layout (offsets relative to the record start):
 *   1. prefix [0, offsetof(struct syscalls_syscall_event, stack))
 *   2. stack: clamp(stack_sz, 0, sizeof stack) bytes, rounded down to 8
 *   3. strings: for each slot i with bit i set in str_present, the bytes up to
 *      (not including) the first NUL plus one NUL
 *   4. sock: a __u32 length (clamped to SYSC_SOCK_MAX) then that many bytes
 *   5. one byte compat
 *   6. one byte binder flag; when it is 1, the fixed header of
 *      struct syscalls_binder_info followed by copied data bytes (at most
 *      SYSC_BINDER_DATA_MAX)
 *
 * All helpers are static inline and allocate no heap memory, so the drain
 * thread stays a few memcpy calls plus at most SYSC_STR_SLOTS strnlen calls.
 *
 * The includer must include <linux/types.h> first: syscalls.h uses __u32/__u64
 * and does not pull that header itself.
 */
#ifndef ANUBEE_SYSCALLS_EVPACK_H
#define ANUBEE_SYSCALLS_EVPACK_H

#include <stddef.h>
#include <string.h>

#include "syscalls/syscalls.h"

/* Valid stack bytes a record carries, clamped to stack[] and rounded to whole
 * 8-byte words. A negative stack_sz carries nothing. */
static inline size_t sysc_pack_stack_bytes(__s32 stack_sz)
{
	long sb = stack_sz;
	if (sb < 0) sb = 0;
	if (sb > (long)sizeof(((struct syscalls_syscall_event *)0)->stack))
		sb = (long)sizeof(((struct syscalls_syscall_event *)0)->stack);
	return (size_t)sb & ~(size_t)7;
}

/* out must hold sizeof(struct syscalls_syscall_event) bytes. Returns the packed
 * length, which is never more than sizeof(struct syscalls_syscall_event). */
static inline size_t sysc_pack_syscall(const struct syscalls_syscall_event *e, void *out)
{
	unsigned char *p = out;
	size_t o = offsetof(struct syscalls_syscall_event, stack);

	memcpy(p, e, o);
	size_t sb = sysc_pack_stack_bytes(e->stack_sz);
	memcpy(p + o, e->stack, sb);
	o += sb;
	for (int i = 0; i < SYSC_STR_SLOTS; i++) {
		if (!(e->str_present & (1u << i)))
			continue;
		size_t l = strnlen(e->str[i], SYSC_STR_MAX - 1);
		memcpy(p + o, e->str[i], l);
		p[o + l] = 0;
		o += l + 1;
	}
	__u32 sl = e->sock_len > SYSC_SOCK_MAX ? SYSC_SOCK_MAX : e->sock_len;
	memcpy(p + o, &sl, sizeof sl);
	o += sizeof sl;
	memcpy(p + o, e->sock, sl);
	o += sl;
	p[o++] = e->compat;
	__u8 bf = e->binder == 1 ? 1 : 0;
	p[o++] = bf;
	if (bf) {
		/* The capture overlays str[3]; copy the fixed header, then only the
		 * valid payload bytes. */
		const struct syscalls_binder_info *bi =
			(const struct syscalls_binder_info *)e->str[3];
		const size_t hdr = offsetof(struct syscalls_binder_info, data);
		__u32 copied = bi->copied;
		if (copied > SYSC_BINDER_DATA_MAX)
			copied = SYSC_BINDER_DATA_MAX;
		memcpy(p + o, bi, hdr);
		memcpy(p + o + offsetof(struct syscalls_binder_info, copied),
		       &copied, sizeof copied);
		o += hdr;
		memcpy(p + o, bi->data, copied);
		o += copied;
	}
	return o;
}

/* Rebuild a full record from n packed bytes. Returns 0 on success, or -1 with
 * *out zeroed when the input is short, inconsistent, or has trailing bytes. */
static inline int sysc_unpack_syscall(const void *in, size_t n,
				      struct syscalls_syscall_event *out)
{
	memset(out, 0, sizeof *out);
	const unsigned char *p = in;
	size_t o = offsetof(struct syscalls_syscall_event, stack);

	if (n < o)
		goto bad;
	memcpy(out, p, o);
	if (out->str_present & ~0xfu)
		goto bad;

	size_t sb = sysc_pack_stack_bytes(out->stack_sz);
	if (o + sb > n)
		goto bad;
	memcpy(out->stack, p + o, sb);
	o += sb;

	for (int i = 0; i < SYSC_STR_SLOTS; i++) {
		if (!(out->str_present & (1u << i)))
			continue;
		size_t avail = n - o;
		if (avail > SYSC_STR_MAX)
			avail = SYSC_STR_MAX;
		const unsigned char *z = memchr(p + o, 0, avail);
		if (!z)
			goto bad;
		size_t l = (size_t)(z - (p + o));
		memcpy(out->str[i], p + o, l + 1);
		o += l + 1;
	}

	__u32 sl;
	if (o + sizeof sl > n)
		goto bad;
	memcpy(&sl, p + o, sizeof sl);
	o += sizeof sl;
	if (sl > SYSC_SOCK_MAX)
		goto bad;
	if (o + sl + 1 > n)
		goto bad;
	memcpy(out->sock, p + o, sl);
	out->sock_len = sl;
	o += sl;
	out->compat = p[o++];

	if (o + 1 > n)
		goto bad;
	__u8 bf = p[o++];
	if (bf > 1)
		goto bad;
	if (bf == 1) {
		struct syscalls_binder_info *bi =
			(struct syscalls_binder_info *)out->str[3];
		const size_t hdr = offsetof(struct syscalls_binder_info, data);
		if (o + hdr > n)
			goto bad;
		memcpy(bi, p + o, hdr);
		o += hdr;
		if (bi->copied > SYSC_BINDER_DATA_MAX)
			goto bad;
		if (o + bi->copied > n)
			goto bad;
		memcpy(bi->data, p + o, bi->copied);
		o += bi->copied;
		out->binder = 1;
	}

	if (o != n)
		goto bad;
	return 0;
bad:
	memset(out, 0, sizeof *out);
	return -1;
}

/* Bytes a snapshot record needs in the queue: its header plus the valid part of
 * snap[] (at most ANUBEE_SNAP_MAX). */
static inline size_t sysc_stack_pack_len(const struct anubee_stack_snapshot *s)
{
	size_t l = s->snap_len;
	if (l > ANUBEE_SNAP_MAX) l = ANUBEE_SNAP_MAX;
	return offsetof(struct anubee_stack_snapshot, snap) + l;
}

/* True when a queued snapshot record of n bytes has a consistent snap_len and
 * carries every byte it claims. */
static inline int sysc_stack_rec_ok(const void *rec, size_t n)
{
	const size_t off = offsetof(struct anubee_stack_snapshot, snap);
	if (n < off) return 0;
	__u32 l;
	memcpy(&l, (const unsigned char *)rec + offsetof(struct anubee_stack_snapshot, snap_len),
	       sizeof l);
	return l <= ANUBEE_SNAP_MAX && n >= off + l;
}

#endif /* ANUBEE_SYSCALLS_EVPACK_H */
