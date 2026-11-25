/* binder_capture.h
 *
 * Walk the write buffer of an ioctl(fd, BINDER_WRITE_READ, &bwr) call and copy
 * the first BC_TRANSACTION / BC_TRANSACTION_SG metadata plus its Parcel data.
 *
 * Shared by the BPF program (which defines SYSC_BINDER_READ as
 * bpf_probe_read_user) and the host test (which defines it over a fake address
 * space). The includer must include <linux/types.h> (userspace) or vmlinux.h
 * (BPF) before this header, and must define:
 *
 *   SYSC_BINDER_READ(dst, n, src)   read n bytes from user address src into dst,
 *                                   returning 0 on success and nonzero on error
 *
 * Commands are _IOC-encoded: the payload size is (cmd >> 16) & 0x3fff, so a
 * command is skipped by 4 + size bytes. Only the transaction payload is read;
 * BC_REPLY and other commands are stepped over. The loop is a fixed four
 * iterations and fully unrolled so the verifier sees the same shape that the
 * host test exercises.
 */
#ifndef ANUBEE_SYSCALLS_BINDER_CAPTURE_H
#define ANUBEE_SYSCALLS_BINDER_CAPTURE_H

#include "syscalls/syscalls.h"

/* Kernel ABI values (arm64, 64-bit binder_uintptr_t), derived with the generic
 * _IOC formula (dir << 30 | size << 16 | type << 8 | nr) rather than a kernel
 * header, which the cross sysroot need not provide. */
#define SYSC_BINDER_WRITE_READ   0xc0306201u   /* _IOWR('b', 1, 48) */
#define SYSC_BC_TRANSACTION      0x40406300u   /* _IOW('b', 0, 64) */
#define SYSC_BC_TRANSACTION_SG   0x40486311u   /* _IOW('b', 17, 72) */

#define SYSC_BINDER_MAX_CMDS     4

/* Heap pointers inside the binder structures carry a pointer tag in the top
 * byte (arm64 top-byte-ignore). Userspace dereferences ignore it, but
 * bpf_probe_read_user() faults on a tagged address, so the tag is stripped
 * before every read of a pointer taken from user memory. */
#define SYSC_BINDER_UNTAG(p)     ((__u64)(p) & 0x00ffffffffffffffULL)

/* struct binder_write_read (48 B): only the write side is used here. */
struct sysc_binder_write_read {
	__u64 write_size;
	__u64 write_consumed;
	__u64 write_buffer;
	__u64 read_size;
	__u64 read_consumed;
	__u64 read_buffer;
};

/* struct binder_transaction_data (64 B): the leading target union is 8 bytes,
 * so the handle is its first word and cookie starts at +8. The first 64 bytes
 * of binder_transaction_data_sg are identical, which is all we read. */
struct sysc_binder_transaction_data {
	__u32 handle;
	__u32 _pad;
	__u64 cookie;
	__u32 code;
	__u32 flags;
	__s32 sender_pid;
	__u32 sender_euid;
	__u64 data_size;
	__u64 offsets_size;
	__u64 data_buffer;
	__u64 data_offsets;
};

/* Read the first transaction command from the write buffer at bwr_ptr and fill
 * *out (cmd, handle, code, flags, data_size and up to SYSC_BINDER_DATA_MAX
 * payload bytes). Returns 1 when a transaction was captured (out->copied may
 * still be 0 if the payload was unreadable) and 0 otherwise. */
static inline int sysc_binder_capture(__u64 bwr_ptr, struct syscalls_binder_info *out)
{
	struct sysc_binder_write_read bwr;

	if (SYSC_BINDER_READ(&bwr, sizeof bwr, SYSC_BINDER_UNTAG(bwr_ptr)) != 0)
		return 0;
	if (bwr.write_consumed >= bwr.write_size)
		return 0;

	__u64 wbuf = SYSC_BINDER_UNTAG(bwr.write_buffer);
	__u64 ptr = wbuf + bwr.write_consumed;
	__u64 end = wbuf + bwr.write_size;

	#ifdef __clang__
	#pragma clang loop unroll(full)
	#endif
	for (int i = 0; i < SYSC_BINDER_MAX_CMDS; i++) {
		__u32 cmd;
		if (ptr > end || end - ptr < 4)
			return 0;
		if (SYSC_BINDER_READ(&cmd, sizeof cmd, ptr) != 0)
			return 0;

		if (cmd == SYSC_BC_TRANSACTION || cmd == SYSC_BC_TRANSACTION_SG) {
			struct sysc_binder_transaction_data td;
			if (SYSC_BINDER_READ(&td, sizeof td, ptr + 4) != 0)
				return 0;

			out->cmd = cmd;
			out->handle = td.handle;
			out->code = td.code;
			out->flags = td.flags;
			out->data_size = td.data_size;
			out->_pad = 0;

			/* Two independent bounds: the conditional clamp, then a mask
			 * on the exact size register the verifier tracks. */
			__u64 n = td.data_size < SYSC_BINDER_DATA_MAX ?
				  td.data_size : SYSC_BINDER_DATA_MAX;
			n &= 0xff;
			out->copied = 0;
			if (n && SYSC_BINDER_READ(out->data, n, SYSC_BINDER_UNTAG(td.data_buffer)) == 0)
				out->copied = (__u32)n;
			return 1;
		}

		__u64 sz = (cmd >> 16) & 0x3fff;
		if (end - ptr < 4 + sz)
			return 0;
		ptr += 4 + sz;
	}
	return 0;
}

#endif /* ANUBEE_SYSCALLS_BINDER_CAPTURE_H */
