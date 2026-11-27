// Host unit tests for the binder write-buffer walk (syscalls/binder_capture.h).
//
// The walk reads user memory only through SYSC_BINDER_READ, which the BPF side
// defines as bpf_probe_read_user and this test defines over a fake address
// space. Layout pins at the end keep the on-record overlay and the ring record
// size fixed.
#include <linux/types.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

// ---- fake user address space ---------------------------------------------

#define MEM_BASE 0x10000000ULL
#define MEM_SIZE 4096

static unsigned char g_mem[MEM_SIZE];
static __u64 g_fail_lo, g_fail_hi;
static int g_fail_on;
static __u64 g_tag;   // pointer tag OR-ed into pointers stored in user structures
static size_t g_max_read;

static int fake_read(void *dst, __u64 n, __u64 src)
{
	if (g_fail_on && src < g_fail_hi && src + n > g_fail_lo)
		return -1;
	if (src < MEM_BASE || n > MEM_SIZE || src + n > MEM_BASE + MEM_SIZE)
		return -1;
	if (n > g_max_read)
		g_max_read = n;
	memcpy(dst, g_mem + (src - MEM_BASE), n);
	return 0;
}

#define SYSC_BINDER_READ(d, n, s) fake_read((d), (__u64)(n), (__u64)(s))

#include "syscalls/binder_capture.h"

static int checks, failures;
#define CHECK(cond, msg) do {                                      \
	checks++;                                                  \
	if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); }   \
} while (0)

// ---- builder --------------------------------------------------------------

#define BWR_ADDR   (MEM_BASE + 0x0)
#define BUF_ADDR   (MEM_BASE + 0x100)
#define DATA_ADDR  (MEM_BASE + 0x800)
#define DATA_END   (DATA_ADDR + 0x400)

// Command numbers used by the tests: the walk cares about the command value and
// its _IOC size field, not about the payload of the skipped commands.
#define BC_ACQUIRE      0x40046212u     // _IOW('b', 18, __u32)
#define BC_FREE_BUFFER  0x40086215u     // _IOW('b', 21, binder_uintptr_t)
#define BC_REPLY        0x40406302u     // _IOW('b', 2, binder_transaction_data)
#define BC_TRANSACTION  0x40406300u
#define BC_TRANSACTION_SG 0x40486311u

struct txn64 {
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

struct bwr48 {
	__u64 write_size;
	__u64 write_consumed;
	__u64 write_buffer;
	__u64 read_size;
	__u64 read_consumed;
	__u64 read_buffer;
};

static __u64 g_off;

static void put(__u64 addr, const void *src, size_t n)
{
	memcpy(g_mem + (addr - MEM_BASE), src, n);
}

static void put_u32(__u64 addr, __u32 v)
{
	put(addr, &v, sizeof v);
}

static void begin(void)
{
	memset(g_mem, 0, sizeof g_mem);
	g_off = 0;
	g_fail_on = 0;
	g_max_read = 0;
	g_tag = 0;
}

static void skip_cmd(__u32 cmd)
{
	put_u32(BUF_ADDR + g_off, cmd);
	g_off += 4 + ((cmd >> 16) & 0x3fffu);
}

static void txn_cmd(__u32 cmd, __u32 handle, __u32 code, __u32 flags,
		    __u64 data_size, __u64 data_ptr)
{
	struct txn64 t;
	memset(&t, 0, sizeof t);
	t.handle = handle;
	t.code = code;
	t.flags = flags;
	t.data_size = data_size;
	t.data_buffer = data_ptr ? (data_ptr | g_tag) : 0;
	put_u32(BUF_ADDR + g_off, cmd);
	put(BUF_ADDR + g_off + 4, &t, sizeof t);
	g_off += sizeof t + 4;
	// BC_TRANSACTION_SG carries an extra buffers_size word after the struct.
	if (cmd == BC_TRANSACTION_SG)
		g_off += 8;
}

static void finish(__u64 consumed)
{
	struct bwr48 b;
	memset(&b, 0, sizeof b);
	b.write_size = g_off;
	b.write_consumed = consumed;
	b.write_buffer = BUF_ADDR | g_tag;
	put(BWR_ADDR, &b, sizeof b);
}

static int capture(struct syscalls_binder_info *out)
{
	memset(out, 0, sizeof *out);
	return sysc_binder_capture(BWR_ADDR, out);
}

static void test_no_transaction(void)
{
	struct syscalls_binder_info o;

	// Four non-transaction commands: nothing captured.
	begin();
	skip_cmd(BC_FREE_BUFFER);
	skip_cmd(BC_ACQUIRE);
	skip_cmd(BC_FREE_BUFFER);
	skip_cmd(BC_ACQUIRE);
	finish(0);
	CHECK(capture(&o) == 0, "no transaction in four commands");
	CHECK(o.copied == 0, "nothing copied without a transaction");

	// A transaction in the fifth command is beyond the walk limit.
	begin();
	skip_cmd(BC_ACQUIRE);
	skip_cmd(BC_ACQUIRE);
	skip_cmd(BC_ACQUIRE);
	skip_cmd(BC_ACQUIRE);
	txn_cmd(BC_TRANSACTION, 1, 2, 0, 0, 0);
	finish(0);
	CHECK(capture(&o) == 0, "transaction in the fifth command is not captured");
}

static void test_position(void)
{
	struct syscalls_binder_info o;

	// First command.
	begin();
	txn_cmd(BC_TRANSACTION, 3, 11, 0x10, 0, 0);
	finish(0);
	CHECK(capture(&o) == 1, "transaction first is captured");
	CHECK(o.cmd == BC_TRANSACTION, "first transaction command stored");
	CHECK(o.handle == 3 && o.code == 11 && o.flags == 0x10, "first txn metadata");

	// Second command.
	begin();
	skip_cmd(BC_FREE_BUFFER);
	txn_cmd(BC_TRANSACTION, 4, 12, 0x11, 0, 0);
	finish(0);
	CHECK(capture(&o) == 1, "transaction second is captured");
	CHECK(o.handle == 4 && o.code == 12, "second txn metadata");

	// Fourth command.
	begin();
	skip_cmd(BC_ACQUIRE);
	skip_cmd(BC_ACQUIRE);
	skip_cmd(BC_ACQUIRE);
	txn_cmd(BC_TRANSACTION, 5, 13, 0, 0, 0);
	finish(0);
	CHECK(capture(&o) == 1, "transaction fourth is captured");
	CHECK(o.handle == 5 && o.code == 13, "fourth txn metadata");

	// write_consumed offsets the start of the walk.
	begin();
	skip_cmd(BC_ACQUIRE);
	txn_cmd(BC_TRANSACTION, 6, 14, 0, 0, 0);
	finish(8);
	CHECK(capture(&o) == 1, "transaction after consumed bytes is captured");
	CHECK(o.handle == 6 && o.code == 14, "consumed-offset txn metadata");
}

static void test_commands(void)
{
	struct syscalls_binder_info o;

	// BC_TRANSACTION_SG is captured with the same layout.
	begin();
	txn_cmd(BC_TRANSACTION_SG, 7, 15, 0x20, 0, 0);
	finish(0);
	CHECK(capture(&o) == 1, "BC_TRANSACTION_SG is captured");
	CHECK(o.cmd == BC_TRANSACTION_SG, "SG command stored");
	CHECK(o.handle == 7 && o.code == 15, "SG txn metadata");

	// BC_REPLY is skipped; a later transaction is still found.
	begin();
	skip_cmd(BC_REPLY);
	txn_cmd(BC_TRANSACTION, 8, 16, 0, 0, 0);
	finish(0);
	CHECK(capture(&o) == 1, "transaction after a reply is captured");
	CHECK(o.handle == 8 && o.code == 16, "post-reply txn metadata");
}

static void test_bounds(void)
{
	struct syscalls_binder_info o;

	// consumed >= size: nothing to walk.
	begin();
	txn_cmd(BC_TRANSACTION, 1, 1, 0, 0, 0);
	finish(g_off);
	CHECK(capture(&o) == 0, "write_consumed == write_size yields nothing");
	begin();
	txn_cmd(BC_TRANSACTION, 1, 1, 0, 0, 0);
	finish(g_off + 8);
	CHECK(capture(&o) == 0, "write_consumed > write_size yields nothing");

	// A size field that would step past the end stops the walk.
	begin();
	put_u32(BUF_ADDR, 0x3fff6201u);           // size 0x3fff, not a transaction
	g_off = 8;                                 // only one command word present
	txn_cmd(BC_TRANSACTION, 1, 1, 0, 0, 0);
	finish(0);
	CHECK(capture(&o) == 0, "huge command size does not walk past the end");
}

// Heap pointers stored in the binder structures carry a tag in the top byte;
// the fake reader (like the kernel helper) rejects tagged addresses, so the
// capture must strip the tag from write_buffer and data_buffer.
static void test_tagged_pointers(void)
{
	struct syscalls_binder_info o;

	begin();
	g_tag = 0xb4ULL << 56;
	for (int k = 0; k < 16; k++)
		g_mem[(DATA_ADDR - MEM_BASE) + k] = (unsigned char)(k + 1);
	skip_cmd(BC_ACQUIRE);
	txn_cmd(BC_TRANSACTION, 5, 21, 0, 16, DATA_ADDR);
	finish(0);
	CHECK(capture(&o) == 1, "tagged write_buffer is captured");
	CHECK(o.handle == 5 && o.code == 21, "tagged write_buffer metadata");
	CHECK(o.copied == 16 && o.data[0] == 1 && o.data[15] == 16,
	      "tagged data_buffer payload is read");
}

static void test_payload(void)
{
	struct syscalls_binder_info o;
	static const struct { __u64 size; __u32 copied; } cases[] = {
		{ 0, 0 }, { 10, 10 }, { 192, 192 }, { 193, 192 }, { 100000, 192 },
	};
	static const unsigned char pattern[192] = { 0 };

	// Data bytes in the fake address space so a successful read is visible.
	for (size_t i = 0; i < sizeof pattern; i++)
		g_mem[(DATA_ADDR - MEM_BASE) + i] = (unsigned char)(i + 1);

	for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		begin();
		for (size_t k = 0; k < sizeof pattern; k++)
			g_mem[(DATA_ADDR - MEM_BASE) + k] = (unsigned char)(k + 1);
		txn_cmd(BC_TRANSACTION, 9, 17, 0, cases[i].size, DATA_ADDR);
		finish(0);
		CHECK(capture(&o) == 1, "transaction with payload is captured");
		CHECK(o.data_size == cases[i].size, "full data_size stored");
		CHECK(o.copied == cases[i].copied, "copied bytes clamped to the limit");
		CHECK(g_max_read <= SYSC_BINDER_DATA_MAX, "payload read never exceeds the limit");
	}
	CHECK(o.data[0] == 1 && o.data[191] == 192, "payload bytes stored in order");

	// Unreadable payload: metadata only, copied stays 0.
	begin();
	txn_cmd(BC_TRANSACTION, 10, 18, 0, 32, MEM_BASE + MEM_SIZE + 0x10);
	finish(0);
	CHECK(capture(&o) == 1, "unreadable payload still captures metadata");
	CHECK(o.handle == 10 && o.code == 18, "metadata survives payload read failure");
	CHECK(o.copied == 0, "unreadable payload copies no bytes");
}

static void test_read_failures(void)
{
	struct syscalls_binder_info o;
	__u64 txn_addr;
	__u64 cmd_addr;

	// bwr itself unreadable.
	begin();
	txn_cmd(BC_TRANSACTION, 1, 1, 0, 0, 0);
	finish(0);
	g_fail_on = 1;
	g_fail_lo = BWR_ADDR;
	g_fail_hi = BWR_ADDR + 1;
	CHECK(capture(&o) == 0, "unreadable binder_write_read yields nothing");

	// Command word unreadable.
	begin();
	txn_cmd(BC_TRANSACTION, 1, 1, 0, 0, 0);
	finish(0);
	g_fail_on = 1;
	g_fail_lo = BUF_ADDR;
	g_fail_hi = BUF_ADDR + 1;
	CHECK(capture(&o) == 0, "unreadable command word yields nothing");

	// Transaction struct unreadable.
	begin();
	txn_cmd(BC_TRANSACTION, 1, 1, 0, 0, 0);
	finish(0);
	txn_addr = BUF_ADDR + 4;
	g_fail_on = 1;
	g_fail_lo = txn_addr;
	g_fail_hi = txn_addr + 1;
	CHECK(capture(&o) == 0, "unreadable transaction struct yields nothing");

	// Command word readable, following command unreadable: the walk stops.
	begin();
	skip_cmd(BC_FREE_BUFFER);
	txn_cmd(BC_TRANSACTION, 1, 1, 0, 0, 0);
	finish(0);
	cmd_addr = BUF_ADDR + 12;      // second command word
	g_fail_on = 1;
	g_fail_lo = cmd_addr;
	g_fail_hi = cmd_addr + 1;
	CHECK(capture(&o) == 0, "read failure while walking stops the walk");
}

static void test_layout(void)
{
	// The capture overlay must stay inside str[3] and the extra flag byte in the
	// tail padding, so the ring record size is unchanged.
	CHECK(sizeof(struct syscalls_syscall_event) == 1448, "ring record size unchanged");
	CHECK(offsetof(struct syscalls_syscall_event, binder) == 1445, "binder flag in tail padding");
	CHECK(offsetof(struct syscalls_syscall_event, str) == 352, "string slots start");
	CHECK(sizeof(struct syscalls_binder_info) == 32 + SYSC_BINDER_DATA_MAX,
	      "capture struct size");
	CHECK(offsetof(struct syscalls_binder_info, data) == 32, "capture data offset");
	CHECK(sizeof(struct syscalls_binder_info) <= SYSC_STR_MAX, "capture fits one slot");
	CHECK(sizeof(struct txn64) == 64, "binder_transaction_data layout pinned");
	CHECK(offsetof(struct txn64, code) == 16, "transaction code offset");
	CHECK(offsetof(struct txn64, data_size) == 32, "transaction data_size offset");
	CHECK(offsetof(struct txn64, data_buffer) == 48, "transaction data buffer offset");
	CHECK(sizeof(struct bwr48) == 48, "binder_write_read layout pinned");
	CHECK(offsetof(struct bwr48, write_buffer) == 16, "write buffer offset");
	CHECK(SYSC_BINDER_WRITE_READ == 0xc0306201u, "BINDER_WRITE_READ command value");
	CHECK(SYSC_BC_TRANSACTION == 0x40406300u, "BC_TRANSACTION command value");
	CHECK(SYSC_BC_TRANSACTION_SG == 0x40486311u, "BC_TRANSACTION_SG command value");
	CHECK(SYSC_BINDER_MAX_CMDS == 4, "walk limit");
}

int main(void)
{
	test_no_transaction();
	test_position();
	test_commands();
	test_bounds();
	test_payload();
	test_tagged_pointers();
	test_read_failures();
	test_layout();

	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
