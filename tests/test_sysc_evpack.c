// Host unit tests for the syscalls compact queue record packer.
#include <linux/types.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "syscalls/evpack.h"
#include "common/evqueue.h"

static int failures;
#define CHECK(cond) do { \
    if (cond) { printf("  ok: %s\n", #cond); } \
    else { printf("  FAIL: %s\n", #cond); failures++; } \
} while (0)

// Fresh typical record with 0xA5 stale bytes, so a field the unpacker forgets
// to rebuild shows up as a mismatch instead of a lucky zero.
static void fill(struct syscalls_syscall_event *e)
{
    memset(e, 0xA5, sizeof *e);
    e->h.type = SYSC_EV_SYSCALL;
    e->h.pid = 100;
    e->h.tid = 101;
    e->nr = 56;
    e->ktime = 123456789;
    for (int i = 0; i < SYSC_SYSCALL_NARGS; i++)
        e->args[i] = 0x1000 + i;
    e->stack_id = 0xdeadbeef;
}

// The binder capture overlays str[3] of an ioctl record (see syscalls.h).
static struct syscalls_binder_info *binder_info(struct syscalls_syscall_event *e)
{
    return (struct syscalls_binder_info *)e->str[3];
}

int main(void)
{
    struct syscalls_syscall_event e, out;
    unsigned char pk[sizeof(struct syscalls_syscall_event) + 16];
    size_t n;

    // 1. Typical open-style record: stack, one string, no sockaddr.
    fill(&e);
    e.stack_sz = 5 * 8;
    for (int i = 0; i < 5; i++)
        e.stack[i] = 0x7000 + i;
    e.str_present = 1;
    memset(e.str[0], 0, sizeof e.str[0]);
    strcpy(e.str[0], "/proc/self/maps");
    e.sock_len = 0;
    e.compat = 0;

    n = sysc_pack_syscall(&e, pk);
    CHECK(n < 400);
    CHECK(n <= sizeof(struct syscalls_syscall_event));
    memset(&out, 0, sizeof out);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
    CHECK(out.h.type == e.h.type);
    CHECK(out.h.pid == e.h.pid);
    CHECK(out.h.tid == e.h.tid);
    CHECK(out.nr == e.nr);
    CHECK(out.ktime == e.ktime);
    for (int i = 0; i < SYSC_SYSCALL_NARGS; i++)
        CHECK(out.args[i] == e.args[i]);
    CHECK(out.stack_sz == e.stack_sz);
    for (int i = 0; i < 5; i++)
        CHECK(out.stack[i] == e.stack[i]);
    CHECK(out.str_present == e.str_present);
    CHECK(strcmp(out.str[0], "/proc/self/maps") == 0);
    CHECK(out.stack_id == e.stack_id);
    CHECK(out.sock_len == 0);
    CHECK(out.compat == 0);

    // Exact length matters: one byte short or one byte long is rejected.
    CHECK(sysc_unpack_syscall(pk, n - 1, &out) == -1);
    CHECK(sysc_unpack_syscall(pk, n + 1, &out) == -1);

    // 2. String slots 0 and 2 set, 1 and 3 absent.
    fill(&e);
    e.stack_sz = 0;
    e.str_present = 5;
    e.sock_len = 0;
    e.compat = 0;
    memset(e.str[0], 0, sizeof e.str[0]);
    memset(e.str[2], 0, sizeof e.str[2]);
    strcpy(e.str[0], "/system/lib64/libc.so");
    strcpy(e.str[2], "O_RDONLY");
    n = sysc_pack_syscall(&e, pk);
    memset(&out, 0, sizeof out);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
    CHECK(strcmp(out.str[0], "/system/lib64/libc.so") == 0);
    CHECK(out.str[1][0] == 0);
    CHECK(strcmp(out.str[2], "O_RDONLY") == 0);
    CHECK(out.str[3][0] == 0);

    // 3. Maximum-length string and a slot with no NUL inside its 256 bytes.
    fill(&e);
    e.stack_sz = 0;
    e.str_present = 1;
    e.sock_len = 0;
    e.compat = 0;
    memset(e.str[0], 'a', SYSC_STR_MAX - 1);
    e.str[0][SYSC_STR_MAX - 1] = 0;
    n = sysc_pack_syscall(&e, pk);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
    CHECK(strcmp(out.str[0], e.str[0]) == 0);

    memset(e.str[0], 'b', SYSC_STR_MAX);
    n = sysc_pack_syscall(&e, pk);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
    CHECK(out.str[0][255] == 0);
    CHECK(out.str[0][0] == 'b' && out.str[0][254] == 'b');

    // 4. Stack sizes: zero, full, out of range, negative.
    fill(&e);
    e.stack_sz = 0;
    e.str_present = 0;
    e.sock_len = 0;
    e.compat = 0;
    n = sysc_pack_syscall(&e, pk);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
    CHECK(out.stack_sz == 0);

    fill(&e);
    e.stack_sz = 256;
    e.str_present = 0;
    e.sock_len = 0;
    e.compat = 0;
    for (int i = 0; i < SYSC_MAX_STACK_DEPTH; i++)
        e.stack[i] = 0x8000 + i;
    n = sysc_pack_syscall(&e, pk);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
    CHECK(out.stack_sz == 256);
    for (int i = 0; i < SYSC_MAX_STACK_DEPTH; i++)
        CHECK(out.stack[i] == e.stack[i]);

    fill(&e);
    e.stack_sz = 4096;                    // larger than stack[]
    e.str_present = 0;
    e.sock_len = 0;
    e.compat = 0;
    n = sysc_pack_syscall(&e, pk);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
    CHECK(out.stack_sz == 4096);           // prefix field is preserved verbatim

    fill(&e);
    e.stack_sz = -8;
    e.str_present = 0;
    e.sock_len = 0;
    e.compat = 0;
    n = sysc_pack_syscall(&e, pk);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);

    // 5. Sockaddr: exact length and clamped out-of-range length.
    fill(&e);
    e.stack_sz = 0;
    e.str_present = 0;
    e.sock_len = 16;
    e.compat = 0;
    for (int i = 0; i < 16; i++)
        e.sock[i] = (unsigned char)i;
    n = sysc_pack_syscall(&e, pk);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
    CHECK(out.sock_len == 16);
    for (int i = 0; i < 16; i++)
        CHECK(out.sock[i] == (unsigned char)i);

    fill(&e);
    e.stack_sz = 0;
    e.str_present = 0;
    e.sock_len = 200;                     // larger than sock[]
    e.compat = 0;
    n = sysc_pack_syscall(&e, pk);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
    CHECK(out.sock_len == SYSC_SOCK_MAX);

    // 6. compat flag.
    fill(&e);
    e.stack_sz = 0;
    e.str_present = 0;
    e.sock_len = 0;
    e.compat = 1;
    n = sysc_pack_syscall(&e, pk);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
    CHECK(out.compat == 1);

    // 7. Malformed input is rejected and leaves the output zeroed.
    {
        unsigned char zero[10] = {0};
        memset(&out, 0x5A, sizeof out);
        CHECK(sysc_unpack_syscall(zero, sizeof zero, &out) == -1);
        CHECK(out.nr == 0 && out.stack_id == 0);
    }

    fill(&e);
    e.stack_sz = 5 * 8;
    for (int i = 0; i < 5; i++)
        e.stack[i] = 0x7000 + i;
    e.str_present = 1;
    e.sock_len = 0;
    e.compat = 0;
    memset(e.str[0], 0, sizeof e.str[0]);
    strcpy(e.str[0], "/proc/self/maps");
    n = sysc_pack_syscall(&e, pk);
    memset(&out, 0x5A, sizeof out);
    CHECK(sysc_unpack_syscall(pk, n - 1, &out) == -1);
    CHECK(out.nr == 0 && out.stack_id == 0);

    pk[n] = 0;                             // one extra trailing byte
    memset(&out, 0x5A, sizeof out);
    CHECK(sysc_unpack_syscall(pk, n + 1, &out) == -1);
    CHECK(out.nr == 0 && out.stack_id == 0);

    {
        __u32 sp = e.str_present | 8u;     // claim a 4th string slot
        memcpy(pk + offsetof(struct syscalls_syscall_event, str_present),
               &sp, sizeof sp);
        memset(&out, 0x5A, sizeof out);
        CHECK(sysc_unpack_syscall(pk, n, &out) == -1);
        CHECK(out.nr == 0 && out.stack_id == 0);
    }

    // 8. Snapshot trim: only the valid snap[] bytes are queued.
    {
        static struct anubee_stack_snapshot snap;
        const size_t off = offsetof(struct anubee_stack_snapshot, snap);

        memset(&snap, 0, sizeof snap);
        snap.snap_len = 0;
        CHECK(sysc_stack_pack_len(&snap) == off);
        snap.snap_len = 4096;
        CHECK(sysc_stack_pack_len(&snap) == off + 4096);
        snap.snap_len = 32768;
        CHECK(sysc_stack_pack_len(&snap) == off + 32768);
        snap.snap_len = 99999;
        CHECK(sysc_stack_pack_len(&snap) == off + ANUBEE_SNAP_MAX);

        snap.snap_len = 4096;
        CHECK(sysc_stack_rec_ok(&snap, off + 4096) == 1);
        CHECK(sysc_stack_rec_ok(&snap, off + 4096 - 1) == 0);
        CHECK(sysc_stack_rec_ok(&snap, off - 1) == 0);
        snap.snap_len = 99999;
        CHECK(sysc_stack_rec_ok(&snap, off + ANUBEE_SNAP_MAX) == 0);
    }

    // 9. Header spare word (parent tgid + exec flag) survives queue packing.
    fill(&e);
    e.stack_sz = 0;
    e.str_present = 0;
    e.sock_len = 0;
    e.compat = 0;
    e.h._pad = 0x80000042u;
    n = sysc_pack_syscall(&e, pk);
    memset(&out, 0, sizeof out);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
    CHECK(out.h._pad == 0x80000042u);

    // 10. Layout pins: the binder overlay lives inside the existing str area and
    // the flag byte fits the tail padding, so the ring record does not grow.
    CHECK(sizeof(struct syscalls_syscall_event) == 1448);
    CHECK(offsetof(struct syscalls_syscall_event, str) == 352);
    CHECK(offsetof(struct syscalls_syscall_event, compat) == 1444);
    CHECK(offsetof(struct syscalls_syscall_event, binder) == 1445);
    CHECK(sizeof(struct syscalls_binder_info) == 32 + SYSC_BINDER_DATA_MAX);
    CHECK(offsetof(struct syscalls_binder_info, data) == 32);
    CHECK(sizeof(struct syscalls_binder_info) <= SYSC_STR_MAX);
    CHECK(SYSC_BINDER_DATA_MAX == 192);

    // 11. Binder flag byte and capture overlay.
    // A record without a capture packs one trailing zero flag byte.
    fill(&e);
    e.stack_sz = 0;
    e.str_present = 0;
    e.sock_len = 0;
    e.compat = 0;
    e.binder = 0;
    n = sysc_pack_syscall(&e, pk);
    CHECK(pk[n - 1] == 0);
    memset(&out, 0, sizeof out);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
    CHECK(out.binder == 0);

    // A non-1 flag value is treated as "not set" by the packer.
    e.binder = 2;
    n = sysc_pack_syscall(&e, pk);
    CHECK(pk[n - 1] == 0);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
    CHECK(out.binder == 0);

    // Copied byte counts 0, 100 and the full 192 round-trip byte-exactly.
    {
        static const __u32 copied_cases[] = { 0, 100, SYSC_BINDER_DATA_MAX };
        for (size_t c = 0; c < sizeof copied_cases / sizeof copied_cases[0]; c++) {
            __u32 copied = copied_cases[c];
            fill(&e);
            e.stack_sz = 0;
            e.str_present = 0;
            e.sock_len = 0;
            e.compat = 0;
            e.binder = 1;
            memset(e.str[3], 0, SYSC_STR_MAX);
            struct syscalls_binder_info *in = binder_info(&e);
            in->cmd = 0x40406300;
            in->handle = 7;
            in->code = 42;
            in->flags = 0x11;
            in->data_size = 100000;
            in->copied = copied;
            for (__u32 i = 0; i < copied; i++)
                in->data[i] = (__u8)(i * 3 + 1);

            n = sysc_pack_syscall(&e, pk);
            memset(&out, 0, sizeof out);
            CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
            CHECK(out.binder == 1);
            const struct syscalls_binder_info *o = binder_info(&out);
            CHECK(o->cmd == 0x40406300);
            CHECK(o->handle == 7);
            CHECK(o->code == 42);
            CHECK(o->flags == 0x11);
            CHECK(o->data_size == 100000);
            CHECK(o->copied == copied);
            CHECK(memcmp(o->data, in->data, copied) == 0);

            // Truncating the capture overlay is rejected.
            CHECK(sysc_unpack_syscall(pk, n - 1, &out) == -1);
            CHECK(out.nr == 0 && out.binder == 0);
        }
    }

    // A copied count above the capture limit clamps on pack.
    fill(&e);
    e.stack_sz = 0;
    e.str_present = 0;
    e.sock_len = 0;
    e.compat = 0;
    e.binder = 1;
    memset(e.str[3], 0, SYSC_STR_MAX);
    binder_info(&e)->copied = SYSC_BINDER_DATA_MAX + 58;
    n = sysc_pack_syscall(&e, pk);
    CHECK(sysc_unpack_syscall(pk, n, &out) == 0);
    CHECK(binder_info(&out)->copied == SYSC_BINDER_DATA_MAX);

    // ... and an out-of-range copied count in packed input is rejected.
    {
        const size_t hdr = offsetof(struct syscalls_binder_info, data);
        size_t hoff = n - SYSC_BINDER_DATA_MAX - hdr;
        __u32 bad = SYSC_BINDER_DATA_MAX + 1;
        memcpy(pk + hoff + offsetof(struct syscalls_binder_info, copied),
               &bad, sizeof bad);
        memset(&out, 0x5A, sizeof out);
        CHECK(sysc_unpack_syscall(pk, n, &out) == -1);
        CHECK(out.nr == 0 && out.binder == 0);
    }

    // 12. Capacity: packed records fit several times more per queue byte.
    {
        struct anubee_evq q;
        int nraw = 0, npk = 0;

        CHECK(anubee_evq_init(&q, 65536) == 0);
        fill(&e);
        e.stack_sz = 5 * 8;
        for (int i = 0; i < 5; i++)
            e.stack[i] = 0x7000 + i;
        e.str_present = 1;
        e.sock_len = 0;
        e.compat = 0;
        memset(e.str[0], 0, sizeof e.str[0]);
        strcpy(e.str[0], "/proc/self/maps");
        while (anubee_evq_push(&q, &e, sizeof e) == 0)
            nraw++;
        anubee_evq_destroy(&q);

        CHECK(anubee_evq_init(&q, 65536) == 0);
        n = sysc_pack_syscall(&e, pk);
        while (anubee_evq_push(&q, pk, n) == 0)
            npk++;
        anubee_evq_destroy(&q);

        printf("  capacity: %d raw records, %d packed records per 64 KiB queue\n",
               nraw, npk);
        CHECK(npk >= 4 * nraw);
    }

    if (failures) { printf("FAILED: %d check(s)\n", failures); return failures ? 1 : 0; }
    printf("test_sysc_evpack: all checks passed\n");
    return 0;
}
