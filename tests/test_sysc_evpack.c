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

    // 9. Capacity: packed records fit several times more per queue byte.
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
