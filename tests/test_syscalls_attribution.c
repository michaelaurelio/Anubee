// Host unit test for src/syscalls/attribution.h (CR2 issuer-only rule): the
// syscall belongs to a target library iff stack[0] (trap PC) or stack[1]
// (immediate caller) lands in one of its ranges — NOT any frame on the chain.
#include <linux/types.h>
#include "syscalls/attribution.h"
#include <stdio.h>

static int failures;
#define CHECK(cond) do { \
    if (cond) { printf("  ok: %s\n", #cond); } \
    else { printf("  FAIL: %s\n", #cond); failures++; } \
} while (0)

static struct syscalls_lib_ranges one_range(__u64 start, __u64 end)
{
    struct syscalls_lib_ranges lr;
    lr.count = 1;
    lr._pad = 0;
    lr.r[0].start = start;
    lr.r[0].end = end;
    return lr;
}

int main(void)
{
    // Target library mapped at [0x1000, 0x2000).
    struct syscalls_lib_ranges lr = one_range(0x1000, 0x2000);

    // Issuer at stack[0] (inline svc / frame-pointer-omitted target): hit.
    {
        __u64 stack[4] = { 0x1500, 0x9000, 0x9100, 0x9200 };
        CHECK(sysc_issuer_hit(&lr, stack, 4) == 1);
    }

    // Issuer at stack[1] (direct caller of the libc syscall wrapper): hit.
    // e.g. target -> mmap(libc wrapper at [0]) -> trap.
    {
        __u64 stack[4] = { 0x9000, 0x1500, 0x9100, 0x9200 };
        CHECK(sysc_issuer_hit(&lr, stack, 4) == 1);
    }

    // Transitive-only: target present at stack[2], but stack[0]/[1] are libc
    // (e.g. target -> malloc -> mmap). This is CR2's false-positive class the
    // old any-frame rule wrongly caught — must NOT hit now.
    {
        __u64 stack[4] = { 0x9000, 0x9100, 0x1500, 0x9200 };
        CHECK(sysc_issuer_hit(&lr, stack, 4) == 0);
    }

    // Target deeper still (stack[3]) — also must not hit.
    {
        __u64 stack[4] = { 0x9000, 0x9100, 0x9200, 0x1500 };
        CHECK(sysc_issuer_hit(&lr, stack, 4) == 0);
    }

    // No target anywhere: miss.
    {
        __u64 stack[4] = { 0x9000, 0x9100, 0x9200, 0x9300 };
        CHECK(sysc_issuer_hit(&lr, stack, 4) == 0);
    }

    // Empty stack (n == 0): miss, no OOB read.
    {
        __u64 stack[4] = { 0x1500, 0x1500, 0x1500, 0x1500 };
        CHECK(sysc_issuer_hit(&lr, stack, 0) == 0);
    }

    // Single-frame stack (n == 1): only stack[0] is probed.
    {
        __u64 stack[4] = { 0x1500, 0x1500, 0x1500, 0x1500 };
        CHECK(sysc_issuer_hit(&lr, stack, 1) == 1);
    }
    {
        __u64 stack[4] = { 0x9000, 0x1500, 0x1500, 0x1500 };
        // stack[1] would hit, but n == 1 means it was never captured (the
        // caller must not read past what bpf_get_stack actually returned).
        CHECK(sysc_issuer_hit(&lr, stack, 1) == 0);
    }

    // Half-open range: exactly at `end` must miss, `start` must hit.
    {
        __u64 at_start[4] = { 0x1000, 0, 0, 0 };
        __u64 at_end[4]   = { 0x2000, 0, 0, 0 };
        CHECK(sysc_issuer_hit(&lr, at_start, 1) == 1);
        CHECK(sysc_issuer_hit(&lr, at_end, 1) == 0);
    }

    // Multi-range: second range should be checked too, for either probe frame.
    {
        struct syscalls_lib_ranges lr2;
        lr2.count = 2;
        lr2._pad = 0;
        lr2.r[0].start = 0x1000; lr2.r[0].end = 0x2000;
        lr2.r[1].start = 0x5000; lr2.r[1].end = 0x6000;
        __u64 stack[2] = { 0x9000, 0x5500 };
        CHECK(sysc_issuer_hit(&lr2, stack, 2) == 1);
    }

    // count == 0 (no ranges armed yet): always miss, regardless of stack.
    {
        struct syscalls_lib_ranges lr0;
        lr0.count = 0;
        lr0._pad = 0;
        __u64 stack[2] = { 0x1500, 0x1500 };
        CHECK(sysc_issuer_hit(&lr0, stack, 2) == 0);
    }

    if (failures) { printf("FAILED: %d check(s)\n", failures); return 1; }
    printf("test_syscalls_attribution: all checks passed\n");
    return 0;
}
