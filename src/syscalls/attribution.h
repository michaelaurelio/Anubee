// attribution.h
//
// "Issued by" heuristic (CR2). The old any-frame-in-range test tagged a syscall
// as belonging to a target library if the library was merely *somewhere* on the
// call chain (e.g. targetlib -> malloc -> mmap counted as a target-lib syscall,
// even though libc's malloc issued it). Only the trap-PC frame and its immediate
// caller can plausibly be the issuer:
//
//   stack[0] - the syscall-wrapper frame itself (the return address into it,
//              from bpf_get_stack). Frame-pointer-independent: this is where
//              control was when the trap fired, so it's reliable even for
//              -fomit-frame-pointer / hand-asm libraries (the FP walk can still
//              be garbage past this point).
//   stack[1] - the immediate caller of that wrapper, i.e. the direct issuer,
//              needs one frame-pointer hop.
//
// Deeper frames are transitive callers, not the issuer, and are intentionally
// not scanned.
#ifndef ANUBEE_SYSCALLS_ATTRIBUTION_H
#define ANUBEE_SYSCALLS_ATTRIBUTION_H

#include "syscalls.h"   // struct syscalls_lib_ranges, SYSC_MAX_RANGES

// Returns 1 if stack[0] or stack[1] lands in one of lr's ranges. Both loops are
// bounded by compile-time constants (2 probe frames, SYSC_MAX_RANGES ranges) so
// every stack[i]/r[j] access is a constant offset the BPF verifier accepts;
// `probe`/`count` are runtime guards only.
static __always_inline int sysc_issuer_hit(const struct syscalls_lib_ranges *lr,
                                           const __u64 *stack, int n)
{
    __u32 count = lr->count;
    if (count > SYSC_MAX_RANGES)
        count = SYSC_MAX_RANGES;
    int probe = n < 2 ? n : 2;   // only stack[0] (trap PC) and stack[1] (issuer)

    #pragma clang loop unroll(full)
    for (int i = 0; i < 2; i++) {
        if (i < probe) {
            __u64 ip = stack[i];
            #pragma clang loop unroll(full)
            for (__u32 j = 0; j < SYSC_MAX_RANGES; j++) {
                if (j < count && ip >= lr->r[j].start && ip < lr->r[j].end)
                    return 1;
            }
        }
    }
    return 0;
}

#endif // ANUBEE_SYSCALLS_ATTRIBUTION_H
