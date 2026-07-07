// SPDX-License-Identifier: GPL-2.0
// Slot indices for the coverage_stats PERCPU map. Shared verbatim between the
// BPF side (coverage.bpf.h) and the userspace reader (coverage.h) so the two
// can never drift. Pure enum - no types, safe to include from a BPF TU.
#ifndef __ARES_COVERAGE_SLOTS_H
#define __ARES_COVERAGE_SLOTS_H

enum {
	COV_TRUNC     = 0,   // stack snapshot hit the 32 KB window (truncated==1)
	COV_DEPTH_CAP = 1,   // stack/span depth cap bit (frames dropped)
	COV_PREARM    = 2,   // syscall dropped in the pre-arm window (CR2)
	COV_SPAN_OPEN = 3,   // span pushed (correlate --returns denominator)
	COV_URET_FIRED= 4,   // return record emitted (correlate --returns numerator)
	COV_SLOT_N    = 5,
};

#endif /* __ARES_COVERAGE_SLOTS_H */
