// SPDX-License-Identifier: GPL-2.0
// Per-run coverage-health record (CR5). One record per engine at teardown makes
// silent tracer degradation explicit: "no message" never means "didn't check".
// Subsumes ares_drops_report (ring/queue drops are coverage fields here).
#ifndef __ARES_COMMON_COVERAGE_H
#define __ARES_COMMON_COVERAGE_H

#include "common/cfi_unwind.h"    // enum cfi_stop_reason
#include "common/coverage_slots.h"

struct ares_sink;   // fwd; full def in common/emit.h

// Histogram width = number of enum cfi_stop_reason values (last + 1). A new
// stop reason grows the array in lockstep; the _Static_assert in coverage.c
// guards the coupling.
#define ARES_CFI_STOP_N  (CFI_SNAP_CFI_GET_NULL + 1)

struct ares_coverage {
	const char *engine;                 // "syscalls" | "funcs" | "correlate"
	// Tier 1: signals already computed, previously discarded
	unsigned long long snaps_total, snaps_truncated;
	unsigned long long cfi_walks;
	unsigned long long cfi_stop[ARES_CFI_STOP_N];
	unsigned long long ring_drops, queue_drops;
	int managed_naming_off;             // unknown ART build seen (bool)
	// Tier 2: new counters
	unsigned long long prearm_drops;
	unsigned long long depth_capped;
	int decode_partial;                 // raw-arg fallback active (bool)
};

// Emit BOTH channels from one call: stderr banner (human) + a
// {"type":"coverage",...}\n JSON line to sink (machine/MCP). sink may be NULL
// (no -o) -> banner only. A run with no degradation collapses to a "clean"
// record / "full coverage" banner.
void ares_coverage_report(struct ares_sink *sink, const struct ares_coverage *cov);

// Short JSON-key name for a cfi_stop_reason ("no_fde", "run_fail", ...). Returns
// "unknown" out of range. CFI_OK / CFI_SNAP_PC_ZERO are clean terminals.
const char *ares_cfi_stop_name(int reason);

// True if a stop reason indicates a *blind* (incomplete) walk, not a clean end.
static inline int ares_cfi_stop_is_blind(int reason)
{
	return reason != CFI_OK && reason != CFI_SNAP_PC_ZERO;
}

// libbpf-backed reader, header-only (mirrors ares_drops_read in runtime.h) so
// coverage.c stays free of a libbpf dependency and remains host-testable.
#ifdef __LIBBPF_LIBBPF_H
#include <bpf/bpf.h>
#include <linux/types.h>
#include <stdlib.h>

static inline unsigned long long ares_coverage_read(int map_fd, unsigned int slot)
{
	int ncpu = libbpf_num_possible_cpus();
	if (ncpu < 1) ncpu = 1;
	__u64 *vals = calloc((size_t)ncpu, sizeof(__u64));
	if (!vals) return 0;
	__u32 k = slot;
	unsigned long long total = 0;
	if (bpf_map_lookup_elem(map_fd, &k, vals) == 0)
		for (int i = 0; i < ncpu; i++)
			total += vals[i];
	free(vals);
	return total;
}
#endif /* __LIBBPF_LIBBPF_H */

#endif /* __ARES_COMMON_COVERAGE_H */
