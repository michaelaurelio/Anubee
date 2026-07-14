// SPDX-License-Identifier: GPL-2.0
// Pure distinct-count + classification logic for the `ares mod
// massdelete-detect` analyzer. No libbpf deps (host-testable): given the raw
// hash ring + touch count from a BPF burst-candidate event, decide whether
// it's a real burst (most touches were genuinely distinct files, not one
// file hit repeatedly).
#ifndef __ARES_MASSDELETE_DETECT_CLASSIFY_H
#define __ARES_MASSDELETE_DETECT_CLASSIFY_H

#include "modules/mod_events.h"   // MASSDELETE_DETECT_THRESHOLD

// crossed the touch threshold AND enough of those touches were distinct files
#define MASSDELETE_DETECT_BURST_DETECTED     (1u << 0)
// traced app holds MANAGE_EXTERNAL_STORAGE ("All files access")
#define MASSDELETE_DETECT_MANAGE_EXT_STORAGE (1u << 1)

// Of MASSDELETE_DETECT_THRESHOLD touches, floor for "real" burst (not 1 file repeated).
#define MASSDELETE_DETECT_DISTINCT_MIN 10

// Count distinct values among the first n entries of hashes. n is normally
// e->touch_count (see massdelete_detect.bpf.c: MASSDELETE_DETECT_RING_LEN >
// MASSDELETE_DETECT_THRESHOLD guarantees the ring never wraps before a window resets, so
// the first touch_count slots are always exactly this window's hashes -- no
// stale cross-window data). Returns 0 for n <= 0.
int burst_distinct_count(const unsigned long long *hashes, int n);

// Decide the alert bitmask. touch_count/distinct_count come from the BPF
// event + burst_distinct_count; manage_ext_storage is tri-state (1 = granted,
// 0 = checked and not granted, negative = unknown/unchecked).
unsigned classify_burst(int touch_count, int distinct_count, int manage_ext_storage);

#endif /* __ARES_MASSDELETE_DETECT_CLASSIFY_H */
