// SPDX-License-Identifier: GPL-2.0
// Pure classification logic for the `ares mod a11y-abuse` analyzer. No libbpf
// deps (host-testable): given the touch_count from a BPF burst event and the
// accessibility-grant check result, decide the alert bitmask. Mirrors
// massdelete_detect_classify.h's shape, simpler -- no distinct-file estimation
// needed here.
#ifndef __ARES_A11Y_ABUSE_CLASSIFY_H
#define __ARES_A11Y_ABUSE_CLASSIFY_H

#include "modules/mod_events.h"   // A11Y_THRESHOLD

// crossed A11Y_THRESHOLD outbound Binder calls to system_server in-window
#define A11Y_BURST_DETECTED  (1u << 0)
// traced app holds a granted AccessibilityService binding
#define A11Y_SERVICE_GRANTED (1u << 1)

// Decide the alert bitmask. touch_count comes from the BPF event (always
// == A11Y_THRESHOLD when the event fires, but re-checked defensively, same
// as classify_burst()); granted is tri-state (1 = granted, 0 = checked and
// not granted, negative = unknown/unchecked).
unsigned classify_a11y(int touch_count, int granted);

#endif /* __ARES_A11Y_ABUSE_CLASSIFY_H */
