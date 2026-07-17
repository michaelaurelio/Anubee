// SPDX-License-Identifier: GPL-2.0
// Pure classification logic for the `anubee mod accessibility-detect` analyzer. No libbpf
// deps (host-testable): given the touch_count from a BPF burst event and the
// accessibility-grant check result, decide the alert bitmask. Mirrors
// massdelete_detect_classify.h's shape, simpler -- no distinct-file estimation
// needed here.
#ifndef __ANUBEE_ACCESSIBILITY_DETECT_CLASSIFY_H
#define __ANUBEE_ACCESSIBILITY_DETECT_CLASSIFY_H

#include "modules/mod_events.h"   // ACCESSIBILITY_DETECT_THRESHOLD

// crossed ACCESSIBILITY_DETECT_THRESHOLD outbound Binder calls to system_server in-window
#define ACCESSIBILITY_DETECT_BURST_DETECTED  (1u << 0)
// traced app holds a granted AccessibilityService binding
#define ACCESSIBILITY_DETECT_SERVICE_GRANTED (1u << 1)

// Decide the alert bitmask. touch_count comes from the BPF event (always
// == ACCESSIBILITY_DETECT_THRESHOLD when the event fires, but re-checked defensively, same
// as classify_burst()); granted is tri-state (1 = granted, 0 = checked and
// not granted, negative = unknown/unchecked).
unsigned classify_accessibility(int touch_count, int granted);

#endif /* __ANUBEE_ACCESSIBILITY_DETECT_CLASSIFY_H */
