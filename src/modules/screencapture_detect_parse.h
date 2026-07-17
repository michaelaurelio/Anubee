// SPDX-License-Identifier: GPL-2.0
// Pure parser for `dumpsys activity services <pkg>` output, used by the
// screencapture-detect analyzer's poll thread (screencapture_detect.c) to detect an
// active MediaProjection screen-capture session. No libbpf/libc-heavy deps
// beyond <string.h> -- host-testable. The exact `types=0x..` field was
// confirmed against real device output (see REAL_FIXTURE in
// tests/test_screencapture_detect_parse.c).
#ifndef __ANUBEE_SCREENCAPTURE_DETECT_PARSE_H
#define __ANUBEE_SCREENCAPTURE_DETECT_PARSE_H

// FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION, from the public
// android.content.pm.ServiceInfo API surface (AOSP frameworks/base). Not a
// BTF/vmlinux.h constant -- this is a userspace-only Android framework
// value, hardcoded here with this comment for provenance.
#define SCREENCAPTURE_DETECT_FGS_TYPE_BIT 0x20

// Parses `buf` (the full stdout of `dumpsys activity services <pkg>`) for a
// ServiceRecord block that:
//   - contains `pkg` as a substring (package-scoped match, same simplicity
//     tradeoff as accessibility_detect_classify's accessibility-grant substring check),
//   - has `isForeground=true`,
//   - has a `types=0x..` hex mask with SCREENCAPTURE_DETECT_FGS_TYPE_BIT set.
// Returns 1 if such a block is found, 0 if not, -1 if buf or pkg is NULL or
// empty (unusable input -- caller should treat this as "unknown", not
// "inactive", and must not alert on it).
//
// On return 1, *out_pid is set to the pid parsed from the same block's
// `app=ProcessRecord{<hash> <pid>:<pkg>/<uid>}` line, or left at -1 if that
// line is missing/unparseable (the caller degrades gracefully: the alert
// still fires, only the Binder-call context enrichment is skipped). On
// return 0 or -1, *out_pid is always set to -1. out_pid may be NULL if the
// caller doesn't need it.
int screencapture_detect_parse_dumpsys(const char *buf, const char *pkg, int *out_pid);

#endif /* __ANUBEE_SCREENCAPTURE_DETECT_PARSE_H */
