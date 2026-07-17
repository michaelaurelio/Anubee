/* SPDX-License-Identifier: GPL-2.0 */
// art_shadow.h — name switch-interpreter (ExecuteSwitchImpl) interpreted Java frames by
// walking ART's live Thread -> ManagedStack -> ShadowFrame chain out of process. Fires at a
// cfi_stack switch-interp terminal, parallel to nterp_chain at an nterp_helper terminal.
// Firewall: /proc/<pid>/mem reads only. BuildID-gated (default-off on unknown ART).
#ifndef ANUBEE_COMMON_ART_SHADOW_H
#define ANUBEE_COMMON_ART_SHADOW_H

#include <stdint.h>
#include "common/art_nterp.h"     // art_reader
#include "common/art_buildid.h"   // struct art_offsets

// Test seam: walk the ShadowFrame chain rooted at `tls_base` using reader `rd`/`rc` and
// the given offsets. Writes innermost-first "pkg.Class.method+0x<dexpc>" (dex_pc-corroborated
// only) into out[0..return). Returns the count (0 on tls_base 0 / no corroborated frame).
int shadow_frame_pick(art_reader rd, void *rc, uint64_t tls_base,
                      const struct art_offsets *o, char out[][256], int max_frames);

// Production: BuildID-gate + /proc/<pid>/mem reader, then shadow_frame_pick. Returns 0 if
// the ART build is unknown, tls_base is 0, or nothing corroborates.
int shadow_frame_chain(int pid, uint64_t tls_base, char out[][256], int max_frames);

#endif
