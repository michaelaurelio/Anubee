/* SPDX-License-Identifier: GPL-2.0 */
// art_buildid.h — gate the version-coupled ShadowFrame/ManagedStack offsets on the
// running libart.so BuildID. An unrecognized build resolves NULL, so the caller
// (shadow_frame_chain) names nothing. Firewall: reads only.
#ifndef ARES_COMMON_ART_BUILDID_H
#define ARES_COMMON_ART_BUILDID_H

#include <stdint.h>

struct art_offsets {
    uint64_t tls_thread_slot;   // tls_base -> Thread*      (TLS_SLOT_ART_THREAD_SELF*8)
    uint64_t managed_stack;     // Thread  -> ManagedStack  (embedded)
    uint64_t ms_link;           // ManagedStack.link_
    uint64_t ms_top_shadow;     // ManagedStack.top_shadow_frame_
    uint64_t sf_link;           // ShadowFrame.link_
    uint64_t sf_method;         // ShadowFrame.method_
    uint64_t sf_dex_pc_ptr;     // ShadowFrame.dex_pc_ptr_
    uint64_t sf_dex_instr;      // ShadowFrame.dex_instructions_
};

// Pure table lookup: offsets for a known libart BuildID (lowercase hex), else NULL.
const struct art_offsets *art_offsets_for_buildid(const char *hexid);

// Read the running libart.so BuildID for `pid` and look it up. NULL on any failure.
const struct art_offsets *art_buildid_offsets(int pid);

#endif
