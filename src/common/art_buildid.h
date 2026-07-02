/* SPDX-License-Identifier: GPL-2.0 */
// art_buildid.h — gate the version-coupled ShadowFrame/ManagedStack offsets on the
// running libart.so BuildID. An unrecognized build resolves NULL, so the caller
// (shadow_frame_chain) names nothing. Firewall: reads only.
#ifndef ARES_COMMON_ART_BUILDID_H
#define ARES_COMMON_ART_BUILDID_H

#include <stdint.h>

struct art_offsets {
    /* Thread / ManagedStack / ShadowFrame (switch-interp walk) */
    uint64_t tls_thread_slot;   // tls_base -> Thread*      (TLS_SLOT_ART_THREAD_SELF*8)
    uint64_t managed_stack;     // Thread  -> ManagedStack  (embedded)
    uint64_t ms_link;           // ManagedStack.link_
    uint64_t ms_top_shadow;     // ManagedStack.top_shadow_frame_
    uint64_t sf_link;           // ShadowFrame.link_
    uint64_t sf_method;         // ShadowFrame.method_
    uint64_t sf_dex_pc_ptr;     // ShadowFrame.dex_pc_ptr_
    /* ArtMethod / Class / DexCache / DexFile (nterp name chase) */
    uint64_t artm_declclass;    // ArtMethod.declaring_class_ (compressed ref)
    uint64_t artm_dexidx;       // ArtMethod.dex_method_index_ (u32)
    uint64_t class_dexcache;    // mirror::Class.dex_cache_ (compressed ref)
    uint64_t dexcache_dexfile;  // mirror::DexCache.dex_file_ (native DexFile*)
    uint64_t dexfile_begin;     // DexFile.begin_ (const u8*)
    uint64_t dexfile_datasize;  // DexFile.data_.size_ (size_t)
};

// Pure table lookup: offsets for a known libart BuildID (lowercase hex), else NULL.
const struct art_offsets *art_offsets_for_buildid(const char *hexid);

// Read the running libart.so BuildID for `pid` and look it up. NULL on any failure.
const struct art_offsets *art_buildid_offsets(int pid);

#endif
