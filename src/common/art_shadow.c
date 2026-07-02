// SPDX-License-Identifier: GPL-2.0
#include "common/art_shadow.h"
#include "common/dex.h"
#include "common/proc_mem.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#define ART_PTR_UNTAG(p) ((uint64_t)(p) & 0x00FFFFFFFFFFFFFFULL)
#define MAX_SEG 8
#define MAX_SF  64

static int sf_dbg(void) { return getenv("ARES_CFI_DEBUG") != NULL; }
#define SFD(...) do { if (sf_dbg()) fprintf(stderr, "[shadow] " __VA_ARGS__); } while (0)

static int rd64(art_reader rd, void *rc, uint64_t va, uint64_t *out) {
    return rd(rc, va, out, 8) == 8;
}

int shadow_frame_pick(art_reader rd, void *rc, uint64_t tls_base,
                      const struct art_offsets *o, char out[][256], int max_frames)
{
    if (!rd || !o || !out || max_frames <= 0 || tls_base == 0)
        return 0;

    uint64_t thread;
    if (!rd64(rd, rc, tls_base + o->tls_thread_slot, &thread)) { SFD("thread read FAIL @tls+0x%llx\n", (unsigned long long)o->tls_thread_slot); return 0; }
    thread = ART_PTR_UNTAG(thread);
    if (thread == 0) { SFD("thread==0 (tls_base=0x%llx)\n", (unsigned long long)tls_base); return 0; }
    SFD("tls=0x%llx thread=0x%llx\n", (unsigned long long)tls_base, (unsigned long long)thread);

    int nc = 0;
    uint64_t ms = thread + o->managed_stack;   // embedded ManagedStack
    for (int seg = 0; seg < MAX_SEG && ms && nc < max_frames; seg++) {
        uint64_t sf;
        if (!rd64(rd, rc, ms + o->ms_top_shadow, &sf)) { SFD("seg%d top_shadow read FAIL\n", seg); break; }
        sf = ART_PTR_UNTAG(sf);
        SFD("seg%d top_shadow_frame=0x%llx\n", seg, (unsigned long long)sf);
        for (int d = 0; d < MAX_SF && sf && nc < max_frames; d++) {
            uint64_t method;
            if (rd64(rd, rc, sf + o->sf_method, &method)) {
                method = ART_PTR_UNTAG(method);
                uint32_t midx; uint64_t begin; struct dex_method_map *map;
                int chased = art_method_chase(rd, rc, o, method, &midx, &begin, &map);
                SFD("  sf=0x%llx method=0x%llx chase=%d\n", (unsigned long long)sf, (unsigned long long)method, chased);
                if (chased) {
                    /* ShadowFrame.method_ is ART's authoritative field: a successful
                     * chase (full ArtMethod->Class->DexCache->DexFile->index chain valid)
                     * proves this is a real managed method. Unlike the nterp path (which
                     * GUESSES the ArtMethod* from stack slots and needs a live dex_pc to
                     * reject stale spills), no corroboration is needed here. The dex_pc
                     * suffix is best-effort: appended only if the frame's dex_pc_ptr_
                     * corroborates this method's code_item, else the bare name is emitted. */
                    char nm[240]; nm[0] = 0;
                    if (dex_name_by_index(map, midx, nm, sizeof nm) && nm[0]) {
                        uint64_t dpp = 0;
                        int dexpc_ok = 0; uint32_t dexpc = 0;
                        if (rd64(rd, rc, sf + o->sf_dex_pc_ptr, &dpp)) {
                            dpp = ART_PTR_UNTAG(dpp);
                            uint32_t rmidx, rinsns;
                            if (dpp >= begin && (dpp - begin) <= 0xffffffffULL &&
                                dex_lookup_range(map, (uint32_t)(dpp - begin), &rmidx, &rinsns) &&
                                rmidx == midx) {
                                dexpc = ((uint32_t)(dpp - begin) - rinsns) / 2;
                                dexpc_ok = 1;
                            }
                        }
                        if (dexpc_ok) snprintf(out[nc], 256, "%s+0x%x", nm, dexpc);
                        else          snprintf(out[nc], 256, "%s", nm);
                        SFD("    NAMED %s (dexpc_ok=%d)\n", out[nc], dexpc_ok);
                        nc++;
                    }
                }
            }
            uint64_t nsf;
            if (!rd64(rd, rc, sf + o->sf_link, &nsf)) break;
            nsf = ART_PTR_UNTAG(nsf);
            if (nsf == sf) break;              // self-loop guard
            sf = nsf;
        }
        uint64_t nms;
        if (!rd64(rd, rc, ms + o->ms_link, &nms)) break;
        nms = ART_PTR_UNTAG(nms);
        if (nms == ms) break;
        ms = nms;
    }
    return nc;
}

static size_t sf_pm_reader(void *ctx, uint64_t va, void *dst, size_t len) {
    return proc_mem_read((int)(intptr_t)ctx, va, dst, len);
}

int shadow_frame_chain(int pid, uint64_t tls_base, char out[][256], int max_frames)
{
    const struct art_offsets *o = art_buildid_offsets(pid);
    SFD("gate pid=%d tls_base=0x%llx offsets=%s\n", pid, (unsigned long long)tls_base, o ? "OK" : "NULL(buildid miss)");
    if (!o || tls_base == 0) return 0;
    int fd = proc_mem_open(pid);
    if (fd < 0) { SFD("proc_mem_open(%d) FAIL\n", pid); return 0; }
    int nc = shadow_frame_pick(sf_pm_reader, (void *)(intptr_t)fd, tls_base, o, out, max_frames);
    close(fd);
    return nc;
}
