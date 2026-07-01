// SPDX-License-Identifier: GPL-2.0
#include "common/art_shadow.h"
#include "common/dex.h"
#include "common/proc_mem.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#define ART_PTR_UNTAG(p) ((uint64_t)(p) & 0x00FFFFFFFFFFFFFFULL)
#define MAX_SEG 8
#define MAX_SF  64

static int rd64(art_reader rd, void *rc, uint64_t va, uint64_t *out) {
    return rd(rc, va, out, 8) == 8;
}

int shadow_frame_pick(art_reader rd, void *rc, uint64_t tls_base,
                      const struct art_offsets *o, char out[][256], int max_frames)
{
    if (!rd || !o || !out || max_frames <= 0 || tls_base == 0)
        return 0;

    uint64_t thread;
    if (!rd64(rd, rc, tls_base + o->tls_thread_slot, &thread)) return 0;
    thread = ART_PTR_UNTAG(thread);
    if (thread == 0) return 0;

    int nc = 0;
    uint64_t ms = thread + o->managed_stack;   // embedded ManagedStack
    for (int seg = 0; seg < MAX_SEG && ms && nc < max_frames; seg++) {
        uint64_t sf;
        if (!rd64(rd, rc, ms + o->ms_top_shadow, &sf)) break;
        sf = ART_PTR_UNTAG(sf);
        for (int d = 0; d < MAX_SF && sf && nc < max_frames; d++) {
            uint64_t method;
            if (rd64(rd, rc, sf + o->sf_method, &method)) {
                method = ART_PTR_UNTAG(method);
                uint32_t midx; uint64_t begin; struct dex_method_map *map;
                if (art_method_chase(rd, rc, method, &midx, &begin, &map)) {
                    uint64_t dpp;
                    if (rd64(rd, rc, sf + o->sf_dex_pc_ptr, &dpp)) {
                        dpp = ART_PTR_UNTAG(dpp);
                        if (dpp >= begin) {
                            uint64_t rel = dpp - begin;
                            uint32_t rmidx, rinsns;
                            if (rel <= 0xffffffffULL &&
                                dex_lookup_range(map, (uint32_t)rel, &rmidx, &rinsns) &&
                                rmidx == midx) {
                                char nm[240];
                                if (dex_name_by_index(map, midx, nm, sizeof nm)) {
                                    uint32_t dexpc = ((uint32_t)rel - rinsns) / 2;
                                    snprintf(out[nc], 256, "%s+0x%x", nm, dexpc);
                                    nc++;
                                }
                            }
                        }
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
    if (!o || tls_base == 0) return 0;
    int fd = proc_mem_open(pid);
    if (fd < 0) return 0;
    int nc = shadow_frame_pick(sf_pm_reader, (void *)(intptr_t)fd, tls_base, o, out, max_frames);
    close(fd);
    return nc;
}
