// SPDX-License-Identifier: GPL-2.0
// THROWAWAY spike — see managed_stack_spike.h. Diagnostic-first: logs every
// self-anchored ManagedStack candidate and the walk output so one device run tells
// us whether the pinned offsets are right.
#include "common/managed_stack_spike.h"
#include <linux/types.h>
#include "common/stack_snapshot.h"
#include "common/proc_mem.h"
#include "common/art_nterp.h"   // art_reader, art_method_resolve, art_method_chase
#include "common/dex.h"         // dex_lookup_range, dex_name_by_index
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// ART apex 370549100 / android15-release, arm64. Offsets pinned in
// docs/superpowers/research/2026-07-02-managed-stack-walk-spike-findings.md
#define TLS_SLOT_ART_THREAD_SELF 7
#define TLSPTR_SELF_OFF          0x48   // self within tls_ptr_sized_values
#define TLSPTR_MANAGED_STACK_OFF 0x18   // managed_stack within tls_ptr_sized_values
#define MS_TAGGED_OFF            0x00
#define MS_LINK_OFF              0x08
#define MS_SHADOW_OFF            0x10
#define MS_TAG_MASK             0x3ULL  // kTaggedJniSpMask (bit0 GenericJNI, bit1 JitJNI)
#define SF_LINK_OFF              0x00
#define SF_METHOD_OFF            0x08
#define THREAD_SCAN_WORDS        1024   // bounded self-anchor scan
#define UNTAG(p) ((p) & 0x00FFFFFFFFFFFFFFULL)  // strip Android top-byte pointer tag (TBI)

struct pmctx { int memfd; };
static size_t pm_rd(void *ctx, uint64_t va, void *dst, size_t len) {
	return proc_mem_read(((struct pmctx *)ctx)->memfd, va, dst, len);
}
static int rd64(art_reader rd, void *rc, uint64_t va, uint64_t *out) {
	*out = 0;
	return rd(rc, va, out, 8) == 8;
}

// Read tagged_top_quick_frame_ at a ManagedStack address, mask the JNI tag, deref
// the SP slot to ArtMethod*, and name it. Returns 1 on a resolved name.
static int name_top_quick(art_reader rd, void *rc, uint64_t ms, char *out, size_t n) {
	uint64_t tagged = 0, artm = 0;
	if (!rd64(rd, rc, ms + MS_TAGGED_OFF, &tagged) || !(UNTAG(tagged) & ~MS_TAG_MASK))
		return 0;
	uint64_t sp = UNTAG(tagged) & ~MS_TAG_MASK;
	if (!rd64(rd, rc, sp, &artm) || !UNTAG(artm))
		return 0;
	return art_method_resolve(rd, rc, UNTAG(artm), out, n);
}

void ares_mstack_spike(int pid, const struct ares_stack_snapshot *snap) {
	static int on = -1;
	if (on < 0) on = getenv("ARES_MSTACK_SPIKE") ? 1 : 0;
	if (!on || !snap->tls_base) return;

	int memfd = proc_mem_open(pid);
	if (memfd < 0) return;
	struct pmctx pc = { memfd };
	art_reader rd = pm_rd;

	uint64_t self = 0;
	if (!rd64(rd, &pc, snap->tls_base + (uint64_t)TLS_SLOT_ART_THREAD_SELF * 8, &self) || !self) {
		fprintf(stderr, "[mstack] tid=%u tls=0x%llx Thread* unread\n",
			snap->h.tid, (unsigned long long)snap->tls_base);
		close(memfd);
		return;
	}
	self = UNTAG(self);   // /proc/mem needs the untagged address

	// Global output budget so hundreds of stacks don't flood.
	static int budget = 120;
	if (budget <= 0) { close(memfd); return; }

	// managed_stack embedded in Thread at Thread+0xA8 (OFFSETOF(Thread,tlsPtr_)=0x90
	// pinned empirically from the raw dump: card_table@0x90, stack_end@0xa0,
	// managed_stack@0xa8, suspend_trigger@0xc0), tlsPtr_+managed_stack(0x18).
	uint64_t ms = self + 0xA8;
	int printed = 0;
	for (int seg = 0; ms && seg < 32; seg++) {
		uint64_t tagged = 0, link = 0, shadow = 0;
		rd64(rd, &pc, ms + MS_TAGGED_OFF, &tagged);
		rd64(rd, &pc, ms + MS_LINK_OFF, &link);   link = UNTAG(link);
		rd64(rd, &pc, ms + MS_SHADOW_OFF, &shadow); shadow = UNTAG(shadow);

		// Approach B: scan the authoritative segment window [sp, link) for
		// resolvable ArtMethod* (each quick frame stores ArtMethod* at its base).
		// link_ is the older (higher-address) ManagedStack node = segment bottom.
		uint64_t sp = UNTAG(tagged) & ~MS_TAG_MASK;
		if (sp) {
			uint64_t bound = (link > sp && link - sp <= 0x8000) ? link : sp + 0x2000;
			uint64_t last = 0;
			int frames = 0;
			for (uint64_t a = sp; a < bound && frames < 64; a += 8) {
				uint64_t v = 0;
				if (!rd64(rd, &pc, a, &v)) break;
				v = UNTAG(v);
				if (!v || v == last) continue;
				uint32_t midx; uint64_t begin; struct dex_method_map *map;
				if (!art_method_chase(rd, &pc, v, &midx, &begin, &map))
					continue;
				// Corroborate: a live dex_pc into THIS method's bytecode sitting
				// near the frame base confirms a real interpreted (nterp) frame; a
				// spilled ArtMethod* arg ref has none. (AOT frames also lack one.)
				int corrob = 0; uint32_t dexpc = 0;
				for (uint64_t c = 0; c <= 0x200; c += 8) {
					uint64_t w = 0;
					if (!rd64(rd, &pc, a + c, &w)) break;
					w = UNTAG(w);
					if (w < begin) continue;
					uint64_t rel = w - begin;
					if (rel > 0xffffffffULL) continue;
					uint32_t rmidx, rinsns;
					if (dex_lookup_range(map, (uint32_t)rel, &rmidx, &rinsns) && rmidx == midx) {
						corrob = 1; dexpc = ((uint32_t)rel - rinsns) / 2; break;
					}
				}
				char nm[256];
				if (!dex_name_by_index(map, midx, nm, sizeof nm)) continue;
				if (corrob)
					fprintf(stderr, "[mstack] tid=%u seg%d f%d @+0x%llx C %s+0x%x\n",
						snap->h.tid, seg, frames, (unsigned long long)(a - sp), nm, dexpc);
				else
					fprintf(stderr, "[mstack] tid=%u seg%d f%d @+0x%llx u %s\n",
						snap->h.tid, seg, frames, (unsigned long long)(a - sp), nm);
				last = v; frames++; printed = 1;
			}
		}

		for (int d = 0; shadow && d < 64; d++) {
			uint64_t a = 0, nx = 0; char sn[256];
			rd64(rd, &pc, shadow + SF_METHOD_OFF, &a); a = UNTAG(a);
			if (a && art_method_resolve(rd, &pc, a, sn, sizeof sn))
				fprintf(stderr, "[mstack] tid=%u seg%d shadow %s\n", snap->h.tid, seg, sn);
			rd64(rd, &pc, shadow + SF_LINK_OFF, &nx); shadow = UNTAG(nx);
		}
		ms = link;
	}
	if (printed) budget--;
	close(memfd);
}
