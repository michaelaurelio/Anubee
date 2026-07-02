// SPDX-License-Identifier: GPL-2.0
// Per-pid /proc/<pid>/maps snapshot cache (module ranges + on-disk paths), with
// LRU eviction and the module-base walk. See symbolize_internal.h.
#include <sys/types.h>
#include "symbolize_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>

// ---- /proc/<pid>/maps ----------------------------------------------------

// ponytail: tune if traces need more concurrent pids; 128 covers typical app + zygote forks.
#define PM_MAX_PIDS 128

static struct procmaps *g_pm;
static size_t g_npm;

long long now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void read_proc_maps(struct procmaps *pm)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/maps", pm->pid);
	FILE *f = fopen(path, "r");
	int oerr = errno;            // capture before now_ms() (clock_gettime) can clobber it
	pm->n    = 0;
	pm->gone = 0;
	pm->last_read_ms = now_ms();
	if (!f) {
		pm->gone = (oerr == ENOENT);
		return;
	}

	char line[512];
	while (fgets(line, sizeof(line), f)) {
		struct ares_map_line ml;
		if (!ares_parse_maps_line(line, &ml))
			continue;

		if (pm->n == pm->cap) {
			size_t nc = pm->cap ? pm->cap * 2 : 256;
			struct ares_map_line *nm = realloc(pm->m, nc * sizeof(*nm));
			if (!nm)
				break;
			pm->m = nm;
			pm->cap = nc;
		}
		pm->m[pm->n++] = ml;
	}
	fclose(f);
}

// pm_get lives above the ART-JIT / vDSO / symbol-cache definitions but reaches
// into them during LRU eviction. The eviction side-effects are extracted into
// pm_evict_pid, defined below those subsystems where all types are complete.

struct procmaps *pm_get(int pid)
{
	long long now = now_ms();

	for (size_t i = 0; i < g_npm; i++) {
		if (g_pm[i].pid == pid) {
			g_pm[i].last_used_ms = now;
			return &g_pm[i];
		}
	}

	size_t slot;
	if (g_npm < PM_MAX_PIDS) {
		// Still under cap: grow the array.
		struct procmaps *np = realloc(g_pm, (g_npm + 1) * sizeof(*np));
		if (!np)
			return NULL;
		g_pm = np;
		slot = g_npm++;
		memset(&g_pm[slot], 0, sizeof(g_pm[slot]));
	} else {
		// At cap: evict the least-recently-used slot and reuse it.
		slot = 0;
		for (size_t i = 1; i < g_npm; i++)
			if (g_pm[i].last_used_ms < g_pm[slot].last_used_ms)
				slot = i;
		pm_evict_pid(g_pm[slot].pid);
		g_pm[slot].n = 0;           // reuse the mapping buffer for the new pid
	}

	g_pm[slot].pid          = pid;
	g_pm[slot].last_used_ms = now;
	read_proc_maps(&g_pm[slot]);
	return &g_pm[slot];
}

// /proc/<pid>/maps is address-sorted and non-overlapping, so binary search.
struct ares_map_line *find_mapping(struct procmaps *pm, uint64_t addr)
{
	size_t lo = 0, hi = pm->n;
	while (lo < hi) {
		size_t mid = (lo + hi) / 2;
		if (addr < pm->m[mid].start)
			hi = mid;
		else if (addr >= pm->m[mid].end)
			lo = mid + 1;
		else
			return &pm->m[mid];
	}
	return NULL;
}

// find_mapping, re-reading /proc/<pid>/maps once (throttled to REFRESH_MS) on a
// miss: a library may have loaded since the cache was last read. This is the one
// place that recovers from a cache populated mid-launch (e.g. the maps were first
// read while only the linker was mapped, before libc/libandroid_runtime), which
// is common under capture-all where snapshots fire during early process launch.
// Used by both the symbolizer (sym_resolve_uncached) and the CFI walk
// (cfi_unwind_snapshot) so a stale cache can't dead-end the unwind at frame 0.
struct ares_map_line *find_mapping_refresh(struct procmaps *pm, uint64_t addr)
{
	struct ares_map_line *hit = find_mapping(pm, addr);
	if (!hit && now_ms() - pm->last_read_ms > REFRESH_MS) {
		read_proc_maps(pm);
		hit = find_mapping(pm, addr);
	}
	return hit;
}

// Force a reread of pid's maps on its next resolve (a library may have loaded);
// used by sym_flush_pid when the caller (e.g. a fresh mmap event) knows the maps
// changed without waiting on the throttled miss-triggered refresh in find_mapping_refresh.
void pm_reset_pid(int pid)
{
	for (size_t i = 0; i < g_npm; i++)
		if (g_pm[i].pid == pid) {
			g_pm[i].n    = 0;
			g_pm[i].gone = 0;
		}
}

// Walk back over the contiguous run of same-path mappings to find the ELF base.
// Also returns the base mapping's [start,end), used to reach the file via
// /proc/<pid>/map_files when its path is deleted/anonymous.
void module_base(struct procmaps *pm, struct ares_map_line *hit,
			uint64_t *load_base, uint64_t *elf_off, uint64_t *base_end)
{
	size_t i = ares_module_base_idx(pm->m, (size_t)(hit - pm->m));
	*load_base = pm->m[i].start;
	*elf_off   = pm->m[i].off;
	*base_end  = pm->m[i].end;
}
