// SPDX-License-Identifier: GPL-2.0
// Per-pid /proc/<pid>/maps snapshot cache (module ranges + on-disk paths), with
// LRU eviction and the module-base walk. Engine 0 is the live-only cache;
// engines > 0 are event-sourced models with versioned lines. See symbolize_internal.h.
#include <sys/types.h>
#include <linux/types.h>
#include "symbolize_internal.h"
#include "common/sym_pid.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

// ---- /proc/<pid>/maps ----------------------------------------------------

#define PM_MAX_PIDS 1024

static struct procmaps g_pm[PM_MAX_PIDS];
static size_t g_npm;            // slots [0, g_npm) are in use
static struct procmaps *g_pin;  // slot that eviction must not pick
static uint64_t g_line_id;      // last line id handed out (unique across models)
static size_t g_mru;            // index of the last slot returned
static unsigned long long g_pm_revived;
static struct pm_stats g_stats;

long long now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Open and parse /proc/<pid>/maps into a fresh array. Returns 0 when the file
// opened, -1 otherwise with *err set to the fopen errno.
static int load_maps(int pid, struct anubee_map_line **out, size_t *nout, int *err)
{
	char path[64];
	char line[512];
	struct anubee_map_line *nm = NULL;
	size_t nn = 0, ncap = 0;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	FILE *f = fopen(path, "r");
	int oerr = errno;
	if (!f) {
		*err = oerr;
		*out = NULL;
		*nout = 0;
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		struct anubee_map_line ml;

		if (!anubee_parse_maps_line(line, &ml))
			continue;
		if (nn == ncap) {
			size_t nc = ncap ? ncap * 2 : 256;
			struct anubee_map_line *t = realloc(nm, nc * sizeof(*nm));

			if (!t)
				break;
			nm = t;
			ncap = nc;
		}
		nm[nn++] = ml;
	}
	fclose(f);
	*out = nm;
	*nout = nn;
	return 0;
}

void read_proc_maps(struct procmaps *pm)
{
	struct anubee_map_line *nm = NULL;
	size_t nn = 0, i;
	int err = 0;

	int opened = load_maps(pm->pid, &nm, &nn, &err);

	pm->gone  = 0;
	pm->stale = 0;
	pm->last_read_ms = now_ms();
	if (opened < 0) {
		pm->gone = (err == ENOENT);
		// A vanished process keeps its last known mappings: they still name
		// the frames recorded before it exited.
		if (pm->gone && pm->n > 0 && pm->exit_ms == 0)
			pm->exit_ms = now_ms();
		if (!pm->gone)
			pm->n = 0;
		return;
	}

	// Parse into a fresh buffer so an empty read (an exited process whose
	// maps file still opens) does not destroy the last good snapshot.
	if (sym_maps_discard_read(pm->n, nn)) {
		free(nm);
		pm->gone = 1;
		if (pm->n > 0 && pm->exit_ms == 0)
			pm->exit_ms = now_ms();
		return;
	}
	for (i = 0; i < nn; i++) {
		nm[i].id = ++g_line_id;
		nm[i].add_seq = 0;
		nm[i].del_seq = SYM_SEQ_LIVE;
	}
	free(pm->m);
	pm->m = nm;
	pm->n = nn;
	pm->cap = nn;
}

// Grow *a to hold at least need lines, doubling from base.
static int ensure_lines(struct anubee_map_line **a, size_t *cap,
			size_t need, size_t base)
{
	size_t nc;
	struct anubee_map_line *t;

	if (need <= *cap)
		return 0;
	nc = *cap ? *cap : base;
	while (nc < need)
		nc *= 2;
	t = realloc(*a, nc * sizeof(*t));
	if (!t)
		return -1;
	*a = t;
	*cap = nc;
	return 0;
}

// ---- slots ---------------------------------------------------------------

struct procmaps *pm_find_e(int engine, int pid)
{
	long long now = now_ms();

	if (g_npm > 0 && g_mru < g_npm &&
	    g_pm[g_mru].pid == pid && g_pm[g_mru].engine == engine) {
		g_pm[g_mru].last_used_ms = now;
		return &g_pm[g_mru];
	}
	for (size_t i = 0; i < g_npm; i++) {
		if (g_pm[i].pid == pid && g_pm[i].engine == engine) {
			g_pm[i].last_used_ms = now;
			g_mru = i;
			return &g_pm[i];
		}
	}
	return NULL;
}

static int victim_better(const struct procmaps *a, const struct procmaps *b)
{
	int ae = a->exit_ms != 0, be = b->exit_ms != 0;

	if (ae != be)
		return ae;
	if (ae && a->exit_ms != b->exit_ms)
		return a->exit_ms < b->exit_ms;
	if (a->last_used_ms != b->last_used_ms)
		return a->last_used_ms < b->last_used_ms;
	return a->pid < b->pid;
}

struct procmaps *pm_alloc_e(int engine, int pid)
{
	struct procmaps *pm = pm_find_e(engine, pid);
	size_t slot, i, best;

	if (pm)
		return pm;

	if (g_npm < PM_MAX_PIDS) {
		slot = g_npm++;
	} else {
		// Never evict the pinned parent; prefer a known-exited pid.
		best = g_npm;
		for (i = 0; i < g_npm; i++) {
			if (&g_pm[i] == g_pin)
				continue;
			if (best == g_npm || victim_better(&g_pm[i], &g_pm[best]))
				best = i;
		}
		if (best == g_npm)
			return NULL;
		pm_evict_pid(g_pm[best].pid);
		g_stats.evictions++;
		slot = best;
	}

	pm = &g_pm[slot];
	struct anubee_map_line *m = pm->m;
	size_t cap = pm->cap;

	free(pm->r);
	memset(pm, 0, sizeof(*pm));
	pm->m = m;
	pm->cap = cap;
	pm->pid = pid;
	pm->engine = engine;
	pm->last_used_ms = now_ms();
	g_mru = slot;
	return pm;
}

struct procmaps *pm_get_e(int engine, int pid)
{
	struct procmaps *pm = pm_find_e(engine, pid);

	if (pm)
		return pm;
	pm = pm_alloc_e(engine, pid);
	if (!pm)
		return NULL;
	read_proc_maps(pm);
	g_stats.seeds++;
	if (pm->n == 0)
		g_stats.seed_fail++;
	pm->seeded = pm->n > 0;
	return pm;
}

struct procmaps *pm_get(int pid)
{
	return pm_get_e(0, pid);
}

// ---- lookups -------------------------------------------------------------

// /proc/<pid>/maps is address-sorted and non-overlapping, so binary search.
struct anubee_map_line *find_mapping(struct procmaps *pm, uint64_t addr)
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

struct anubee_map_line *find_mapping_at(struct procmaps *pm, uint64_t addr,
					uint64_t seq)
{
	struct anubee_map_line *h = find_mapping(pm, addr);

	if (h && h->add_seq <= seq)
		return h;
	if (seq != SYM_SEQ_LIVE) {
		for (size_t i = 0; i < pm->rn; i++) {
			struct anubee_map_line *l = &pm->r[i];

			if (l->start <= addr && addr < l->end &&
			    l->add_seq <= seq && seq < l->del_seq)
				return l;
		}
	}
	return NULL;
}

// Retire the live lines overlapping [s, e) at seq, keeping the parts outside.
static void retire_range(struct procmaps *pm, uint64_t seq, uint64_t s, uint64_t e)
{
	size_t lo, hi, i0, i1, i, rem, retired = 0, tail, k, newn;
	struct anubee_map_line left, right;
	int has_left, has_right;

	if (pm->n == 0 || s >= e)
		return;

	// First live line with end > s.
	lo = 0;
	hi = pm->n;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (pm->m[mid].end <= s)
			lo = mid + 1;
		else
			hi = mid;
	}
	i0 = lo;
	// First live line with start >= e.
	lo = i0;
	hi = pm->n;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (pm->m[mid].start < e)
			lo = mid + 1;
		else
			hi = mid;
	}
	i1 = lo;
	if (i0 >= i1)
		return;

	for (i = i0; i < i1; i++)
		if (pm->m[i].add_seq < seq)
			retired++;

	has_left = pm->m[i0].start < s;
	has_right = pm->m[i1 - 1].end > e;
	rem = (size_t)has_left + (size_t)has_right;
	newn = pm->n - (i1 - i0) + rem;

	if (retired && ensure_lines(&pm->r, &pm->rcap, pm->rn + retired, 64))
		return;
	if (ensure_lines(&pm->m, &pm->cap, newn, 256))
		return;

	if (has_left) {
		left = pm->m[i0];
		left.end = s;
		left.id = ++g_line_id;
		left.add_seq = seq;
		left.del_seq = SYM_SEQ_LIVE;
		left.xstate = 0;
	}
	if (has_right) {
		right = pm->m[i1 - 1];
		right.start = e;
		right.off = pm->m[i1 - 1].off + (e - pm->m[i1 - 1].start);
		right.id = ++g_line_id;
		right.add_seq = seq;
		right.del_seq = SYM_SEQ_LIVE;
		right.xstate = 0;
	}

	for (i = i0; i < i1; i++) {
		if (pm->m[i].add_seq < seq) {
			pm->r[pm->rn] = pm->m[i];
			pm->r[pm->rn].del_seq = seq;
			pm->rn++;
		}
	}

	tail = pm->n - i1;
	memmove(&pm->m[i0 + rem], &pm->m[i1], tail * sizeof(*pm->m));
	k = i0;
	if (has_left)
		pm->m[k++] = left;
	if (has_right)
		pm->m[k++] = right;
	pm->n = newn;
}

void pm_apply_map(int engine, int pid, uint64_t seq, uint64_t start, uint64_t end,
		  uint64_t pgoff, uint64_t inode, uint32_t dev, const char *path)
{
	struct procmaps *pm = pm_get_e(engine, pid);
	struct anubee_map_line nl;
	size_t lo, hi, pos;

	if (!pm)
		return;
	// Room for the new line plus a possible split into two remainders.
	if (ensure_lines(&pm->m, &pm->cap, pm->n + 2, 256))
		return;
	g_stats.maps++;
	retire_range(pm, seq, start, end);

	lo = 0;
	hi = pm->n;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (pm->m[mid].start < start)
			lo = mid + 1;
		else
			hi = mid;
	}
	pos = lo;

	memset(&nl, 0, sizeof(nl));
	nl.start = start;
	nl.end = end;
	nl.off = pgoff * (uint64_t)sysconf(_SC_PAGESIZE);
	nl.exec = 1;
	if (path)
		snprintf(nl.path, sizeof(nl.path), "%s", path);
	nl.inode = inode;
	nl.dev = dev;
	nl.id = ++g_line_id;
	nl.add_seq = seq;
	nl.del_seq = SYM_SEQ_LIVE;

	memmove(&pm->m[pos + 1], &pm->m[pos], (pm->n - pos) * sizeof(*pm->m));
	pm->m[pos] = nl;
	pm->n++;
	pm->seeded = 1;
}

void pm_apply_unmap(int engine, int pid, uint64_t seq, uint64_t start, uint64_t end)
{
	struct procmaps *pm = pm_get_e(engine, pid);

	if (!pm)
		return;
	g_stats.unmaps++;
	retire_range(pm, seq, start, end);
}

static int cmp_line_start(const void *a, const void *b)
{
	const struct anubee_map_line *x = a, *y = b;

	if (x->start < y->start)
		return -1;
	if (x->start > y->start)
		return 1;
	if (x->end < y->end)
		return -1;
	if (x->end > y->end)
		return 1;
	return 0;
}

void pm_seed_from_parent(int engine, int pid, int ppid, uint64_t seq)
{
	struct procmaps *parent, *child;
	size_t cnt = 0, i;

	if (ppid <= 1 || ppid == pid)
		return;
	parent = pm_get_e(engine, ppid);
	if (!parent)
		return;

	g_pin = parent;
	child = pm_alloc_e(engine, pid);
	g_pin = NULL;
	if (!child || child == parent)
		return;
	if (child->seeded && child->n > 0)
		return;

	for (i = 0; i < parent->n; i++)
		if (parent->m[i].add_seq <= seq)
			cnt++;
	for (i = 0; i < parent->rn; i++)
		if (parent->r[i].add_seq <= seq && seq < parent->r[i].del_seq)
			cnt++;

	if (cnt && ensure_lines(&child->m, &child->cap, cnt, 256))
		return;

	child->n = 0;
	for (i = 0; i < parent->n; i++) {
		if (parent->m[i].add_seq > seq)
			continue;
		child->m[child->n] = parent->m[i];
		child->m[child->n].id = ++g_line_id;
		child->m[child->n].add_seq = 0;
		child->m[child->n].del_seq = SYM_SEQ_LIVE;
		child->m[child->n].xstate = 0;
		child->n++;
	}
	for (i = 0; i < parent->rn; i++) {
		if (parent->r[i].add_seq > seq || seq >= parent->r[i].del_seq)
			continue;
		child->m[child->n] = parent->r[i];
		child->m[child->n].id = ++g_line_id;
		child->m[child->n].add_seq = 0;
		child->m[child->n].del_seq = SYM_SEQ_LIVE;
		child->m[child->n].xstate = 0;
		child->n++;
	}
	if (child->n > 1)
		qsort(child->m, child->n, sizeof(*child->m), cmp_line_start);
	child->seeded = 1;
	child->last_read_ms = now_ms();
	g_stats.parent_seeds++;
}

// ---- live rereads --------------------------------------------------------

static int overlaps_live(struct procmaps *pm, uint64_t s, uint64_t e)
{
	size_t lo = 0, hi = pm->n;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (pm->m[mid].end <= s)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo < pm->n && pm->m[lo].start < e;
}

// Merge a fresh /proc read into the model without retiring anything.
static void pm_merge_proc(struct procmaps *pm)
{
	struct anubee_map_line *nm = NULL, *out;
	size_t nn = 0, acc = 0, i, j, k;
	int err = 0;

	int opened = load_maps(pm->pid, &nm, &nn, &err);

	pm->last_read_ms = now_ms();
	pm->stale = 0;
	if (opened < 0) {
		if (err == ENOENT) {
			pm->gone = 1;
			if (pm->n > 0 && pm->exit_ms == 0)
				pm->exit_ms = now_ms();
			pm->dirty = 0;
		}
		return;
	}
	if (nn == 0) {
		free(nm);
		pm->gone = 1;
		if (pm->n > 0 && pm->exit_ms == 0)
			pm->exit_ms = now_ms();
		pm->dirty = 0;
		return;
	}
	g_stats.merges++;
	pm->gone = 0;
	pm->dirty = 0;

	for (i = 0; i < nn; i++) {
		struct anubee_map_line x = nm[i];
		uint64_t add = 0;

		if (overlaps_live(pm, x.start, x.end))
			continue;
		for (j = 0; j < pm->rn; j++)
			if (pm->r[j].start < x.end && pm->r[j].end > x.start &&
			    pm->r[j].del_seq > add)
				add = pm->r[j].del_seq;
		x.id = ++g_line_id;
		x.add_seq = add;
		x.del_seq = SYM_SEQ_LIVE;
		nm[acc++] = x;
	}
	if (acc == 0) {
		free(nm);
		return;
	}

	out = malloc((pm->n + acc) * sizeof(*out));
	if (!out) {
		free(nm);
		return;
	}
	i = 0;
	j = 0;
	k = 0;
	while (i < pm->n && j < acc) {
		if (pm->m[i].start <= nm[j].start)
			out[k++] = pm->m[i++];
		else
			out[k++] = nm[j++];
	}
	while (i < pm->n)
		out[k++] = pm->m[i++];
	while (j < acc)
		out[k++] = nm[j++];
	free(pm->m);
	pm->m = out;
	pm->n = k;
	pm->cap = pm->n;
	free(nm);
}

// A gone pid answered again: it was reused by a new process.
static void pm_revive(struct procmaps *pm, uint64_t seq)
{
	struct anubee_map_line *nm = NULL;
	size_t nn = 0, i, retire = 0;
	int err = 0;

	if (load_maps(pm->pid, &nm, &nn, &err) < 0 || nn == 0) {
		free(nm);
		pm->last_read_ms = now_ms();
		return;
	}
	pm->last_read_ms = now_ms();
	if (seq != SYM_SEQ_LIVE) {
		for (i = 0; i < pm->n; i++)
			if (pm->m[i].add_seq < seq)
				retire++;
		if (retire && ensure_lines(&pm->r, &pm->rcap, pm->rn + retire, 64)) {
			free(nm);
			return;
		}
		for (i = 0; i < pm->n; i++) {
			if (pm->m[i].add_seq < seq) {
				pm->r[pm->rn] = pm->m[i];
				pm->r[pm->rn].del_seq = seq;
				pm->rn++;
			}
		}
	}
	for (i = 0; i < nn; i++) {
		nm[i].id = ++g_line_id;
		nm[i].add_seq = (seq == SYM_SEQ_LIVE) ? 0 : seq;
		nm[i].del_seq = SYM_SEQ_LIVE;
	}
	free(pm->m);
	pm->m = nm;
	pm->n = nn;
	pm->cap = nn;
	pm->gone = 0;
	pm->exit_ms = 0;
	pm->dirty = 0;
	pm->stale = 0;
	pm->gen++;
	g_pm_revived++;
}

// find_mapping, re-reading /proc/<pid>/maps once (throttled to REFRESH_MS) on a
// miss: a library may have loaded since the cache was last read. This is the one
// place that recovers from a cache populated mid-launch (e.g. the maps were first
// read while only the linker was mapped, before libc/libandroid_runtime), which
// is common under capture-all where snapshots fire during early process launch.
// Used by both the symbolizer (sym_resolve_uncached) and the CFI walk
// (cfi_unwind_snapshot) so a stale cache can't dead-end the unwind at frame 0.
struct anubee_map_line *find_mapping_refresh(struct procmaps *pm, uint64_t addr)
{
	if (pm->stale)
		read_proc_maps(pm);
	struct anubee_map_line *hit = find_mapping(pm, addr);
	if (!hit && now_ms() - pm->last_read_ms > REFRESH_MS) {
		read_proc_maps(pm);
		hit = find_mapping(pm, addr);
	}
	return hit;
}

struct anubee_map_line *find_mapping_refresh_at(struct procmaps *pm, uint64_t addr,
						uint64_t seq)
{
	struct anubee_map_line *hit;
	long long now;

	if (pm->engine == 0)
		return find_mapping_refresh(pm, addr);

	hit = find_mapping_at(pm, addr, seq);
	if (hit)
		return hit;
	now = now_ms();
	if (!pm->gone && (pm->stale || pm->dirty ||
			  now - pm->last_read_ms > REFRESH_MS)) {
		pm_merge_proc(pm);
		hit = find_mapping_at(pm, addr, seq);
	} else if (pm->gone && now - pm->last_read_ms > REFRESH_MS) {
		pm_revive(pm, seq);
		hit = find_mapping_at(pm, addr, seq);
	}
	return hit;
}

// ---- housekeeping --------------------------------------------------------

// Force a reread of pid's maps on its next resolve (a library may have loaded);
// used by sym_flush_pid when the caller (e.g. a fresh mmap event) knows the maps
// changed without waiting on the throttled miss-triggered refresh in find_mapping_refresh.
void pm_reset_pid(int pid)
{
	for (size_t i = 0; i < g_npm; i++)
		if (g_pm[i].pid == pid)
			g_pm[i].stale = 1;   // reread on the next lookup; keep the old snapshot if that fails
}

void pm_mark_dirty_all(int engine)
{
	for (size_t i = 0; i < g_npm; i++)
		if (g_pm[i].engine == engine && !g_pm[i].gone)
			g_pm[i].dirty = 1;
}

void pm_compact(int engine, uint64_t oldest_open_seq)
{
	for (size_t i = 0; i < g_npm; i++) {
		struct procmaps *pm = &g_pm[i];
		size_t w = 0;

		if (pm->engine != engine)
			continue;
		for (size_t j = 0; j < pm->rn; j++)
			if (pm->r[j].del_seq > oldest_open_seq)
				pm->r[w++] = pm->r[j];
		pm->rn = w;
	}
}

void pm_note_exit(int engine, int pid)
{
	struct procmaps *pm = pm_find_e(engine, pid);

	if (pm && pm->exit_ms == 0)
		pm->exit_ms = now_ms();
}

void pm_stats_get(struct pm_stats *out)
{
	if (!out)
		return;
	*out = g_stats;
	out->revives = g_pm_revived;
	out->models = 0;
	out->lines = 0;
	out->retired = 0;
	for (size_t i = 0; i < g_npm; i++) {
		out->models++;
		out->lines += g_pm[i].n;
		out->retired += g_pm[i].rn;
	}
}

// Largest line valid at seq with a start below cur, or NULL.
static struct anubee_map_line *pred_line_at(struct procmaps *pm,
					    struct anubee_map_line *cur,
					    uint64_t seq)
{
	struct anubee_map_line *best = NULL;
	uint64_t best_start = 0;
	size_t lo = 0, hi = pm->n;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (pm->m[mid].start < cur->start)
			lo = mid + 1;
		else
			hi = mid;
	}
	while (lo > 0) {
		struct anubee_map_line *p = &pm->m[lo - 1];

		if (p->add_seq <= seq) {
			best = p;
			best_start = p->start;
			break;
		}
		lo--;
	}
	for (size_t i = 0; i < pm->rn; i++) {
		struct anubee_map_line *p = &pm->r[i];

		if (p->start >= cur->start)
			continue;
		if (p->add_seq > seq || seq >= p->del_seq)
			continue;
		if (!best || p->start > best_start) {
			best = p;
			best_start = p->start;
		}
	}
	return best;
}

static int is_filler_line(const struct anubee_map_line *l)
{
	return l->path[0] == '\0' || l->path[0] == '[';
}

// Load base, ELF offset and end of the base mapping for hit in the view of the
// model at sequence seq (SYM_SEQ_LIVE = current lines).
void module_base_at(struct procmaps *pm, struct anubee_map_line *hit, uint64_t seq,
		    uint64_t *load_base, uint64_t *elf_off, uint64_t *base_end)
{
	struct anubee_map_line *cur = hit;

	while (cur) {
		struct anubee_map_line *p = pred_line_at(pm, cur, seq);

		while (p && is_filler_line(p))
			p = pred_line_at(pm, p, seq);
		if (!p || strcmp(p->path, cur->path) != 0 || p->off >= cur->off)
			break;
		cur = p;
	}

	*load_base = cur->start;
	*elf_off   = cur->off;
	*base_end  = cur->end;

	// Exec-only line: the kernel maps just a library's executable segment, so
	// the same-path first segment is missing from the model. Recover the ELF
	// base from the program headers instead.
	if (cur != hit || !hit->exec || hit->path[0] != '/')
		return;

	uint64_t start = 0;
	size_t plen = strlen(hit->path);

	if (plen >= 4 && strcmp(hit->path + plen - 4, ".apk") == 0) {
		if (!apk_so_member_at(hit->path, hit->off, &start))
			return;
	}
	if (hit->off == start)
		return;

	if (hit->xstate == 1) {
		*load_base = hit->xbase;
		*elf_off   = hit->xelf;
		*base_end  = hit->end;
		return;
	}
	if (hit->xstate == -1)
		return;

	int fd = open_module_file(hit->path, pm->pid, hit->start, hit->end,
				  hit->inode, hit->dev);
	if (fd >= 0) {
		uint64_t lb;

		int r = elf_exec_load_base(fd, start, hit->off, hit->start, &lb);

		close(fd);
		if (r == 0) {
			hit->xstate = 1;
			hit->xbase = lb;
			hit->xelf = start;
			*load_base = lb;
			*elf_off   = start;
			*base_end  = hit->end;
			return;
		}
	}
	hit->xstate = -1;
}

// Walk back over the contiguous run of same-path mappings to find the ELF base.
// Also returns the base mapping's [start,end), used to reach the file via
// /proc/<pid>/map_files when its path is deleted/anonymous.
void module_base(struct procmaps *pm, struct anubee_map_line *hit,
			uint64_t *load_base, uint64_t *elf_off, uint64_t *base_end)
{
	module_base_at(pm, hit, SYM_SEQ_LIVE, load_base, elf_off, base_end);
}
