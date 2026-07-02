// symbolize.c — see symbolize.h.
//
// Two caches:
//   * per-pid /proc/<pid>/maps snapshot (module ranges + on-disk paths), reread
//     lazily on a lookup miss (throttled) since libraries can load over time;
//   * per-(path, elf-offset) parsed symbol table, so each ELF is read once. The
//     table merges three sources: .dynsym (exported), .symtab (full static
//     symbols, present on unstripped builds), and .gnu_debugdata — the
//     LZMA-compressed "mini-debug-info" ELF that Android system libraries ship
//     instead of a plain .symtab, and where their real function names survive.
//
// A module's load base is the start of the contiguous run of same-path mappings
// containing the address; the ELF begins at that run's file offset (0 for a
// plain .so, non-zero for a library mapped directly out of an APK). A symbol's
// link-time st_value relates to runtime as: runtime = st_value + load_base, so
// we look up (addr - load_base) in the symbol table.

#include "symbolize.h"
#include "common/maps.h"      // ares_parse_maps_line
#include "common/proc_mem.h"  // proc_mem_open / proc_mem_read (live target memory)
#include "common/cfi_unwind.h"
#include "common/emit.h"      // struct jbuf, jb_s / jb_u64 / jb_hex / jb_esc / jb_c
#include "common/managed_frame.h" // ares_is_interp_frame, ares_managed_chain_build (impure bodies here)
#include "common/art_nterp.h" // nterp_name
#include "common/art_shadow.h"   // shadow_frame_chain — switch-interp ShadowFrame naming
#include <linux/types.h>      // __u64 / __u32 / __u8 required by stack_snapshot.h
#include "common/stack_snapshot.h"
#include "symbolize_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <elf.h>
#include <lzma.h>
#include <pthread.h>
#include <sys/stat.h>

// ---- address -> symbol cache --------------------------------------------
//
// Backtraces are extremely repetitive (a loop hits the same stack thousands of
// times), so caching the resolved string per (pid,addr) amortizes nearly all of
// the per-frame work — the linear map/dynsym lookups only run on the first sight
// of each distinct address. This is what lets the JSON drain keep up under a
// firehose. Open-addressing hash table, cleared when a pid's maps change.

#define SC_STR 120

struct sc_ent {
	uint64_t addr;
	int pid;
	int used;
	char sym[SC_STR];
};

static struct sc_ent *g_sc;
static size_t g_sc_cap, g_sc_used;

static uint64_t sc_hash(int pid, uint64_t addr)
{
	uint64_t h = addr ^ ((uint64_t)(uint32_t)pid * 0x9e3779b97f4a7c15ULL);
	h *= 0xbf58476d1ce4e5b9ULL;
	h ^= h >> 31;
	return h;
}

static void sc_clear(void)
{
	if (g_sc)
		memset(g_sc, 0, g_sc_cap * sizeof(*g_sc));
	g_sc_used = 0;
}

// Called by pm_get when it evicts the LRU procmaps slot.
void pm_evict_pid(int pid)
{
	jit_reset_pid(pid);
	vdso_reset_pid(pid);
	sc_clear();                 // ponytail: global clear; per-pid eviction too costly
}

static int sc_get(int pid, uint64_t addr, char *out, size_t outsz)
{
	if (!g_sc)
		return 0;
	size_t mask = g_sc_cap - 1, i = sc_hash(pid, addr) & mask;
	for (size_t probe = 0; probe < g_sc_cap; probe++) {
		struct sc_ent *e = &g_sc[i];
		if (!e->used)
			return 0;
		if (e->addr == addr && e->pid == pid) {
			snprintf(out, outsz, "%s", e->sym);
			return 1;
		}
		i = (i + 1) & mask;
	}
	return 0;
}

static void sc_put(int pid, uint64_t addr, const char *sym)
{
	if (!g_sc) {
		g_sc_cap = 1u << 16;
		g_sc = calloc(g_sc_cap, sizeof(*g_sc));
		if (!g_sc) { g_sc_cap = 0; return; }
	}
	// ponytail: clear-and-rebuild at the ceiling; per-pid eviction too costly on open-addressed table.
#define SC_MAX_CAP (1u << 18)
	if ((g_sc_used + 1) * 4 >= g_sc_cap * 3) {          // grow at 75% load
		if (g_sc_cap >= SC_MAX_CAP) {
			sc_clear();   // hit ceiling; cache rebuilds lazily on subsequent misses
		} else {
			size_t ncap = g_sc_cap * 2, nmask = ncap - 1;
			struct sc_ent *ng = calloc(ncap, sizeof(*ng));
			if (ng) {
				for (size_t k = 0; k < g_sc_cap; k++) {
					if (!g_sc[k].used)
						continue;
					size_t j = sc_hash(g_sc[k].pid, g_sc[k].addr) & nmask;
					while (ng[j].used)
						j = (j + 1) & nmask;
					ng[j] = g_sc[k];
				}
				free(g_sc);
				g_sc = ng;
				g_sc_cap = ncap;
			}
		}
	}
	size_t mask = g_sc_cap - 1, i = sc_hash(pid, addr) & mask;
	while (g_sc[i].used && !(g_sc[i].addr == addr && g_sc[i].pid == pid))
		i = (i + 1) & mask;
	if (!g_sc[i].used)
		g_sc_used++;
	g_sc[i].used = 1;
	g_sc[i].pid = pid;
	g_sc[i].addr = addr;
	snprintf(g_sc[i].sym, sizeof(g_sc[i].sym), "%s", sym);
}

// ponytail: one global lock; split per-cache only if profiling shows contention.
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

// Returns 1 if the result is stable enough to cache (a real mapping), 0 for an
// unmapped/transient address (which a later mmap could turn into a real symbol).
static int sym_resolve_uncached(int pid, unsigned long long addr, char *out, size_t outsz);

void sym_resolve(int pid, unsigned long long addr, char *out, size_t outsz)
{
	pthread_mutex_lock(&g_lock);
	if (sc_get(pid, (uint64_t)addr, out, outsz)) {
		pthread_mutex_unlock(&g_lock);
		return;
	}
	if (sym_resolve_uncached(pid, addr, out, outsz))
		sc_put(pid, (uint64_t)addr, out);
	pthread_mutex_unlock(&g_lock);
}

static int sym_resolve_uncached(int pid, unsigned long long addr, char *out, size_t outsz)
{
	struct procmaps *pm = pm_get(pid);
	if (!pm) {
		snprintf(out, outsz, "0x%llx", addr);
		return 0;
	}

	struct ares_map_line *hit = find_mapping_refresh(pm, (uint64_t)addr);
	if (!hit) {
		// Not in any mapping: pid exited before maps were read, stale frame, or bad unwind.
		if (pm->gone)
			snprintf(out, outsz, "0x%llx [pid %d gone]", addr, pid);
		else
			snprintf(out, outsz, "0x%llx [unmapped]", addr);
		return 0;
	}

	uint64_t load_base, elf_off, base_end;
	module_base(pm, hit, &load_base, &elf_off, &base_end);

	// Anonymous memory with no name. If it's executable it's most often ART's JIT
	// code cache (else a packer/obfuscator or RASP-allocated code region): try to
	// name it from ART's in-process JIT descriptor. An unnamed *executable* anon
	// address is returned as NOT cacheable (0) so it can upgrade to a real method
	// name once ART compiles/publishes it; non-executable anon is stable and cached.
	if (hit->path[0] == '\0') {
		unsigned long long off = (unsigned long long)((uint64_t)addr - hit->start);
		if (hit->exec) {
			if (jit_resolve(pid, (uint64_t)addr, out, outsz))
				return 1;
			snprintf(out, outsz, "[anon]+0x%llx", off);
			return 0;
		}
		snprintf(out, outsz, "[anon]+0x%llx", off);
		return 1;
	}

	char base[MAX_PATH_LEN];
	display_name(hit->path, base, sizeof(base));
	uint64_t vaddr = (uint64_t)addr - load_base;

	// Kernel-named anonymous regions ("[anon:scudo:primary]", "[stack]", ...)
	// aren't openable as ELF. An *executable* one is most often ART's JIT code
	// cache mapped under a name (e.g. "[anon_shmem:dalvik-jit-code-cache]"): try
	// the in-process JIT descriptor first, exactly as for the empty-name exec
	// case above. A miss on an executable region is returned NOT cacheable (0) so
	// the frame can upgrade once ART compiles/publishes the method; a
	// non-executable region is stable, cached, and just shows name + offset.
	// (A deleted/renamed real library still has '/' first and is recovered below
	// via /proc/<pid>/map_files.)
	if (hit->path[0] == '[') {
		// The vDSO is a real, immutable ELF mapped without a backing file:
		// name __kernel_* frames from its .dynsym (read out of live memory).
		// A miss is final (the symbol set is complete), so it is cacheable —
		// unlike a JIT miss, which returns 0 to allow a later upgrade.
		if (!strcmp(base, "[vdso]")) {
			if (vdso_resolve(pid, (uint64_t)addr, load_base, base_end, out, outsz))
				return 1;
			snprintf(out, outsz, "%s+0x%llx", base, (unsigned long long)vaddr);
			return 1;
		}
		if (hit->exec) {
			if (jit_resolve(pid, (uint64_t)addr, out, outsz))
				return 1;
			snprintf(out, outsz, "%s+0x%llx", base, (unsigned long long)vaddr);
			return 0;
		}
		snprintf(out, outsz, "%s+0x%llx", base, (unsigned long long)vaddr);
		return 1;
	}

	// APK-embedded stored .so: show "base.apk -> libfoo.so" as the display name.
	// dynsym_get still uses hit->path + elf_off to open the ELF inside the APK —
	// the symbol resolution is already correct; this only improves the label.
	const char *inner_so = apk_so_name(hit->path, elf_off);
	if (inner_so) {
		char apk[MAX_PATH_LEN];
		memcpy(apk, base, sizeof(apk));
		snprintf(base, sizeof(base), "%.125s -> %.125s", apk, inner_so);
	}

	struct dynsym *ds = dynsym_get(hit->path, elf_off, pid, load_base, base_end);
	uint64_t delta = 0;
	const char *name = sym_lookup(ds, vaddr, &delta);
	if (name) {
		if (delta)
			snprintf(out, outsz, "%s!%s+0x%llx", base, name, (unsigned long long)delta);
		else
			snprintf(out, outsz, "%s!%s", base, name);
	} else {
		snprintf(out, outsz, "%s+0x%llx", base, (unsigned long long)vaddr);
	}
	return 1;
}

int cfi_unwind_snapshot(int pid, const struct ares_stack_snapshot *snap,
			uint64_t *out_pcs, int max, uint64_t *out_sps,
			struct cfi_step_diag *out_diags)
{
	struct ares_unwind_regs r;
	unwind_regs_from_snapshot(snap, &r);
	/* cfi_step operates on uint64_t arrays; ares_unwind_regs uses __u64.
	 * They are the same width but distinct types — copy to avoid -Wincompatible-pointer-types. */
	uint64_t regs[CFI_NREG];
	uint64_t sp = (uint64_t)r.sp;
	uint64_t pc = (uint64_t)r.pc;
	for (int k = 0; k < CFI_NREG; k++)
		regs[k] = (uint64_t)r.x[k];
	// One-shot forced maps re-read for this unwind: the snapshot is captured at
	// syscall time but symbolized later in the drain. Under capture-all the first
	// time we see a pid is often mid-launch, so its cached maps can predate the
	// libraries this stack runs through (libc/libandroid_runtime), and the
	// REFRESH_MS throttle suppresses the corrective re-read during the launch
	// burst. cfi_unwind_snapshot runs once per *distinct* stack (deduped), so a
	// single throttle-ignoring re-read here is bounded and unblocks the walk
	// without touching the throttled FP-backtrace path.
	int forced_reread = 0;
	int n = 0;
	for (int iter = 0; iter < max && iter < 256; iter++) {
		if (out_sps) out_sps[n] = sp;   /* SP of the frame whose PC we record */
		out_pcs[n++] = pc;
		if (n >= max) break;
		if (pc == 0) {
			if (out_diags) out_diags[n - 1].stop_reason = CFI_SNAP_PC_ZERO;
			break;
		}
		struct procmaps *pm = pm_get(pid);
		if (!pm) break;
		struct ares_map_line *hit = find_mapping_refresh(pm, pc);
		if (!hit && !forced_reread) {
			forced_reread = 1;
			read_proc_maps(pm);
			hit = find_mapping(pm, pc);
		}
		if (!hit) {
			if (out_diags) out_diags[n - 1].stop_reason = CFI_SNAP_NO_MAPPING;
			break;
		}
		uint64_t load_base, elf_off, base_end;
		module_base(pm, hit, &load_base, &elf_off, &base_end);
		/* IMPORTANT: cfi_get returns a pointer into a realloc'able cache; use the
		 * section (cfi_step) before the next iteration's cfi_get. Never hold it
		 * across calls. */
		struct cfi_section *sec = cfi_get(hit->path, elf_off, load_base, pid, hit->start, hit->end);
		if (!sec) {
			if (out_diags) {
				struct cfi_step_diag *d = &out_diags[n - 1];
				d->module_pc = pc - load_base;
				d->load_base = load_base;
				d->elf_off   = elf_off;
				snprintf(d->path, sizeof(d->path), "%s", hit->path ? hit->path : "");
				d->stop_reason = CFI_SNAP_CFI_GET_NULL;
			}
			break;
		}
		uint64_t module_pc = pc - load_base;
		struct cfi_step_diag *dp = NULL;
		if (out_diags) {
			dp = &out_diags[n - 1];   /* out_pcs[n-1] is the frame whose step we take */
			dp->module_pc = module_pc;
			dp->load_base = load_base;
			dp->elf_off   = elf_off;
			snprintf(dp->path, sizeof(dp->path), "%s", hit->path ? hit->path : "");
		}
		int rc = cfi_step(sec, module_pc, regs, &sp, &pc,
				  (const uint8_t *)snap->snap, snap->sp, (size_t)snap->snap_len,
				  dp);
		if (rc != 1) break;
	}
	return n;
}

void sym_flush_pid(int pid)
{
	pthread_mutex_lock(&g_lock);
	pm_reset_pid(pid);
	jit_reset_pid(pid);
	vdso_reset_pid(pid);
	sc_clear();                             // addresses may have moved
	pthread_mutex_unlock(&g_lock);
}

// Resolve the managed method chain for an already-CFI-walked snapshot. Mirrors
// the nterp-terminal logic in syscalls' emit_cfi_backtrace (single source now):
// only an nterp_helper terminal places the ArtMethod* at the managed frame base,
// so only then do we name the interpreted method.
int ares_managed_chain(int pid, const struct ares_stack_snapshot *s,
                       const uint64_t *pcs, const uint64_t *sps, int n,
                       char *out, size_t cap)
{
    if (n <= 0) return 0;
    static _Thread_local char store[64][320];
    const char *syms[64];
    int m = n < 64 ? n : 64;
    for (int i = 0; i < m; i++) {
        sym_resolve(pid, pcs[i], store[i], sizeof(store[i]));
        syms[i] = store[i];
    }
    char chain[16][256];
    const char *nptr[16];
    int nn = 0;
    if (strstr(syms[m - 1], "nterp_helper")) {
        nn = nterp_chain(pid, s, sps[m - 1], chain, 16);
        if (nn == 0 && nterp_name(pid, s, sps[m - 1], chain[0], sizeof(chain[0])))
            nn = 1;   /* fallback: never regress today's single-frame naming */
        for (int k = 0; k < nn; k++) nptr[k] = chain[k];
    }
    return ares_managed_chain_build(syms, m, nptr, nn, out, cap);
}

void ares_emit_cfi_stack_json(struct jbuf *j, int pid,
                              const struct ares_stack_snapshot *s,
                              const uint64_t *pcs, const uint64_t *sps, int n,
                              const struct cfi_step_diag *diags)
{
    jb_s(j, "{\"type\":\"cfi_stack\",\"pid\":"); jb_u64(j, s->h.pid);
    jb_s(j, ",\"tid\":");      jb_u64(j, s->h.tid);
    jb_s(j, ",\"stack_id\":"); jb_u64(j, s->stack_id);
    jb_s(j, ",\"cfi_backtrace\":[");
    char sym[320];
    for (int i = 0; i < n; i++) {
        if (i) jb_c(j, ',');
        sym_resolve(pid, pcs[i], sym, sizeof(sym));
        jb_s(j, "{\"frame\":"); jb_u64(j, (unsigned)i);
        jb_s(j, ",\"addr\":\""); jb_hex(j, pcs[i]);
        jb_s(j, "\",\"symbol\":\""); jb_esc(j, sym); jb_c(j, '"');
        if (strstr(sym, "art_jni_trampoline")) jb_s(j, ",\"kind\":\"jni-trampoline\"");
        else if (strstr(sym, ".oat!") || strstr(sym, ".odex!") || strstr(sym, ".vdex!"))
            jb_s(j, ",\"kind\":\"managed\"");
        else if (ares_is_interp_frame(sym)) jb_s(j, ",\"kind\":\"interp\"");
        else jb_s(j, ",\"kind\":\"native\"");
        if (diags) {
            const struct cfi_step_diag *d = &diags[i];
            jb_s(j, ",\"module_pc\":\""); jb_hex(j, d->module_pc);
            jb_s(j, "\",\"load_base\":\""); jb_hex(j, d->load_base);
            jb_s(j, "\",\"elf_off\":\""); jb_hex(j, d->elf_off);
            jb_s(j, "\",\"fde_found\":"); jb_u64(j, (unsigned)d->fde_found);
            jb_s(j, ",\"fde_pc_lo\":\""); jb_hex(j, d->fde_pc_lo);
            jb_s(j, "\",\"fde_pc_hi\":\""); jb_hex(j, d->fde_pc_hi);
            jb_s(j, "\",\"cfa_reg\":"); jb_u64(j, d->cfa_reg);
            jb_s(j, ",\"cfa\":\""); jb_hex(j, d->cfa);
            jb_s(j, "\",\"ra_kind\":"); jb_u64(j, d->ra_kind);
            jb_s(j, ",\"ra_slot\":\""); jb_hex(j, d->ra_slot);
            jb_s(j, "\",\"ra_value\":\""); jb_hex(j, d->ra_value);
            jb_s(j, "\",\"stop_reason\":"); jb_u64(j, (unsigned)d->stop_reason);
            jb_s(j, ",\"diag_path\":\""); jb_esc(j, d->path); jb_c(j, '"');
        }
        jb_c(j, '}');
    }
    if (n > 0 && strstr(sym, "nterp_helper")) {
        /* Name the full interpreted chain above the terminal; fall back to the
         * single-frame nterp_name so we never regress. Innermost-first; each frame
         * numbered continuing from n. */
        char chain[16][256];
        int nn = nterp_chain(pid, s, sps[n - 1], chain, 16);
        if (nn == 0 && nterp_name(pid, s, sps[n - 1], chain[0], sizeof(chain[0])))
            nn = 1;
        for (int k = 0; k < nn; k++) {
            jb_c(j, ',');
            jb_s(j, "{\"frame\":"); jb_u64(j, (unsigned)(n + k));
            jb_s(j, ",\"addr\":\"0x0\",\"symbol\":\""); jb_esc(j, chain[k]);
            jb_s(j, "\",\"kind\":\"interp\"}");
        }
    }
    else if (n > 0 && strstr(sym, "ExecuteSwitchImpl")) {
        /* Switch-interpreter terminal: the Java caller runs on heap ShadowFrames, not
         * on the captured stack. Walk ART's live Thread->ManagedStack->ShadowFrame chain
         * (BuildID-gated, /proc/mem reads only). Innermost-first; numbered continuing from n. */
        char chain[16][256];
        int nn = shadow_frame_chain(pid, s->tls_base, chain, 16);
        for (int k = 0; k < nn; k++) {
            jb_c(j, ',');
            jb_s(j, "{\"frame\":"); jb_u64(j, (unsigned)(n + k));
            jb_s(j, ",\"addr\":\"0x0\",\"symbol\":\""); jb_esc(j, chain[k]);
            jb_s(j, "\",\"kind\":\"interp\"}");
        }
    }
    jb_s(j, "]}\n");
}
