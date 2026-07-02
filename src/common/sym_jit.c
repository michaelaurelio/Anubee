// SPDX-License-Identifier: GPL-2.0
// ART JIT symbol resolution via the GDB JIT interface (__jit_debug_descriptor),
// read out of /proc/<pid>/mem. See symbolize_internal.h.
#include <sys/types.h>
#include "symbolize_internal.h"
#include "common/proc_mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <elf.h>

// ---- ART JIT symbols (GDB JIT interface, read from live memory) -----------
//
// ART's JIT compiles Java methods into an anonymous executable mapping (the JIT
// code cache), which has no backing file, so the ELF/dynsym path above can only
// say "[anon]". But ART publishes one in-process ELF image per JIT method (or a
// repacked batch) through the GDB JIT interface: a global `__jit_debug_descriptor`
// in libart.so heads a linked list of `jit_code_entry`, each pointing at an
// in-memory mini-ELF whose .symtab names the compiled Java method and gives its
// runtime address range. Reading that out of /proc/<pid>/mem lets us name JIT
// frames on-device, the same source simpleperf/libunwindstack use.
//
// We model the modern 64-bit Android layout by byte offset (not a C struct) so
// padding/ABI assumptions can't bite, version-check the descriptor, and snapshot
// ART's action_seqlock_ around the walk so we never publish a torn list.

#define JIT_MAX_ENTRIES   65536          // cycle/runaway guard on the linked list
#define JIT_MAX_SYMFILE   (64u << 20)    // sanity cap on one mini-ELF

// JITDescriptor field offsets (64-bit): version u32 @0, action_flag u32 @4,
// relevant_entry ptr @8, head ptr @16, flags u32 @24, sizeof_descriptor u32 @28,
// sizeof_entry u32 @32, action_seqlock_ u32 @36, action_timestamp u64 @40.
#define JIT_DESC_BYTES    48
#define JD_VERSION        0
#define JD_HEAD           16
#define JD_SEQLOCK        36
// jit_code_entry: next ptr @0, prev ptr @8, symfile_addr ptr @16, symfile_size u64 @24.
#define JCE_BYTES         32
#define JCE_NEXT          0
#define JCE_SYMADDR       16
#define JCE_SYMSIZE       24

static uint32_t rd_u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t rd_u64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

struct jit_entry { uint64_t start, end; uint32_t name_off; };

struct jit_map {
	struct jit_entry *e;
	size_t n, cap;
	char *arena;                    // name arena, NUL at offset 0 (see arena_add)
	size_t arena_len, arena_cap;
};

struct art_ctx {
	int pid;
	int memfd;                      // cached /proc/<pid>/mem, -1 until opened
	int located;                    // 0 unknown, 1 descriptor found, -1 give up
	uint64_t desc_va;               // runtime addr of __jit_debug_descriptor
	uint64_t last_head;             // descriptor head ptr at last successful build
	uint32_t last_seqlock;          // action_seqlock_ at last successful build
	long long next_refresh_ms;      // throttle (REFRESH_MS), like procmaps
	struct jit_map jit;
};

static struct art_ctx *g_art;
static size_t g_nart;

// Reusable scratch for reading one mini-ELF; worker-thread-only, so a static is
// fine and avoids a malloc/free per JIT entry on every rebuild.
static uint8_t *g_jit_scratch;
static size_t g_jit_scratch_cap;

static int jit_scratch_ensure(size_t n)
{
	if (n <= g_jit_scratch_cap)
		return 1;
	size_t nc = g_jit_scratch_cap ? g_jit_scratch_cap : (64u << 10);
	while (nc < n)
		nc *= 2;
	uint8_t *nb = realloc(g_jit_scratch, nc);
	if (!nb)
		return 0;
	g_jit_scratch = nb;
	g_jit_scratch_cap = nc;
	return 1;
}

static uint32_t jit_arena_add(struct jit_map *jm, const char *name)
{
	if (!jm->arena) {
		jm->arena_cap = 8192;
		jm->arena = malloc(jm->arena_cap);
		if (!jm->arena) { jm->arena_cap = 0; return 0; }
		jm->arena[0] = '\0';
		jm->arena_len = 1;
	}
	size_t len = strlen(name) + 1;
	if (jm->arena_len + len > jm->arena_cap) {
		size_t nc = jm->arena_cap * 2;
		while (nc < jm->arena_len + len)
			nc *= 2;
		char *na = realloc(jm->arena, nc);
		if (!na)
			return 0;
		jm->arena = na;
		jm->arena_cap = nc;
	}
	uint32_t off = (uint32_t)jm->arena_len;
	memcpy(jm->arena + jm->arena_len, name, len);
	jm->arena_len += len;
	return off;
}

static void jit_add(struct jit_map *jm, uint64_t start, uint64_t size, const char *name)
{
	if (!start || name[0] == '\0')
		return;
	if (jm->n == jm->cap) {
		size_t nc = jm->cap ? jm->cap * 2 : 256;
		struct jit_entry *ne = realloc(jm->e, nc * sizeof(*ne));
		if (!ne)
			return;
		jm->e = ne;
		jm->cap = nc;
	}
	uint32_t off = jit_arena_add(jm, name);
	if (!off)
		return;
	jm->e[jm->n].start = start;
	jm->e[jm->n].end = size ? start + size : start + 1;
	jm->e[jm->n].name_off = off;
	jm->n++;
}

static void jit_reset(struct jit_map *jm)
{
	jm->n = 0;
	if (jm->arena)
		jm->arena_len = 1;      // keep the leading NUL, reuse the buffer
}

// Parse one in-memory JIT mini-ELF (already copied into `buf`) and add its code
// symbols as ABSOLUTE runtime ranges. ART builds these ELFs with the method's
// real runtime address baked into st_value (load bias 0), so we store st_value
// directly. Treat every offset as untrusted (target-controlled) and bounds-check.
static void jit_ingest_elf(struct jit_map *jm, const uint8_t *buf, size_t len)
{
	Elf64_Ehdr eh;
	if (len < sizeof(eh))
		return;
	memcpy(&eh, buf, sizeof(eh));
	if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64)
		return;
	if (eh.e_shoff == 0 || eh.e_shnum == 0 || eh.e_shentsize < sizeof(Elf64_Shdr))
		return;
	if (eh.e_shoff + (uint64_t)eh.e_shnum * eh.e_shentsize > len)
		return;

	for (int i = 0; i < eh.e_shnum; i++) {
		Elf64_Shdr sec;
		memcpy(&sec, buf + eh.e_shoff + (size_t)i * eh.e_shentsize, sizeof(sec));
		if ((sec.sh_type != SHT_SYMTAB && sec.sh_type != SHT_DYNSYM) ||
		    sec.sh_link >= eh.e_shnum || sec.sh_entsize == 0)
			continue;
		Elf64_Shdr str;
		memcpy(&str, buf + eh.e_shoff + (size_t)sec.sh_link * eh.e_shentsize, sizeof(str));
		if (sec.sh_offset + sec.sh_size > len || str.sh_offset + str.sh_size > len)
			continue;
		size_t count = sec.sh_size / sec.sh_entsize;
		for (size_t k = 0; k < count; k++) {
			Elf64_Sym es;
			memcpy(&es, buf + sec.sh_offset + k * sec.sh_entsize, sizeof(es));
			if (es.st_value == 0 || es.st_shndx == SHN_UNDEF || es.st_name == 0)
				continue;
			unsigned t = ELF64_ST_TYPE(es.st_info);
			if (t != STT_FUNC && t != STT_NOTYPE)
				continue;            // JIT methods are code symbols
			if (es.st_name >= str.sh_size)
				continue;
			jit_add(jm, es.st_value, es.st_size,
				(const char *)buf + str.sh_offset + es.st_name);
		}
	}
}

static int jit_cmp(const void *a, const void *b)
{
	uint64_t x = ((const struct jit_entry *)a)->start, y = ((const struct jit_entry *)b)->start;
	return (x > y) - (x < y);
}

static const char *jit_lookup(struct jit_map *jm, uint64_t addr, uint64_t *delta)
{
	if (jm->n == 0)
		return NULL;
	size_t lo = 0, hi = jm->n;
	while (lo < hi) {
		size_t mid = (lo + hi) / 2;
		if (jm->e[mid].start <= addr)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo == 0)
		return NULL;
	struct jit_entry *je = &jm->e[lo - 1];
	if (addr >= je->end)
		return NULL;
	*delta = addr - je->start;
	return jm->arena + je->name_off;
}

// Look up one symbol's link-time value in the .dynsym of the ELF backing `path`
// (any symbol type — used for the data object __jit_debug_descriptor, which the
// code-only dynsym cache filters out). Returns 0 if not found.
static uint64_t elf_dynsym_value(const char *path, uint64_t elf_off, int pid,
				 uint64_t vstart, uint64_t vend, const char *name)
{
	int fd = open_module_file(path, pid, vstart, vend);
	if (fd < 0)
		return 0;

	uint64_t found = 0;
	Elf64_Ehdr eh;
	if (pread_all(fd, &eh, sizeof(eh), (off_t)elf_off) != 0)
		goto out;
	if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64)
		goto out;
	if (eh.e_shoff == 0 || eh.e_shnum == 0 || eh.e_shentsize != sizeof(Elf64_Shdr))
		goto out;

	size_t shsz = (size_t)eh.e_shnum * eh.e_shentsize;
	Elf64_Shdr *sh = malloc(shsz);
	if (!sh)
		goto out;
	if (pread_all(fd, sh, shsz, (off_t)(elf_off + eh.e_shoff)) != 0) {
		free(sh);
		goto out;
	}

	for (int i = 0; i < eh.e_shnum && !found; i++) {
		if (sh[i].sh_type != SHT_DYNSYM || sh[i].sh_link >= eh.e_shnum ||
		    sh[i].sh_entsize == 0)
			continue;
		Elf64_Shdr *ss = &sh[i], *st = &sh[sh[i].sh_link];
		if (ss->sh_size == 0 || st->sh_size == 0 ||
		    ss->sh_size > (64u << 20) || st->sh_size > (64u << 20))
			continue;
		char *strbuf = malloc(st->sh_size);
		char *symbuf = malloc(ss->sh_size);
		if (strbuf && symbuf &&
		    pread_all(fd, strbuf, st->sh_size, (off_t)(elf_off + st->sh_offset)) == 0 &&
		    pread_all(fd, symbuf, ss->sh_size, (off_t)(elf_off + ss->sh_offset)) == 0) {
			size_t cnt = ss->sh_size / ss->sh_entsize;
			for (size_t k = 0; k < cnt; k++) {
				Elf64_Sym es;
				memcpy(&es, symbuf + k * ss->sh_entsize, sizeof(es));
				if (es.st_name == 0 || es.st_name >= st->sh_size)
					continue;
				if (strcmp(strbuf + es.st_name, name) == 0) {
					found = es.st_value;
					break;
				}
			}
		}
		free(strbuf);
		free(symbuf);
	}
	free(sh);
out:
	close(fd);
	return found;
}

static struct art_ctx *art_get(int pid)
{
	for (size_t i = 0; i < g_nart; i++)
		if (g_art[i].pid == pid)
			return &g_art[i];

	struct art_ctx *na = realloc(g_art, (g_nart + 1) * sizeof(*na));
	if (!na)
		return NULL;
	g_art = na;
	struct art_ctx *ac = &g_art[g_nart++];
	memset(ac, 0, sizeof(*ac));
	ac->pid = pid;
	ac->memfd = -1;
	return ac;
}

static void art_reset(struct art_ctx *ac)
{
	if (ac->memfd >= 0) {
		close(ac->memfd);
		ac->memfd = -1;
	}
	ac->located = 0;
	ac->desc_va = 0;
	ac->last_head = 0;
	ac->last_seqlock = 0;
	ac->next_refresh_ms = 0;
	jit_reset(&ac->jit);
}

// Find libart.so in the target's maps and resolve __jit_debug_descriptor to a
// runtime address. located: 0 keep trying (libart not mapped yet), 1 found,
// -1 give up (libart present but no symbol / unsupported).
static void art_locate(struct art_ctx *ac, struct procmaps *pm)
{
	if (ac->located != 0)
		return;
	for (size_t i = 0; i < pm->n; i++) {
		if (strcmp(basename_of(pm->m[i].path), "libart.so") != 0)
			continue;
		uint64_t load_base, elf_off, base_end;
		module_base(pm, &pm->m[i], &load_base, &elf_off, &base_end);
		uint64_t val = elf_dynsym_value(pm->m[i].path, elf_off, ac->pid,
						load_base, base_end, "__jit_debug_descriptor");
		ac->located = val ? 1 : -1;
		ac->desc_va = val ? val + load_base : 0;
		return;
	}
	// libart not mapped yet — leave located at 0; the throttle bounds retries.
}

// Rebuild the JIT interval map from ART's descriptor if it changed. Snapshots
// action_seqlock_ before and after the walk and retries on a concurrent update,
// so a half-modified linked list is never published.
static void art_refresh(struct art_ctx *ac)
{
	if (ac->located != 1 || ac->desc_va == 0)
		return;
	if (ac->memfd < 0) {
		ac->memfd = proc_mem_open(ac->pid);
		if (ac->memfd < 0) { ac->located = -1; return; }
	}

	uint8_t desc[JIT_DESC_BYTES];
	if (proc_mem_read(ac->memfd, ac->desc_va, desc, sizeof(desc)) != sizeof(desc))
		return;
	if (rd_u32(desc + JD_VERSION) != 1) {           // unsupported/unexpected layout
		ac->located = -1;
		return;
	}
	uint32_t seq = rd_u32(desc + JD_SEQLOCK);
	uint64_t head = rd_u64(desc + JD_HEAD);
	if ((seq & 1) == 0 && seq == ac->last_seqlock && head == ac->last_head && ac->jit.n)
		return;                                  // unchanged since last build

	for (int attempt = 0; attempt < 4; attempt++) {
		if (proc_mem_read(ac->memfd, ac->desc_va, desc, sizeof(desc)) != sizeof(desc))
			return;
		uint32_t s1 = rd_u32(desc + JD_SEQLOCK);
		if (s1 & 1)
			continue;                        // writer mid-update; re-snapshot
		head = rd_u64(desc + JD_HEAD);

		jit_reset(&ac->jit);
		uint64_t entry = head;
		size_t guard = 0;
		while (entry && guard++ < JIT_MAX_ENTRIES) {
			uint8_t ce[JCE_BYTES];
			if (proc_mem_read(ac->memfd, entry, ce, sizeof(ce)) != sizeof(ce))
				break;
			uint64_t symaddr = rd_u64(ce + JCE_SYMADDR);
			uint64_t symsize = rd_u64(ce + JCE_SYMSIZE);
			if (symaddr && symsize >= sizeof(Elf64_Ehdr) &&
			    symsize <= JIT_MAX_SYMFILE && jit_scratch_ensure(symsize)) {
				if (proc_mem_read(ac->memfd, symaddr, g_jit_scratch, symsize) >=
				    sizeof(Elf64_Ehdr))
					jit_ingest_elf(&ac->jit, g_jit_scratch, symsize);
			}
			entry = rd_u64(ce + JCE_NEXT);
		}

		uint8_t d2[JIT_DESC_BYTES];
		if (proc_mem_read(ac->memfd, ac->desc_va, d2, sizeof(d2)) != sizeof(d2))
			return;
		if (rd_u32(d2 + JD_SEQLOCK) == s1) {     // consistent snapshot — publish
			if (ac->jit.n)
				qsort(ac->jit.e, ac->jit.n, sizeof(struct jit_entry), jit_cmp);
			ac->last_seqlock = s1;
			ac->last_head = head;
			return;
		}
		// changed under us; discard the partial map and retry
	}
}

// Resolve an anonymous-executable address to a JIT-compiled Java method, if any.
// Locating/refresh is throttled like the procmaps reread, so the common case is
// just a binary search. Returns 1 (and fills out) on a named hit, else 0.
int jit_resolve(int pid, uint64_t addr, char *out, size_t outsz)
{
	struct art_ctx *ac = art_get(pid);
	if (!ac)
		return 0;
	long long t = now_ms();
	if (t >= ac->next_refresh_ms) {
		ac->next_refresh_ms = t + REFRESH_MS;
		if (ac->located != 1) {
			struct procmaps *pm = pm_get(pid);
			if (pm)
				art_locate(ac, pm);
		}
		art_refresh(ac);
	}
	uint64_t delta = 0;
	const char *nm = jit_lookup(&ac->jit, addr, &delta);
	if (!nm)
		return 0;
	if (delta)
		snprintf(out, outsz, "[JIT]!%s+0x%llx", nm, (unsigned long long)delta);
	else
		snprintf(out, outsz, "[JIT]!%s", nm);
	return 1;
}

// Reset the ART/JIT cache for one pid (called on procmaps LRU eviction and on
// sym_flush_pid). Re-locates libart + rebuilds the JIT map on the next resolve.
void jit_reset_pid(int pid)
{
	for (size_t i = 0; i < g_nart; i++)
		if (g_art[i].pid == pid)
			art_reset(&g_art[i]);
}
