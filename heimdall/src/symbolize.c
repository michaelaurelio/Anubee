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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <elf.h>
#include <lzma.h>

#define MAX_PATH_LEN 256
#define REFRESH_MS   250

// ---- /proc/<pid>/maps ----------------------------------------------------

struct mapping {
	uint64_t start, end, off;
	int exec;
	char path[MAX_PATH_LEN];
};

struct procmaps {
	int pid;
	struct mapping *m;
	size_t n, cap;
	long long last_read_ms;
};

static struct procmaps *g_pm;
static size_t g_npm;

static long long now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void read_proc_maps(struct procmaps *pm)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/maps", pm->pid);
	FILE *f = fopen(path, "r");
	pm->n = 0;
	pm->last_read_ms = now_ms();
	if (!f)
		return;

	char line[512];
	while (fgets(line, sizeof(line), f)) {
		uint64_t start, end, off;
		char perms[8], p[MAX_PATH_LEN];
		p[0] = '\0';
		int got = sscanf(line, "%" SCNx64 "-%" SCNx64 " %7s %" SCNx64 " %*s %*s %255[^\n]",
				 &start, &end, perms, &off, p);
		if (got < 4)
			continue;

		if (pm->n == pm->cap) {
			size_t nc = pm->cap ? pm->cap * 2 : 256;
			struct mapping *nm = realloc(pm->m, nc * sizeof(*nm));
			if (!nm)
				break;
			pm->m = nm;
			pm->cap = nc;
		}
		struct mapping *mp = &pm->m[pm->n++];
		mp->start = start;
		mp->end = end;
		mp->off = off;
		mp->exec = (perms[2] == 'x');
		char *q = p;
		while (*q == ' ')
			q++;
		snprintf(mp->path, sizeof(mp->path), "%s", q);
	}
	fclose(f);
}

static struct procmaps *pm_get(int pid)
{
	for (size_t i = 0; i < g_npm; i++)
		if (g_pm[i].pid == pid)
			return &g_pm[i];

	struct procmaps *np = realloc(g_pm, (g_npm + 1) * sizeof(*np));
	if (!np)
		return NULL;
	g_pm = np;
	struct procmaps *pm = &g_pm[g_npm++];
	memset(pm, 0, sizeof(*pm));
	pm->pid = pid;
	read_proc_maps(pm);
	return pm;
}

// /proc/<pid>/maps is address-sorted and non-overlapping, so binary search.
static struct mapping *find_mapping(struct procmaps *pm, uint64_t addr)
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

// Walk back over the contiguous run of same-path mappings to find the ELF base.
// Also returns the base mapping's [start,end), used to reach the file via
// /proc/<pid>/map_files when its path is deleted/anonymous.
static void module_base(struct procmaps *pm, struct mapping *hit,
			uint64_t *load_base, uint64_t *elf_off, uint64_t *base_end)
{
	size_t i = (size_t)(hit - pm->m);
	while (i > 0 &&
	       pm->m[i - 1].end == pm->m[i].start &&
	       !strcmp(pm->m[i - 1].path, pm->m[i].path))
		i--;
	*load_base = pm->m[i].start;
	*elf_off = pm->m[i].off;
	*base_end = pm->m[i].end;
}

// ---- symbols (.dynsym / .symtab / .gnu_debugdata) ------------------------

struct sym {
	uint64_t value, size;
	uint32_t name_off;      // offset into dynsym.str (the name arena)
};

struct dynsym {
	char path[MAX_PATH_LEN];
	uint64_t elf_off;
	char *str;              // name arena (NUL at offset 0; real names >= 1)
	size_t strn;            // bytes used in the arena
	size_t strcap;          // bytes allocated in the arena
	struct sym *s;
	size_t ns;
	int ok;                 // 1 = parsed (maybe empty), 0 = failed/skip
};

static struct dynsym *g_ds;
static size_t g_nds;

static int sym_cmp(const void *a, const void *b)
{
	uint64_t x = ((const struct sym *)a)->value, y = ((const struct sym *)b)->value;
	return (x > y) - (x < y);
}

static int pread_all(int fd, void *buf, size_t n, off_t off)
{
	char *p = buf;
	while (n) {
		ssize_t r = pread(fd, p, n, off);
		if (r <= 0)
			return -1;
		p += r;
		n -= (size_t)r;
		off += r;
	}
	return 0;
}

// Open the backing file. For a normal library this is just the path. For a
// library the target deleted from disk after mapping (a common anti-analysis
// trick — the path shows as ".../lib.so (deleted)"), the on-disk open fails, so
// we reach the still-mapped inode through /proc/<pid>/map_files/<start>-<end>.
static int open_module_file(const char *path, int pid, uint64_t vstart, uint64_t vend)
{
	char real[MAX_PATH_LEN];
	snprintf(real, sizeof(real), "%s", path);
	char *del = strstr(real, " (deleted)");
	if (del)
		*del = '\0';

	int fd = open(real, O_RDONLY | O_CLOEXEC);
	if (fd >= 0)
		return fd;

	if (pid > 0) {
		char mf[96];
		snprintf(mf, sizeof(mf), "/proc/%d/map_files/%llx-%llx",
			 pid, (unsigned long long)vstart, (unsigned long long)vend);
		fd = open(mf, O_RDONLY | O_CLOEXEC);
	}
	return fd;
}

// Copy a symbol name into the per-module arena, returning its offset. The arena
// starts with a NUL byte so a real name is always at offset >= 1, letting 0
// double as "allocation failed" without colliding with a valid name.
static uint32_t arena_add(struct dynsym *ds, const char *name)
{
	if (!ds->str) {
		ds->strcap = 4096;
		ds->str = malloc(ds->strcap);
		if (!ds->str) { ds->strcap = 0; return 0; }
		ds->str[0] = '\0';
		ds->strn = 1;
	}
	size_t len = strlen(name) + 1;
	if (ds->strn + len > ds->strcap) {
		size_t nc = ds->strcap * 2;
		while (nc < ds->strn + len)
			nc *= 2;
		char *ns = realloc(ds->str, nc);
		if (!ns)
			return 0;
		ds->str = ns;
		ds->strcap = nc;
	}
	uint32_t off = (uint32_t)ds->strn;
	memcpy(ds->str + ds->strn, name, len);
	ds->strn += len;
	return off;
}

// Append every named, valued function/code symbol from one in-memory symbol
// table (Elf64_Sym entries + its string table) to the module's sorted set.
// Used for .dynsym, .symtab and the .gnu_debugdata-embedded .symtab alike.
static void add_symbols(struct dynsym *ds, const void *symbuf, size_t symbytes,
			size_t entsize, const char *str, size_t strn)
{
	if (entsize == 0)
		entsize = sizeof(Elf64_Sym);
	size_t count = symbytes / entsize;
	if (count == 0)
		return;

	struct sym *ns = realloc(ds->s, (ds->ns + count) * sizeof(struct sym));
	if (!ns)
		return;
	ds->s = ns;

	for (size_t i = 0; i < count; i++) {
		Elf64_Sym es;
		memcpy(&es, (const char *)symbuf + i * entsize, sizeof(es));
		if (es.st_value == 0 || es.st_shndx == SHN_UNDEF || es.st_name == 0)
			continue;                // imported/anonymous
		unsigned t = ELF64_ST_TYPE(es.st_info);
		if (t == STT_OBJECT || t == STT_SECTION || t == STT_FILE || t == STT_TLS)
			continue;                // data/metadata, not code we'd land in
		if (es.st_name >= strn)
			continue;
		uint32_t off = arena_add(ds, str + es.st_name);
		if (!off)
			continue;
		ds->s[ds->ns].value = es.st_value;
		ds->s[ds->ns].size = es.st_size;
		ds->s[ds->ns].name_off = off;
		ds->ns++;
	}
}

// Read a symtab section + its linked strtab from the on-disk ELF (at elf_off)
// and fold them into the symbol set.
static void ingest_fd_section(struct dynsym *ds, int fd, uint64_t elf_off,
			      const Elf64_Shdr *symsec, const Elf64_Shdr *strsec)
{
	if (!symsec || !strsec || symsec->sh_size == 0)
		return;
	char *strbuf = malloc(strsec->sh_size ? strsec->sh_size : 1);
	char *symbuf = malloc(symsec->sh_size);
	if (!strbuf || !symbuf)
		goto out;
	if (pread_all(fd, strbuf, strsec->sh_size, (off_t)(elf_off + strsec->sh_offset)) != 0 ||
	    pread_all(fd, symbuf, symsec->sh_size, (off_t)(elf_off + symsec->sh_offset)) != 0)
		goto out;
	add_symbols(ds, symbuf, symsec->sh_size, symsec->sh_entsize, strbuf, strsec->sh_size);
out:
	free(strbuf);
	free(symbuf);
}

// One-shot XZ/LZMA decode of .gnu_debugdata into a heap buffer; grows the output
// on LZMA_BUF_ERROR. mini-debug-info is small (typically a few hundred KB).
static int decompress_xz(const uint8_t *in, size_t inlen, uint8_t **out, size_t *outlen)
{
	size_t cap = inlen * 5 + 4096;
	for (int tries = 0; tries < 8; tries++) {
		uint8_t *buf = malloc(cap);
		if (!buf)
			return -1;
		uint64_t memlimit = UINT64_MAX;
		size_t in_pos = 0, out_pos = 0;
		lzma_ret r = lzma_stream_buffer_decode(&memlimit, 0, NULL,
						       in, &in_pos, inlen,
						       buf, &out_pos, cap);
		if (r == LZMA_OK) {
			*out = buf;
			*outlen = out_pos;
			return 0;
		}
		free(buf);
		if (r == LZMA_BUF_ERROR) {
			cap *= 2;
			continue;
		}
		return -1;
	}
	return -1;
}

// Parse the .symtab/.strtab out of the decompressed mini-debug-info ELF (held
// fully in `buf`) and fold its symbols in. The embedded symbols' st_value are
// link-time addresses of the outer module, so they resolve through the same
// (addr - load_base) lookup. The buffer is from the target's own files — treat
// every offset as untrusted and bounds-check it.
static void ingest_embedded(struct dynsym *ds, const uint8_t *buf, size_t len)
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
		if (sec.sh_type != SHT_SYMTAB || sec.sh_link >= eh.e_shnum)
			continue;
		Elf64_Shdr str;
		memcpy(&str, buf + eh.e_shoff + (size_t)sec.sh_link * eh.e_shentsize, sizeof(str));
		if (sec.sh_offset + sec.sh_size > len || str.sh_offset + str.sh_size > len)
			continue;
		add_symbols(ds, buf + sec.sh_offset, sec.sh_size, sec.sh_entsize,
			    (const char *)buf + str.sh_offset, str.sh_size);
	}
}

// Build the module's symbol set from every source the ELF at `elf_off` offers:
// .dynsym, .symtab, and the .gnu_debugdata mini-debug-info. All feed one sorted,
// value-deduped array used by sym_lookup.
static void parse_symbols(struct dynsym *ds, int pid, uint64_t vstart, uint64_t vend)
{
	ds->ok = 0;
	if (ds->path[0] == '\0' || ds->path[0] == '[')
		return;

	int fd = open_module_file(ds->path, pid, vstart, vend);
	if (fd < 0)
		return;

	Elf64_Ehdr eh;
	if (pread_all(fd, &eh, sizeof(eh), (off_t)ds->elf_off) != 0)
		goto done;
	if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64)
		goto done;
	if (eh.e_shoff == 0 || eh.e_shnum == 0 || eh.e_shentsize != sizeof(Elf64_Shdr))
		goto done;                       // no/odd section headers

	size_t shsz = (size_t)eh.e_shnum * eh.e_shentsize;
	Elf64_Shdr *sh = malloc(shsz);
	if (!sh)
		goto done;
	if (pread_all(fd, sh, shsz, (off_t)(ds->elf_off + eh.e_shoff)) != 0) {
		free(sh);
		goto done;
	}

	// Section-name string table, needed to find .gnu_debugdata by name.
	char *shstr = NULL;
	size_t shstrn = 0;
	if (eh.e_shstrndx < eh.e_shnum) {
		Elf64_Shdr *s = &sh[eh.e_shstrndx];
		if (s->sh_size && s->sh_size < (64u << 20)) {
			shstr = malloc(s->sh_size);
			if (shstr && pread_all(fd, shstr, s->sh_size,
					       (off_t)(ds->elf_off + s->sh_offset)) == 0)
				shstrn = s->sh_size;
			else { free(shstr); shstr = NULL; }
		}
	}

	for (int i = 0; i < eh.e_shnum; i++) {
		if (sh[i].sh_type == SHT_DYNSYM || sh[i].sh_type == SHT_SYMTAB) {
			if (sh[i].sh_link < eh.e_shnum)
				ingest_fd_section(ds, fd, ds->elf_off, &sh[i], &sh[sh[i].sh_link]);
		} else if (shstr && sh[i].sh_name < shstrn &&
			   strcmp(shstr + sh[i].sh_name, ".gnu_debugdata") == 0 &&
			   sh[i].sh_size && sh[i].sh_size < (64u << 20)) {
			uint8_t *cz = malloc(sh[i].sh_size);
			if (cz && pread_all(fd, cz, sh[i].sh_size,
					    (off_t)(ds->elf_off + sh[i].sh_offset)) == 0) {
				uint8_t *raw = NULL;
				size_t rawn = 0;
				if (decompress_xz(cz, sh[i].sh_size, &raw, &rawn) == 0) {
					ingest_embedded(ds, raw, rawn);
					free(raw);
				}
			}
			free(cz);
		}
	}
	free(shstr);
	free(sh);

	if (ds->ns) {
		qsort(ds->s, ds->ns, sizeof(struct sym), sym_cmp);
		// The same address can appear in several sources; keep one per value
		// (the first after the stable sort, i.e. typically the .dynsym name).
		size_t w = 0;
		for (size_t r = 0; r < ds->ns; r++) {
			if (w > 0 && ds->s[w - 1].value == ds->s[r].value)
				continue;
			ds->s[w++] = ds->s[r];
		}
		ds->ns = w;
	}
	ds->ok = 1;

done:
	close(fd);
}

static struct dynsym *dynsym_get(const char *path, uint64_t elf_off,
				 int pid, uint64_t vstart, uint64_t vend)
{
	for (size_t i = 0; i < g_nds; i++)
		if (g_ds[i].elf_off == elf_off && !strcmp(g_ds[i].path, path))
			return &g_ds[i];

	struct dynsym *nd = realloc(g_ds, (g_nds + 1) * sizeof(*nd));
	if (!nd)
		return NULL;
	g_ds = nd;
	struct dynsym *ds = &g_ds[g_nds++];
	memset(ds, 0, sizeof(*ds));
	snprintf(ds->path, sizeof(ds->path), "%s", path);
	ds->elf_off = elf_off;
	parse_symbols(ds, pid, vstart, vend);
	return ds;
}

// Nearest symbol whose value <= vaddr. Returns name + delta, or NULL when the
// address falls outside any symbol (so we show a bare offset instead of
// mislabelling it with the previous exported symbol).
static const char *sym_lookup(struct dynsym *ds, uint64_t vaddr, uint64_t *delta)
{
	if (!ds || !ds->ok || ds->ns == 0)
		return NULL;

	size_t lo = 0, hi = ds->ns;
	while (lo < hi) {
		size_t mid = (lo + hi) / 2;
		if (ds->s[mid].value <= vaddr)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo == 0)
		return NULL;
	struct sym *s = &ds->s[lo - 1];
	uint64_t d = vaddr - s->value;
	if (s->size) {
		if (d >= s->size)
			return NULL;             // past the function => unexported code
	} else if (d > 0x1000) {
		return NULL;                     // size-less label: only a small slack
	}
	*delta = d;
	return ds->str + s->name_off;
}

// ---- public --------------------------------------------------------------

static const char *basename_of(const char *p)
{
	const char *b = strrchr(p, '/');
	return b ? b + 1 : p;
}

// Display name: basename with a trailing " (deleted)" stripped.
static void display_name(const char *path, char *buf, size_t n)
{
	snprintf(buf, n, "%s", basename_of(path));
	char *del = strstr(buf, " (deleted)");
	if (del)
		*del = '\0';
}

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
	if ((g_sc_used + 1) * 4 >= g_sc_cap * 3) {          // grow at 75% load
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

// Returns 1 if the result is stable enough to cache (a real mapping), 0 for an
// unmapped/transient address (which a later mmap could turn into a real symbol).
static int sym_resolve_uncached(int pid, unsigned long long addr, char *out, size_t outsz);

void sym_resolve(int pid, unsigned long long addr, char *out, size_t outsz)
{
	if (sc_get(pid, (uint64_t)addr, out, outsz))
		return;
	if (sym_resolve_uncached(pid, addr, out, outsz))
		sc_put(pid, (uint64_t)addr, out);
}

static int sym_resolve_uncached(int pid, unsigned long long addr, char *out, size_t outsz)
{
	struct procmaps *pm = pm_get(pid);
	if (!pm) {
		snprintf(out, outsz, "0x%llx", addr);
		return 0;
	}

	struct mapping *hit = find_mapping(pm, (uint64_t)addr);
	if (!hit && now_ms() - pm->last_read_ms > REFRESH_MS) {
		read_proc_maps(pm);             // a library may have loaded since
		hit = find_mapping(pm, (uint64_t)addr);
	}
	if (!hit) {
		// Not in any mapping: stale frame, or a bad frame-pointer unwind.
		snprintf(out, outsz, "0x%llx [unmapped]", addr);
		return 0;
	}

	uint64_t load_base, elf_off, base_end;
	module_base(pm, hit, &load_base, &elf_off, &base_end);

	// Anonymous executable memory with no name: JIT cache, a packer/obfuscator
	// or RASP-allocated code region, a thread stack, etc. Not ELF-backed, so no
	// symbol — but say so explicitly rather than printing a bare address.
	if (hit->path[0] == '\0') {
		snprintf(out, outsz, "[anon]+0x%llx",
			 (unsigned long long)((uint64_t)addr - hit->start));
		return 1;
	}

	char base[MAX_PATH_LEN];
	display_name(hit->path, base, sizeof(base));
	uint64_t vaddr = (uint64_t)addr - load_base;

	// Kernel-named anonymous regions ("[anon:scudo:primary]", "[stack]", ...)
	// aren't openable as ELF — show the region name + offset so its nature is
	// visible. (A deleted/renamed real library still has '/' first and is
	// recovered below via /proc/<pid>/map_files.)
	if (hit->path[0] == '[') {
		snprintf(out, outsz, "%s+0x%llx", base, (unsigned long long)vaddr);
		return 1;
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

void sym_flush_pid(int pid)
{
	for (size_t i = 0; i < g_npm; i++)
		if (g_pm[i].pid == pid)
			g_pm[i].n = 0;          // force reread on next resolve
	sc_clear();                             // addresses may have moved
}
