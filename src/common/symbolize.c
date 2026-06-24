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
#include "common/proc_mem.h"  // proc_mem_open / proc_mem_read (live target memory)

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

// Sort the symbol set by value and keep one entry per address: several sources
// (.dynsym, .symtab, .gnu_debugdata) can name the same address; the first after
// the sort wins (typically the .dynsym name). Shared by parse_symbols (disk
// modules) and vdso_build (the in-memory vDSO).
static void dynsym_finalize(struct dynsym *ds)
{
	if (!ds->ns)
		return;
	qsort(ds->s, ds->ns, sizeof(struct sym), sym_cmp);
	size_t w = 0;
	for (size_t r = 0; r < ds->ns; r++) {
		if (w > 0 && ds->s[w - 1].value == ds->s[r].value)
			continue;
		ds->s[w++] = ds->s[r];
	}
	ds->ns = w;
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

	dynsym_finalize(ds);
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
static int jit_resolve(int pid, uint64_t addr, char *out, size_t outsz)
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

// ---- vDSO symbols (in-memory ELF, read from live memory) -----------------
//
// The kernel maps the vDSO as "[vdso]": a complete, small, immutable ELF with no
// backing file. Its .dynsym names __kernel_rt_sigreturn / __kernel_clock_gettime
// / __kernel_gettimeofday / __kernel_clock_getres. /proc/<pid>/mem is preadable
// (it is indexed by virtual address) and the whole vDSO image — including its
// section headers — is mapped contiguously in [base,end), so we pread the image
// straight off the mem fd and feed .dynsym/.symtab through the same
// ingest_fd_section / add_symbols / sym_lookup used for on-disk modules. Symbol
// st_value are offsets from the vDSO base (load bias = base), so a lookup uses
// (addr - base), exactly the runtime = st_value + load_base relation a regular
// module uses. Built once per pid; the vDSO never changes after exec, so unlike
// the JIT cache both a hit and a miss are final and cacheable.

struct vdso_ctx {
	int pid;
	uint64_t base;          // [vdso] start the ds was built for (0 = not built)
	struct dynsym ds;       // ds.ok gates lookups; path/elf_off unused here
};

static struct vdso_ctx *g_vdso;
static size_t g_nvdso;

static struct vdso_ctx *vdso_get(int pid)
{
	for (size_t i = 0; i < g_nvdso; i++)
		if (g_vdso[i].pid == pid)
			return &g_vdso[i];

	struct vdso_ctx *nv = realloc(g_vdso, (g_nvdso + 1) * sizeof(*nv));
	if (!nv)
		return NULL;
	g_vdso = nv;
	struct vdso_ctx *vc = &g_vdso[g_nvdso++];
	memset(vc, 0, sizeof(*vc));
	vc->pid = pid;
	return vc;
}

static void vdso_free(struct vdso_ctx *vc)
{
	free(vc->ds.s);
	free(vc->ds.str);
	memset(&vc->ds, 0, sizeof(vc->ds));
	vc->base = 0;
}

// Read the vDSO image at [base,end) off the target's mem fd and ingest its
// dynamic/static symbol tables. Every offset is target-controlled — bound it
// against the mapping span before trusting it.
static void vdso_build(struct vdso_ctx *vc, uint64_t base, uint64_t end)
{
	int fd = proc_mem_open(vc->pid);
	if (fd < 0)
		return;
	uint64_t span = end > base ? end - base : 0;

	Elf64_Ehdr eh;
	if (pread_all(fd, &eh, sizeof(eh), (off_t)base) != 0)
		goto out;
	if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64)
		goto out;
	if (eh.e_shoff == 0 || eh.e_shnum == 0 || eh.e_shentsize != sizeof(Elf64_Shdr))
		goto out;
	uint64_t shsz = (uint64_t)eh.e_shnum * eh.e_shentsize;
	if (eh.e_shoff + shsz > span)            // section headers must be mapped
		goto out;

	Elf64_Shdr *sh = malloc(shsz);
	if (!sh)
		goto out;
	if (pread_all(fd, sh, shsz, (off_t)(base + eh.e_shoff)) != 0) {
		free(sh);
		goto out;
	}

	for (int i = 0; i < eh.e_shnum; i++) {
		if ((sh[i].sh_type != SHT_DYNSYM && sh[i].sh_type != SHT_SYMTAB) ||
		    sh[i].sh_link >= eh.e_shnum)
			continue;
		Elf64_Shdr *link = &sh[sh[i].sh_link];
		// Bound both sections fully within the mapped image. Size first so the
		// (span - size) subtractions below cannot underflow; then the offset.
		if (sh[i].sh_size > span || link->sh_size > span ||
		    sh[i].sh_offset > span - sh[i].sh_size ||
		    link->sh_offset > span - link->sh_size)
			continue;
		ingest_fd_section(&vc->ds, fd, base, &sh[i], link);
	}
	free(sh);

	dynsym_finalize(&vc->ds);
	vc->ds.ok = 1;
out:
	close(fd);
}

// Resolve an address inside the [vdso] mapping to a kernel symbol. Builds the
// per-pid symbol set on first sight (or rebuilds if the base moved, e.g. re-exec).
// Returns 1 (and fills out) on a named hit, else 0.
static int vdso_resolve(int pid, uint64_t addr, uint64_t base, uint64_t end,
			char *out, size_t outsz)
{
	struct vdso_ctx *vc = vdso_get(pid);
	if (!vc)
		return 0;
	if (vc->base != base) {                 // first sight or vDSO relocated
		vdso_free(vc);
		vc->base = base;
		vdso_build(vc, base, end);
	}
	uint64_t delta = 0;
	const char *nm = sym_lookup(&vc->ds, addr - base, &delta);
	if (!nm)
		return 0;
	if (delta)
		snprintf(out, outsz, "[vdso]!%s+0x%llx", nm, (unsigned long long)delta);
	else
		snprintf(out, outsz, "[vdso]!%s", nm);
	return 1;
}

// ---- APK-embedded .so name resolution ------------------------------------
//
// Android 6+ allows direct mmap of page-aligned stored (uncompressed) .so files
// from inside APKs. When /proc/<pid>/maps shows a mapping backed by a .apk file,
// elf_off (from module_base) is the ELF start inside the APK, matching the
// stored .so's data_start in the ZIP central directory. The symbol resolution via
// dynsym_get(path, elf_off, ...) already works correctly because the APK is
// opened at elf_off to read the ELF. This code only adds the display-name
// refinement: "base.apk -> libfoo.so!func+0x..." instead of "base.apk!...".
//
// The ZIP central directory is parsed once per APK path and cached in a small
// fixed array (APKs typically contain a handful of .so files under lib/).

#define APK_SO_MAX    32
#define APK_CACHE_MAX  8

struct apk_so_entry {
	char     name[128];    // inner .so basename, e.g. "libnative.so"
	uint64_t data_start;   // ELF start byte offset within the APK
	uint64_t size;
};

struct apk_cache {
	char path[MAX_PATH_LEN];
	struct apk_so_entry entries[APK_SO_MAX];
	int count;
};

static struct apk_cache g_apk[APK_CACHE_MAX];
static int g_napk;

static struct apk_cache *apk_parse(const char *path)
{
	if (g_napk >= APK_CACHE_MAX)
		return NULL;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	// Locate EOCD record (signature 50 4b 05 06) by scanning backward.
	off_t fsize = lseek(fd, 0, SEEK_END);
	if (fsize < 22) { close(fd); return NULL; }

	off_t eocd_off = -1;
	uint8_t buf[22];
	off_t limit = fsize - 22 - 65535;
	if (limit < 0) limit = 0;
	for (off_t p = fsize - 22; p >= limit; p--) {
		if (pread_all(fd, buf, 4, p) != 0) break;
		if (buf[0]==0x50 && buf[1]==0x4b && buf[2]==0x05 && buf[3]==0x06) {
			if (pread_all(fd, buf, 22, p) == 0) { eocd_off = p; break; }
		}
	}
	if (eocd_off < 0) { close(fd); return NULL; }

#define APK_LE16(b,o) ((uint16_t)((b)[(o)] | ((unsigned)(b)[(o)+1]<<8)))
#define APK_LE32(b,o) ((uint32_t)((b)[(o)] | ((unsigned)(b)[(o)+1]<<8) | \
                                  ((unsigned)(b)[(o)+2]<<16) | ((unsigned)(b)[(o)+3]<<24)))

	off_t    cd_off      = (off_t)APK_LE32(buf, 16);
	uint16_t num_entries = APK_LE16(buf, 10);

	struct apk_cache *c = &g_apk[g_napk];
	snprintf(c->path, sizeof(c->path), "%s", path);
	c->count = 0;

	off_t cpos = cd_off;
	uint8_t cde[46];
	char fname[256];
	for (int i = 0; i < num_entries && c->count < APK_SO_MAX; i++) {
		if (pread_all(fd, cde, 46, cpos) != 0) break;
		if (cde[0]!=0x50 || cde[1]!=0x4b || cde[2]!=0x01 || cde[3]!=0x02) break;
		cpos += 46;

		uint16_t method    = APK_LE16(cde, 10);
		uint32_t comp_size = APK_LE32(cde, 20);
		uint16_t fname_len = APK_LE16(cde, 28);
		uint16_t extra_len = APK_LE16(cde, 30);
		uint16_t cmt_len   = APK_LE16(cde, 32);
		uint32_t lhdr_off  = APK_LE32(cde, 42);

		uint16_t rlen = fname_len < 255 ? fname_len : 255;
		ssize_t  n    = pread(fd, fname, rlen, cpos);
		if (n < 0) break;
		fname[n] = '\0';
		cpos += (off_t)fname_len + extra_len + cmt_len;

		// Only stored (uncompressed) .so files under lib/
		if (method != 0) continue;
		if (strncmp(fname, "lib/", 4) != 0) continue;
		const char *base = strrchr(fname, '/');
		base = base ? base + 1 : fname;
		size_t blen = strlen(base);
		if (blen < 4 || strcmp(base + blen - 3, ".so") != 0) continue;

		// Local file header gives the actual extra field length (may differ from CD).
		uint8_t lfh[30];
		if (pread_all(fd, lfh, 30, (off_t)lhdr_off) != 0) continue;
		if (lfh[0]!=0x50 || lfh[1]!=0x4b || lfh[2]!=0x03 || lfh[3]!=0x04) continue;
		uint64_t data_start = (uint64_t)lhdr_off + 30 + APK_LE16(lfh, 26) + APK_LE16(lfh, 28);

		struct apk_so_entry *e = &c->entries[c->count++];
		snprintf(e->name, sizeof(e->name), "%s", base);
		e->data_start = data_start;
		e->size       = (uint64_t)comp_size;
	}

#undef APK_LE16
#undef APK_LE32

	close(fd);
	g_napk++;
	return c;
}

static struct apk_cache *apk_get(const char *path)
{
	for (int i = 0; i < g_napk; i++)
		if (strcmp(g_apk[i].path, path) == 0)
			return &g_apk[i];
	return apk_parse(path);
}

// Return the inner .so basename for a stored .so mapped from an APK at elf_off,
// or NULL if the path is not an APK or the offset doesn't match any entry.
static const char *apk_so_name(const char *path, uint64_t elf_off)
{
	size_t plen = strlen(path);
	if (plen < 4 || strcmp(path + plen - 4, ".apk") != 0)
		return NULL;
	struct apk_cache *c = apk_get(path);
	if (!c)
		return NULL;
	for (int i = 0; i < c->count; i++)
		if (c->entries[i].data_start == elf_off)
			return c->entries[i].name;
	return NULL;
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
		char tmp[MAX_PATH_LEN];
		snprintf(tmp, sizeof(tmp), "%s -> %s", base, inner_so);
		snprintf(base, sizeof(base), "%s", tmp);
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
	for (size_t i = 0; i < g_nart; i++)
		if (g_art[i].pid == pid)
			art_reset(&g_art[i]);   // re-locate libart + rebuild JIT map
	for (size_t i = 0; i < g_nvdso; i++)
		if (g_vdso[i].pid == pid)
			vdso_free(&g_vdso[i]);     // force rebuild on next resolve
	sc_clear();                             // addresses may have moved
}
