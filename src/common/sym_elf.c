// SPDX-License-Identifier: GPL-2.0
// ELF symbol tables (.dynsym/.symtab/.gnu_debugdata) + per-module CFI cache +
// module file I/O helpers. Feeds both on-disk modules and the in-memory vDSO.
// See symbolize_internal.h.
#include <sys/types.h>
#include "symbolize_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <lzma.h>
#include <elf.h>
#include <sys/stat.h>

// ---- symbols (.dynsym / .symtab / .gnu_debugdata) ------------------------

static struct dynsym *g_ds;
static size_t g_nds;

// ---- per-module CFI cache (mirrors dynsym cache) -------------------------

struct cfimod {
	char     path[MAX_PATH_LEN];
	uint64_t elf_off;
	uint64_t load_base;        /* runtime base; module_vaddr = runtime_pc - load_base */
	struct cfi_section sec;    /* owns its CFI bytes (sec.owned) */
	int      ok;               /* 1 = loaded (sec valid, maybe 0 FDEs), 0 = failed/skip */
};

static struct cfimod *g_cfi;
static size_t g_ncfi;

static int sym_cmp(const void *a, const void *b)
{
	uint64_t x = ((const struct sym *)a)->value, y = ((const struct sym *)b)->value;
	return (x > y) - (x < y);
}

int pread_all(int fd, void *buf, size_t n, off_t off)
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
int open_module_file(const char *path, int pid, uint64_t vstart, uint64_t vend)
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
		ares_map_files_path(mf, sizeof(mf), pid, vstart, vend);
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
void add_symbols(struct dynsym *ds, const void *symbuf, size_t symbytes,
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
void ingest_fd_section(struct dynsym *ds, int fd, uint64_t elf_off,
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
void dynsym_finalize(struct dynsym *ds)
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

// (path,elf_off) -> index into g_ds[]/g_cfi[] (AA5). Replaces the linear
// scan+strcmp dynsym_get/cfi_get used to do per lookup with an O(1)-amortized
// hash probe; the strcmp only runs once, to confirm a hash hit, not per candidate.
// Grows like symbolize.c's sc_ent but with no eviction ceiling — an ELF/CFI cache
// entry is expensive to reparse, and the realistic module count per trace is small.
struct elfidx_ent { uint64_t elf_off; uint32_t path_hash; size_t idx; int used; };

static uint32_t elf_path_hash(const char *path, uint64_t elf_off)
{
	uint32_t h = 2166136261u;                 // FNV-1a
	for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
		h ^= *p;
		h *= 16777619u;
	}
	h ^= (uint32_t)(elf_off ^ (elf_off >> 32));
	return h;
}

static struct elfidx_ent *g_ds_idx;  static size_t g_ds_idx_cap, g_ds_idx_used;
static struct elfidx_ent *g_cfi_idx; static size_t g_cfi_idx_cap, g_cfi_idx_used;

static ssize_t elfidx_get(struct elfidx_ent *tab, size_t cap, const char *path,
			  uint64_t elf_off)
{
	if (!cap) return -1;
	uint32_t ph = elf_path_hash(path, elf_off);
	size_t mask = cap - 1, i = ph & mask;
	for (size_t probe = 0; probe < cap; probe++) {
		struct elfidx_ent *e = &tab[i];
		if (!e->used) return -1;
		if (e->elf_off == elf_off && e->path_hash == ph)
			return (ssize_t)e->idx;   // caller re-verifies path via the real array
		i = (i + 1) & mask;
	}
	return -1;
}

static void elfidx_put(struct elfidx_ent **tab, size_t *cap, size_t *used,
			const char *path, uint64_t elf_off, size_t idx)
{
	if (!*cap) {
		*cap = 256;
		*tab = calloc(*cap, sizeof(**tab));
		if (!*tab) { *cap = 0; return; }
	}
	if ((*used + 1) * 4 >= *cap * 3) {          // grow at 75% load, no ceiling
		size_t ncap = *cap * 2, nmask = ncap - 1;
		struct elfidx_ent *ng = calloc(ncap, sizeof(*ng));
		if (ng) {
			for (size_t k = 0; k < *cap; k++) {
				if (!(*tab)[k].used) continue;
				size_t j = (*tab)[k].path_hash & nmask;
				while (ng[j].used) j = (j + 1) & nmask;
				ng[j] = (*tab)[k];
			}
			free(*tab);
			*tab = ng;
			*cap = ncap;
		}
	}
	uint32_t ph = elf_path_hash(path, elf_off);
	size_t mask = *cap - 1, i = ph & mask;
	while ((*tab)[i].used) i = (i + 1) & mask;  // idx is always new (never overwrites)
	(*tab)[i].used = 1;
	(*tab)[i].elf_off = elf_off;
	(*tab)[i].path_hash = ph;
	(*tab)[i].idx = idx;
	(*used)++;
}

struct dynsym *dynsym_get(const char *path, uint64_t elf_off,
				 int pid, uint64_t vstart, uint64_t vend)
{
	ssize_t hit = elfidx_get(g_ds_idx, g_ds_idx_cap, path, elf_off);
	if (hit >= 0 && !strcmp(g_ds[hit].path, path))
		return &g_ds[hit];

	struct dynsym *nd = realloc(g_ds, (g_nds + 1) * sizeof(*nd));
	if (!nd)
		return NULL;
	g_ds = nd;
	size_t idx = g_nds;
	struct dynsym *ds = &g_ds[idx];
	memset(ds, 0, sizeof(*ds));
	snprintf(ds->path, sizeof(ds->path), "%s", path);
	ds->elf_off = elf_off;
	parse_symbols(ds, pid, vstart, vend);
	g_nds++;
	elfidx_put(&g_ds_idx, &g_ds_idx_cap, &g_ds_idx_used, path, elf_off, idx);
	return ds;
}

// Nearest symbol whose value <= vaddr. Returns name + delta, or NULL when the
// address falls outside any symbol (so we show a bare offset instead of
// mislabelling it with the previous exported symbol).
const char *sym_lookup(struct dynsym *ds, uint64_t vaddr, uint64_t *delta)
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

// ---- CFI loader + cache --------------------------------------------------
//
// find_gnu_debugdata: locate the .gnu_debugdata section (xz-compressed mini-ELF
// carrying .debug_frame for OAT/odex files) in an in-memory ELF64 image.
// Every offset is untrusted (on-device file); bounds-check all accesses.
//
// cfi_get: cache-on-(elf_off,path); tries native .eh_frame/.debug_frame first,
// then falls back to .debug_frame inside the xz-compressed .gnu_debugdata.
// Mirrors dynsym_get's grow/append pattern exactly.

/* Locate the .gnu_debugdata section in an in-memory ELF64 image.
 * Returns 0 and fills *off and *size (byte offsets into buf) on success,
 * -1 if absent or malformed. Every offset is bounds-checked against len. */
static int __attribute__((unused))
find_gnu_debugdata(const uint8_t *buf, size_t len, size_t *off, size_t *size)
{
	if (len < sizeof(Elf64_Ehdr))
		return -1;

	Elf64_Ehdr eh;
	memcpy(&eh, buf, sizeof(eh));

	if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64)
		return -1;
	if (eh.e_shoff == 0 || eh.e_shnum == 0 || eh.e_shentsize < sizeof(Elf64_Shdr))
		return -1;
	if (eh.e_shoff > len)            /* else (len - e_shoff) underflows below */
		return -1;

	/* Overflow-safe: (e_shnum * e_shentsize) must not exceed (len - e_shoff). */
	if (eh.e_shnum > (len - eh.e_shoff) / eh.e_shentsize)
		return -1;

	/* Validate shstrndx before use. */
	if (eh.e_shstrndx == SHN_UNDEF || eh.e_shstrndx >= eh.e_shnum)
		return -1;

	/* Read the shstrtab section header. */
	Elf64_Shdr shstr_hdr;
	memcpy(&shstr_hdr, buf + eh.e_shoff + (size_t)eh.e_shstrndx * eh.e_shentsize,
	       sizeof(shstr_hdr));

	/* Bounds-check the shstrtab content. */
	if (shstr_hdr.sh_size == 0 || shstr_hdr.sh_offset > len ||
	    shstr_hdr.sh_size > len - shstr_hdr.sh_offset)
		return -1;

	const char *shstrtab = (const char *)buf + shstr_hdr.sh_offset;
	size_t shstrn = (size_t)shstr_hdr.sh_size;

	/* Walk section headers looking for ".gnu_debugdata". */
	for (uint16_t i = 0; i < eh.e_shnum; i++) {
		Elf64_Shdr sh;
		memcpy(&sh, buf + eh.e_shoff + (size_t)i * eh.e_shentsize, sizeof(sh));

		if (sh.sh_name == 0 || sh.sh_name >= shstrn)
			continue;
		if (strcmp(shstrtab + sh.sh_name, ".gnu_debugdata") != 0)
			continue;
		if (sh.sh_size == 0)
			return -1;

		/* Bounds-check the section content. */
		if (sh.sh_offset > len || sh.sh_size > len - sh.sh_offset)
			return -1;

		*off  = (size_t)sh.sh_offset;
		*size = (size_t)sh.sh_size;
		return 0;
	}
	return -1;
}

#define CFI_MAX_MODULE_BYTES (256u << 20)  /* 256 MB sanity cap */

/* Return the cached cfi_section for (path, elf_off), loading it on first sight.
 * Returns NULL if the module has no usable CFI or could not be read.
 * Mirrors dynsym_get: grow/append, ok=0 on failure so future calls short-circuit. */
struct cfi_section *
cfi_get(const char *path, uint64_t elf_off, uint64_t load_base,
	int pid, uint64_t vstart, uint64_t vend)
{
	/* 1. Cache hit by (elf_off, path) — O(1)-amortized via the index hash. */
	ssize_t hit = elfidx_get(g_cfi_idx, g_cfi_idx_cap, path, elf_off);
	if (hit >= 0 && !strcmp(g_cfi[hit].path, path))
		return g_cfi[hit].ok ? &g_cfi[hit].sec : NULL;

	/* 2. Append a new entry (failed-by-default); index it immediately so every
	 * return path below (success or failure) short-circuits next time. */
	struct cfimod *nc = realloc(g_cfi, (g_ncfi + 1) * sizeof(*nc));
	if (!nc)
		return NULL;
	g_cfi = nc;
	size_t idx = g_ncfi++;
	struct cfimod *m = &g_cfi[idx];
	memset(m, 0, sizeof(*m));
	snprintf(m->path, sizeof(m->path), "%s", path);
	m->elf_off   = elf_off;
	elfidx_put(&g_cfi_idx, &g_cfi_idx_cap, &g_cfi_idx_used, path, elf_off, idx);
	m->load_base = load_base;
	m->ok        = 0;

	/* Skip pseudo/anonymous paths (same guard as parse_symbols / dynsym_get). */
	if (path[0] == '\0' || path[0] == '[')
		return NULL;

	int fd = open_module_file(path, pid, vstart, vend);
	if (fd < 0)
		return NULL;

	/* 3. Read the module image from elf_off to EOF. */
	struct stat stbuf;
	if (fstat(fd, &stbuf) != 0 || (uint64_t)stbuf.st_size <= elf_off) {
		close(fd);
		return NULL;
	}
	size_t len = (size_t)((uint64_t)stbuf.st_size - elf_off);
	if (len > CFI_MAX_MODULE_BYTES) {
		close(fd);
		return NULL;
	}
	uint8_t *buf = malloc(len);
	if (!buf || pread_all(fd, buf, len, (off_t)elf_off) != 0) {
		free(buf);
		close(fd);
		return NULL;
	}
	close(fd);

	/* 4. Native path: .eh_frame (or .debug_frame) in the top-level ELF. */
	if (cfi_load_elf(buf, len, &m->sec) == 0) {
		free(buf);
		m->ok = 1;
		return &m->sec;
	}

	/* 5. OAT/odex path: .debug_frame inside xz-compressed .gnu_debugdata. */
	size_t gd_off, gd_size;
	if (find_gnu_debugdata(buf, len, &gd_off, &gd_size) == 0) {
		uint8_t *inner = NULL;
		size_t inner_len = 0;
		if (decompress_xz(buf + gd_off, gd_size, &inner, &inner_len) == 0) {
			int r = cfi_load_elf(inner, inner_len, &m->sec);
			free(inner);
			if (r == 0) {
				free(buf);
				m->ok = 1;
				return &m->sec;
			}
		}
	}

	free(buf);
	return NULL;   /* m->ok stays 0; future calls short-circuit */
}

// ---- public --------------------------------------------------------------

const char *basename_of(const char *p)
{
	const char *b = strrchr(p, '/');
	return b ? b + 1 : p;
}

// Display name: basename with a trailing " (deleted)" stripped.
void display_name(const char *path, char *buf, size_t n)
{
	snprintf(buf, n, "%s", basename_of(path));
	char *del = strstr(buf, " (deleted)");
	if (del)
		*del = '\0';
}
