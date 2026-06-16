// dump.c — see dump.h.
//
// Memory-image dump + ELF rebuild for a native library, done live against
// /proc/<pid>/mem. The pipeline mirrors (and extends) F8LEFT/SoFixer:
//
//   1. locate the module's load base from /proc/<pid>/maps;
//   2. read its whole [base, base+image) range out of memory, page by page,
//      zero-filling unreadable holes — this captures any data a packer hid in
//      the gaps between PT_LOAD segments (SoFixer's FixDumpSoPhdr), and tolerates
//      the PROT_NONE guard pages a normal loader leaves there;
//   3. rewrite every program header so the file mirrors memory
//      (p_offset = p_paddr = p_vaddr, p_filesz = p_memsz), and grow each
//      PT_LOAD's size to the next segment so the gaps are inside a segment;
//   4. de-rebase the .dynamic pointer entries (the runtime linker may have
//      rewritten them to absolute addresses) and extract the dynamic info;
//   5. un-apply relative relocations (DT_RELA R_AARCH64_RELATIVE and DT_RELR) so
//      .data/GOT hold file-relative values again, as a fresh .so would;
//   6. regenerate a full section-header table from the dynamic info (.dynsym,
//      .dynstr, .hash/.gnu.hash, .rela.dyn, .rela.plt, .plt, .text, init/fini
//      arrays, .dynamic, .data, .shstrtab);
//   7. append the section headers and write the file.
//
// The result loads in IDA/Ghidra with named sections and dynamic symbols, as
// the live post-decryption image. aarch64 / ELF64 only.

#include "rebuild.h"
#include "common/proc_mem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <fnmatch.h>
#include <elf.h>

#define DUMP_MAX_PATH  256
#define DUMP_MAX_IMAGE (512ull << 20)   // sanity cap on a reconstructed image
#define DUMP_PAGE      0x1000ull
#define DUMP_MAX_SHDRS 32

// Tags / types not guaranteed to be in every <elf.h>.
#ifndef DT_RELR
#define DT_RELR   0x24
#define DT_RELRSZ 0x23
#endif
#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef6
#endif
#ifndef SHT_GNU_HASH
#define SHT_GNU_HASH 0x6ffffff6
#endif
#ifndef R_AARCH64_RELATIVE
#define R_AARCH64_RELATIVE 1027
#endif

static int g_raw;

void dump_set_raw(int on) { g_raw = on; }

// ---- /proc/<pid>/maps -----------------------------------------------------

struct dmap {
	uint64_t start, end, off;
	char path[DUMP_MAX_PATH];
};

static int read_maps(int pid, struct dmap **out)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;

	struct dmap *m = NULL;
	size_t n = 0, cap = 0;
	char line[512];
	while (fgets(line, sizeof(line), f)) {
		uint64_t start, end, off;
		char perms[8], p[DUMP_MAX_PATH];
		p[0] = '\0';
		int got = sscanf(line, "%" SCNx64 "-%" SCNx64 " %7s %" SCNx64 " %*s %*s %255[^\n]",
				 &start, &end, perms, &off, p);
		if (got < 4)
			continue;
		if (n == cap) {
			size_t nc = cap ? cap * 2 : 256;
			struct dmap *nm = realloc(m, nc * sizeof(*nm));
			if (!nm)
				break;
			m = nm;
			cap = nc;
		}
		m[n].start = start;
		m[n].end = end;
		m[n].off = off;
		char *q = p;
		while (*q == ' ')
			q++;
		snprintf(m[n].path, sizeof(m[n].path), "%s", q);
		n++;
	}
	fclose(f);
	*out = m;
	return (int)n;
}

// Walk back over the contiguous run of same-path mappings to the load base.
static uint64_t load_base_of(const struct dmap *m, int hit)
{
	int i = hit;
	while (i > 0 && m[i - 1].end == m[i].start && !strcmp(m[i - 1].path, m[i].path))
		i--;
	return m[i].start;
}

static const char *basename_of(const char *p)
{
	const char *b = strrchr(p, '/');
	return b ? b + 1 : p;
}

// Does the module at `path` match the user's `pattern`? A pattern containing
// glob metacharacters (* ? [) is matched with fnmatch against the basename
// (with any " (deleted)" suffix stripped) — so a protector that loads its
// payload under a per-run name like "e_<pid>" is caught with 'e_*' or
// 'e_[0-9]*'. A plain pattern keeps the original substring-of-full-path match.
int dump_name_matches(const char *pattern, const char *path)
{
	if (strpbrk(pattern, "*?[")) {
		char bn[DUMP_MAX_PATH];
		snprintf(bn, sizeof(bn), "%s", basename_of(path));
		char *del = strstr(bn, " (deleted)");
		if (del)
			*del = '\0';
		return fnmatch(pattern, bn, 0) == 0;
	}
	return strstr(path, pattern) != NULL;
}

// ---- dynamic info extracted from PT_DYNAMIC -------------------------------
//
// All addresses are stored as file-relative virtual offsets (== file offset in
// the rebuilt image), after de-rebasing.

struct soinfo {
	uint64_t symtab, strtab, strsz;
	uint64_t hash;  uint32_t nbucket, nchain;
	uint64_t gnu_hash;
	uint64_t rela, relasz, relaent;
	uint64_t jmprel, pltrelsz; int plt_is_rela;
	uint64_t relr, relrsz;
	uint64_t init_array, init_arraysz;
	uint64_t fini_array, fini_arraysz;
	uint64_t dynamic_off; uint32_t dynamic_count;
};

static int dyn_tag_is_ptr(int64_t tag)
{
	switch (tag) {
	case DT_PLTGOT: case DT_HASH: case DT_STRTAB: case DT_SYMTAB:
	case DT_RELA: case DT_INIT: case DT_FINI: case DT_REL:
	case DT_JMPREL: case DT_INIT_ARRAY: case DT_FINI_ARRAY:
	case DT_PREINIT_ARRAY: case DT_GNU_HASH: case DT_VERSYM:
	case DT_VERDEF: case DT_VERNEED: case DT_RELR:
		return 1;
	}
	return 0;
}

// Walk the .dynamic array in the image: de-rebase pointer entries that the
// linker turned absolute (value within [base, base+image)), drop DT_DEBUG, and
// record everything the section/relocation rebuild needs. `dyn_off` is the file
// offset (== vaddr) of PT_DYNAMIC in the image.
static void parse_dynamic(uint8_t *img, uint64_t image_sz, uint64_t base,
			  uint64_t dyn_off, uint64_t dyn_size, struct soinfo *si)
{
	memset(si, 0, sizeof(*si));
	si->dynamic_off = dyn_off;
	if (dyn_off >= image_sz)
		return;
	uint64_t avail = image_sz - dyn_off;
	if (dyn_size && dyn_size < avail)
		avail = dyn_size;

	Elf64_Dyn *d = (Elf64_Dyn *)(img + dyn_off);
	uint64_t count = 0;
	for (uint64_t off = 0; off + sizeof(*d) <= avail; off += sizeof(*d), d++) {
		count++;
		if (d->d_tag == DT_NULL)
			break;
		if (d->d_tag == DT_DEBUG) {
			d->d_un.d_ptr = 0;
			continue;
		}
		// De-rebase: absolute runtime pointer -> file-relative offset.
		if (dyn_tag_is_ptr(d->d_tag)) {
			uint64_t v = d->d_un.d_ptr;
			if (v >= base && v < base + image_sz)
				d->d_un.d_ptr = v - base;
		}
		uint64_t v = d->d_un.d_ptr;
		switch (d->d_tag) {
		case DT_SYMTAB:        si->symtab = v; break;
		case DT_STRTAB:        si->strtab = v; break;
		case DT_STRSZ:         si->strsz = v; break;
		case DT_HASH:          si->hash = v; break;
		case DT_GNU_HASH:      si->gnu_hash = v; break;
		case DT_RELA:          si->rela = v; break;
		case DT_RELASZ:        si->relasz = v; break;
		case DT_RELAENT:       si->relaent = v; break;
		case DT_JMPREL:        si->jmprel = v; break;
		case DT_PLTRELSZ:      si->pltrelsz = v; break;
		case DT_PLTREL:        si->plt_is_rela = (v == DT_RELA); break;
		case DT_RELR:          si->relr = v; break;
		case DT_RELRSZ:        si->relrsz = v; break;
		case DT_INIT_ARRAY:    si->init_array = v; break;
		case DT_INIT_ARRAYSZ:  si->init_arraysz = v; break;
		case DT_FINI_ARRAY:    si->fini_array = v; break;
		case DT_FINI_ARRAYSZ:  si->fini_arraysz = v; break;
		}
	}
	si->dynamic_count = (uint32_t)count;

	// SysV hash header: nbucket, nchain (= number of dynamic symbols).
	if (si->hash && si->hash + 8 <= image_sz) {
		si->nbucket = ((uint32_t *)(img + si->hash))[0];
		si->nchain  = ((uint32_t *)(img + si->hash))[1];
	}
}

// ---- relative-relocation un-applying --------------------------------------
//
// In the dumped image the linker has already added the load base to every
// relative-relocated slot. A fresh file holds the un-relocated value, so the
// loader can re-apply it. Undo it for the two relative forms (RELA/RELR);
// symbolic/PLT relocations are left as-is (their resolved target is often the
// more useful thing to see, and SoFixer's "external pointer" hack for them is
// fragile). Android packed relocations (DT_ANDROID_REL[A]) are not decoded.

static void unapply_relocs(uint8_t *img, uint64_t image_sz, uint64_t base,
			   const struct soinfo *si)
{
	// DT_RELA: write back the addend for R_AARCH64_RELATIVE entries (the slot in
	// memory holds base+addend; the addend is the original file value).
	if (si->rela && si->relasz) {
		uint64_t end = si->rela + si->relasz;
		if (end > image_sz)
			end = image_sz;
		for (uint64_t o = si->rela; o + sizeof(Elf64_Rela) <= end; o += sizeof(Elf64_Rela)) {
			Elf64_Rela *r = (Elf64_Rela *)(img + o);
			if ((r->r_info & 0xffffffff) != R_AARCH64_RELATIVE)
				continue;
			if (r->r_offset + 8 <= image_sz)
				*(uint64_t *)(img + r->r_offset) = (uint64_t)r->r_addend;
		}
	}

	// DT_RELR: a packed table of relative relocations carrying no addend — each
	// target slot holds its own original value plus the load base, so subtract
	// the base back out. Entries alternate: an even value is an address; an odd
	// value is a bitmap of the 63 slots following the last address.
	if (si->relr && si->relrsz) {
		uint64_t end = si->relr + si->relrsz;
		if (end > image_sz)
			end = image_sz;
		uint64_t where = 0;
		for (uint64_t o = si->relr; o + sizeof(uint64_t) <= end; o += sizeof(uint64_t)) {
			uint64_t entry = *(uint64_t *)(img + o);
			if ((entry & 1) == 0) {
				where = entry;
				if (where + 8 <= image_sz)
					*(uint64_t *)(img + where) -= base;
				where += 8;
			} else {
				uint64_t w = where;
				for (uint64_t bits = entry >> 1; bits; bits >>= 1, w += 8)
					if ((bits & 1) && w + 8 <= image_sz)
						*(uint64_t *)(img + w) -= base;
				where += 63 * 8;
			}
		}
	}
}

// ---- section-header reconstruction ----------------------------------------

struct shbuild {
	Elf64_Shdr sh[DUMP_MAX_SHDRS];
	int gap[DUMP_MAX_SHDRS];        // 1 => size this by the gap to the next shdr
	int n;
	char strtab[1024];
	size_t strn;
};

static uint32_t sh_name(struct shbuild *b, const char *name)
{
	uint32_t off = (uint32_t)b->strn;
	size_t len = strlen(name) + 1;
	if (b->strn + len <= sizeof(b->strtab)) {
		memcpy(b->strtab + b->strn, name, len);
		b->strn += len;
	}
	return off;
}

static Elf64_Shdr *sh_add(struct shbuild *b, const char *name, uint32_t type, uint64_t flags)
{
	if (b->n >= DUMP_MAX_SHDRS)
		return NULL;
	Elf64_Shdr *s = &b->sh[b->n];
	memset(s, 0, sizeof(*s));
	s->sh_name = sh_name(b, name);
	s->sh_type = type;
	s->sh_flags = flags;
	b->n++;
	return s;
}

// Build the section headers from the dynamic info. `image_sz` is the loaded
// size; sections live at file offset == vaddr. Mirrors SoFixer's RebuildShdr.
static void build_shdrs(struct shbuild *b, const struct soinfo *si, uint64_t image_sz)
{
	memset(b, 0, sizeof(*b));
	b->strtab[0] = '\0';
	b->strn = 1;                    // index 0 = empty name

	sh_add(b, "", SHT_NULL, 0);     // index 0: null section

	if (si->symtab) {
		Elf64_Shdr *s = sh_add(b, ".dynsym", SHT_DYNSYM, SHF_ALLOC);
		if (s) {
			s->sh_addr = s->sh_offset = si->symtab;
			s->sh_addralign = 8;
			s->sh_entsize = sizeof(Elf64_Sym);
			// Exact size when the symbol count is known (DT_HASH nchain),
			// else let the post-sort gap fill it.
			if (si->nchain)
				s->sh_size = (uint64_t)si->nchain * sizeof(Elf64_Sym);
			else
				b->gap[b->n - 1] = 1;
		}
	}
	if (si->strtab) {
		Elf64_Shdr *s = sh_add(b, ".dynstr", SHT_STRTAB, SHF_ALLOC);
		if (s) {
			s->sh_addr = s->sh_offset = si->strtab;
			s->sh_size = si->strsz;
			s->sh_addralign = 1;
		}
	}
	if (si->hash) {
		Elf64_Shdr *s = sh_add(b, ".hash", SHT_HASH, SHF_ALLOC);
		if (s) {
			s->sh_addr = s->sh_offset = si->hash;
			s->sh_size = ((uint64_t)si->nbucket + si->nchain + 2) * sizeof(uint32_t);
			s->sh_addralign = 4;
			s->sh_entsize = 4;
		}
	}
	if (si->gnu_hash) {
		Elf64_Shdr *s = sh_add(b, ".gnu.hash", SHT_GNU_HASH, SHF_ALLOC);
		if (s) {
			s->sh_addr = s->sh_offset = si->gnu_hash;
			s->sh_addralign = 8;
			b->gap[b->n - 1] = 1;   // size unknown without parsing
		}
	}
	if (si->rela) {
		Elf64_Shdr *s = sh_add(b, ".rela.dyn", SHT_RELA, SHF_ALLOC);
		if (s) {
			s->sh_addr = s->sh_offset = si->rela;
			s->sh_size = si->relasz;
			s->sh_addralign = 8;
			s->sh_entsize = sizeof(Elf64_Rela);
		}
	}
	if (si->relr) {
		Elf64_Shdr *s = sh_add(b, ".relr.dyn", SHT_RELR, SHF_ALLOC);
		if (s) {
			s->sh_addr = s->sh_offset = si->relr;
			s->sh_size = si->relrsz;
			s->sh_addralign = 8;
			s->sh_entsize = sizeof(uint64_t);
		}
	}
	if (si->jmprel) {
		Elf64_Shdr *s = sh_add(b, ".rela.plt", SHT_RELA, SHF_ALLOC | SHF_INFO_LINK);
		if (s) {
			s->sh_addr = s->sh_offset = si->jmprel;
			s->sh_size = si->pltrelsz;
			s->sh_addralign = 8;
			s->sh_entsize = sizeof(Elf64_Rela);
		}
	}
	if (si->init_array) {
		Elf64_Shdr *s = sh_add(b, ".init_array", SHT_INIT_ARRAY, SHF_ALLOC | SHF_WRITE);
		if (s) {
			s->sh_addr = s->sh_offset = si->init_array;
			s->sh_size = si->init_arraysz;
			s->sh_addralign = 8;
		}
	}
	if (si->fini_array) {
		Elf64_Shdr *s = sh_add(b, ".fini_array", SHT_FINI_ARRAY, SHF_ALLOC | SHF_WRITE);
		if (s) {
			s->sh_addr = s->sh_offset = si->fini_array;
			s->sh_size = si->fini_arraysz;
			s->sh_addralign = 8;
		}
	}
	if (si->dynamic_off) {
		Elf64_Shdr *s = sh_add(b, ".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE);
		if (s) {
			s->sh_addr = s->sh_offset = si->dynamic_off;
			s->sh_size = (uint64_t)si->dynamic_count * sizeof(Elf64_Dyn);
			s->sh_addralign = 8;
			s->sh_entsize = sizeof(Elf64_Dyn);
		}
	}
	// Bound the two synthetic catch-all sections by the metadata already laid
	// out: read-only metadata clusters at low addresses (after it comes the
	// code/rodata), writable metadata at high addresses (after it comes .data).
	uint64_t ro_end = 0, wr_end = 0;
	for (int i = 1; i < b->n; i++) {
		uint64_t e = b->sh[i].sh_addr + b->sh[i].sh_size;
		if (b->sh[i].sh_flags & SHF_WRITE) {
			if (e > wr_end) wr_end = e;
		} else if (b->sh[i].sh_flags & SHF_ALLOC) {
			if (e > ro_end) ro_end = e;
		}
	}

	// Synthetic ".text" spanning the code/rodata: from the end of the read-only
	// metadata up to the first writable section (sized by the gap after sort).
	{
		Elf64_Shdr *s = sh_add(b, ".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR);
		if (s) {
			s->sh_addr = s->sh_offset = ro_end;
			s->sh_addralign = 16;
			b->gap[b->n - 1] = 1;
		}
	}
	// ".data": the writable tail, from the end of the writable metadata to the
	// loaded size.
	{
		Elf64_Shdr *s = sh_add(b, ".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);
		if (s) {
			s->sh_addr = s->sh_offset = wr_end ? wr_end : ro_end;
			s->sh_addralign = 8;
			b->gap[b->n - 1] = 1;
		}
	}
	// .shstrtab lives just past the loaded image (not allocated). Its address is
	// set to image_sz so it sorts last.
	{
		Elf64_Shdr *s = sh_add(b, ".shstrtab", SHT_STRTAB, 0);
		if (s) {
			s->sh_addr = image_sz;
			s->sh_offset = image_sz;                // patched to real offset later
			s->sh_addralign = 1;
		}
	}

	// Sort allocated sections by address (keep index 0 null first). .shstrtab
	// has sh_flags 0; everything allocated sorts ahead of it by address anyway.
	for (int i = 1; i < b->n; i++)
		for (int j = i + 1; j < b->n; j++)
			if (b->sh[i].sh_addr > b->sh[j].sh_addr) {
				Elf64_Shdr t = b->sh[i]; b->sh[i] = b->sh[j]; b->sh[j] = t;
				int g = b->gap[i]; b->gap[i] = b->gap[j]; b->gap[j] = g;
			}

	// Gap-size the sections whose size we left for the layout to decide.
	for (int i = 1; i < b->n; i++) {
		if (!b->gap[i])
			continue;
		uint64_t next = (i + 1 < b->n) ? b->sh[i + 1].sh_addr : image_sz;
		if (next == 0 || next < b->sh[i].sh_addr)
			next = image_sz;
		b->sh[i].sh_size = next - b->sh[i].sh_addr;
	}

	// Clamp any remaining overlaps so no allocated section runs into the next.
	for (int i = 1; i < b->n; i++) {
		if (!(b->sh[i].sh_flags & SHF_ALLOC))
			continue;
		uint64_t lim = (i + 1 < b->n && (b->sh[i + 1].sh_flags & SHF_ALLOC))
				       ? b->sh[i + 1].sh_offset : image_sz;
		if (b->sh[i].sh_offset + b->sh[i].sh_size > lim && lim >= b->sh[i].sh_offset)
			b->sh[i].sh_size = lim - b->sh[i].sh_offset;
	}

	// Wire up sh_link now that final indices are known.
	int dynsym = 0, dynstr = 0;
	for (int i = 1; i < b->n; i++) {
		if (b->sh[i].sh_type == SHT_DYNSYM)
			dynsym = i;
		else if (b->sh[i].sh_type == SHT_STRTAB && (b->sh[i].sh_flags & SHF_ALLOC))
			dynstr = i;
	}
	for (int i = 1; i < b->n; i++) {
		switch (b->sh[i].sh_type) {
		case SHT_DYNSYM:  b->sh[i].sh_link = dynstr; break;
		case SHT_HASH:
		case SHT_GNU_HASH:
		case SHT_RELA:
		case SHT_RELR:    b->sh[i].sh_link = dynsym; break;
		case SHT_DYNAMIC: b->sh[i].sh_link = dynstr; break;
		}
	}
}

// ---- per-module dump ------------------------------------------------------

static int write_file(const char *outpath, const uint8_t *buf, size_t sz)
{
	int fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return -1;
	const uint8_t *p = buf;
	size_t left = sz;
	while (left) {
		ssize_t w = write(fd, p, left);
		if (w <= 0) { close(fd); return -1; }
		p += w; left -= (size_t)w;
	}
	close(fd);
	return 0;
}

static int dump_one(int pid, int memfd, uint64_t base, const char *name, const char *outdir,
		    uint64_t *covered_end)
{
	Elf64_Ehdr eh;
	if (proc_mem_read(memfd, base, &eh, sizeof(eh)) != sizeof(eh) ||
	    memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "[dump] %s @0x%llx: no ELF64 header in memory (unmapped/encrypted?)\n",
			name, (unsigned long long)base);
		return -1;
	}
	if (eh.e_phoff == 0 || eh.e_phnum == 0 || eh.e_phentsize < sizeof(Elf64_Phdr)) {
		fprintf(stderr, "[dump] %s: no usable program headers\n", name);
		return -1;
	}

	size_t phsz = (size_t)eh.e_phnum * eh.e_phentsize;
	Elf64_Phdr *ph = malloc(phsz);
	if (!ph)
		return -1;
	if (proc_mem_read(memfd, base + eh.e_phoff, ph, phsz) != phsz) {
		fprintf(stderr, "[dump] %s: cannot read program headers\n", name);
		free(ph);
		return -1;
	}

	// Loaded size = highest PT_LOAD end (page-rounded). Segments are laid out by
	// vaddr; the first PT_LOAD of a .so starts at vaddr 0.
	uint64_t image_sz = 0, dyn_off = 0, dyn_size = 0;
	for (int i = 0; i < eh.e_phnum; i++) {
		Elf64_Phdr *p = (Elf64_Phdr *)((char *)ph + (size_t)i * eh.e_phentsize);
		if (p->p_type == PT_LOAD) {
			uint64_t end = p->p_vaddr + p->p_memsz;
			if (end > image_sz)
				image_sz = end;
		} else if (p->p_type == PT_DYNAMIC) {
			dyn_off = p->p_vaddr;
			dyn_size = p->p_memsz;
		}
	}
	image_sz = (image_sz + DUMP_PAGE - 1) & ~(DUMP_PAGE - 1);
	if (image_sz == 0 || image_sz > DUMP_MAX_IMAGE) {
		fprintf(stderr, "[dump] %s: implausible image size %llu\n",
			name, (unsigned long long)image_sz);
		free(ph);
		return -1;
	}
	*covered_end = base + image_sz;     // range this module owns (for dedup)

	uint8_t *img = calloc(1, image_sz);
	if (!img) {
		free(ph);
		return -1;
	}

	// Capture the whole range from memory (gaps and all), then rewrite the phdrs
	// so the file mirrors memory and each PT_LOAD spans up to the next one.
	size_t got = proc_mem_read(memfd, base, img, image_sz);

	// Sort PT_LOAD vaddrs to expand p_memsz to the next segment (SoFixer's
	// FixDumpSoPhdr): make the inter-segment gaps part of a loadable segment.
	for (int i = 0; i < eh.e_phnum; i++) {
		Elf64_Phdr *p = (Elf64_Phdr *)((char *)ph + (size_t)i * eh.e_phentsize);
		if (p->p_type == PT_LOAD) {
			uint64_t next = image_sz;
			for (int j = 0; j < eh.e_phnum; j++) {
				Elf64_Phdr *q = (Elf64_Phdr *)((char *)ph + (size_t)j * eh.e_phentsize);
				if (q->p_type == PT_LOAD && q->p_vaddr > p->p_vaddr && q->p_vaddr < next)
					next = q->p_vaddr;
			}
			p->p_memsz = next - p->p_vaddr;
		}
		p->p_filesz = p->p_memsz;
		p->p_paddr  = p->p_vaddr;
		p->p_offset = p->p_vaddr;
	}
	if (eh.e_phoff + phsz <= image_sz)
		memcpy(img + eh.e_phoff, ph, phsz);
	free(ph);

	struct shbuild b;
	b.n = 0;
	if (!g_raw) {
		struct soinfo si;
		parse_dynamic(img, image_sz, base, dyn_off, dyn_size, &si);
		unapply_relocs(img, image_sz, base, &si);
		build_shdrs(&b, &si, image_sz);
	}

	// Assemble: [loaded image] [.shstrtab] [section headers].
	uint64_t shstr_off = image_sz;
	uint64_t shdr_off = (b.n ? (shstr_off + b.strn + 7) & ~7ull : 0);
	uint64_t total = b.n ? shdr_off + (uint64_t)b.n * sizeof(Elf64_Shdr) : image_sz;

	uint8_t *out = calloc(1, total);
	if (!out) {
		free(img);
		return -1;
	}
	memcpy(out, img, image_sz);
	free(img);

	// Patch the ELF header and, if rebuilt, fix the .shstrtab offset + lay out
	// the section name table and header array.
	Elf64_Ehdr *oeh = (Elf64_Ehdr *)out;
	*oeh = eh;
	oeh->e_type = ET_DYN;
	if (b.n) {
		for (int i = 0; i < b.n; i++)
			if (b.sh[i].sh_type == SHT_STRTAB && b.sh[i].sh_flags == 0) {
				b.sh[i].sh_offset = shstr_off;
				b.sh[i].sh_size = b.strn;
				oeh->e_shstrndx = (uint16_t)i;
			}
		memcpy(out + shstr_off, b.strtab, b.strn);
		memcpy(out + shdr_off, b.sh, (size_t)b.n * sizeof(Elf64_Shdr));
		oeh->e_shoff = shdr_off;
		oeh->e_shnum = (uint16_t)b.n;
		oeh->e_shentsize = sizeof(Elf64_Shdr);
	} else {
		oeh->e_shoff = 0;
		oeh->e_shnum = 0;
		oeh->e_shstrndx = 0;
	}

	char bn[DUMP_MAX_PATH];
	snprintf(bn, sizeof(bn), "%s", basename_of(name));
	char *del = strstr(bn, " (deleted)");
	if (del)
		*del = '\0';

	char outpath[DUMP_MAX_PATH + 96];
	snprintf(outpath, sizeof(outpath), "%s/%s.%d.%llx.so",
		 outdir, bn, pid, (unsigned long long)base);

	int rc = write_file(outpath, out, total);
	free(out);
	if (rc != 0) {
		fprintf(stderr, "[dump] %s: cannot write %s: %s\n", name, outpath, strerror(errno));
		return -1;
	}

	printf("[dump] %s (pid %d) -> %s  (%llu bytes, %llu from memory, %s)\n",
	       bn, pid, outpath, (unsigned long long)total, (unsigned long long)got,
	       g_raw ? "raw image" : "rebuilt");
	return 0;
}

int dump_pid_modules(int pid, const char *substr, const char *outdir)
{
	struct dmap *m = NULL;
	int n = read_maps(pid, &m);
	if (n < 0)
		return -1;

	int memfd = proc_mem_open(pid);
	if (memfd < 0) {
		fprintf(stderr, "[dump] pid %d: cannot open /proc/%d/mem: %s\n",
			pid, pid, strerror(errno));
		free(m);
		return -1;
	}

	uint64_t done_bases[64];                       // bases already attempted
	struct { uint64_t s, e; } cov[64];             // ranges of modules dumped
	int ndone = 0, ncov = 0, dumped = 0;

	// Maps are address-sorted, so the ELF header (lowest segment) of a module is
	// seen before its later segments. A library deleted-after-mapping shows the
	// same path on every segment; if its segments are mapped non-contiguously,
	// the base-walk yields a different "base" for the gapped segment even though
	// it belongs to the module already dumped (whose full vaddr range we read
	// from its program headers). Skip any candidate inside a dumped range so we
	// neither re-dump it nor warn about its (header-less) middle.
	for (int i = 0; i < n; i++) {
		if (!m[i].path[0] || !dump_name_matches(substr, m[i].path))
			continue;
		uint64_t base = load_base_of(m, i);

		int skip = 0;
		for (int k = 0; k < ndone && !skip; k++)
			if (done_bases[k] == base)
				skip = 1;
		for (int k = 0; k < ncov && !skip; k++)
			if (base >= cov[k].s && base < cov[k].e)
				skip = 1;
		if (skip)
			continue;

		if (ndone < (int)(sizeof(done_bases) / sizeof(done_bases[0])))
			done_bases[ndone++] = base;

		uint64_t end = 0;
		if (dump_one(pid, memfd, base, m[i].path, outdir, &end) == 0) {
			dumped++;
			if (end > base && ncov < (int)(sizeof(cov) / sizeof(cov[0]))) {
				cov[ncov].s = base;
				cov[ncov].e = end;
				ncov++;
			}
		}
	}

	close(memfd);
	free(m);
	return dumped;
}

int dump_one_at(int pid, unsigned long long addr, const char *name, const char *outdir)
{
	struct dmap *m = NULL;
	int n = read_maps(pid, &m);
	if (n < 0)
		return -1;

	int hit = -1;
	for (int i = 0; i < n; i++)
		if (addr >= m[i].start && addr < m[i].end) { hit = i; break; }
	if (hit < 0) { free(m); return -1; }

	uint64_t base = load_base_of(m, hit);
	free(m);

	int memfd = proc_mem_open(pid);
	if (memfd < 0)
		return -1;

	uint64_t covered_end = 0;
	int rc = dump_one(pid, memfd, base, name, outdir, &covered_end);
	close(memfd);
	return rc;
}
