// symbolize.c — see symbolize.h.
//
// Two caches:
//   * per-pid /proc/<pid>/maps snapshot (module ranges + on-disk paths), reread
//     lazily on a lookup miss (throttled) since libraries can load over time;
//   * per-(path, elf-offset) parsed .dynsym, so each ELF is read once.
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

static struct mapping *find_mapping(struct procmaps *pm, uint64_t addr)
{
	for (size_t i = 0; i < pm->n; i++)
		if (addr >= pm->m[i].start && addr < pm->m[i].end)
			return &pm->m[i];
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

// ---- .dynsym -------------------------------------------------------------

struct sym {
	uint64_t value, size;
	uint32_t name_off;
};

struct dynsym {
	char path[MAX_PATH_LEN];
	uint64_t elf_off;
	char *str;
	size_t strn;
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

// Parse the .dynsym/.dynstr of the ELF at `elf_off` inside the module.
static void parse_dynsym(struct dynsym *ds, int pid, uint64_t vstart, uint64_t vend)
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
	if (eh.e_shoff == 0 || eh.e_shnum == 0)
		goto done;                       // section headers stripped

	size_t shsz = (size_t)eh.e_shnum * eh.e_shentsize;
	Elf64_Shdr *sh = malloc(shsz);
	if (!sh)
		goto done;
	if (pread_all(fd, sh, shsz, (off_t)(ds->elf_off + eh.e_shoff)) != 0) {
		free(sh);
		goto done;
	}

	Elf64_Shdr *dynsym = NULL, *dynstr = NULL;
	for (int i = 0; i < eh.e_shnum; i++) {
		if (sh[i].sh_type == SHT_DYNSYM) {
			dynsym = &sh[i];
			if (sh[i].sh_link < eh.e_shnum)
				dynstr = &sh[sh[i].sh_link];
			break;
		}
	}
	if (!dynsym || !dynstr || dynsym->sh_entsize == 0) {
		free(sh);
		goto done;
	}

	ds->strn = dynstr->sh_size;
	ds->str = malloc(ds->strn ? ds->strn : 1);
	if (!ds->str || pread_all(fd, ds->str, ds->strn, (off_t)(ds->elf_off + dynstr->sh_offset)) != 0) {
		free(ds->str); ds->str = NULL; free(sh);
		goto done;
	}

	size_t count = (size_t)(dynsym->sh_size / dynsym->sh_entsize);
	ds->s = malloc((count ? count : 1) * sizeof(struct sym));
	if (!ds->s) {
		free(ds->str); ds->str = NULL; free(sh);
		goto done;
	}

	for (size_t i = 0; i < count; i++) {
		Elf64_Sym es;
		if (pread_all(fd, &es, sizeof(es),
			      (off_t)(ds->elf_off + dynsym->sh_offset + i * dynsym->sh_entsize)) != 0)
			break;
		if (es.st_value == 0 || es.st_shndx == SHN_UNDEF || es.st_name == 0)
			continue;                // imported/anonymous
		if (es.st_name >= ds->strn)
			continue;
		ds->s[ds->ns].value = es.st_value;
		ds->s[ds->ns].size = es.st_size;
		ds->s[ds->ns].name_off = es.st_name;
		ds->ns++;
	}
	free(sh);
	qsort(ds->s, ds->ns, sizeof(struct sym), sym_cmp);
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
	parse_dynsym(ds, pid, vstart, vend);
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

void sym_resolve(int pid, unsigned long long addr, char *out, size_t outsz)
{
	struct procmaps *pm = pm_get(pid);
	if (!pm) {
		snprintf(out, outsz, "0x%llx", addr);
		return;
	}

	struct mapping *hit = find_mapping(pm, (uint64_t)addr);
	if (!hit && now_ms() - pm->last_read_ms > REFRESH_MS) {
		read_proc_maps(pm);             // a library may have loaded since
		hit = find_mapping(pm, (uint64_t)addr);
	}
	if (!hit) {
		// Not in any mapping: stale frame, or a bad frame-pointer unwind.
		snprintf(out, outsz, "0x%llx [unmapped]", addr);
		return;
	}

	uint64_t load_base, elf_off, base_end;
	module_base(pm, hit, &load_base, &elf_off, &base_end);

	// Anonymous executable memory with no name: JIT cache, a packer/obfuscator
	// or RASP-allocated code region, a thread stack, etc. Not ELF-backed, so no
	// symbol — but say so explicitly rather than printing a bare address.
	if (hit->path[0] == '\0') {
		snprintf(out, outsz, "[anon]+0x%llx",
			 (unsigned long long)((uint64_t)addr - hit->start));
		return;
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
		return;
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
}

void sym_flush_pid(int pid)
{
	for (size_t i = 0; i < g_npm; i++)
		if (g_pm[i].pid == pid)
			g_pm[i].n = 0;          // force reread on next resolve
}
