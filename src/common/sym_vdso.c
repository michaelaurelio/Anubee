// SPDX-License-Identifier: GPL-2.0
// [vdso] symbol resolution: read the in-memory vDSO ELF off /proc/<pid>/mem and
// name __kernel_* frames via its .dynsym. See symbolize_internal.h.
#include <sys/types.h>
#include "symbolize_internal.h"
#include "common/proc_mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <elf.h>

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
int vdso_resolve(int pid, uint64_t addr, uint64_t base, uint64_t end,
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

// Reset the vDSO symbol cache for one pid (called on procmaps LRU eviction and
// on sym_flush_pid). Forces a rebuild on the next resolve.
void vdso_reset_pid(int pid)
{
	for (size_t i = 0; i < g_nvdso; i++)
		if (g_vdso[i].pid == pid)
			vdso_free(&g_vdso[i]);
}
