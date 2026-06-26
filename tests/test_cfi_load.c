/* tests/test_cfi_load.c */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "common/cfi_unwind.h"

static uint8_t *slurp(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb"); assert(f);
	fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
	assert(sz > 0);
	uint8_t *b = malloc((size_t)sz);
	assert(b && fread(b, 1, (size_t)sz, f) == (size_t)sz);
	fclose(f); *n = (size_t)sz; return b;
}

int main(int argc, char **argv)
{
	assert(argc > 2);   /* argv[1]=eh_frame_sample.so  argv[2]=debug_frame_sample.elf */

	/* .eh_frame path: section is OWNED, source can be freed before use */
	size_t n1; uint8_t *eh = slurp(argv[1], &n1);
	struct cfi_section s1;
	assert(cfi_load_elf(eh, n1, &s1) == 0);
	free(eh);                                    /* prove the section owns its bytes */
	assert(s1.owned != NULL && s1.nfde == 6);
	const struct cfi_fde *g = cfi_lookup(&s1, 0x5e0);
	assert(g && g->pc_lo == 0x5c0 && g->pc_hi == 0x990);
	struct cfi_cfa_state st;
	assert(cfi_run_program(&s1, 0x5e0, &st) == 0);   /* engine still works on owned copy */
	assert(st.cfa_reg == 31 && st.cfa_off == 272);
	cfi_section_free(&s1);

	/* .debug_frame path */
	size_t n2; uint8_t *df = slurp(argv[2], &n2);
	struct cfi_section s2;
	assert(cfi_load_elf(df, n2, &s2) == 0);
	free(df);
	assert(s2.owned != NULL && s2.nfde == 2);
	const struct cfi_fde *t = cfi_lookup(&s2, 0x2d6350);
	assert(t && t->pc_lo == 0x2d6310 && t->pc_hi == 0x2d63dc);
	cfi_section_free(&s2);

	/* neither section present -> -1, and a non-ELF buffer -> -1 */
	uint8_t junk[64]; for (int i = 0; i < 64; i++) junk[i] = (uint8_t)i;
	struct cfi_section s3;
	assert(cfi_load_elf(junk, sizeof(junk), &s3) == -1);

	return 0;
}
