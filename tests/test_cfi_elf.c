/* tests/test_cfi_elf.c */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "common/cfi_unwind.h"

int main(int argc, char **argv)
{
	assert(argc > 1);
	FILE *f = fopen(argv[1], "rb");
	assert(f);
	fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
	assert(n > 0);
	uint8_t *buf = malloc((size_t)n);
	assert(buf && fread(buf, 1, (size_t)n, f) == (size_t)n);
	fclose(f);

	/* extract .debug_frame from the real ELF */
	const uint8_t *df = NULL; size_t dl = 0;
	assert(cfi_extract_debug_frame(buf, (size_t)n, &df, &dl) == 0);
	assert(df >= buf && df + dl <= buf + n);   /* slice is inside the image */
	assert(dl == 88);

	/* it parses and the trampoline-range FDE is found */
	struct cfi_section s;
	assert(cfi_parse_debug_frame(&s, df, dl) == 0 && s.nfde == 2);
	const struct cfi_fde *g = cfi_lookup(&s, 0x2d6350);
	assert(g && g->pc_lo == 0x2d6310 && g->pc_hi == 0x2d63dc);
	assert(cfi_lookup(&s, 0x1000) != NULL);
	assert(cfi_lookup(&s, 0x500)  == NULL);
	cfi_section_free(&s);

	/* negatives: non-ELF buffer and a too-short buffer both fail cleanly */
	const uint8_t *d2 = NULL; size_t l2 = 0;
	uint8_t junk[4] = { 1, 2, 3, 4 };
	assert(cfi_extract_debug_frame(junk, sizeof(junk), &d2, &l2) == -1);
	assert(cfi_extract_debug_frame(buf, 8, &d2, &l2) == -1);   /* valid magic prefix but truncated */

	free(buf);
	return 0;
}
