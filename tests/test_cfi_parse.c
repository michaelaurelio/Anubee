/* tests/test_cfi_parse.c */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "common/cfi_unwind.h"

static const uint8_t DF[] = {
    0x14, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x04, 0x00, 0x08, 0x00, 0x01, 0x7c, 0x1e,
    0x0c, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0e, 0x10, 0x9e, 0x01, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x63, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x10, 0x9e, 0x01, 0x00, 0x00, 0x00, 0x00
};

int main(void)
{
	struct cfi_section s;
	assert(cfi_parse_debug_frame(&s, DF, sizeof(DF)) == 0);
	assert(s.nfde == 2);

	/* CIE at offset 0 */
	struct cfi_cie cie;
	assert(cfi_read_cie(&s, 0, &cie) == 0);
	assert(cie.version == 4);
	assert(cie.addr_size == 8);
	assert(cie.code_align == 1);
	assert(cie.data_align == -4);
	assert(cie.ra_reg == 30);

	/* lookup inside FDE1 */
	const struct cfi_fde *f = cfi_lookup(&s, 0x1000);
	assert(f && f->pc_lo == 0x1000 && f->pc_hi == 0x1100 && f->cie_off == 0);
	assert(cfi_lookup(&s, 0x10ff) == f);          /* last byte in range */
	assert(cfi_lookup(&s, 0x1100) == NULL);        /* one past the end -> miss */

	/* lookup inside FDE2 (trampoline-like range) */
	const struct cfi_fde *g = cfi_lookup(&s, 0x2d6350);
	assert(g && g->pc_lo == 0x2d6310 && g->pc_hi == 0x2d63dc);

	/* gaps and below-range miss */
	assert(cfi_lookup(&s, 0x500)  == NULL);
	assert(cfi_lookup(&s, 0x2000) == NULL);

	/* FDE instruction slices are non-empty and within the section */
	assert(f->insn_len > 0 && f->insn_off + f->insn_len <= sizeof(DF));

	cfi_section_free(&s);

	/* malformed: truncated section must fail cleanly, not crash */
	struct cfi_section bad;
	assert(cfi_parse_debug_frame(&bad, DF, 6) == -1);

	/* regression: a section parsed directly (not via cfi_load_elf) must have its
	 * owned pointer initialized, so cfi_section_free is safe. Poison the struct so
	 * an uninitialized owned would be a non-NULL garbage pointer -> free() abort
	 * (the original CI segfault: "free(): invalid size"). */
	struct cfi_section poisoned;
	memset(&poisoned, 0xAA, sizeof(poisoned));
	assert(cfi_parse_debug_frame(&poisoned, DF, sizeof(DF)) == 0);
	cfi_section_free(&poisoned);   /* must not crash */

	return 0;
}
