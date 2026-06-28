/* tests/test_cfi_eh.c — .eh_frame parsing (task 4c-eh) */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "common/cfi_unwind.h"

int main(int argc, char **argv)
{
	assert(argc > 1);
	FILE *f = fopen(argv[1], "rb"); assert(f);
	fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
	uint8_t *buf = malloc((size_t)n);
	assert(buf && fread(buf, 1, (size_t)n, f) == (size_t)n);
	fclose(f);

	const uint8_t *eh = NULL; size_t el = 0; uint64_t evaddr = 0;
	assert(cfi_extract_eh_frame(buf, (size_t)n, &eh, &el, &evaddr) == 0);
	assert(evaddr == 0xab8);                 /* .eh_frame sh_addr in the fixture */

	struct cfi_section s;
	assert(cfi_parse_eh_frame(&s, eh, el, evaddr) == 0);
	assert(s.nfde == 6);

	/* FDE ranges resolved from pcrel pointers */
	const struct cfi_fde *a = cfi_lookup(&s, 0x4f0);
	assert(a && a->pc_lo == 0x4e0 && a->pc_hi == 0x510);
	const struct cfi_fde *g = cfi_lookup(&s, 0x5e0);
	assert(g && g->pc_lo == 0x5c0 && g->pc_hi == 0x990);
	assert(cfi_lookup(&s, 0x100) == NULL);   /* below all FDEs */

	/* CIE fields parse correctly through cfi_read_cie (eh dialect) */
	struct cfi_cie cie;
	assert(cfi_read_cie(&s, g->cie_off, &cie) == 0);
	assert(cie.version == 1 && cie.code_align == 4 && cie.data_align == -8 && cie.ra_reg == 30);

	/* Engine runs over an eh FDE unchanged: at pc 0x5e0 the prologue has set CFA=sp+272,
	 * x29 saved at CFA-272, x30 (RA) at CFA-264. */
	struct cfi_cfa_state st;
	assert(cfi_run_program(&s, 0x5e0, &st) == 0);
	assert(st.cfa_reg == 31 && st.cfa_off == 272);
	assert(st.cols[29].kind == CFI_AT_CFA && st.cols[29].off == -272);
	assert(st.cols[30].kind == CFI_AT_CFA && st.cols[30].off == -264);

	/* Leaf frame: FDE [0x4e0,0x510) is nop-only (no RA rule), like a libc syscall
	 * stub. The return-address register must default to SAME (RA lives in x30),
	 * NOT undefined — else cfi_step would treat it as top-of-stack and stop the
	 * unwind at the very first frame. */
	struct cfi_cfa_state lst;
	assert(cfi_run_program(&s, 0x4e0, &lst) == 0);
	assert(lst.cols[30].kind == CFI_SAME);

	cfi_section_free(&s);

	/* negatives: non-ELF + truncated fail cleanly */
	const uint8_t *e2; size_t l2; uint64_t v2;
	uint8_t junk[4] = {1,2,3,4};
	assert(cfi_extract_eh_frame(junk, 4, &e2, &l2, &v2) == -1);
	free(buf);
	return 0;
}
