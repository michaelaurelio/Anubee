#include <assert.h>
#include <stdint.h>
#include "common/dwarf.h"

int main(void)
{
	/* fixed-width little-endian */
	const uint8_t fx[] = { 0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x90 };
	struct dwarf_cur c; dwarf_cur_init(&c, fx, sizeof(fx));
	assert(dwarf_u8(&c) == 0x78);
	dwarf_cur_init(&c, fx, sizeof(fx));
	assert(dwarf_u16(&c) == 0x5678);
	dwarf_cur_init(&c, fx, sizeof(fx));
	assert(dwarf_u32(&c) == 0x12345678u);
	dwarf_cur_init(&c, fx, sizeof(fx));
	assert(dwarf_u64(&c) == 0x90ABCDEF12345678ull);
	assert(c.err == 0);

	/* unsigned LEB128: 0, 127, 128, 624485 (0xE5 0x8E 0x26) */
	const uint8_t u0[] = { 0x00 };               dwarf_cur_init(&c, u0, 1); assert(dwarf_uleb(&c) == 0);
	const uint8_t u127[] = { 0x7f };             dwarf_cur_init(&c, u127, 1); assert(dwarf_uleb(&c) == 127);
	const uint8_t u128[] = { 0x80, 0x01 };       dwarf_cur_init(&c, u128, 2); assert(dwarf_uleb(&c) == 128);
	const uint8_t ub[] = { 0xE5, 0x8E, 0x26 };   dwarf_cur_init(&c, ub, 3); assert(dwarf_uleb(&c) == 624485);

	/* signed LEB128: 0, -1 (0x7f), -2 (0x7e), 63 (0x3f), -128 (0x80 0x7f), data_align -4 (0x7c) */
	const uint8_t s0[] = { 0x00 };               dwarf_cur_init(&c, s0, 1); assert(dwarf_sleb(&c) == 0);
	const uint8_t sm1[] = { 0x7f };              dwarf_cur_init(&c, sm1, 1); assert(dwarf_sleb(&c) == -1);
	const uint8_t sm2[] = { 0x7e };              dwarf_cur_init(&c, sm2, 1); assert(dwarf_sleb(&c) == -2);
	const uint8_t s63[] = { 0x3f };              dwarf_cur_init(&c, s63, 1); assert(dwarf_sleb(&c) == 63);
	const uint8_t sm128[] = { 0x80, 0x7f };      dwarf_cur_init(&c, sm128, 2); assert(dwarf_sleb(&c) == -128);
	const uint8_t sm4[] = { 0x7c };              dwarf_cur_init(&c, sm4, 1); assert(dwarf_sleb(&c) == -4);

	/* overrun safety: reading past the end sets err and returns 0, and stays sticky */
	const uint8_t one[] = { 0xAA };
	dwarf_cur_init(&c, one, 1);
	assert(dwarf_u8(&c) == 0xAA);
	assert(c.err == 0);
	assert(dwarf_u32(&c) == 0);     /* only 0 bytes left -> overrun */
	assert(c.err == 1);
	assert(dwarf_u8(&c) == 0);      /* sticky */

	/* skip past end sets err */
	dwarf_cur_init(&c, fx, sizeof(fx));
	dwarf_skip(&c, 4); assert(c.err == 0 && c.pos == 4);
	dwarf_skip(&c, 100); assert(c.err == 1);

	return 0;
}
