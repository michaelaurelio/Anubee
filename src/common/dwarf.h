#ifndef ARES_DWARF_H
#define ARES_DWARF_H
#include <stdint.h>
#include <stddef.h>

/* Overrun-safe little-endian cursor over a fixed buffer. Any read past the end sets
 * err=1 and returns 0; once err is set it stays set and all reads return 0. */
struct dwarf_cur {
	const uint8_t *buf;
	size_t len;
	size_t pos;
	int    err;
};

void     dwarf_cur_init(struct dwarf_cur *c, const uint8_t *buf, size_t len);
uint8_t  dwarf_u8(struct dwarf_cur *c);
uint16_t dwarf_u16(struct dwarf_cur *c);
uint32_t dwarf_u32(struct dwarf_cur *c);
uint64_t dwarf_u64(struct dwarf_cur *c);
uint64_t dwarf_uleb(struct dwarf_cur *c);   /* unsigned LEB128 */
int64_t  dwarf_sleb(struct dwarf_cur *c);   /* signed LEB128 (sign-extended) */
void     dwarf_skip(struct dwarf_cur *c, size_t n);   /* advance pos by n (clamped, sets err on overrun) */

#endif
