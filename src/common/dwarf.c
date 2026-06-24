#include "common/dwarf.h"

void dwarf_cur_init(struct dwarf_cur *c, const uint8_t *buf, size_t len)
{
	c->buf = buf; c->len = len; c->pos = 0; c->err = 0;
}

static int avail(struct dwarf_cur *c, size_t n)
{
	if (c->err || c->pos + n > c->len) { c->err = 1; return 0; }
	return 1;
}

uint8_t dwarf_u8(struct dwarf_cur *c)
{
	if (!avail(c, 1)) return 0;
	return c->buf[c->pos++];
}

uint16_t dwarf_u16(struct dwarf_cur *c)
{
	if (!avail(c, 2)) return 0;
	uint16_t v = (uint16_t)c->buf[c->pos] | ((uint16_t)c->buf[c->pos + 1] << 8);
	c->pos += 2; return v;
}

uint32_t dwarf_u32(struct dwarf_cur *c)
{
	if (!avail(c, 4)) return 0;
	uint32_t v = (uint32_t)c->buf[c->pos]
		   | ((uint32_t)c->buf[c->pos + 1] << 8)
		   | ((uint32_t)c->buf[c->pos + 2] << 16)
		   | ((uint32_t)c->buf[c->pos + 3] << 24);
	c->pos += 4; return v;
}

uint64_t dwarf_u64(struct dwarf_cur *c)
{
	if (!avail(c, 8)) return 0;
	uint64_t v = 0;
	for (int i = 0; i < 8; i++)
		v |= (uint64_t)c->buf[c->pos + i] << (8 * i);
	c->pos += 8; return v;
}

uint64_t dwarf_uleb(struct dwarf_cur *c)
{
	uint64_t result = 0;
	int shift = 0;
	for (;;) {
		if (!avail(c, 1)) return 0;
		uint8_t b = c->buf[c->pos++];
		if (shift < 64)
			result |= (uint64_t)(b & 0x7f) << shift;
		shift += 7;
		if (!(b & 0x80)) break;
	}
	return result;
}

int64_t dwarf_sleb(struct dwarf_cur *c)
{
	int64_t result = 0;
	int shift = 0;
	uint8_t b = 0;
	for (;;) {
		if (!avail(c, 1)) return 0;
		b = c->buf[c->pos++];
		if (shift < 64)
			result |= (int64_t)(b & 0x7f) << shift;
		shift += 7;
		if (!(b & 0x80)) break;
	}
	/* sign-extend if the sign bit of the last byte is set and we have room */
	if (shift < 64 && (b & 0x40))
		result |= -((int64_t)1 << shift);
	return result;
}

void dwarf_skip(struct dwarf_cur *c, size_t n)
{
	if (!avail(c, n)) return;
	c->pos += n;
}
