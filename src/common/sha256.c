// SPDX-License-Identifier: GPL-2.0
// sha256.c - see sha256.h. Public-domain FIPS 180-4 construction.
#include "common/sha256.h"

#include <string.h>

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define S0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define S1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define s0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define s1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

static void sha256_block(struct sha256_ctx *c, const uint8_t *p)
{
	uint32_t w[64];
	for (int i = 0; i < 16; i++)
		w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
		       ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
	for (int i = 16; i < 64; i++)
		w[i] = s1(w[i - 2]) + w[i - 7] + s0(w[i - 15]) + w[i - 16];

	uint32_t a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
	uint32_t e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];

	for (int i = 0; i < 64; i++) {
		uint32_t t1 = h + S1(e) + ((e & f) ^ (~e & g)) + K[i] + w[i];
		uint32_t t2 = S0(a) + ((a & b) ^ (a & cc) ^ (b & cc));
		h = g; g = f; f = e; e = d + t1;
		d = cc; cc = b; b = a; a = t1 + t2;
	}

	c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
	c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

void sha256_init(struct sha256_ctx *c)
{
	c->state[0] = 0x6a09e667; c->state[1] = 0xbb67ae85;
	c->state[2] = 0x3c6ef372; c->state[3] = 0xa54ff53a;
	c->state[4] = 0x510e527f; c->state[5] = 0x9b05688c;
	c->state[6] = 0x1f83d9ab; c->state[7] = 0x5be0cd19;
	c->bitlen = 0;
	c->buflen = 0;
}

void sha256_update(struct sha256_ctx *c, const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;
	c->bitlen += (uint64_t)len * 8;
	while (len) {
		size_t want = 64 - c->buflen;
		size_t take = len < want ? len : want;
		memcpy(c->buf + c->buflen, p, take);
		c->buflen += take;
		p += take;
		len -= take;
		if (c->buflen == 64) {
			sha256_block(c, c->buf);
			c->buflen = 0;
		}
	}
}

void sha256_final_hex(struct sha256_ctx *c, char out[65])
{
	static const char hx[] = "0123456789abcdef";
	uint64_t bits = c->bitlen;

	c->buf[c->buflen++] = 0x80;
	if (c->buflen > 56) {
		memset(c->buf + c->buflen, 0, 64 - c->buflen);
		sha256_block(c, c->buf);
		c->buflen = 0;
	}
	memset(c->buf + c->buflen, 0, 56 - c->buflen);
	for (int i = 0; i < 8; i++)
		c->buf[56 + i] = (uint8_t)(bits >> (56 - i * 8));
	sha256_block(c, c->buf);

	for (int i = 0; i < 8; i++) {
		uint8_t b[4] = {
			(uint8_t)(c->state[i] >> 24), (uint8_t)(c->state[i] >> 16),
			(uint8_t)(c->state[i] >> 8),  (uint8_t)(c->state[i]),
		};
		for (int k = 0; k < 4; k++) {
			out[i * 8 + k * 2]     = hx[b[k] >> 4];
			out[i * 8 + k * 2 + 1] = hx[b[k] & 0xf];
		}
	}
	out[64] = '\0';
}
