// SPDX-License-Identifier: GPL-2.0
// Vendored SHA-256 (FIPS 180-4). ANUBEE links no crypto library, and the modcmp
// record (`anubee dump --check`) needs a stable digest of a module's executable
// segments so a verdict can be correlated with a dumped artifact across runs.
// Public-domain reference construction; no external deps, so host tests link it.
#ifndef ANUBEE_COMMON_SHA256_H
#define ANUBEE_COMMON_SHA256_H

#include <stddef.h>
#include <stdint.h>

struct sha256_ctx {
	uint32_t state[8];
	uint64_t bitlen;
	uint8_t  buf[64];
	size_t   buflen;
};

void sha256_init(struct sha256_ctx *c);
void sha256_update(struct sha256_ctx *c, const void *data, size_t len);
// Finalize into 64 lowercase hex chars + NUL. Hex rather than raw bytes because
// every caller wants the string form (the modcmp record), so the conversion
// lives here once instead of being re-rolled at each call site.
void sha256_final_hex(struct sha256_ctx *c, char out[65]);

#endif /* ANUBEE_COMMON_SHA256_H */
