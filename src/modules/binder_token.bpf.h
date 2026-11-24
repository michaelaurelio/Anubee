// SPDX-License-Identifier: GPL-2.0
// Source-shared (#include'd into each engine's BPF unit, never a shared
// runtime object): FNV-1a hash of a Binder Parcel's AIDL interface token.
// The Parcel starts with int32 policy, int32 work-source uid, int32 header
// magic, then String16 (int32 length + UTF-16 chars); the hash covers the
// UTF-16 bytes, matching binder_token_hash()/binder_descriptor_hash() in
// binder_api_parse.c. 0 = no plausible token.
#ifndef __ANUBEE_BINDER_TOKEN_BPF_H
#define __ANUBEE_BINDER_TOKEN_BPF_H

#define BINDER_TOKEN_LEN_OFF 12     // int32 length of the String16 token
#define BINDER_TOKEN_MAX_CH  120    // longest token hashed (real ones are < 80)

// raw: a buffer whose size is mask + 1 (a power of two); n: bytes valid in it.
static __always_inline __u64 binder_token_fnv(const unsigned char *raw, __u32 mask, __u32 n)
{
	__s32 len = 0;
	__builtin_memcpy(&len, &raw[BINDER_TOKEN_LEN_OFF], 4);
	if (len <= 0 || len > BINDER_TOKEN_MAX_CH || BINDER_TOKEN_LEN_OFF + 4 + 2 * len > n)
		return 0;
	__u64 h = 1469598103934665603ULL;
	for (int i = 0; i < 2 * BINDER_TOKEN_MAX_CH; i++) {
		if (i >= 2 * len)
			break;
		h ^= raw[(BINDER_TOKEN_LEN_OFF + 4 + i) & mask];
		h *= 1099511628211ULL;
	}
	return h;
}

#endif /* __ANUBEE_BINDER_TOKEN_BPF_H */
