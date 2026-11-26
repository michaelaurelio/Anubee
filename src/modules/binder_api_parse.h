// SPDX-License-Identifier: GPL-2.0
// Pure helpers for `anubee mod binder-api` (host-tested in
// tests/test_binder_api_parse.c):
//  - decode the interface token from the start of a transaction's Parcel;
//  - name AIDL methods from DEX: an AIDL interface's generated `$Stub` class
//    holds `static final int TRANSACTION_<method> = <code>` constants, read
//    from the class_def's static_values -- so names come from the device's
//    own framework.jar and match its Android build, with no hardcoded table.
#ifndef __ANUBEE_BINDER_API_PARSE_H
#define __ANUBEE_BINDER_API_PARSE_H

#include <stddef.h>
#include <stdint.h>

// Offset of the String16 interface token in an AIDL Parcel (Android 10+):
// int32 strict-mode policy, int32 work-source uid, int32 'SYST'/'VNDR'.
#define BINDER_TOKEN_OFF 12

// Decode the token from raw[0..n) into out (ASCII; non-ASCII UTF-16 units
// become '?'). Returns the token length, or -1 if raw doesn't start with a
// plausible token (bad length, truncated, or non-printable characters).
int binder_parcel_token(const unsigned char *raw, size_t n, char *out, size_t outsz);

// FNV-1a over the token's UTF-16LE bytes -- the same hash binder_api.bpf.c
// computes, so userspace can match kernel counters to decoded tokens.
uint64_t binder_token_hash(const unsigned char *raw, size_t n);
// The same hash for a descriptor string (e.g. to arm an in-kernel token
// match): what binder_token_hash returns for a Parcel carrying it. 0 for "".
uint64_t binder_descriptor_hash(const char *descriptor);

// What an IContentProvider transaction is about, from its Parcel prefix.
struct binder_cp_detail {
    char uri[384];        // content://... (URI-bearing calls), or ""
    char authority[128];  // CALL: provider authority, e.g. "settings"
    char method[128];     // CALL: e.g. "GET_secure"
    char arg[128];        // CALL: e.g. "android_id" ("" if null)
};
// is_call: the transaction is IContentProvider CALL (named from the jar, so
// version-independent). Returns 1 if anything was extracted, else 0.
// Covers Uri marshalled as one string (UTF-8 String8, as Android 16 does;
// or UTF-16). A Uri split into scheme/authority/path parts isn't decoded.
int binder_cp_describe(const unsigned char *raw, size_t n, int is_call,
                       struct binder_cp_detail *out);

struct binder_names;
struct binder_names *binder_names_new(void);
void binder_names_free(struct binder_names *bn);
// Index every `...$Stub` class's TRANSACTION_ constants. The DEX bytes must
// outlive bn (names point into them). Returns the number of methods added.
int binder_names_add_dex(struct binder_names *bn, const uint8_t *dex, size_t len);
// Same for every stored (uncompressed) classes*.dex entry of a jar/zip, as
// /system/framework jars ship them. Returns methods added (0 if none).
int binder_names_add_jar(struct binder_names *bn, const uint8_t *zip, size_t len);
// Method name for (interface descriptor, code), or NULL.
const char *binder_names_lookup(const struct binder_names *bn, const char *iface, uint32_t code);
int binder_names_count(const struct binder_names *bn);

#endif /* __ANUBEE_BINDER_API_PARSE_H */
