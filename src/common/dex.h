#ifndef ANUBEE_COMMON_DEX_H
#define ANUBEE_COMMON_DEX_H

#include <stdint.h>
#include <stddef.h>

struct dex_method_map;   // opaque; built once per DEX image

// Parse the DEX image [img, img+len) and build a sorted map of method bytecode
// ranges. Returns NULL on a non-DEX / malformed-header / allocation failure.
// The returned map does NOT alias img — img may be freed after this returns.
struct dex_method_map *dex_map_build(const uint8_t *img, size_t len);

// Release a map built by dex_map_build (NULL-safe).
void dex_map_free(struct dex_method_map *m);

// Resolve a byte offset into the original DEX image to the method whose
// code_item.insns covers it. On a hit, writes "pkg.Class.method" to out and
// returns 1; on a miss (offset outside every method, or unresolvable name)
// returns 0 and leaves out untouched.
int dex_map_lookup(const struct dex_method_map *m, uint32_t off,
                   char *out, size_t outsz);

// Resolve a byte offset into the DEX image to the covering method's index and the
// image offset of its code_item.insns (bytecode start). On a hit writes both
// out-params and returns 1; on a miss returns 0 and leaves them untouched. Used to
// corroborate an nterp ArtMethod* candidate against a live dex_pc found on the stack
// (same method + a valid in-range dex_pc => the true managed frame).
int dex_lookup_range(const struct dex_method_map *m, uint32_t off,
                     uint32_t *method_idx, uint32_t *insns_off);

// Resolve a DEX method_ids index directly to "pkg.Class.method" (the index-keyed
// sibling of dex_map_lookup, for callers that already hold a method_index — e.g.
// an ART managed-stack walk). On a hit writes "pkg.Class.method" to out and
// returns 1; on a bad/unresolvable index or buffer overflow returns 0.
int dex_name_by_index(const struct dex_method_map *m, uint32_t method_idx,
                      char *out, size_t outsz);

#endif /* ANUBEE_COMMON_DEX_H */
