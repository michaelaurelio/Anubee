#ifndef ARES_COMMON_DEX_H
#define ARES_COMMON_DEX_H

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

// Resolve a DEX method_ids index directly to "pkg.Class.method" (the index-keyed
// sibling of dex_map_lookup, for callers that already hold a method_index — e.g.
// an ART managed-stack walk). On a hit writes "pkg.Class.method" to out and
// returns 1; on a bad/unresolvable index or buffer overflow returns 0.
int dex_name_by_index(const struct dex_method_map *m, uint32_t method_idx,
                      char *out, size_t outsz);

#endif /* ARES_COMMON_DEX_H */
