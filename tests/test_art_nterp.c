// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the nterp ArtMethod->name chase (art_method_resolve). Builds a
// synthetic ART address space — ArtMethod -> mirror::Class -> mirror::DexCache ->
// DexFile -> dex image — over the committed sample.dex fixture, and asserts the
// version-coupled offset walk resolves an ArtMethod to "pkg.Class.method". The chase
// reads target memory only through the injected art_reader, so no device is needed.
#include "common/art_nterp.h"
#include "common/dex.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                   \
    checks++;                                                   \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); }   \
} while (0)

// synthetic flat address space: a list of [base,len) regions backed by buffers.
struct region { uint64_t base; const uint8_t *data; size_t len; };
struct mem { struct region r[8]; int n; };

static size_t memrd(void *ctx, uint64_t va, void *dst, size_t len)
{
    struct mem *m = ctx;
    for (int i = 0; i < m->n; i++) {
        struct region *r = &m->r[i];
        if (va >= r->base && va + len <= r->base + r->len) {
            memcpy(dst, r->data + (va - r->base), len);
            return len;
        }
    }
    return 0;   // unmapped -> short read -> resolver treats as failure
}

static void add_region(struct mem *m, uint64_t base, const uint8_t *data, size_t len)
{
    m->r[m->n].base = base; m->r[m->n].data = data; m->r[m->n].len = len; m->n++;
}

static void w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void w64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

static uint8_t *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    if (n <= 0) { fprintf(stderr, "empty fixture\n"); exit(2); }
    uint8_t *b = malloc((size_t)n);
    if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) exit(2);
    fclose(f); *len = (size_t)n; return b;
}

// Find the method_ids index whose name is `want` in the fixture (so the synthetic
// ArtMethod carries a real index, independent of fixture internals).
static uint32_t idx_of(struct dex_method_map *map, const char *want)
{
    char nb[256];
    for (uint32_t i = 0; i < 4096; i++)
        if (dex_name_by_index(map, i, nb, sizeof(nb)) == 1 && strcmp(nb, want) == 0)
            return i;
    fprintf(stderr, "method '%s' not in fixture\n", want); exit(2);
}

// Layout offsets mirrored from art_nterp.c's version table.
#define O_DECL 0x00
#define O_MIDX 0x08
#define O_CLASS_DC 0x10
#define O_DC_DF 0x10
#define O_DF_BEGIN 0x08
#define O_DF_SIZE 0x20

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "tests/fixtures/sample.dex";
    size_t dexlen; uint8_t *dex = slurp(path, &dexlen);
    struct dex_method_map *probe = dex_map_build(dex, dexlen);
    CHECK(probe != NULL, "fixture builds");
    uint32_t greet_idx = idx_of(probe, "com.ares.Sample.greet");
    dex_map_free(probe);

    // addresses: Class/DexCache are compressed (must fit in u32); DexFile/dex are
    // native 64-bit. AM 8-aligned and >= 0x1000.
    const uint64_t AM = 0x4000, C = 0x20000000, DC = 0x21000000,
                   DF = 0x700000000ULL, BEGIN = 0x30000000;

    uint8_t am[16]   = {0};  w32(am + O_DECL, (uint32_t)C);  w32(am + O_MIDX, greet_idx);
    uint8_t cls[32]  = {0};  w32(cls + O_CLASS_DC, (uint32_t)DC);
    uint8_t dc[32]   = {0};  w64(dc + O_DC_DF, DF);
    uint8_t df[48]   = {0};  w64(df + O_DF_BEGIN, BEGIN); w64(df + O_DF_SIZE, dexlen);

    struct mem m = {0};
    add_region(&m, AM, am, sizeof(am));
    add_region(&m, C, cls, sizeof(cls));
    add_region(&m, DC, dc, sizeof(dc));
    add_region(&m, DF, df, sizeof(df));
    add_region(&m, BEGIN, dex, dexlen);

    char out[256];

    // Happy path: full chase resolves the method name.
    art_nterp_cache_reset();
    CHECK(art_method_resolve(memrd, &m, AM, out, sizeof(out)) == 1 &&
          strcmp(out, "com.ares.Sample.greet") == 0,
          "ArtMethod chase resolves greet");

    // Misaligned / tiny pointer -> rejected before any read.
    CHECK(art_method_resolve(memrd, &m, AM + 1, out, sizeof(out)) == 0,
          "misaligned ArtMethod -> miss");
    CHECK(art_method_resolve(memrd, &m, 0x10, out, sizeof(out)) == 0,
          "implausible low ArtMethod -> miss");

    // declaring_class_ == 0 -> miss (no class to chase).
    { uint8_t am0[16] = {0}; w32(am0 + O_MIDX, greet_idx);
      struct mem m2 = m; m2.r[0].data = am0;
      CHECK(art_method_resolve(memrd, &m2, AM, out, sizeof(out)) == 0,
            "null declaring_class -> miss"); }

    // Candidate that points into unmapped memory -> short read -> miss, no crash.
    CHECK(art_method_resolve(memrd, &m, 0x900000, out, sizeof(out)) == 0,
          "unmapped ArtMethod -> miss");

    // Cached second lookup still resolves (exercises the DexFile image cache).
    CHECK(art_method_resolve(memrd, &m, AM, out, sizeof(out)) == 1 &&
          strcmp(out, "com.ares.Sample.greet") == 0,
          "second lookup hits dex cache, still resolves");

    // DexFile size sanity: a target-supplied size of 0 or an absurd size must be
    // rejected before reading the image (don't trust the target's size blindly).
    { uint8_t df0[48]; memcpy(df0, df, sizeof(df0)); w64(df0 + O_DF_SIZE, 0);
      struct mem mz = m; mz.r[3].data = df0;
      art_nterp_cache_reset();
      CHECK(art_method_resolve(memrd, &mz, AM, out, sizeof(out)) == 0,
            "zero dex size -> miss"); }
    { uint8_t dfb[48]; memcpy(dfb, df, sizeof(dfb)); w64(dfb + O_DF_SIZE, 1ull << 30);
      struct mem mb = m; mb.r[3].data = dfb;
      art_nterp_cache_reset();
      CHECK(art_method_resolve(memrd, &mb, AM, out, sizeof(out)) == 0,
            "absurd dex size -> miss"); }

    art_nterp_cache_reset();
    free(dex);
    printf("%s: %d checks, %d failures\n", argv[0], checks, failures);
    return failures ? 1 : 0;
}
