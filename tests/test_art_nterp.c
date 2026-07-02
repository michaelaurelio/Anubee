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

// idx_of but rebuilds a throwaway map from the raw dex (probe is freed by now).
static uint32_t idx_of2(uint8_t *dex, size_t dexlen, const char *want)
{
    struct dex_method_map *p = dex_map_build(dex, dexlen);
    if (!p) { fprintf(stderr, "rebuild failed\n"); exit(2); }
    uint32_t r = idx_of(p, want);
    dex_map_free(p);
    return r;
}

// Layout offsets mirrored from art_nterp.c's version table.
#define O_DECL 0x00
#define O_MIDX 0x08
#define O_CLASS_DC 0x10
#define O_DC_DF 0x10
#define O_DF_BEGIN 0x08
#define O_DF_SIZE 0x20

#include "common/art_buildid.h"   /* struct art_offsets */
static const struct art_offsets T_OFF = {
    .artm_declclass = O_DECL, .artm_dexidx = O_MIDX, .class_dexcache = O_CLASS_DC,
    .dexcache_dexfile = O_DC_DF, .dexfile_begin = O_DF_BEGIN, .dexfile_datasize = O_DF_SIZE,
};

// Method names used in the nterp_chain_pick test.
// Indices from sample.dex: 0=<init> 1=add 2=greet 5=StringBuilder.append
#define METHOD0_NAME "com.ares.Sample.add"
#define METHOD1_NAME "com.ares.Sample.greet"
#define METHOD2_NAME "com.ares.Sample.<init>"
#define STALE_NAME   "java.lang.StringBuilder.append"

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
    CHECK(art_method_resolve(memrd, &m, &T_OFF, AM, out, sizeof(out)) == 1 &&
          strcmp(out, "com.ares.Sample.greet") == 0,
          "ArtMethod chase resolves greet");

    // TBI-tagged native pointers: DexCache.dex_file_ and DexFile.begin_ carry an
    // Android top-byte tag on some targets. They must be untagged before deref
    // (/proc/mem rejects tagged addresses) — regression for the tagged-DexFile bug
    // that made nterp naming silently resolve nothing on such targets.
    {
        const uint64_t TAG = 0xb4ULL << 56;
        uint8_t dc_t[32] = {0}; w64(dc_t + O_DC_DF, TAG | DF);
        uint8_t df_t[48] = {0}; w64(df_t + O_DF_BEGIN, TAG | BEGIN);
                                w64(df_t + O_DF_SIZE, dexlen);
        struct mem mt = m;      // regions: 0=AM 1=C 2=DC 3=DF 4=BEGIN
        mt.r[2].data = dc_t;
        mt.r[3].data = df_t;
        art_nterp_cache_reset();
        CHECK(art_method_resolve(memrd, &mt, &T_OFF, AM, out, sizeof(out)) == 1 &&
              strcmp(out, "com.ares.Sample.greet") == 0,
              "TBI-tagged DexFile/begin pointers untagged -> chase resolves");
    }
    art_nterp_cache_reset();

    // Misaligned / tiny pointer -> rejected before any read.
    CHECK(art_method_resolve(memrd, &m, &T_OFF, AM + 1, out, sizeof(out)) == 0,
          "misaligned ArtMethod -> miss");
    CHECK(art_method_resolve(memrd, &m, &T_OFF, 0x10, out, sizeof(out)) == 0,
          "implausible low ArtMethod -> miss");

    // declaring_class_ == 0 -> miss (no class to chase).
    { uint8_t am0[16] = {0}; w32(am0 + O_MIDX, greet_idx);
      struct mem m2 = m; m2.r[0].data = am0;
      CHECK(art_method_resolve(memrd, &m2, &T_OFF, AM, out, sizeof(out)) == 0,
            "null declaring_class -> miss"); }

    // Candidate that points into unmapped memory -> short read -> miss, no crash.
    CHECK(art_method_resolve(memrd, &m, &T_OFF, 0x900000, out, sizeof(out)) == 0,
          "unmapped ArtMethod -> miss");

    // Cached second lookup still resolves (exercises the DexFile image cache).
    CHECK(art_method_resolve(memrd, &m, &T_OFF, AM, out, sizeof(out)) == 1 &&
          strcmp(out, "com.ares.Sample.greet") == 0,
          "second lookup hits dex cache, still resolves");

    // DexFile size sanity: a target-supplied size of 0 or an absurd size must be
    // rejected before reading the image (don't trust the target's size blindly).
    { uint8_t df0[48]; memcpy(df0, df, sizeof(df0)); w64(df0 + O_DF_SIZE, 0);
      struct mem mz = m; mz.r[3].data = df0;
      art_nterp_cache_reset();
      CHECK(art_method_resolve(memrd, &mz, &T_OFF, AM, out, sizeof(out)) == 0,
            "zero dex size -> miss"); }
    { uint8_t dfb[48]; memcpy(dfb, df, sizeof(dfb)); w64(dfb + O_DF_SIZE, 1ull << 30);
      struct mem mb = m; mb.r[3].data = dfb;
      art_nterp_cache_reset();
      CHECK(art_method_resolve(memrd, &mb, &T_OFF, AM, out, sizeof(out)) == 0,
            "absurd dex size -> miss"); }

    // ---- nterp_pick: dex_pc corroboration picks the right method ----------------
    // Second synthetic ArtMethod resolving a DIFFERENT method (add) — the stale
    // pointer that must NOT win despite sitting closer to nterp_sp.
    uint32_t add_i = idx_of2(dex, dexlen, "com.ares.Sample.add");
    const uint64_t AM_ADD = 0x5000;
    uint8_t am_add[16] = {0};
    w32(am_add + O_DECL, (uint32_t)C);
    w32(am_add + O_MIDX, add_i);
    add_region(&m, AM_ADD, am_add, sizeof(am_add));

    // Synthetic stack: stale add-ArtMethod* closer to nterp_sp (no dex_pc beside it);
    // real greet-ArtMethod* farther up WITH a matching dex_pc just above it.
    const uint64_t STK = 0x7000000000ULL, NSP = STK + 0x40;
    uint8_t stack[0x400] = {0};
    w64(stack + (size_t)((NSP + 0x10) - STK), AM_ADD);          // stale (add)
    w64(stack + (size_t)((NSP + 0x80) - STK), AM);              // real (greet)
    w64(stack + (size_t)((NSP + 0x88) - STK), BEGIN + 0x190);   // greet dex_pc

    char pk[256];
    art_nterp_cache_reset();
    CHECK(nterp_pick(memrd, &m, &T_OFF, stack, STK, sizeof(stack), NSP, pk, sizeof(pk)) == 1 &&
          strcmp(pk, "com.ares.Sample.greet+0x6") == 0,
          "nterp_pick corroborates greet (not stale add) + dexpc suffix");

    // Fallback: only the stale add ArtMethod*, no dex_pc anywhere -> bare name.
    uint8_t stack2[0x400] = {0};
    w64(stack2 + (size_t)((NSP + 0x10) - STK), AM_ADD);
    art_nterp_cache_reset();
    CHECK(nterp_pick(memrd, &m, &T_OFF, stack2, STK, sizeof(stack2), NSP, pk, sizeof(pk)) == 1 &&
          strcmp(pk, "com.ares.Sample.add") == 0,
          "nterp_pick falls back to bare name when uncorroborated");

    // No candidate at all -> miss.
    uint8_t stack3[0x400] = {0};
    art_nterp_cache_reset();
    CHECK(nterp_pick(memrd, &m, &T_OFF, stack3, STK, sizeof(stack3), NSP, pk, sizeof(pk)) == 0,
          "nterp_pick returns 0 with no ArtMethod candidate");

    // Nearest corroborated wins: add (nearer, corroborated) and greet (farther,
    // corroborated) are both on the stack with a matching dex_pc beside each;
    // assert the nearer-to-nterp_sp candidate (add) is returned.
    // add [0x170,0x174): dex_pc 0x170 -> dexpc=(0x170-0x170)/2=0 -> "+0x0"
    // greet [0x184,0x1ac): dex_pc 0x190 -> dexpc=(0x190-0x184)/2=6 -> "+0x6"
    uint8_t stack4[0x400] = {0};
    w64(stack4 + (size_t)((NSP + 0x10) - STK), AM_ADD);         /* add  (nearer, corroborated) */
    w64(stack4 + (size_t)((NSP + 0x18) - STK), BEGIN + 0x170);  /* add  dex_pc -> +0x0 */
    w64(stack4 + (size_t)((NSP + 0x80) - STK), AM);             /* greet (farther, corroborated) */
    w64(stack4 + (size_t)((NSP + 0x88) - STK), BEGIN + 0x190);  /* greet dex_pc -> +0x6 */
    art_nterp_cache_reset();
    CHECK(nterp_pick(memrd, &m, &T_OFF, stack4, STK, sizeof(stack4), NSP, pk, sizeof(pk)) == 1 &&
          strcmp(pk, "com.ares.Sample.add+0x0") == 0,
          "nterp_pick: nearest corroborated (add+0x0) wins over farther corroborated (greet+0x6)");

    // ---- nterp_chain_pick: 3-frame chain with one interleaved stale ---------------
    // Frame layout ascending from NSP (innermost-first == lowest offset):
    //   NSP+0x10: AM_ADD  (add,   METHOD0) + dex_pc BEGIN+0x170 at NSP+0x18 -> +0x0
    //   NSP+0x60: AM_STALE (StringBuilder.append) — valid chase, no bytecode range
    //             in sample.dex so corroboration always fails: dropped
    //   NSP+0x80: AM      (greet, METHOD1) + dex_pc BEGIN+0x190 at NSP+0x88 -> +0x6
    //   NSP+0x100: AM_INIT (<init>, METHOD2) + dex_pc BEGIN+0x1bc at NSP+0x108 -> +0x0
    uint32_t init_i = idx_of2(dex, dexlen, METHOD2_NAME);

    const uint64_t AM_INIT = 0x8000;
    uint8_t am_init[16] = {0};
    w32(am_init + O_DECL, (uint32_t)C);
    w32(am_init + O_MIDX, init_i);
    add_region(&m, AM_INIT, am_init, sizeof(am_init));

    // Stale: midx=5 (java.lang.StringBuilder.append) has no bytecode in sample.dex,
    // so dex_lookup_range never matches rmidx==5 — corroboration always fails.
    const uint64_t AM_STALE = 0x9000;
    uint8_t am_stale[16] = {0};
    w32(am_stale + O_DECL, (uint32_t)C);
    w32(am_stale + O_MIDX, 5);                /* StringBuilder.append */
    add_region(&m, AM_STALE, am_stale, sizeof(am_stale));

    uint8_t stack_chain[0x400] = {0};
    w64(stack_chain + (size_t)((NSP + 0x10)  - STK), AM_ADD);          /* f0: add   */
    w64(stack_chain + (size_t)((NSP + 0x18)  - STK), BEGIN + 0x170);   /* f0 dex_pc -> add+0x0   */
    w64(stack_chain + (size_t)((NSP + 0x60)  - STK), AM_STALE);        /* stale: no dex_pc       */
    w64(stack_chain + (size_t)((NSP + 0x80)  - STK), AM);              /* f1: greet */
    w64(stack_chain + (size_t)((NSP + 0x88)  - STK), BEGIN + 0x190);   /* f1 dex_pc -> greet+0x6 */
    w64(stack_chain + (size_t)((NSP + 0x100) - STK), AM_INIT);         /* f2: <init>             */
    w64(stack_chain + (size_t)((NSP + 0x108) - STK), BEGIN + 0x1bc);   /* f2 dex_pc -> <init>+0x0 */

    char chain[8][256];
    art_nterp_cache_reset();
    int nc = nterp_chain_pick(memrd, &m, &T_OFF, stack_chain, STK, sizeof(stack_chain), NSP,
                              chain, 8);
    CHECK(nc == 3, "three corroborated frames");
    CHECK(nc > 0 && strstr(chain[0], METHOD0_NAME) && strstr(chain[0], "+0x"),
          "f0 named + dexpc");
    CHECK(nc > 1 && strstr(chain[1], METHOD1_NAME), "f1 named");
    CHECK(nc > 2 && strstr(chain[2], METHOD2_NAME), "f2 named");
    for (int i = 0; i < nc; i++)
        CHECK(!strstr(chain[i], STALE_NAME), "stale skipped");

    art_nterp_cache_reset();
    free(dex);
    printf("%s: %d checks, %d failures\n", argv[0], checks, failures);
    return failures ? 1 : 0;
}
