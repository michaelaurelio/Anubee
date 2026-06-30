// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the DEX offset->method resolver. Uses a committed real
// .dex fixture (tests/fixtures/sample.dex: class com.ares.Sample) whose method
// insns offsets were read from `dexdump -d` (see tests/fixtures/README.md).
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

static uint8_t *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fprintf(stderr, "empty fixture\n"); exit(2); }
    uint8_t *buf = malloc((size_t)n);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) { exit(2); }
    fclose(f);
    *len = (size_t)n;
    return buf;
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "tests/fixtures/sample.dex";
    size_t len;
    uint8_t *img = slurp(path, &len);

    // build succeeds on the real fixture; the map must not alias img.
    struct dex_method_map *m = dex_map_build(img, len);
    CHECK(m != NULL, "build succeeds on real fixture");
    free(img);
    img = NULL;

    // Real insns ranges from the committed fixture (see tests/fixtures/README.md):
    //   add [0x170,0x174)  greet [0x184,0x1ac)  <init> [0x1bc,0x1c4)
    char out[256];
    CHECK(dex_map_lookup(m, 0x172, out, sizeof(out)) == 1 &&
          strcmp(out, "com.ares.Sample.add") == 0, "0x172 -> add");
    CHECK(dex_map_lookup(m, 0x190, out, sizeof(out)) == 1 &&
          strcmp(out, "com.ares.Sample.greet") == 0, "0x190 -> greet");
    CHECK(dex_map_lookup(m, 0x1c0, out, sizeof(out)) == 1 &&
          strcmp(out, "com.ares.Sample.<init>") == 0, "0x1c0 -> <init>");
    CHECK(dex_map_lookup(m, 0x10, out, sizeof(out)) == 0, "0x10 header -> miss");
    CHECK(dex_map_lookup(m, 0x180, out, sizeof(out)) == 0, "0x180 gap -> miss");
    CHECK(dex_map_lookup(m, 0x300, out, sizeof(out)) == 0, "0x300 past-last -> miss");

    // dex_name_by_index: every method reachable by index resolves to its name.
    {
        int saw_add = 0, saw_greet = 0, saw_init = 0;
        char nb[256];
        for (uint32_t idx = 0; idx < 4096; idx++) {
            if (dex_name_by_index(m, idx, nb, sizeof(nb)) != 1)
                continue;
            if (strcmp(nb, "com.ares.Sample.add") == 0)    saw_add = 1;
            if (strcmp(nb, "com.ares.Sample.greet") == 0)   saw_greet = 1;
            if (strcmp(nb, "com.ares.Sample.<init>") == 0)  saw_init = 1;
        }
        CHECK(saw_add,   "dex_name_by_index resolves add");
        CHECK(saw_greet, "dex_name_by_index resolves greet");
        CHECK(saw_init,  "dex_name_by_index resolves <init>");
        // out-of-range index -> miss, no crash, out untouched-as-miss.
        CHECK(dex_name_by_index(m, 0xffffffu, nb, sizeof(nb)) == 0,
              "dex_name_by_index out-of-range -> miss");
        // tiny buffer -> miss (overflow guarded).
        char tiny[4];
        CHECK(dex_name_by_index(m, 0, tiny, sizeof(tiny)) == 0 ||
              strlen(tiny) < sizeof(tiny),
              "dex_name_by_index respects buffer bound");
    }

    dex_map_free(m);

    // truncated buffer (cut mid-class_data) -> build NULL or lookup miss, no crash.
    { size_t l3; uint8_t *i3 = slurp(path, &l3);
      size_t cut = l3 > 0x150 ? 0x150 : l3 / 2;
      struct dex_method_map *t = dex_map_build(i3, cut);
      if (t) { dex_map_lookup(t, 0x172, out, sizeof(out)); dex_map_free(t); }
      free(i3);
      CHECK(1, "truncated build/lookup does not crash"); }

    // corrupt every string_data_off to point out of bounds -> name resolution
    // fails -> lookup returns 0, no overread (the range hit still happens).
    { size_t l4; uint8_t *i4 = slurp(path, &l4);
      uint32_t sids_off = (uint32_t)i4[60] | ((uint32_t)i4[61] << 8) |
                          ((uint32_t)i4[62] << 16) | ((uint32_t)i4[63] << 24);
      uint32_t sids_sz  = (uint32_t)i4[56] | ((uint32_t)i4[57] << 8) |
                          ((uint32_t)i4[58] << 16) | ((uint32_t)i4[59] << 24);
      uint32_t bad = (uint32_t)l4 + 1000;
      for (uint32_t k = 0; k < sids_sz; k++) {
          uint8_t *e = i4 + sids_off + (size_t)k * 4;
          e[0] = (uint8_t)bad; e[1] = (uint8_t)(bad >> 8);
          e[2] = (uint8_t)(bad >> 16); e[3] = (uint8_t)(bad >> 24);
      }
      struct dex_method_map *cm = dex_map_build(i4, l4);
      CHECK(cm != NULL, "build ok with corrupt strings (ranges still valid)");
      if (cm) {
          CHECK(dex_map_lookup(cm, 0x172, out, sizeof(out)) == 0,
                "corrupt string_data_off -> miss, no overread");
          dex_map_free(cm);
      }
      free(i4); }

    // malformed header: corrupt the magic -> build returns NULL.
    { size_t l2; uint8_t *i2 = slurp(path, &l2);
      i2[1] = 'X';   // "dXx\n..." -> bad magic
      struct dex_method_map *bad = dex_map_build(i2, l2);
      CHECK(bad == NULL, "bad magic -> NULL");
      dex_map_free(bad);
      free(i2); }

    // too short for a header -> build returns NULL.
    { uint8_t tiny[16] = {'d','e','x','\n','0','3','5',0};
      CHECK(dex_map_build(tiny, sizeof(tiny)) == NULL, "short buffer -> NULL"); }

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
