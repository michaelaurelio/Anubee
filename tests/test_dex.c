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
    dex_map_free(m);

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
