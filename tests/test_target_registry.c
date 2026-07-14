// Host unit test for src/common/target_registry.c — the shared addr->symbol
// resolver lifted out of funcs.c so correlate.c can also name its span-
// opening [func] lines (mod!func) instead of a bare runtime address. The
// hash cache and lower-12-bit ASLR fallback are moved verbatim from funcs.c
// (unchanged behavior); this test drives the direct (offset, mod_path) match
// path against a real /proc/self/maps entry, since that's the path both
// funcs and correlate hit on every resolved span/call.
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common/maps.h"
#include "common/target_registry.h"

int main(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { printf("skip: /proc/self/maps unavailable\n"); return 0; }

    struct ares_map_line ml;
    int found = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        struct ares_map_line cur;
        if (!ares_parse_maps_line(line, &cur)) continue;
        if (!cur.exec || cur.path[0] != '/') continue;
        ml = cur;
        found = 1;
        break;
    }
    fclose(f);
    if (!found) { printf("skip: no executable file-backed mapping in /proc/self/maps\n"); return 0; }

    probe_target_t tgt;
    memset(&tgt, 0, sizeof(tgt));
    tgt.pid = getpid();
    snprintf(tgt.mod_path, sizeof(tgt.mod_path), "%s", ml.path);
    tgt.offset = (unsigned long)ml.off;
    snprintf(tgt.func_name, sizeof(tgt.func_name), "test_fn");

    int before = target_registry_count;
    assert(target_registry_add(tgt));
    assert(target_registry_count == before + 1);

    // entry_addr = ml.start + 0 maps back to file_offset == ml.off, i.e.
    // exactly the target we just registered — the direct-match path (no
    // ASLR fallback needed).
    bool used_fallback = true;
    probe_target_t *got = find_target_by_entry_addr(ml.start, getpid(), &used_fallback);
    assert(got != NULL);
    assert(!used_fallback);
    assert(strcmp(got->mod_path, ml.path) == 0);
    assert(strcmp(got->func_name, "test_fn") == 0);

    // Same address again must hit the hash cache (still resolves, no crash).
    used_fallback = true;
    probe_target_t *got2 = find_target_by_entry_addr(ml.start, getpid(), &used_fallback);
    assert(got2 == got);
    assert(!used_fallback);

    // A pid with no such mapping (pid 1, unlikely to share this exact
    // module+offset) must miss cleanly, not crash.
    bool uf2 = false;
    find_target_by_entry_addr(0xdeadbeef0000ULL, 1, &uf2);

    printf("all checks passed\n");
    return 0;
}
