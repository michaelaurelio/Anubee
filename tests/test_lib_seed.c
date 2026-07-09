// Host unit test for the syscalls lib-filter maps-seed predicate (lib-filter
// attribution defect fix, BACKLOG.md).
#include <stdio.h>
#include <string.h>
#include "syscalls/lib_seed.h"

static int failures;
#define CHECK(cond) do { \
    if (cond) { printf("  ok: %s\n", #cond); } \
    else { printf("  FAIL: %s\n", #cond); failures++; } \
} while (0)

static struct ares_map_line line(const char *path, int exec)
{
    struct ares_map_line ml = {0};
    ml.exec = exec;
    snprintf(ml.path, sizeof(ml.path), "%s", path);
    return ml;
}

int main(void)
{
    struct ares_map_line l;

    // Executable libc.so, exact substring selector -> arms.
    l = line("/apex/com.android.runtime/lib64/bionic/libc.so", 1);
    CHECK(lib_seed_line_arms(&l, "libc.so") == 1);

    // Same mapping, but not executable (e.g. .rodata segment) -> skip.
    l = line("/apex/com.android.runtime/lib64/bionic/libc.so", 0);
    CHECK(lib_seed_line_arms(&l, "libc.so") == 0);

    // Executable, but a different library -> skip.
    l = line("/system/lib64/libother.so", 1);
    CHECK(lib_seed_line_arms(&l, "libc.so") == 0);

    // Glob selector matches on basename only, not the directory.
    l = line("/data/app/~~x/base.apk!/lib/arm64-v8a/libe_1234.so", 1);
    CHECK(lib_seed_line_arms(&l, "libe_*") == 1);
    l = line("/data/app/~~x/base.apk!/lib/arm64-v8a/libe_1234.so", 1);
    CHECK(lib_seed_line_arms(&l, "libe_[0-9]*") == 1);

    // Anonymous/special mapping (empty path) -> skip regardless of exec.
    l = line("", 1);
    CHECK(lib_seed_line_arms(&l, "libc.so") == 0);

    // Empty selector -> never arms (mirrors lib_name_matches's g_lib[0] guard).
    l = line("/system/lib64/libc.so", 1);
    CHECK(lib_seed_line_arms(&l, "") == 0);

    if (failures) { printf("FAILED: %d check(s)\n", failures); return 1; }
    printf("test_lib_seed: all checks passed\n");
    return 0;
}
