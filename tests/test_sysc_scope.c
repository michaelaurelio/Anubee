// Host unit test for src/syscalls/scope.h: the pure parsing/validation
// helpers behind syscall:LIBPATTERN!NAME per-syscall library scoping.
#include "syscalls/scope.h"
#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(cond) do { \
    if (cond) { printf("  ok: %s\n", #cond); } \
    else { printf("  FAIL: %s\n", #cond); failures++; } \
} while (0)

int main(void)
{
    char libpat[256], name[64];

    // Scoped: "LIBPATTERN!NAME" splits on the first '!'.
    CHECK(sysc_scope_split("libc.so!openat", libpat, sizeof(libpat), name, sizeof(name)) == 1);
    CHECK(strcmp(libpat, "libc.so") == 0);
    CHECK(strcmp(name, "openat") == 0);

    // Regex library pattern (mirrors funcs:'s existing "/lib.*/!open" case) —
    // the '/'-delimited regex itself has no '!' in practice, so the first '!'
    // is still the correct, unambiguous split point.
    CHECK(sysc_scope_split("/lib.*\\.so/!read", libpat, sizeof(libpat), name, sizeof(name)) == 1);
    CHECK(strcmp(libpat, "/lib.*\\.so/") == 0);
    CHECK(strcmp(name, "read") == 0);

    // Unscoped: no '!' at all -> 0, untouched.
    CHECK(sysc_scope_split("openat", libpat, sizeof(libpat), name, sizeof(name)) == 0);

    // Malformed: '!' present but one side is empty.
    CHECK(sysc_scope_split("libc.so!", libpat, sizeof(libpat), name, sizeof(name)) == -1);
    CHECK(sysc_scope_split("!openat", libpat, sizeof(libpat), name, sizeof(name)) == -1);
    CHECK(sysc_scope_split("!", libpat, sizeof(libpat), name, sizeof(name)) == -1);

    // Malformed: doesn't fit the output buffer.
    {
        char tiny[4];
        CHECK(sysc_scope_split("libc.so!openat", tiny, sizeof(tiny), name, sizeof(name)) == -1);
        CHECK(sysc_scope_split("libc.so!openat", libpat, sizeof(libpat), tiny, sizeof(tiny)) == -1);
    }

    // -s/-x LIST membership, mirroring install_syscall_filter's own
    // tokenization (comma-separated, leading spaces per entry skipped).
    CHECK(sysc_list_contains("openat,read,write", "read") == true);
    CHECK(sysc_list_contains("openat, read, write", "read") == true);   // leading space
    CHECK(sysc_list_contains("openat,read,write", "close") == false);
    CHECK(sysc_list_contains("openat", "openat") == true);
    CHECK(sysc_list_contains("", "openat") == false);
    CHECK(sysc_list_contains(NULL, "openat") == false);
    // Substring-of-a-token must not false-positive (exact-token match only).
    CHECK(sysc_list_contains("openat64", "openat") == false);

    if (failures) { printf("FAILED: %d check(s)\n", failures); return 1; }
    printf("test_sysc_scope: all checks passed\n");
    return 0;
}
