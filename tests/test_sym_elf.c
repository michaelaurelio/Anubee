// SPDX-License-Identifier: GPL-2.0
// Host-compilable unit tests for common/sym_elf.c's ELF bounds-checking fixes
// (AUDIT.md C1, C2): the shared elf_shtab_in_bounds() helper, and add_symbols()'s
// NUL-termination check over the untrusted ELF string table.
#include <sys/types.h>
#include "common/symbolize_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks = 0, failures = 0;

#define CHECK(cond, msg) do {                                 \
    checks++;                                                 \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

int main(void)
{
    // --- elf_shtab_in_bounds (AUDIT.md C2) ---
    CHECK(elf_shtab_in_bounds(64, 10, sizeof(Elf64_Shdr), 4096) == 1,
          "shtab_in_bounds: normal in-bounds table");
    CHECK(elf_shtab_in_bounds((uint64_t)-4, 10, sizeof(Elf64_Shdr), 4096) == 0,
          "shtab_in_bounds: e_shoff near UINT64_MAX rejected (no overflow wrap)");

    // --- add_symbols (AUDIT.md C1): unterminated name near end of strtab ---
    {
        struct dynsym ds;
        memset(&ds, 0, sizeof(ds));

        char str[16];
        memset(str, 'A', sizeof(str)); // no NUL anywhere in the buffer

        Elf64_Sym sym;
        memset(&sym, 0, sizeof(sym));
        sym.st_name  = sizeof(str) - 2; // < strn, but no NUL from here to end
        sym.st_value = 0x1000;
        sym.st_shndx = 1;
        sym.st_info  = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);

        add_symbols(&ds, &sym, sizeof(sym), sizeof(sym), str, sizeof(str));
        CHECK(ds.ns == 0, "add_symbols: unterminated name skipped, no crash");

        free(ds.s);
        free(ds.str);
    }

    // --- add_symbols: properly NUL-terminated name is still accepted ---
    {
        struct dynsym ds;
        memset(&ds, 0, sizeof(ds));

        char str[16];
        memset(str, 0, sizeof(str));
        strcpy(str + 2, "fn"); // "fn\0" at offset 2

        Elf64_Sym sym;
        memset(&sym, 0, sizeof(sym));
        sym.st_name  = 2;
        sym.st_value = 0x2000;
        sym.st_shndx = 1;
        sym.st_info  = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);

        add_symbols(&ds, &sym, sizeof(sym), sizeof(sym), str, sizeof(str));
        CHECK(ds.ns == 1, "add_symbols: valid NUL-terminated name accepted");
        if (ds.ns == 1)
            CHECK(strcmp(ds.str + ds.s[0].name_off, "fn") == 0,
                  "add_symbols: name retrievable from arena");

        free(ds.s);
        free(ds.str);
    }

    printf("\n%s: %d checks, %d failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
