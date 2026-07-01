// SPDX-License-Identifier: GPL-2.0
#include "common/art_buildid.h"
#include "common/maps.h"        // ares_parse_maps_line, struct ares_map_line
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Known ART builds. Offsets are spike-verified; see
// docs/superpowers/research/2026-07-02-managed-stack-walk-spike-findings.md.
static const struct { const char *id; struct art_offsets off; } k_table[] = {
    { "1f156fc62660d075a8d675db850b95d5",
      { .tls_thread_slot = 0x38, .managed_stack = 0xA8, .ms_link = 0x08,
        .ms_top_shadow = 0x10, .sf_link = 0x00, .sf_method = 0x08,
        .sf_dex_pc_ptr = 0x18, .sf_dex_instr = 0x20 } },
};

const struct art_offsets *art_offsets_for_buildid(const char *hexid)
{
    if (!hexid) return NULL;
    for (size_t i = 0; i < sizeof(k_table)/sizeof(k_table[0]); i++)
        if (strcmp(hexid, k_table[i].id) == 0)
            return &k_table[i].off;
    return NULL;
}

// Read the ELF .note.gnu.build-id from a file, format as lowercase hex.
// Returns 1 on success. Small, self-contained ELF64 note scan.
static int read_build_id_hex(const char *path, char *out, size_t outsz)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    int ok = 0;
    unsigned char e[64];
    if (fread(e, 1, sizeof e, f) != sizeof e || memcmp(e, "\x7f""ELF", 4) != 0) { fclose(f); return 0; }
    // ELF64: e_shoff@0x28, e_shentsize@0x3a, e_shnum@0x3c
    uint64_t shoff; memcpy(&shoff, e + 0x28, 8);
    uint16_t shentsize, shnum;
    memcpy(&shentsize, e + 0x3a, 2); memcpy(&shnum, e + 0x3c, 2);
    for (uint16_t i = 0; i < shnum && !ok; i++) {
        unsigned char sh[64];
        if (fseek(f, (long)(shoff + (uint64_t)i * shentsize), SEEK_SET) != 0) break;
        if (fread(sh, 1, shentsize < sizeof sh ? shentsize : sizeof sh, f) != (shentsize < sizeof sh ? shentsize : sizeof sh)) break;
        uint32_t sh_type; memcpy(&sh_type, sh + 0x04, 4);
        if (sh_type != 7 /*SHT_NOTE*/) continue;
        uint64_t off, size; memcpy(&off, sh + 0x18, 8); memcpy(&size, sh + 0x20, 8);
        if (size == 0 || size > 4096) continue;
        unsigned char nb[4096];
        if (fseek(f, (long)off, SEEK_SET) != 0) break;
        if (fread(nb, 1, size, f) != size) break;
        // walk notes: namesz@0, descsz@4, type@8, name(namesz, 4-aligned), desc(descsz)
        size_t p = 0;
        while (p + 12 <= size) {
            uint32_t namesz, descsz, type;
            memcpy(&namesz, nb + p, 4); memcpy(&descsz, nb + p + 4, 4); memcpy(&type, nb + p + 8, 4);
            size_t name_off = p + 12, desc_off = name_off + ((namesz + 3) & ~3u);
            if (type == 3 /*NT_GNU_BUILD_ID*/ && descsz > 0 && desc_off + descsz <= size) {
                if (descsz * 2 + 1 > outsz) break;
                for (uint32_t b = 0; b < descsz; b++)
                    snprintf(out + b * 2, 3, "%02x", nb[desc_off + b]);
                ok = 1; break;
            }
            p = desc_off + ((descsz + 3) & ~3u);
        }
    }
    fclose(f);
    return ok;
}

const struct art_offsets *art_buildid_offsets(int pid)
{
    char maps[64];
    snprintf(maps, sizeof maps, "/proc/%d/maps", pid);
    FILE *f = fopen(maps, "r");
    if (!f) return NULL;
    char line[512], libart[256] = {0};
    while (fgets(line, sizeof line, f)) {
        struct ares_map_line ml;
        if (ares_parse_maps_line(line, &ml) && ml.path[0] &&
            strstr(ml.path, "/libart.so")) {
            snprintf(libart, sizeof libart, "%s", ml.path);
            break;
        }
    }
    fclose(f);
    if (!libart[0]) return NULL;
    char hex[64];
    if (!read_build_id_hex(libart, hex, sizeof hex)) return NULL;
    return art_offsets_for_buildid(hex);
}
