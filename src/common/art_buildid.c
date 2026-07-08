// SPDX-License-Identifier: GPL-2.0
#include "common/art_buildid.h"
#include "common/maps.h"        // ares_parse_maps_line, struct ares_map_line
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>      // getenv, strtoull

// Known ART builds. Offsets are spike-verified; see
// docs/superpowers/research/2026-07-02-managed-stack-walk-spike-findings.md.
static const struct { const char *id; struct art_offsets off; } k_table[] = {
    { "1f156fc62660d075a8d675db850b95d5",
      { .tls_thread_slot = 0x38, .managed_stack = 0xA8, .ms_link = 0x08,
        .ms_top_shadow = 0x10, .sf_link = 0x00, .sf_method = 0x08,
        .sf_dex_pc_ptr = 0x18,
        .artm_declclass = 0x00, .artm_dexidx = 0x08, .class_dexcache = 0x10,
        .dexcache_dexfile = 0x10, .dexfile_begin = 0x08, .dexfile_datasize = 0x20 } },
};

// Trim leading/trailing spaces/tabs/CR of [s, e): returns first non-space; writes
// '\0' after the last non-space.
static char *trim(char *s, char *e)
{
    while (s < e && (*s == ' ' || *s == '\t')) s++;
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r')) e--;
    *e = '\0';
    return s;
}

/* Set once when an unknown libart BuildID disables managed naming this run.
 * Read by ares_art_naming_disabled() for the CR5 coverage record. */
static int g_naming_disabled = 0;

int art_offsets_parse(const char *text, char *buildid_out, size_t bidsz,
                      struct art_offsets *out)
{
    struct { const char *k; uint64_t *v; } F[] = {
        {"tls_thread_slot", &out->tls_thread_slot}, {"managed_stack", &out->managed_stack},
        {"ms_link", &out->ms_link}, {"ms_top_shadow", &out->ms_top_shadow},
        {"sf_link", &out->sf_link}, {"sf_method", &out->sf_method},
        {"sf_dex_pc_ptr", &out->sf_dex_pc_ptr}, {"artm_declclass", &out->artm_declclass},
        {"artm_dexidx", &out->artm_dexidx}, {"class_dexcache", &out->class_dexcache},
        {"dexcache_dexfile", &out->dexcache_dexfile}, {"dexfile_begin", &out->dexfile_begin},
        {"dexfile_datasize", &out->dexfile_datasize},
    };
    const int NF = (int)(sizeof F / sizeof F[0]);   /* 13 */
    unsigned seen = 0;
    int have_bid = 0;

    const char *p = text;
    char line[256];
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len >= sizeof line) len = sizeof line - 1;
        memcpy(line, p, len); line[len] = '\0';
        p = nl ? nl + 1 : p + strlen(p);

        char *ls = trim(line, line + strlen(line));
        if (*ls == '\0' || *ls == '#') continue;         /* blank / comment */
        char *eq = strchr(ls, '=');
        if (!eq) return 0;                                /* malformed line */
        char *key = trim(ls, eq);
        char *val = trim(eq + 1, ls + strlen(ls));
        if (strcmp(key, "buildid") == 0) {
            snprintf(buildid_out, bidsz, "%s", val);
            have_bid = 1;
            continue;
        }
        int hit = -1;
        for (int i = 0; i < NF; i++) if (strcmp(key, F[i].k) == 0) { hit = i; break; }
        if (hit < 0) return 0;                            /* unknown key */
        char *end = NULL;
        unsigned long long v = strtoull(val, &end, 0);
        if (end == val || (end && *end != '\0')) return 0; /* bad number */
        *F[hit].v = (uint64_t)v;
        seen |= 1u << hit;
    }
    return have_bid && seen == ((1u << NF) - 1);
}

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
// Test seam: exposed (not static) so test_art_buildid.c can drive it directly.
int read_build_id_hex(const char *path, char *out, size_t outsz)
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
    // sh_type/off/size below are read at fixed offsets up to 0x28; a shentsize
    // that short would leave them reading uninitialized `sh[]` bytes.
    if (shentsize < 0x28) { fclose(f); return 0; }
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

// Lazily (once per process) parse the ARES_ART_OFFSETS file, if set. Return its offsets
// iff the parsed BuildID matches `target_hex`; else NULL (caller falls back to k_table).
static const struct art_offsets *override_lookup(const char *target_hex)
{
    static int inited = 0, valid = 0;
    static char ov_bid[64];
    static struct art_offsets ov;
    if (!inited) {
        inited = 1;
        const char *path = getenv("ARES_ART_OFFSETS");
        if (path) {
            FILE *f = fopen(path, "rb");
            if (!f) {
                fprintf(stderr, "[ares] ARES_ART_OFFSETS open failed (%s); ignoring\n", path);
            } else {
                char buf[4096];
                size_t n = fread(buf, 1, sizeof buf - 1, f);
                buf[n] = '\0';
                fclose(f);
                if (art_offsets_parse(buf, ov_bid, sizeof ov_bid, &ov))
                    valid = 1;
                else
                    fprintf(stderr, "[ares] ARES_ART_OFFSETS parse failed; ignoring\n");
            }
        }
    }
    if (valid && target_hex && strcmp(ov_bid, target_hex) == 0) {
        static int noted = 0;
        if (!noted) {
            noted = 1;
            fprintf(stderr, "[ares] using ARES_ART_OFFSETS override for libart BuildID %s\n",
                    target_hex);
        }
        return &ov;
    }
    return NULL;
}

const struct art_offsets *art_buildid_offsets(int pid)
{
    static int   cache_pid = -2;               /* -2 = never resolved */
    static const struct art_offsets *cache_off = NULL;
    if (pid == cache_pid)
        return cache_off;

    const struct art_offsets *o = NULL;
    char hex[64] = {0};

    char maps[64];
    snprintf(maps, sizeof maps, "/proc/%d/maps", pid);
    FILE *f = fopen(maps, "r");
    if (f) {
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
        if (libart[0] && read_build_id_hex(libart, hex, sizeof hex)) {
            o = override_lookup(hex);          /* candidate row wins for a matching BuildID */
            if (!o)
                o = art_offsets_for_buildid(hex);
        }
    }

    cache_pid = pid;
    cache_off = o;

    /* Warn once — only when a BuildID was actually read but is not in the table
     * (a genuinely unrecognized ART build). A transient pid whose libart could
     * not be read (hex empty) is an expected miss, not an unknown build, so it
     * must not raise the "naming disabled" alarm. */
    if (!o && hex[0]) {
        if (!g_naming_disabled) {
            g_naming_disabled = 1;
            fprintf(stderr,
                "[ares] libart BuildID %s not in offset table; managed-frame "
                "naming disabled (add a k_table row).\n",
                hex);
        }
    }
    return o;
}

int ares_art_naming_disabled(void)
{
    return g_naming_disabled;
}
