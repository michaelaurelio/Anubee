// SPDX-License-Identifier: GPL-2.0
#include "common/probe_resolve.h"
#include "common/maps.h"
#include "common/pattern_match.h"

#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned long seg_vaddr_to_off(const struct load_seg *segs, int n,
                                unsigned long vaddr)
{
    for (int i = 0; i < n; i++) {
        if (vaddr >= segs[i].vaddr && vaddr < segs[i].vaddr + segs[i].filesz)
            return vaddr - segs[i].vaddr + segs[i].offset;
    }
    return SEG_VADDR_BAD; // not in any PT_LOAD; caller must skip this symbol
}

// Build a PT_LOAD table from the open Elf handle and convert vaddr to file
// offset. Cap at 32 segments (enough for any real .so); a vaddr outside all
// collected segments yields SEG_VADDR_BAD — caller skips, not wrong-offset attach.
static unsigned long vaddr_to_file_off(Elf *elf, unsigned long vaddr)
{
    size_t phnum;
    if (elf_getphdrnum(elf, &phnum) != 0)
        return SEG_VADDR_BAD;
    struct load_seg segs[32];
    int n = 0;
    for (size_t i = 0; i < phnum && n < 32; i++) {
        GElf_Phdr phdr;
        if (!gelf_getphdr(elf, (int)i, &phdr)) continue;
        if (phdr.p_type != PT_LOAD) continue;
        segs[n].vaddr  = (unsigned long)phdr.p_vaddr;
        segs[n].offset = (unsigned long)phdr.p_offset;
        segs[n].filesz = (unsigned long)phdr.p_filesz;
        n++;
    }
    return seg_vaddr_to_off(segs, n, vaddr);
}

static void copy_str(char *dst, const char *src, size_t dstsz)
{
    if (dstsz == 0)
        return;
    size_t n = strnlen(src, dstsz - 1);
    memcpy(dst, src, n);
    dst[n] = '\0';
}

bool mod_matches(const char *full_path, regex_t *re, bool *has_slash, int count)
{
    if (count == 0) return true;
    const char *target;

    for (int i = 0; i < count; i++) {
        if (has_slash[i]) {
            target = full_path;
        } else {
            target = strrchr(full_path, '/');
            target = target ? target + 1 : full_path;
        }
        if (regexec(&re[i], target, 0, NULL, 0) == 0) {
            return true;
        }
    }
    return false;
}

static bool func_matches(const char *func_name, regex_t *re, int count)
{
    if (count == 0) return true;

    for (int i = 0; i < count; i++) {
        if (regexec(&re[i], func_name, 0, NULL, 0) == 0) {
            return true;
        }
    }
    return false;
}

bool is_duplicate(probe_target_t *targets, int count, const char *mod_path, unsigned long offset)
{
    for (int i = 0; i < count; i++) {
        if (targets[i].offset == offset && strcmp(targets[i].mod_path, mod_path) == 0) {
            return true;
        }
    }
    return false;
}

int resolve_targets(const struct probe_resolve_ctx *ctx, pid_t pid,
                    probe_target_t *targets, int max_targets)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    if (ctx->verbose) ctx->log("  [scan] > opening %s\n", maps_path);

    FILE *f = fopen(maps_path, "r");
    if (!f) {
        ctx->log("  [scan] > fopen %s failed: %s\n", maps_path, strerror(errno));
        return -1;
    }

    char line[512];
    int count = 0;
    int n_rx = 0, n_matched = 0;

    while (fgets(line, sizeof(line), f) && count < max_targets) {
        struct ares_map_line ml;
        if (!ares_parse_maps_line(line, &ml)) continue;
        if (ml.path[0] != '/') continue;
        if (!ml.exec) continue;
        const char *path = ml.path;

        if (ctx->verbose) ctx->log("  [maps] > rx[%d]: %s\n", n_rx, path);
        n_rx++;

        if (!mod_matches(path, ctx->mod_re, ctx->mod_has_slash, ctx->mod_re_count)) {
            if (ctx->verbose) ctx->log("  [maps]   | skip (no -I match)\n");
            continue;
        }
        if (ctx->verbose) ctx->log("  [maps]   | match! opening ELF...\n");
        n_matched++;

        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            if (ctx->verbose) ctx->log("  [scan] > skip (open failed: %s)\n", strerror(errno));
            continue;
        }
        if (ctx->verbose) ctx->log("  [maps]   | ELF fd=%d, parsing sections...\n", fd);

        Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
        if (!elf) {
            if (ctx->verbose) ctx->log("  [scan]   | skip (not a valid ELF)\n");
            close(fd);
            continue;
        }

        Elf_Scn *scn = NULL;

        while ((scn = elf_nextscn(elf, scn)) != NULL && count < max_targets) {
            GElf_Shdr shdr;
            if (!gelf_getshdr(scn, &shdr)) continue;

            if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) continue;
            if (shdr.sh_entsize == 0) continue;

            Elf_Data *data = elf_getdata(scn, NULL);
            if (!data) continue;

            int num_symbols = shdr.sh_size / shdr.sh_entsize;
            if (ctx->verbose) ctx->log("  [scan]   | %s: %d symbols\n",
                shdr.sh_type == SHT_SYMTAB ? "SHT_SYMTAB" : "SHT_DYNSYM", num_symbols);

            for (int i = 0; i < num_symbols && count < max_targets; i++) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);

                if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue;
                if (sym.st_value == 0) continue;

                const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (!name || name[0] == '\0') continue;
                bool entry_match = func_matches(name, ctx->func_re, ctx->func_re_count);
                // When -r given but not -i, don't apply default "match all" for entry probes
                if (ctx->func_re_count == 0 && ctx->func_ret_re_count > 0) entry_match = false;
                bool ret_match = ctx->func_ret_re_count > 0 &&
                                 func_matches(name, ctx->func_ret_re, ctx->func_ret_re_count);
                if (!entry_match && !ret_match) continue;

                if (ctx->verbose) ctx->log(" [match] > %s!%s @ 0x%lx%s\n",
                    path, name, (unsigned long)sym.st_value,
                    (!entry_match && ret_match) ? " (ret-only)" : "");

                if (!is_duplicate(ctx->targets, *ctx->target_count + count, path, (unsigned long)sym.st_value)) {
                    unsigned long off = vaddr_to_file_off(elf, (unsigned long)sym.st_value);
                    if (off == SEG_VADDR_BAD) {
                        if (ctx->verbose) ctx->log("  [scan]   | skip %s: vaddr 0x%lx in no PT_LOAD\n", name, (unsigned long)sym.st_value);
                        continue;
                    }
                    targets[count].pid = pid;
                    copy_str(targets[count].mod_path, path, sizeof(targets[count].mod_path));
                    copy_str(targets[count].func_name, name, sizeof(targets[count].func_name));
                    targets[count].offset = off;
                    targets[count].arg_count = -1;
                    memset(targets[count].arg_types, 0, sizeof(targets[count].arg_types));
                    targets[count].ret_only = !entry_match && ret_match;
                    targets[count].ret_type = ret_match ? ARG_VAL : ARG_NONE;
                    count++;
                }
            }
        }
        elf_end(elf);
        close(fd);
        if (ctx->verbose) ctx->log("  [maps]   | ELF done, symbols so far: %d\n", count);
    }

    if (ctx->verbose) ctx->log("  [scan] > done: %d rx entries, %d matched, %d found\n",
        n_rx, n_matched, count);
    fclose(f);
    return count;
}

int resolve_targets_for_file(const struct probe_resolve_ctx *ctx,
                              pid_t pid, const char *path,
                              unsigned long map_start, unsigned long map_end,
                              probe_target_t *targets, int max_targets)
{
    if (ctx->verbose) ctx->log("  [scan] > %s (map event)\n", path);

    int fd = open(path, O_RDONLY);
    if (fd < 0 && map_start && map_end) {
        char map_files[80];
        ares_map_files_path(map_files, sizeof(map_files), pid, map_start, map_end);
        fd = open(map_files, O_RDONLY);
        if (fd >= 0 && ctx->verbose)
            ctx->log("  [scan] > opened via map_files (file deleted from fs)\n");
    }
    if (fd < 0) {
        if (ctx->verbose) ctx->log("  [scan] > skip (open failed: %s)\n", strerror(errno));
        return -1;
    }

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        if (ctx->verbose) ctx->log("  [scan]   | skip (not a valid ELF)\n");
        close(fd);
        return -1;
    }

    int count = 0;
    Elf_Scn *scn = NULL;

    while ((scn = elf_nextscn(elf, scn)) != NULL && count < max_targets) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) continue;

        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) continue;
        if (shdr.sh_entsize == 0) continue;

        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data) continue;

        int num_symbols = shdr.sh_size / shdr.sh_entsize;
        if (ctx->verbose) ctx->log("  [scan]   | %s: %d symbols\n",
            shdr.sh_type == SHT_SYMTAB ? "SHT_SYMTAB" : "SHT_DYNSYM", num_symbols);

        for (int i = 0; i < num_symbols && count < max_targets; i++) {
            GElf_Sym sym;
            gelf_getsym(data, i, &sym);

            if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue;
            if (sym.st_value == 0) continue;

            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name || name[0] == '\0') continue;

            bool entry_match = func_matches(name, ctx->func_re, ctx->func_re_count);
            if (ctx->func_re_count == 0 && ctx->func_ret_re_count > 0) entry_match = false;
            bool ret_match = ctx->func_ret_re_count > 0 &&
                             func_matches(name, ctx->func_ret_re, ctx->func_ret_re_count);
            if (!entry_match && !ret_match) continue;

            if (ctx->verbose) ctx->log(" [match] > %s!%s @ 0x%lx%s\n",
                path, name, (unsigned long)sym.st_value,
                (!entry_match && ret_match) ? " (ret-only)" : "");

            if (!is_duplicate(ctx->targets, *ctx->target_count + count, path, (unsigned long)sym.st_value)) {
                unsigned long off = vaddr_to_file_off(elf, (unsigned long)sym.st_value);
                if (off == SEG_VADDR_BAD) {
                    if (ctx->verbose) ctx->log("  [scan]   | skip %s: vaddr 0x%lx in no PT_LOAD\n", name, (unsigned long)sym.st_value);
                    continue;
                }
                targets[count].pid = pid;
                copy_str(targets[count].mod_path, path, sizeof(targets[count].mod_path));
                copy_str(targets[count].func_name, name, sizeof(targets[count].func_name));
                targets[count].offset = off;
                targets[count].arg_count = -1;
                memset(targets[count].arg_types, 0, sizeof(targets[count].arg_types));
                targets[count].ret_only = !entry_match && ret_match;
                targets[count].ret_type = ret_match ? ARG_VAL : ARG_NONE;
                count++;
            }
        }
    }
    elf_end(elf);
    close(fd);

    return count;
}

bool custom_spec_matches_path(const custom_probe_spec_t *spec, const char *path)
{
    // A '/' in the pattern means full-path substring match — unless it's a
    // /regex/-delimited pattern, whose delimiters are also slashes.
    if (strchr(spec->mod, '/') && !pm_is_regex(spec->mod))
        return strstr(path, spec->mod) != NULL;
    const char *bname = strrchr(path, '/');
    bname = bname ? bname + 1 : path;
    if (pm_is_regex(spec->mod))
        return pm_regex(spec->mod, bname);
    // exact=true: was fnmatch(*?) else strcmp; pm_match's glob trigger set
    // widens to "*?[" (was "*?" here) — no existing specs/*.spec line uses '['.
    return pm_match(spec->mod, bname, /*exact=*/true);
}

int parse_custom_probe_spec(const char *input, custom_probe_spec_t *out,
                            void (*log)(const char *fmt, ...))
{
    memset(out, 0, sizeof(*out));
    out->arg_count = -1;
    out->ret_type  = ARG_NONE;

    char buf[512];
    copy_str(buf, input, sizeof(buf));

    // Strip an optional "KIND:" prefix. Unrecognized text before ':' is NOT a
    // kind (e.g. "libc.so!open" has no such prefix, and MODULE!FUNC can't
    // collide with these tokens) — out->kind stays SPEC_KIND_FUNCS (0, from
    // the memset above) when no prefix matches, preserving today's semantics.
    {
        static const struct { const char *p; spec_kind_t k; } KINDS[] = {
            { "funcs:",   SPEC_KIND_FUNCS },
            { "syscall:", SPEC_KIND_SYSCALL },
            { "lib:",     SPEC_KIND_LIB },
            { "mod:",     SPEC_KIND_MOD },
        };
        for (size_t i = 0; i < sizeof(KINDS) / sizeof(KINDS[0]); i++) {
            size_t n = strlen(KINDS[i].p);
            if (strncmp(buf, KINDS[i].p, n) == 0) {
                out->kind = KINDS[i].k;
                memmove(buf, buf + n, strlen(buf + n) + 1);
                break;
            }
        }
    }

    // syscall:/lib:/mod: kinds: no (args)/>ret grammar, just an optional
    // leading '!' (deny, syscall:/lib: only) and a bare pattern/name.
    if (out->kind == SPEC_KIND_SYSCALL || out->kind == SPEC_KIND_LIB) {
        char *p = buf;
        if (*p == '!') { out->deny = true; p++; }
        if (strchr(p, '(') || strchr(p, '>')) {
            log("   [err] > %s spec does not support (args)/>ret: %s\n",
                out->kind == SPEC_KIND_SYSCALL ? "syscall:" : "lib:", input);
            return -1;
        }
        if (p[0] == '\0') {
            log("   [err] > empty pattern in spec: %s\n", input);
            return -1;
        }
        copy_str(out->mod, p, sizeof(out->mod));
        return 0;
    }
    if (out->kind == SPEC_KIND_MOD) {
        if (buf[0] == '\0') {
            log("   [err] > empty name in spec: %s\n", input);
            return -1;
        }
        copy_str(out->mod, buf, sizeof(out->mod));
        return 0;
    }

    // SPEC_KIND_FUNCS (default): existing MODULE!FUNC[@OFFSET][(ARGS)][>RET]
    // grammar, unchanged below. A "funcs:" prefix has already been stripped
    // above if present; MODULE/FUNC sides may be plain, glob (*?[), or
    // /regex/-delimited — the split logic here doesn't need to know which,
    // since '/' isn't a delimiter it acts on.

    // Strip '>rettype' suffix (outside any parentheses): e.g. "libc.so!fgets(S,V,V)>V"
    {
        bool in_paren = false;
        for (char *p = buf; *p; p++) {
            if (*p == '(') in_paren = true;
            else if (*p == ')') in_paren = false;
            else if (*p == '>' && !in_paren) {
                *p = '\0';
                char *rp = p + 1;
                while (*rp == ' ') rp++;
                if (*rp == 'S' || *rp == 's')      out->ret_type = ARG_STR;
                else if (*rp == 'V' || *rp == 'v') out->ret_type = ARG_VAL;
                else {
                    log("   [err] > unknown return type '%c' in spec: %s\n", *rp, input);
                    return -1;
                }
                break;
            }
        }
    }

    char *paren = strchr(buf, '(');
    if (paren) {
        *paren = '\0';
        char *close = strchr(paren + 1, ')');
        if (!close) {
            log("   [err] > malformed spec (unclosed '('): %s\n", input);
            return -1;
        }
        *close = '\0';
        out->arg_count = 0;
        char *save = NULL;
        for (char *tok = strtok_r(paren + 1, ",", &save);
             tok && out->arg_count < 8;
             tok = strtok_r(NULL, ",", &save)) {
            while (*tok == ' ') tok++;
            if (*tok == 'S' || *tok == 's')
                out->arg_types[out->arg_count++] = ARG_STR;
            else if (*tok == 'V' || *tok == 'v')
                out->arg_types[out->arg_count++] = ARG_VAL;
            else if (*tok == 'F' || *tok == 'f')
                out->arg_types[out->arg_count++] = ARG_FD;
            else if (*tok == 'A' || *tok == 'a')
                out->arg_types[out->arg_count++] = ARG_SOCKADDR;
            else {
                log("   [err] > unknown arg type '%c' in spec: %s\n", *tok, input);
                return -1;
            }
        }
    }

    char *bang = strchr(buf, '!');
    if (bang) {
        *bang = '\0';
        copy_str(out->mod, buf, sizeof(out->mod));
        char *at = strchr(bang + 1, '@');
        if (at) {
            *at = '\0';
            copy_str(out->func, bang + 1, sizeof(out->func));
            out->offset = strtoul(at + 1, NULL, 0);
        } else {
            copy_str(out->func, bang + 1, sizeof(out->func));
        }
    } else {
        char *at = strchr(buf, '@');
        if (!at) {
            log("   [err] > invalid spec (need '!' or '@'): %s\n", input);
            return -1;
        }
        *at = '\0';
        copy_str(out->mod, buf, sizeof(out->mod));
        out->offset = strtoul(at + 1, NULL, 0);
    }

    if (out->mod[0] == '\0') {
        log("   [err] > empty module in spec: %s\n", input);
        return -1;
    }
    if (out->func[0] == '\0' && out->offset == 0) {
        log("   [err] > spec needs function name or offset: %s\n", input);
        return -1;
    }
    // '>rettype' without '()': return-only probe (no CALL event, like -r)
    // '()>rettype' or '(args)>rettype': paired (CALL + RET)
    out->ret_only = (out->ret_type != ARG_NONE && out->arg_count == -1);
    return 0;
}

int resolve_custom_spec_for_path(pid_t pid, const char *path,
                                  const custom_probe_spec_t *spec,
                                  probe_target_t *out)
{
    out->pid = pid;
    copy_str(out->mod_path, path, sizeof(out->mod_path));
    copy_str(out->func_name, spec->func, sizeof(out->func_name));
    out->runtime_entry_addr = 0;
    out->arg_count = spec->arg_count;
    memcpy(out->arg_types, spec->arg_types, sizeof(spec->arg_types));
    out->ret_type = spec->ret_type;
    out->ret_only = spec->ret_only;

    if (spec->offset > 0) {
        // @offset is a FILE offset (not a readelf/nm vaddr) — used raw, no ELF parse.
        out->offset = spec->offset;
        return 0;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) { close(fd); return -1; }

    int found = -1;
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL && found < 0) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) continue;
        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) continue;
        if (shdr.sh_entsize == 0) continue;
        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data) continue;
        int num = shdr.sh_size / shdr.sh_entsize;
        for (int i = 0; i < num && found < 0; i++) {
            GElf_Sym sym;
            gelf_getsym(data, i, &sym);
            if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue;
            if (sym.st_value == 0) continue;
            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (name && strcmp(name, spec->func) == 0) {
                unsigned long off = vaddr_to_file_off(elf, (unsigned long)sym.st_value);
                if (off != SEG_VADDR_BAD) { out->offset = off; found = 0; }
            }
        }
    }
    elf_end(elf);
    close(fd);
    return found;
}
