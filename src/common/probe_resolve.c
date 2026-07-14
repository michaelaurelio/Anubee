// SPDX-License-Identifier: GPL-2.0
#include "common/probe_resolve.h"
#include "common/maps.h"
#include "common/pattern_match.h"

#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdarg.h>
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

bool is_duplicate(probe_target_t *targets, int count, const char *mod_path, unsigned long offset)
{
    for (int i = 0; i < count; i++) {
        if (targets[i].offset == offset && strcmp(targets[i].mod_path, mod_path) == 0) {
            return true;
        }
    }
    return false;
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

// Fallback logger substituted below when a caller passes log == NULL (e.g.
// engines with no existing per-line-error logger of their own) — every
// existing "log(...)" call site in this function stays unguarded/unchanged;
// NULL is made safe once here instead of at each of the 9 error sites.
static void default_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

int parse_custom_probe_spec(const char *input, custom_probe_spec_t *out,
                            void (*log)(const char *fmt, ...))
{
    return parse_custom_probe_spec_ex(input, out, SPEC_KIND_FUNCS, NULL, log);
}

int parse_custom_probe_spec_ex(const char *input, custom_probe_spec_t *out,
                               spec_kind_t default_kind, bool *used_default,
                               void (*log)(const char *fmt, ...))
{
    if (!log) log = default_log;
    if (used_default) *used_default = false;

    memset(out, 0, sizeof(*out));
    out->arg_count = -1;
    out->ret_type  = ARG_NONE;

    char buf[512];
    copy_str(buf, input, sizeof(buf));

    // Strip an optional "KIND:" prefix. Unrecognized text before ':' is NOT a
    // kind (e.g. "libc.so!open" has no such prefix, and MODULE!FUNC can't
    // collide with these tokens) — out->kind stays SPEC_KIND_FUNCS (0, from
    // the memset above) when no prefix matches, preserving today's semantics,
    // unless default_kind says otherwise (see below).
    {
        static const struct { const char *p; spec_kind_t k; } KINDS[] = {
            { "funcs:",   SPEC_KIND_FUNCS },
            { "syscall:", SPEC_KIND_SYSCALL },
            { "lib:",     SPEC_KIND_LIB },
            { "mod:",     SPEC_KIND_MOD },
        };
        bool matched = false;
        for (size_t i = 0; i < sizeof(KINDS) / sizeof(KINDS[0]); i++) {
            size_t n = strlen(KINDS[i].p);
            if (strncmp(buf, KINDS[i].p, n) == 0) {
                out->kind = KINDS[i].k;
                memmove(buf, buf + n, strlen(buf + n) + 1);
                matched = true;
                break;
            }
        }
        // No explicit prefix: catch a typo'd/unrecognized kind attempt (e.g.
        // "sycall:openat") before it gets misread as a MODULE!FUNC spec or a
        // literal pattern. An identifier immediately followed by ':' — before
        // any of the chars that start the funcs grammar or a /regex/ — reads
        // as "someone meant a KIND: prefix"; reject it outright rather than
        // silently mis-parsing.
        if (!matched && buf[0] != '/') {
            const char *p = buf;
            while ((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_')
                p++;
            if (p != buf && *p == ':') {
                log("   [err] > unknown spec kind in '%s' (expected funcs:/syscall:/lib:/mod:)\n",
                    input);
                return -1;
            }
        }

        // Otherwise let a caller-supplied default_kind (e.g. syscalls' -e
        // defaulting to syscall:) apply, but only when the bare text isn't
        // already funcs-shaped ('!' or '@' *after* skipping a leading '!',
        // which is the syscall:/lib: deny marker, not a MODULE!FUNC
        // separator — "!ptrace" must still default, "libc.so!fn" must not)
        // — so a funcs-style value pasted into a non-funcs engine's -e still
        // parses as funcs: (and is correctly, silently ignored by that
        // engine's own kind filter) instead of being force-fit into a
        // nonsensical syscall/lib/mod pattern.
        const char *scan = (*buf == '!') ? buf + 1 : buf;
        bool funcs_shaped = strchr(scan, '!') || strchr(scan, '@');
        if (!matched && default_kind != SPEC_KIND_FUNCS && !funcs_shaped) {
            out->kind = default_kind;
            if (used_default) *used_default = true;
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

int resolve_custom_spec_matches_for_path(pid_t pid, const char *path,
                                          const custom_probe_spec_t *spec,
                                          probe_target_t *out, int max_out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) { close(fd); return -1; }

    int count = 0;
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL && count < max_out) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) continue;
        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) continue;
        if (shdr.sh_entsize == 0) continue;
        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data) continue;
        int num = shdr.sh_size / shdr.sh_entsize;
        for (int i = 0; i < num && count < max_out; i++) {
            GElf_Sym sym;
            gelf_getsym(data, i, &sym);
            if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue;
            if (sym.st_value == 0) continue;
            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name || name[0] == '\0') continue;
            if (!pm_regex(spec->func, name)) continue;
            unsigned long off = vaddr_to_file_off(elf, (unsigned long)sym.st_value);
            if (off == SEG_VADDR_BAD) continue;
            out[count].pid = pid;
            copy_str(out[count].mod_path, path, sizeof(out[count].mod_path));
            copy_str(out[count].func_name, name, sizeof(out[count].func_name));
            out[count].offset = off;
            out[count].runtime_entry_addr = 0;
            out[count].arg_count = spec->arg_count;
            memcpy(out[count].arg_types, spec->arg_types, sizeof(spec->arg_types));
            out[count].ret_type = spec->ret_type;
            out[count].ret_only = spec->ret_only;
            count++;
        }
    }
    elf_end(elf);
    close(fd);
    return count;
}
