// SPDX-License-Identifier: GPL-2.0
// `anubee mod prop-read` — userspace analyzer for system property read events.
// Owns the prop_read BPF skeleton lifecycle; attaches uprobes manually after
// resolving symbols from libc.so. Kernel side: src/modules/prop_read.bpf.c.
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "prop_read.skel.h"
#include "common/analyzer.h"
#include "common/engine_args.h"
#include "common/emit.h"
#include "common/runtime.h"
#include "common/probe_resolve.h"
#include "common/human_out.h"      // SYM1 Phase 4c: shared stdout formatter
#include "modules/mod_events.h"
#include "modules/mod_emit.h"

// ── per-property access counters ─────────────────────────────────────────────

#define PROP_STAT_MAX 512

typedef struct {
    char     name[PROP_NAME_LEN];
    uint32_t count;
} prop_stat_t;

static prop_stat_t prop_stats[PROP_STAT_MAX];
static int         prop_stat_count = 0;

static void prop_stat_add(const char *name)
{
    for (int i = 0; i < prop_stat_count; i++) {
        if (strcmp(prop_stats[i].name, name) == 0) {
            prop_stats[i].count++;
            return;
        }
    }
    if (prop_stat_count >= PROP_STAT_MAX) return;
    strncpy(prop_stats[prop_stat_count].name, name, PROP_NAME_LEN - 1);
    prop_stats[prop_stat_count].name[PROP_NAME_LEN - 1] = '\0';
    prop_stats[prop_stat_count].count = 1;
    prop_stat_count++;
}

static int prop_stat_cmp_desc(const void *a, const void *b)
{
    uint32_t ca = ((const prop_stat_t *)a)->count;
    uint32_t cb = ((const prop_stat_t *)b)->count;
    return (ca > cb) ? -1 : (ca < cb) ? 1 : 0;
}

// ── RASP-sensitive property list ──────────────────────────────────────────────
// Properties in this list are highlighted in the summary table.
// Edit to add or remove entries; NULL terminates the list.
static const char *const rasp_props[] = {
    "ro.debuggable",
    "ro.secure",
    "ro.build.type",            // "user" vs "userdebug"/"eng"
    "ro.build.tags",            // "release-keys" vs "test-keys"
    "ro.build.fingerprint",
    "ro.build.selinux",
    "ro.boot.verifiedbootstate",
    "ro.boot.veritymode",
    "ro.product.model",
    "ro.product.brand",
    "ro.product.device",
    "persist.sys.usb.config",   // USB debugging state
    "service.adb.root",         // adbd running as root
    "ro.build.version.release",
    "ro.build.version.sdk",
    NULL,
};

static bool is_rasp_prop(const char *name)
{
    for (int i = 0; rasp_props[i]; i++)
        if (strcmp(rasp_props[i], name) == 0) return true;
    return false;
}

static void pr_print_summary(void)
{
    if (prop_stat_count == 0) return;

    qsort(prop_stats, prop_stat_count, sizeof(prop_stat_t), prop_stat_cmp_desc);

    uint64_t total = 0;
    int rasp_count = 0;
    for (int i = 0; i < prop_stat_count; i++) {
        total += prop_stats[i].count;
        if (is_rasp_prop(prop_stats[i].name)) rasp_count++;
    }

    int use_color = isatty(STDOUT_FILENO);

#define SEP "  \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80" \
            "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"     \
            "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"     \
            "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"     \
            "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"     \
            "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"     \
            "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"     \
            "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\n"

    printf("[prop] \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 Property Access Summary "
           "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
           "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
           "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
           "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\n");
    printf("[prop]       Count  Property\n");
    printf("[prop]" SEP);

    for (int i = 0; i < prop_stat_count; i++) {
        bool rasp = is_rasp_prop(prop_stats[i].name);
        if (rasp && use_color)
            printf("[prop]  \033[1;33m[!] %6u  %s\033[0m\n",
                   prop_stats[i].count, prop_stats[i].name);
        else if (rasp)
            printf("[prop]  [!] %6u  %s\n",
                   prop_stats[i].count, prop_stats[i].name);
        else
            printf("[prop]      %6u  %s\n",
                   prop_stats[i].count, prop_stats[i].name);
    }

    printf("[prop]" SEP);
    printf("[prop]  %llu total access%s across %d unique propert%s (%d RASP-flagged)\n",
           (unsigned long long)total, total == 1 ? "" : "es",
           prop_stat_count, prop_stat_count == 1 ? "y" : "ies",
           rasp_count);
#undef SEP
}

// File twin of pr_print_summary: same tally, one {"type":"prop_read_summary",...}
// record. prop_stats is already sorted by pr_print_summary before this runs.
static void pr_emit_summary(struct anubee_sink *s)
{
    if (prop_stat_count == 0) return;

    uint64_t total = 0;
    int rasp_count = 0;
    for (int i = 0; i < prop_stat_count; i++) {
        total += prop_stats[i].count;
        if (is_rasp_prop(prop_stats[i].name)) rasp_count++;
    }

    struct jbuf *j = &s->jb;
    j->len = 0;
    jb_c(j, '{');
    jb_s(j, "\"type\":\"prop_read_summary\"");
    jb_s(j, ",\"total\":");        jb_u64(j, total);
    jb_s(j, ",\"unique_props\":"); jb_u64(j, (unsigned long long)prop_stat_count);
    jb_s(j, ",\"rasp_count\":");   jb_u64(j, (unsigned long long)rasp_count);
    jb_s(j, ",\"props\":[");
    for (int i = 0; i < prop_stat_count; i++) {
        if (i) jb_c(j, ',');
        jb_s(j, "{\"name\":\"");  jb_esc(j, prop_stats[i].name); jb_c(j, '"');
        jb_s(j, ",\"count\":");   jb_u64(j, prop_stats[i].count);
        jb_s(j, ",\"rasp\":");    jb_s(j, is_rasp_prop(prop_stats[i].name) ? "true" : "false");
        jb_c(j, '}');
    }
    jb_c(j, ']');
    jb_c(j, '}');
    anubee_sink_emit(s);
}

// ── BPF skeleton + link state ─────────────────────────────────────────────────

static struct prop_read_bpf *g_skel         = NULL;
static struct ring_buffer   *g_rb           = NULL;
static struct bpf_link      *pr_ff          = NULL;

static struct bpf_link *pr_link_get      = NULL;
static struct bpf_link *pr_link_get_ret  = NULL;
static struct bpf_link *pr_link_find     = NULL;
static struct bpf_link *pr_link_find_ret = NULL;
static struct bpf_link *pr_link_fore     = NULL;
static struct bpf_link *pr_link_cb       = NULL;

// ── libc path candidates ──────────────────────────────────────────────────────

static const char *libc_paths[] = {
    "/apex/com.android.runtime/lib64/bionic/libc.so",
    "/system/lib64/libc.so",
    NULL,
};

// ── ELF symbol resolver ───────────────────────────────────────────────────────

static unsigned long find_symbol_in_elf(const char *path, const char *sym_name)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return 0;

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) { close(fd); return 0; }

    // PT_LOAD table for vaddr->file-offset conversion (uprobes want a file
    // offset; st_value is a vaddr). libc maps p_vaddr == p_offset so this is a
    // no-op there today, but keeps prop_read correct for any skewed library.
    struct load_seg segs[32];
    int nseg = 0;
    {
        size_t phnum = 0;
        if (elf_getphdrnum(elf, &phnum) == 0) {
            for (size_t i = 0; i < phnum && nseg < 32; i++) {
                GElf_Phdr phdr;
                if (!gelf_getphdr(elf, (int)i, &phdr)) continue;
                if (phdr.p_type != PT_LOAD) continue;
                segs[nseg].vaddr  = (unsigned long)phdr.p_vaddr;
                segs[nseg].offset = (unsigned long)phdr.p_offset;
                segs[nseg].filesz = (unsigned long)phdr.p_filesz;
                nseg++;
            }
        }
    }

    unsigned long offset = 0;
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL && !offset) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) continue;
        if (shdr.sh_type != SHT_DYNSYM) continue;
        if (shdr.sh_entsize == 0) continue;
        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data) continue;
        int num = (int)(shdr.sh_size / shdr.sh_entsize);
        for (int i = 0; i < num; i++) {
            GElf_Sym sym;
            gelf_getsym(data, i, &sym);
            if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue;
            if (sym.st_value == 0) continue;
            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (name && strcmp(name, sym_name) == 0) {
                unsigned long off = seg_vaddr_to_off(segs, nseg, (unsigned long)sym.st_value);
                if (off != SEG_VADDR_BAD) offset = off;   // sentinel -> leave offset 0 (not found)
                break;
            }
        }
    }
    elf_end(elf);
    close(fd);
    return offset;
}

// ── ring-buffer callback ──────────────────────────────────────────────────────

static int pr_handle_event(void *ctx, void *data, size_t sz)
{
    struct anubee_mod_ctx *mc = ctx;
    if (sz < sizeof(struct prop_event)) return 0;
    const struct prop_event *e = data;

    // tally always — summary must populate even under -o (which forces quiet)
    switch (e->h.type) {
    case MOD_EV_PROP_GET:  if (!e->is_ret) prop_stat_add(e->name); break;
    case MOD_EV_PROP_FIND: if (!e->is_ret) prop_stat_add(e->name); break;
    case MOD_EV_PROP_READ: prop_stat_add(e->name);                 break;
    default: break;
    }

    if (!mc->quiet) {
        switch (e->h.type) {

        // SYM1 Phase 4c: printf -> ts_print (adds the shared "HH:MM:SS " prefix).
        case MOD_EV_PROP_GET:
            if (!e->is_ret) {
                ts_print("[prop]  GET   CALL  PID:%-6d (%s)  %s\n",
                    e->h.pid, e->comm, e->name);
            } else {
                const char *val = e->value[0] ? e->value : "(empty)";
                ts_print("[prop]  GET   RET   PID:%-6d (%s)  %s = %s\n",
                    e->h.pid, e->comm, e->name, val);
            }
            break;

        case MOD_EV_PROP_FIND:
            if (!e->is_ret) {
                ts_print("[prop]  FIND  CALL  PID:%-6d (%s)  %s\n",
                    e->h.pid, e->comm, e->name);
            } else if (e->found) {
                ts_print("[prop]  FIND  RET   PID:%-6d (%s)  %s = %s\n",
                    e->h.pid, e->comm, e->name, e->value);
            } else {
                ts_print("[prop]  FIND  RET   PID:%-6d (%s)  %s = (not found)\n",
                    e->h.pid, e->comm, e->name);
            }
            break;

        case MOD_EV_PROP_SCAN:
            ts_print("[prop]  SCAN  CALL  PID:%-6d (%s)\n",
                e->h.pid, e->comm);
            break;

        case MOD_EV_PROP_READ:
            ts_print("[prop]  READCB      PID:%-6d (%s)  %s = %s\n",
                e->h.pid, e->comm, e->name, e->value);
            break;

        default:
            break;
        }
    }

    if (mc->sink != NULL) {
        mod_emit_prop(&mc->sink->jb, e);
        anubee_sink_emit(mc->sink);
    }

    return 0;
}

// ── BPF lifecycle ─────────────────────────────────────────────────────────────

static struct ring_buffer *pr_setup(int uid, struct anubee_mod_ctx *mc)
{
    g_skel = prop_read_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "mod prop-read: failed to open BPF skeleton\n");
        return NULL;
    }
    if (prop_read_bpf__load(g_skel)) {
        fprintf(stderr, "mod prop-read: failed to load BPF\n");
        goto err;
    }

    __u8 one = 1;
    if (uid > 0) {
        __u32 u = (__u32)uid;
        bpf_map_update_elem(bpf_map__fd(g_skel->maps.target_uids), &u, &one, BPF_ANY);
    }
    if (mc->tgt && mc->tgt->n > 0) {
        for (int i = 0; i < mc->tgt->n; i++) {
            __u32 tgid = (__u32)mc->tgt->pids[i];
            bpf_map_update_elem(bpf_map__fd(g_skel->maps.target_pids), &tgid, &one, BPF_ANY);
        }
    }

    // Manual uprobe attach — symbols have no auto-attach target in the BPF SEC.
    elf_version(EV_CURRENT);

    const char *libc_path = NULL;
    for (int i = 0; libc_paths[i]; i++) {
        if (find_symbol_in_elf(libc_paths[i], "__system_property_get")) {
            libc_path = libc_paths[i];
            break;
        }
    }
    if (!libc_path) {
        fprintf(stderr, "mod prop-read: libc.so not found\n");
        goto err;
    }

    unsigned long off_get     = find_symbol_in_elf(libc_path, "__system_property_get");
    unsigned long off_find    = find_symbol_in_elf(libc_path, "__system_property_find");
    unsigned long off_foreach = find_symbol_in_elf(libc_path, "__system_property_foreach");
    unsigned long off_cb      = find_symbol_in_elf(libc_path, "__system_property_read_callback");

    if (off_get) {
        pr_link_get = bpf_program__attach_uprobe(
            g_skel->progs.on_prop_get, false, -1, libc_path, off_get);
        pr_link_get_ret = bpf_program__attach_uprobe(
            g_skel->progs.on_prop_get_ret, true, -1, libc_path, off_get);
    }

    if (off_find) {
        pr_link_find = bpf_program__attach_uprobe(
            g_skel->progs.on_prop_find, false, -1, libc_path, off_find);
        pr_link_find_ret = bpf_program__attach_uprobe(
            g_skel->progs.on_prop_find_ret, true, -1, libc_path, off_find);
    }

    if (off_foreach)
        pr_link_fore = bpf_program__attach_uprobe(
            g_skel->progs.on_prop_fore, false, -1, libc_path, off_foreach);

    if (off_cb)
        pr_link_cb = bpf_program__attach_uprobe(
            g_skel->progs.on_prop_read_callback, false, -1, libc_path, off_cb);

    if (!off_get && !off_find && !off_foreach && !off_cb) {
        fprintf(stderr, "mod prop-read: no property symbols resolved from %s\n", libc_path);
        goto err;
    }

    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        pr_ff = bpf_program__attach(g_skel->progs.anubee_follow_fork);
        if (!pr_ff) fprintf(stderr, "mod prop-read: follow-fork attach failed (non-fatal)\n");
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb),
                            pr_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod prop-read: failed to create ring buffer\n");
        goto err;
    }
    return g_rb;

err:
    if (pr_ff)            { bpf_link__destroy(pr_ff);            pr_ff            = NULL; }
    if (pr_link_get)      { bpf_link__destroy(pr_link_get);      pr_link_get      = NULL; }
    if (pr_link_get_ret)  { bpf_link__destroy(pr_link_get_ret);  pr_link_get_ret  = NULL; }
    if (pr_link_find)     { bpf_link__destroy(pr_link_find);     pr_link_find     = NULL; }
    if (pr_link_find_ret) { bpf_link__destroy(pr_link_find_ret); pr_link_find_ret = NULL; }
    if (pr_link_fore)     { bpf_link__destroy(pr_link_fore);     pr_link_fore     = NULL; }
    if (pr_link_cb)       { bpf_link__destroy(pr_link_cb);       pr_link_cb       = NULL; }
    prop_read_bpf__destroy(g_skel);
    g_skel = NULL;
    return NULL;
}

static void pr_teardown(void)
{
    if (pr_ff)            { bpf_link__destroy(pr_ff);            pr_ff            = NULL; }
    if (pr_link_get)      { bpf_link__destroy(pr_link_get);      pr_link_get      = NULL; }
    if (pr_link_get_ret)  { bpf_link__destroy(pr_link_get_ret);  pr_link_get_ret  = NULL; }
    if (pr_link_find)     { bpf_link__destroy(pr_link_find);     pr_link_find     = NULL; }
    if (pr_link_find_ret) { bpf_link__destroy(pr_link_find_ret); pr_link_find_ret = NULL; }
    if (pr_link_fore)     { bpf_link__destroy(pr_link_fore);     pr_link_fore     = NULL; }
    if (pr_link_cb)       { bpf_link__destroy(pr_link_cb);       pr_link_cb       = NULL; }
    if (g_rb)   { ring_buffer__free(g_rb);              g_rb   = NULL; }
    if (g_skel) { prop_read_bpf__destroy(g_skel);       g_skel = NULL; }
}

static unsigned long long pr_drops(void)
{
    return g_skel ? anubee_drops_read(bpf_map__fd(g_skel->maps.dropped)) : 0;
}

// ── analyzer registration ─────────────────────────────────────────────────────

const anubee_analyzer_t analyzer_prop_read = {
    .name          = "prop-read",
    .description   = "Trace all system property reads (_get, _find, _foreach, _read_callback)",
    .setup         = pr_setup,
    .teardown      = pr_teardown,
    .print_summary = pr_print_summary,
    .emit_summary  = pr_emit_summary,
    .drops         = pr_drops,
};
