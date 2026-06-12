#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <bpf/libbpf.h>
#include "module.h"
#include "ares-tracer-priv.h"

static struct bpf_link *pr_link_get      = NULL;
static struct bpf_link *pr_link_get_ret  = NULL;
static struct bpf_link *pr_link_find     = NULL;
static struct bpf_link *pr_link_find_ret = NULL;
static struct bpf_link *pr_link_fore     = NULL;
static struct bpf_link *pr_link_cb       = NULL;

static const char *libc_paths[] = {
    "/apex/com.android.runtime/lib64/bionic/libc.so",
    "/system/lib64/libc.so",
    NULL,
};

static unsigned long find_symbol_in_elf(const char *path, const char *sym_name)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return 0;

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) { close(fd); return 0; }

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
                offset = (unsigned long)sym.st_value;
                break;
            }
        }
    }
    elf_end(elf);
    close(fd);
    return offset;
}

static void pr_pre_attach(struct ares_tracer_bpf *skel)
{
    bpf_program__set_autoattach(skel->progs.on_prop_get,           false);
    bpf_program__set_autoattach(skel->progs.on_prop_get_ret,       false);
    bpf_program__set_autoattach(skel->progs.on_prop_find,          false);
    bpf_program__set_autoattach(skel->progs.on_prop_find_ret,      false);
    bpf_program__set_autoattach(skel->progs.on_prop_fore,          false);
    bpf_program__set_autoattach(skel->progs.on_prop_read_callback, false);
}

static int pr_attach(struct ares_tracer_bpf *skel)
{
    elf_version(EV_CURRENT);

    const char *libc_path = NULL;
    for (int i = 0; libc_paths[i]; i++) {
        if (find_symbol_in_elf(libc_paths[i], "__system_property_get")) {
            libc_path = libc_paths[i];
            break;
        }
    }
    if (!libc_path) {
        err_print("   [bpf] > prop-read: libc.so not found\n");
        return -2;
    }

    unsigned long off_get     = find_symbol_in_elf(libc_path, "__system_property_get");
    unsigned long off_find    = find_symbol_in_elf(libc_path, "__system_property_find");
    unsigned long off_foreach = find_symbol_in_elf(libc_path, "__system_property_foreach");
    unsigned long off_cb      = find_symbol_in_elf(libc_path, "__system_property_read_callback");

    if (off_get) {
        pr_link_get = bpf_program__attach_uprobe(
            skel->progs.on_prop_get, false, -1, libc_path, off_get);
        pr_link_get_ret = bpf_program__attach_uprobe(
            skel->progs.on_prop_get_ret, true, -1, libc_path, off_get);
    }

    if (off_find) {
        pr_link_find = bpf_program__attach_uprobe(
            skel->progs.on_prop_find, false, -1, libc_path, off_find);
        pr_link_find_ret = bpf_program__attach_uprobe(
            skel->progs.on_prop_find_ret, true, -1, libc_path, off_find);
    }

    if (off_foreach)
        pr_link_fore = bpf_program__attach_uprobe(
            skel->progs.on_prop_fore, false, -1, libc_path, off_foreach);

    if (off_cb)
        pr_link_cb = bpf_program__attach_uprobe(
            skel->progs.on_prop_read_callback, false, -1, libc_path, off_cb);

    if (!off_get && !off_find && !off_foreach && !off_cb) {
        err_print("   [bpf] > prop-read: no property symbols resolved from %s\n", libc_path);
        return -2;
    }

    ts_print("[prop]  > property tracing enabled (%s)\n", libc_path);
    return 0;
}

static void pr_detach(void)
{
    if (pr_link_get)      { bpf_link__destroy(pr_link_get);      pr_link_get      = NULL; }
    if (pr_link_get_ret)  { bpf_link__destroy(pr_link_get_ret);  pr_link_get_ret  = NULL; }
    if (pr_link_find)     { bpf_link__destroy(pr_link_find);     pr_link_find     = NULL; }
    if (pr_link_find_ret) { bpf_link__destroy(pr_link_find_ret); pr_link_find_ret = NULL; }
    if (pr_link_fore)     { bpf_link__destroy(pr_link_fore);     pr_link_fore     = NULL; }
    if (pr_link_cb)       { bpf_link__destroy(pr_link_cb);       pr_link_cb       = NULL; }
}

static int pr_handle_event(const struct event_header *hdr, const void *data, size_t sz)
{
    if (sz < sizeof(struct prop_event)) return -1;
    const struct prop_event *e = data;

    switch (hdr->type) {

    case ARES_EVENT_PROP_GET:
        if (!e->is_ret) {
            ts_print("[prop]  GET   CALL  PID:%-6d (%s)  %s\n",
                hdr->pid, e->comm, e->name);
        } else {
            const char *val = e->value[0] ? e->value : "(empty)";
            ts_print("[prop]  GET   RET   PID:%-6d (%s)  %s = %s\n",
                hdr->pid, e->comm, e->name, val);
        }
        return 0;

    case ARES_EVENT_PROP_FIND:
        if (!e->is_ret) {
            ts_print("[prop]  FIND  CALL  PID:%-6d (%s)  %s\n",
                hdr->pid, e->comm, e->name);
        } else if (e->found) {
            ts_print("[prop]  FIND  RET   PID:%-6d (%s)  %s = %s\n",
                hdr->pid, e->comm, e->name, e->value);
        } else {
            ts_print("[prop]  FIND  RET   PID:%-6d (%s)  %s = (not found)\n",
                hdr->pid, e->comm, e->name);
        }
        return 0;

    case ARES_EVENT_PROP_SCAN:
        ts_print("[prop]  SCAN  CALL  PID:%-6d (%s)\n",
            hdr->pid, e->comm);
        return 0;

    case ARES_EVENT_PROP_READ:
        ts_print("[prop]  READCB      PID:%-6d (%s)  %s = %s\n",
            hdr->pid, e->comm, e->name, e->value);
        return 0;

    default:
        return -1;
    }
}

ares_module_t module_prop_read = {
    .name         = "prop-read",
    .description  = "Trace all system property reads (_get, _find, _foreach, _read_callback)",
    .pre_attach   = pr_pre_attach,
    .attach       = pr_attach,
    .detach       = pr_detach,
    .handle_event = pr_handle_event,
};
