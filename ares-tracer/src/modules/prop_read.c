#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <bpf/libbpf.h>
#include "module.h"
#include "ares-tracer-priv.h"

static struct bpf_link *prop_read_link = NULL;

// Known bionic libc paths, tried in order (APEX first for API 29+)
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
    bpf_program__set_autoattach(skel->progs.on_prop_read_callback, false);
}

static int pr_attach(struct ares_tracer_bpf *skel)
{
    elf_version(EV_CURRENT);

    const char *libc_path = NULL;
    unsigned long offset = 0;

    for (int i = 0; libc_paths[i] && !offset; i++) {
        offset = find_symbol_in_elf(libc_paths[i], "__system_property_read_callback");
        if (offset)
            libc_path = libc_paths[i];
    }

    if (!offset) {
        err_print("   [bpf] > prop-read: __system_property_read_callback not found in libc\n");
        return -2;
    }

    prop_read_link = bpf_program__attach_uprobe(
        skel->progs.on_prop_read_callback, false, -1, libc_path, offset);
    if (!prop_read_link) {
        err_print("   [bpf] > prop-read: failed to attach uprobe on %s+0x%lx\n",
                  libc_path, offset);
        return -2;
    }

    ts_print("[prop]  > property read tracing enabled (%s+0x%lx)\n", libc_path, offset);
    return 0;
}

static void pr_detach(void)
{
    if (prop_read_link) { bpf_link__destroy(prop_read_link); prop_read_link = NULL; }
}

static int pr_handle_event(const struct event_header *hdr, const void *data, size_t sz)
{
    if (hdr->type != ARES_EVENT_PROP_READ)
        return -1;
    const struct prop_read_event *e = data;
    if (sz < sizeof(*e)) return 0;
    ts_print("[prop]  > [READ]  PID:%d (%s) name=%s value=%s\n",
        e->h.pid, e->comm, e->name, e->value);
    return 0;
}

ares_module_t module_prop_read = {
    .name         = "prop-read",
    .description  = "Trace system property reads via __system_property_read_callback",
    .pre_attach   = pr_pre_attach,
    .attach       = pr_attach,
    .detach       = pr_detach,
    .handle_event = pr_handle_event,
};
