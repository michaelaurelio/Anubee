// SPDX-License-Identifier: GPL-2.0
// `ares correlate` — span-gated function->syscall correlation.
//
// Attaches entry uprobes to spec'd functions (MODULE!FUNC) and a span-gated
// do_el0_svc kprobe; every syscall issued while a probed function is on the
// thread's stack is emitted carrying that function's span id. Reuses the shared
// launch (src/common/launch) and probe resolution (src/common/probe_resolve);
// the span stack lives in the BPF object (src/common/span_stack.bpf.h).
//
// v1 scope: custom specs (-e/-F) + -p (full) / -P (best-effort post-launch);
// SP-based span close (no uretprobe/return values); raw syscall args (no decode).
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "correlate.skel.h"
#include "correlate.h"
#include "common/emit.h"
#include "common/launch.h"
#include "common/probe_resolve.h"

// nr -> name table (generated for the device's arm64 ABI).
static const struct { long nr; const char *name; } syscall_names[] = {
#include "syscalls_gen.h"
};

static const char *syscall_name(long nr)
{
    for (size_t i = 0; i < sizeof(syscall_names) / sizeof(syscall_names[0]); i++)
        if (syscall_names[i].nr == nr)
            return syscall_names[i].name;
    return "?";
}

static volatile sig_atomic_t exiting = 0;
static void on_sigint(int sig) { (void)sig; if (exiting) _exit(130); exiting = 1; }

static FILE *g_jsonl = NULL;
static int   g_quiet = 0;

static void log_stderr(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static int handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct corr_event_header))
        return 0;
    const struct corr_event_header *h = data;

    if (h->type == CORR_EV_FUNC) {
        if (sz < sizeof(struct corr_func_event)) return 0;
        const struct corr_func_event *e = data;
        if (!g_quiet)
            printf("[func]    > span=%llu parent=%llu pid=%u tid=%u @ 0x%llx\n",
                   (unsigned long long)e->span, (unsigned long long)e->parent_span,
                   e->h.pid, e->h.tid, (unsigned long long)e->entry_addr);
        if (g_jsonl) {
            static struct jbuf cj;   // reused; handle_event is single-threaded (ring_buffer__poll)
            cj.len = 0;
            corr_emit_func(&cj, e);
            fwrite(cj.b, 1, cj.len, g_jsonl);
            fputc('\n', g_jsonl);
            fflush(g_jsonl);
        }
    } else if (h->type == CORR_EV_SYSCALL) {
        if (sz < sizeof(struct corr_syscall_event)) return 0;
        const struct corr_syscall_event *e = data;
        const char *name = syscall_name((long)e->nr);
        if (!g_quiet)
            printf("[syscall] > span=%llu pid=%u tid=%u %s (nr=%llu)\n",
                   (unsigned long long)e->span, e->h.pid, e->h.tid, name,
                   (unsigned long long)e->nr);
        if (g_jsonl) {
            static struct jbuf cj;   // reused; handle_event is single-threaded (ring_buffer__poll)
            cj.len = 0;
            corr_emit_syscall(&cj, e, name);
            fwrite(cj.b, 1, cj.len, g_jsonl);
            fputc('\n', g_jsonl);
            fflush(g_jsonl);
        }
    }
    return 0;
}

// Scan /proc/<pid>/maps and attach the entry uprobe at every spec'd function.
static int attach_uprobes_for_pid(struct ares_correlate *skel, pid_t pid,
                                  const custom_probe_spec_t *specs, int nspec)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        fprintf(stderr, "correlate: cannot open %s: %s\n", maps_path, strerror(errno));
        return -1;
    }

    // Small dedup of (path,offset) already attached for this pid.
    struct { char path[256]; unsigned long off; } done[256];
    int ndone = 0, attached = 0;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char perms[5], path[256] = "";
        if (sscanf(line, "%*x-%*x %4s %*x %*s %*d %255s", perms, path) < 1) continue;
        if (path[0] != '/' || !strchr(perms, 'x')) continue;

        for (int s = 0; s < nspec; s++) {
            if (!custom_spec_matches_path(&specs[s], path)) continue;
            probe_target_t tgt;
            if (resolve_custom_spec_for_path(pid, path, &specs[s], &tgt) != 0)
                continue;

            int dup = 0;
            for (int d = 0; d < ndone; d++)
                if (done[d].off == tgt.offset && strcmp(done[d].path, path) == 0) { dup = 1; break; }
            if (dup) continue;
            if (ndone < 256) {
                snprintf(done[ndone].path, sizeof(done[ndone].path), "%s", path);
                done[ndone].off = tgt.offset;
                ndone++;
            }

            struct bpf_link *link = bpf_program__attach_uprobe(
                skel->progs.corr_uprobe_entry, false, pid, path, tgt.offset);
            const char *bname = strrchr(path, '/');
            bname = bname ? bname + 1 : path;
            if (link) {
                printf("[spec] > %s!%s @ 0x%lx\n", bname,
                       tgt.func_name[0] ? tgt.func_name : "?", tgt.offset);
                attached++;
            } else {
                fprintf(stderr, "[spec] > FAILED: %s!%s @ 0x%lx\n", bname,
                        tgt.func_name[0] ? tgt.func_name : "?", tgt.offset);
            }
        }
    }
    fclose(f);
    return attached;
}

static int install_uid(struct ares_correlate *skel, int uid)
{
    if (uid <= 0) return -1;
    __u32 vuid = (__u32)uid, one = 1;
    return bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY);
}

static void usage(void)
{
    fprintf(stderr,
        "usage: ares correlate [options] (-p PID | -P PACKAGE)\n"
        "\n"
        "Attach entry uprobes to spec'd functions + a span-gated syscall kprobe;\n"
        "emit each in-span syscall tagged with the enclosing function's span.\n"
        "\n"
        "options:\n"
        "  -p PID[,PID...]   attach to running PID(s)\n"
        "  -P PACKAGE        launch a package fresh and attach to it\n"
        "  -e SPEC           probe spec MODULE!FUNC[(S|V,...)] (repeatable)\n"
        "  -F FILE           load probe specs from a file (one per line, # = comment)\n"
        "  -o FILE           write structured JSONL\n"
        "  -h                show this help\n");
}

int cmd_correlate(int argc, char **argv)
{
    pid_t pids[64]; int pid_count = 0;
    const char *pkg = NULL, *out_path = NULL;
    custom_probe_spec_t specs[64]; int nspec = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(); return 0; }
        else if (!strcmp(a, "-q")) g_quiet = 1;
        else if (!strcmp(a, "-p")) {
            if (++i >= argc) { fprintf(stderr, "correlate: -p needs PID\n"); return 1; }
            char *tok = strtok(argv[i], ",");
            while (tok && pid_count < 64) { pids[pid_count++] = (pid_t)atoi(tok); tok = strtok(NULL, ","); }
        } else if (!strcmp(a, "-P")) {
            if (++i >= argc) { fprintf(stderr, "correlate: -P needs PACKAGE\n"); return 1; }
            pkg = argv[i];
        } else if (!strcmp(a, "-e")) {
            if (++i >= argc) { fprintf(stderr, "correlate: -e needs SPEC\n"); return 1; }
            if (nspec < 64 && parse_custom_probe_spec(argv[i], &specs[nspec], log_stderr) == 0)
                nspec++;
        } else if (!strcmp(a, "-F")) {
            if (++i >= argc) { fprintf(stderr, "correlate: -F needs FILE\n"); return 1; }
            FILE *sf = fopen(argv[i], "r");
            if (!sf) { fprintf(stderr, "correlate: cannot open %s\n", argv[i]); return 1; }
            char line[512];
            while (fgets(line, sizeof(line), sf) && nspec < 64) {
                char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
                if (line[0] == '\0' || line[0] == '#') continue;
                if (parse_custom_probe_spec(line, &specs[nspec], log_stderr) == 0) nspec++;
            }
            fclose(sf);
        } else if (!strcmp(a, "-o")) {
            if (++i >= argc) { fprintf(stderr, "correlate: -o needs FILE\n"); return 1; }
            out_path = argv[i];
        } else { fprintf(stderr, "correlate: unknown arg '%s'\n", a); usage(); return 1; }
    }

    if ((pid_count == 0 && !pkg) || (pid_count > 0 && pkg)) {
        fprintf(stderr, "correlate: specify exactly one of -p or -P\n");
        return 1;
    }
    if (nspec == 0) {
        fprintf(stderr, "correlate: no probe specs (-e / -F)\n");
        return 1;
    }
    if (out_path) {
        g_jsonl = fopen(out_path, "w");
        if (!g_jsonl) { fprintf(stderr, "correlate: cannot open %s: %s\n", out_path, strerror(errno)); return 1; }
    }

    libbpf_set_print(libbpf_print_fn);

    struct ares_correlate *skel = ares_correlate__open();
    if (!skel) { fprintf(stderr, "correlate: open skeleton failed\n"); goto err_file; }
    if (ares_correlate__load(skel)) {
        fprintf(stderr, "correlate: BPF load failed (eBPF privileges / SELinux permissive?)\n");
        goto err_skel;
    }

    // -P: install UID before launch so the kprobe gates from the start.
    if (pkg) {
        int uid = ares_resolve_uid(pkg);
        if (uid < 0) { fprintf(stderr, "correlate: cannot resolve UID for %s\n", pkg); goto err_skel; }
        if (install_uid(skel, uid) != 0) { fprintf(stderr, "correlate: install UID failed\n"); goto err_skel; }
        char cmd[512], comp[256];
        snprintf(cmd, sizeof(cmd), "am force-stop %s", pkg); ares_sh_exec(cmd, NULL, 0);
        if (ares_resolve_component(pkg, comp, sizeof(comp)) != 0) {
            fprintf(stderr, "correlate: cannot resolve launcher for %s\n", pkg); goto err_skel;
        }
        snprintf(cmd, sizeof(cmd), "am start -n %s", comp);
        printf("launching: %s\n", cmd);
        ares_sh_exec(cmd, NULL, 0);
        sleep(1);  // let the process spawn + map its libs
        char pidbuf[32] = "";
        snprintf(cmd, sizeof(cmd), "pidof %s", pkg);
        ares_sh_exec(cmd, pidbuf, sizeof(pidbuf));
        pid_t p = (pid_t)atoi(pidbuf);
        if (p <= 0) { fprintf(stderr, "correlate: could not find launched PID for %s\n", pkg); goto err_skel; }
        pids[pid_count++] = p;
    } else {
        // -p: install each pid's UID.
        for (int i = 0; i < pid_count; i++) {
            int uid = ares_get_pid_uid(pids[i]);
            if (install_uid(skel, uid) != 0)
                fprintf(stderr, "correlate: install UID for PID %d failed\n", pids[i]);
            else
                printf("[probe] > PID %d UID %d\n", pids[i], uid);
        }
    }

    // Span-gated syscall kprobe (one, shared).
    struct bpf_link *kp = bpf_program__attach(skel->progs.corr_on_svc);
    if (!kp) { fprintf(stderr, "correlate: attach do_el0_svc kprobe failed\n"); goto err_skel; }

    int total = 0;
    for (int i = 0; i < pid_count; i++) {
        int n = attach_uprobes_for_pid(skel, pids[i], specs, nspec);
        if (n > 0) total += n;
    }
    if (total == 0)
        fprintf(stderr, "correlate: warning — no uprobes attached (no spec'd functions found)\n");

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "correlate: ring buffer failed\n"); bpf_link__destroy(kp); goto err_skel; }

    signal(SIGINT, on_sigint);
    printf("correlating %d uprobe(s) -> syscalls ... Ctrl-C to stop\n", total);
    while (!exiting) {
        int err = ring_buffer__poll(rb, 200);
        if (err < 0 && err != -EINTR) break;
    }

    ring_buffer__free(rb);
    bpf_link__destroy(kp);
    ares_correlate__destroy(skel);
    if (g_jsonl) fclose(g_jsonl);
    return 0;

err_skel:
    ares_correlate__destroy(skel);
err_file:
    if (g_jsonl) fclose(g_jsonl);
    return 1;
}
