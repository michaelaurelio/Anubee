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
#include "common/engine_args.h"
#include "common/runtime.h"
#include "common/maps.h"
#include "common/syscall_index.h"
#include "common/coverage.h"

const char *argp_program_bug_address = "<michael.windarta@binus.ac.id>";

// nr -> name table (generated for the device's arm64 ABI).
static const struct ares_sysent syscall_names[] = {
#include "syscalls_gen.h"
};
static struct ares_sysindex g_sysidx;

static const char *syscall_name(long nr)
{
    const char *n = ares_sysindex_name(&g_sysidx, nr);
    return n ? n : "?";
}

static volatile sig_atomic_t exiting = 0;

static struct ares_sink g_sink;
static int              g_quiet = 0;

// Tracked uprobe links so teardown can bpf_link__destroy them (the syscall
// kprobe is tracked separately via g_kp). Grown on demand; on OOM we drop
// tracking for the new link — it stays attached and is reaped at process exit.
static struct bpf_link **g_uprobe_links = NULL;
static int g_uprobe_nlinks = 0, g_uprobe_cap = 0;

static void track_uprobe_link(struct bpf_link *link)
{
    if (g_uprobe_nlinks == g_uprobe_cap) {
        int ncap = g_uprobe_cap ? g_uprobe_cap * 2 : 64;
        struct bpf_link **n = realloc(g_uprobe_links, (size_t)ncap * sizeof(*n));
        if (!n) return;
        g_uprobe_links = n;
        g_uprobe_cap = ncap;
    }
    g_uprobe_links[g_uprobe_nlinks++] = link;
}

static void destroy_uprobe_links(void)
{
    for (int i = 0; i < g_uprobe_nlinks; i++)
        bpf_link__destroy(g_uprobe_links[i]);
    free(g_uprobe_links);
    g_uprobe_links = NULL;
    g_uprobe_nlinks = g_uprobe_cap = 0;
}

static void log_stderr(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

// ponytail: libbpf_print_fn removed; ares_libbpf_quiet from common/runtime.h used instead

static int handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct trace_event_header))
        return 0;
    const struct trace_event_header *h = data;

    if (h->type == CORR_EV_FUNC) {
        if (sz < sizeof(struct corr_func_event)) return 0;
        const struct corr_func_event *e = data;
        if (!g_quiet)
            printf("[func]    > span=%llu parent=%llu pid=%u tid=%u @ 0x%llx\n",
                   (unsigned long long)e->span, (unsigned long long)e->parent_span,
                   e->h.pid, e->h.tid, (unsigned long long)e->entry_addr);
        if (g_sink.f) {
            corr_emit_func(&g_sink.jb, e);
            ares_sink_emit(&g_sink);
        }
    } else if (h->type == CORR_EV_SYSCALL) {
        if (sz < sizeof(struct corr_syscall_event)) return 0;
        const struct corr_syscall_event *e = data;
        const char *name = syscall_name((long)e->nr);
        if (!g_quiet)
            printf("[syscall] > span=%llu pid=%u tid=%u %s (nr=%llu)\n",
                   (unsigned long long)e->span, e->h.pid, e->h.tid, name,
                   (unsigned long long)e->nr);
        if (g_sink.f) {
            corr_emit_syscall(&g_sink.jb, e, name);
            ares_sink_emit(&g_sink);
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
    int ndone = 0, attached = 0, warned = 0;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        struct ares_map_line ml;
        if (!ares_parse_maps_line(line, &ml)) continue;
        if (ml.path[0] != '/' || !ml.exec) continue;
        const char *path = ml.path;

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
            } else if (!warned) {
                fprintf(stderr, "correlate: warning — dedup table full (256) for PID %d; "
                                "duplicate uprobes may be attached\n", pid);
                warned = 1;
            }

            struct bpf_link *link = bpf_program__attach_uprobe(
                skel->progs.corr_uprobe_entry, false, pid, path, tgt.offset);
            const char *bname = strrchr(path, '/');
            bname = bname ? bname + 1 : path;
            if (link) {
                track_uprobe_link(link);
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

// ---- argp parser ----------------------------------------------------------

static const char corr_doc[] =
    "Attach entry uprobes to spec'd functions + a span-gated syscall kprobe;\n"
    "emit each in-span syscall tagged with the enclosing function's span.\v"
    "Exactly one of -p or -P must be given. At least one -e or -F is required.\n"
    "Example: ares correlate -P com.example.app -e 'libnative.so!Java_*' -o out.jsonl";
static const char corr_args_doc[] = "";

struct corr_args {
    const char        *pkg;
    const char        *out_path;
    int                quiet;
    struct target_args tgt;
    custom_probe_spec_t specs[64];
    int                nspec;
};

// Only the flags actually wired. -J/-b/-Q have nothing to attach here.
static const struct argp_option corr_options[] = {
    TARGET_ARGP_OPTIONS,
    { "package", 'P', "PACKAGE",   0, "Launch a package fresh and attach to it", 0 },
    { "spec",    'e', "SPEC",      0, "Probe spec MODULE!FUNC[(S|V,...)] (repeatable)", 0 },
    { "specs",   'F', "FILE",      0, "Load probe specs from a file (one per line, # = comment)", 0 },
    { "output",  'o', "FILE",      0, "Write structured JSONL (implies -q)", 0 },
    { "quiet",   'q', NULL,        0, "Suppress per-event console output", 0 },
    { 0 }
};

static error_t corr_parse_opt(int key, char *arg, struct argp_state *state)
{
    struct corr_args *a = state->input;
    switch (key) {
    case 'P': a->pkg      = arg; break;
    case 'o': a->out_path = arg; break;
    case 'q': a->quiet    = 1;   break;
    case 'p': case ARES_KEY_SIBLINGS: case ARES_KEY_NO_FOLLOW:
        return parse_target_arg(key, arg, state, &a->tgt);
    case 'e':
        if (a->nspec >= 64)
            fprintf(stderr, "correlate: warning — spec cap (64) reached; '%s' ignored\n", arg);
        else if (parse_custom_probe_spec(arg, &a->specs[a->nspec], log_stderr) == 0)
            a->nspec++;
        break;
    case 'F': {
        FILE *sf = fopen(arg, "r");
        if (!sf) argp_error(state, "cannot open '%s': %s", arg, strerror(errno));
        char line[512];
        while (fgets(line, sizeof(line), sf) && a->nspec < 64) {
            char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
            if (line[0] == '\0' || line[0] == '#') continue;
            if (parse_custom_probe_spec(line, &a->specs[a->nspec], log_stderr) == 0) a->nspec++;
        }
        if (a->nspec >= 64 && !feof(sf))
            fprintf(stderr, "correlate: warning — spec cap (64) reached; "
                            "remaining lines in '%s' ignored\n", arg);
        fclose(sf);
        break;
    }
    case ARGP_KEY_END:
        if ((a->tgt.n == 0 && !a->pkg) || (a->tgt.n > 0 && a->pkg))
            argp_error(state, "specify exactly one of -p or -P");
        if (a->nspec == 0)
            argp_error(state, "no probe specs given (-e SPEC or -F FILE)");
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp corr_argp = { corr_options, corr_parse_opt, corr_args_doc, corr_doc, 0, 0, 0 };

// ---- three-phase driver ---------------------------------------------------
// correlate_setup/run/teardown are kept global for signature parity with the
// other engines. rc is plumbed through for future coordinator use but is not
// consumed: correlate's -P launch stays inside setup because uprobe attach needs
// the child PID (only known post-launch) before setup returns.
// ponytail: correlate stays standalone — trace --correlate is deferred; the
// coordinator would need a post-launch correlate_attach(pid) step (5th public fn).

// Cross-phase state: published by correlate_setup, consumed by run/teardown.
static struct ares_correlate *g_skel;
static struct bpf_link        *g_kp;
static struct bpf_link        *g_ff;
static struct ring_buffer     *g_rb;
static int                     g_total;

int correlate_setup(int argc, char **argv, const struct ares_run_ctx *rc)
{
    ares_sysindex_build(&g_sysidx, syscall_names,
                        sizeof(syscall_names) / sizeof(syscall_names[0]));
    (void)rc;  // plumbed for parity; trace --correlate wiring deferred (post-launch attach)
    // ponytail: static so specs/pkg strings (pointing into argv) outlive setup.
    static struct corr_args ca = { 0 };
    if (argp_parse(&corr_argp, argc, argv, 0, NULL, &ca) != 0)
        return 1;

    g_quiet = ca.quiet || (ca.out_path != NULL);
    if (ca.out_path && ares_sink_open(&g_sink, ca.out_path, "event", 1) != 0) {
        fprintf(stderr, "correlate: cannot open %s: %s\n", ca.out_path, strerror(errno));
        return 1;
    }

    libbpf_set_print(ares_libbpf_quiet);

    struct ares_correlate *skel = ares_correlate__open();
    if (!skel) { fprintf(stderr, "correlate: open skeleton failed\n"); goto err_file; }
    if (ares_correlate__load(skel)) {
        fprintf(stderr, "correlate: BPF load failed (eBPF privileges / SELinux permissive?)\n");
        goto err_skel;
    }

    // -P: install UID before launch so the kprobe gates from the start.
    if (ca.pkg) {
        int uid = ares_resolve_uid(ca.pkg);
        if (uid < 0) { fprintf(stderr, "correlate: cannot resolve UID for %s\n", ca.pkg); goto err_skel; }
        if (install_uid(skel, uid) != 0) { fprintf(stderr, "correlate: install UID failed\n"); goto err_skel; }
        ares_launch_banner(ca.pkg, uid);
        pid_t p;
        if (ares_launch_app(ca.pkg, NULL, &p) != 0) {
            fprintf(stderr, "correlate: launch failed for %s\n", ca.pkg); goto err_skel;
        }
        sleep(1);  // let the process map its libs before uprobe attach
        ca.tgt.pids[ca.tgt.n++] = p;
    } else {
        // -p: arm target_pids for each PID; arm target_uids only if --siblings.
        __u8 one = 1;
        for (int i = 0; i < ca.tgt.n; i++) {
            __u32 tgid = (__u32)ca.tgt.pids[i];
            bpf_map_update_elem(bpf_map__fd(skel->maps.target_pids), &tgid, &one, BPF_ANY);
            if (ca.tgt.siblings) {
                int uid = ares_get_pid_uid(ca.tgt.pids[i]);
                if (install_uid(skel, uid) != 0)
                    fprintf(stderr, "correlate: install UID for PID %d failed\n", ca.tgt.pids[i]);
            }
        }
        if (!ca.tgt.no_follow) {
            g_ff = bpf_program__attach(skel->progs.ares_follow_fork);
            if (!g_ff) fprintf(stderr, "correlate: follow-fork attach failed (non-fatal)\n");
        }
    }

    // Span-gated syscall kprobe (one, shared).
    struct bpf_link *kp = bpf_program__attach(skel->progs.corr_on_svc);
    if (!kp) { fprintf(stderr, "correlate: attach do_el0_svc kprobe failed\n"); goto err_skel; }

    int total = 0;
    for (int i = 0; i < ca.tgt.n; i++) {
        int n = attach_uprobes_for_pid(skel, ca.tgt.pids[i], ca.specs, ca.nspec);
        if (n > 0) total += n;
    }
    if (total == 0)
        fprintf(stderr, "correlate: warning — no uprobes attached (no spec'd functions found)\n");

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "correlate: ring buffer failed\n"); bpf_link__destroy(kp); destroy_uprobe_links(); goto err_skel; }

    g_skel  = skel;
    g_kp    = kp;
    g_rb    = rb;
    g_total = total;
    return 0;

err_skel:
    destroy_uprobe_links();
    ares_correlate__destroy(skel);
err_file:
    if (g_sink.f) ares_sink_close(&g_sink);
    return 1;
}

int correlate_run(volatile sig_atomic_t *stop)
{
    printf("correlating %d uprobe(s) -> syscalls ... Ctrl-C to stop\n", g_total);
    ares_rb_poll_until(g_rb, stop);
    return 0;
}

void correlate_teardown(void)
{
    if (g_rb) {
        ring_buffer__free(g_rb);
        g_rb = NULL;
    }
    if (g_kp) {
        bpf_link__destroy(g_kp);
        g_kp = NULL;
    }
    if (g_ff) {
        bpf_link__destroy(g_ff);
        g_ff = NULL;
    }
    destroy_uprobe_links();
    if (g_skel) {
        // Always report the final tally, so "no message" never means "didn't
        // check". Subsumes the old ares_drops_report: ring/queue drops are
        // coverage fields here. No worker queue in correlate (ring drained
        // inline) -> queue_drops = 0.
        struct ares_coverage cov = { .engine = "correlate" };
        int covfd = bpf_map__fd(g_skel->maps.coverage_stats);
        cov.depth_capped   = ares_coverage_read(covfd, COV_DEPTH_CAP);
        cov.ring_drops     = ares_drops_read(bpf_map__fd(g_skel->maps.dropped));
        cov.queue_drops    = 0;
        cov.decode_partial = 1;   // raw syscall args, no decode
        ares_coverage_report(&g_sink, &cov);
        ares_correlate__destroy(g_skel);
        g_skel = NULL;
    }
    if (g_sink.f) { ares_sink_close(&g_sink); ares_sink_report(&g_sink); }
}

// ---- entry point (thin standalone wrapper) --------------------------------

int cmd_correlate(int argc, char **argv)
{
    if (correlate_setup(argc, argv, NULL) != 0)
        return 1;

    ares_install_stop_handler(&exiting);
    correlate_run(&exiting);
    correlate_teardown();
    return 0;
}
