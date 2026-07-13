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
// SP-based span close by default, --returns opts a target into an authoritative
// uretprobe pop; syscall args get string/fd/sockaddr/flags decode (see corr_emit.c).
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "correlate.skel.h"
#include "correlate.h"
#include "common/emit.h"
#include "common/launch.h"
#include "common/probe_resolve.h"
#include "common/probe_spec_loader.h"
#include "common/target_validate.h"
#include "common/pattern_match.h"
#include "common/syscall_argtypes.h"
#include "common/engine_args.h"
#include "common/runtime.h"
#include "common/maps.h"
#include "common/syscall_index.h"
#include "common/syscall_table.h"
#include "common/engine_driver.h"  // correlate_setup/_run/_teardown (AA3)
#include "common/coverage.h"
#include "common/human_out.h"      // SYM1 Phase 2: shared stdout detail-line printer

const char *argp_program_bug_address = "<michael.windarta@binus.ac.id>";

// nr -> name table (generated for the device's arm64 ABI). R9 residual: table
// data now lives once in common/syscall_table.c, shared with syscalls.c.
static struct ares_sysindex g_sysidx;

static const char *syscall_name(long nr)
{
    const char *n = ares_sysindex_name(&g_sysidx, nr);
    return n ? n : "?";
}

// Syscall arg-decode tables (g_str_args/g_sock_args/g_fd_args) + install_arg_types/
// install_sock_args/arg_fd_mask/arg_sock_index now live in
// common/syscall_argtypes.{h,c} (EPIC I2) - shared verbatim with syscalls.c
// instead of duplicated here.

static volatile sig_atomic_t exiting = 0;

static struct ares_sink g_sink;
static int              g_quiet = 0;
static int              g_returns = 0;  // --returns: attach a uretprobe per target too

// SYM1 Phase 5c: end-of-run summary counters -- plain counts, no per-name
// tally (unlike syscalls/funcs). Not the same as the BPF-map-read
// cov.spans_opened/cov.returns_captured at teardown (those are only
// populated under --returns; these are simple userspace counters,
// unconditionally correct regardless of mode). Tallied unconditionally so
// the summary survives -q.
static unsigned long long g_sum_spans_opened;
static unsigned long long g_sum_syscalls_captured;
static unsigned long long g_sum_returns_captured;

// Console twin of corr_emit_summary (below). Plain text, no box-drawing/color.
static void corr_print_summary(void)
{
    if (!g_sum_spans_opened && !g_sum_syscalls_captured && !g_sum_returns_captured) return;
    printf("-- Correlate Summary --\n");
    printf("  %llu span%s opened, %llu syscall%s captured, %llu return%s captured\n",
           g_sum_spans_opened, g_sum_spans_opened == 1 ? "" : "s",
           g_sum_syscalls_captured, g_sum_syscalls_captured == 1 ? "" : "s",
           g_sum_returns_captured, g_sum_returns_captured == 1 ? "" : "s");
}

static void corr_emit_summary(struct ares_sink *s)
{
    if (!s->f) return;
    if (!g_sum_spans_opened && !g_sum_syscalls_captured && !g_sum_returns_captured) return;
    struct jbuf *j = &s->jb;
    j->len = 0;
    jb_c(j, '{');
    jb_s(j, "\"type\":\"correlate_summary\"");
    jb_s(j, ",\"spans_opened\":");      jb_u64(j, g_sum_spans_opened);
    jb_s(j, ",\"syscalls_captured\":"); jb_u64(j, g_sum_syscalls_captured);
    jb_s(j, ",\"returns_captured\":");  jb_u64(j, g_sum_returns_captured);
    jb_c(j, '}');
    ares_sink_emit(s);
}

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
        g_sum_spans_opened++; // SYM1 Phase 5c: tallied unconditionally so the summary survives -q.
        if (!g_quiet)
            // SYM1 Phase 4d: was printf(...).
            ts_print("[func]    > span=%llu parent=%llu pid=%u tid=%u @ 0x%llx\n",
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
        g_sum_syscalls_captured++; // SYM1 Phase 5c: tallied unconditionally so the summary survives -q.
        // SYM1 Phase 2: hoisted above the stdout/file split — both channels may
        // be live under dual-channel (Phase 1), and both want the same decode.
        unsigned fdmask = arg_fd_mask(e->nr);
        int sockidx = arg_sock_index(e->nr);
        if (!g_quiet) {
            // SYM1 Phase 4d: was printf(...).
            ts_print("[syscall] > span=%llu pid=%u tid=%u %s (nr=%llu)\n",
                   (unsigned long long)e->span, e->h.pid, e->h.tid, name,
                   (unsigned long long)e->nr);
            // Decoded args (paths/fds/sockaddrs/flag names) — same precedence
            // corr_emit_syscall's "decoded":[...] JSON array already had,
            // closing the sharpest stdout/file content gap (§3.3).
            for (int i = 0; i < CORR_SYS_ARGS; i++) {
                char dec[300];
                if (corr_decode_arg(e, i, fdmask, sockidx, dec, sizeof(dec)))
                    human_detail("syscall", "args[%d] %s\n", i, dec);
                else
                    human_detail("syscall", "args[%d] 0x%llx\n", i, (unsigned long long)e->args[i]);
            }
        }
        if (g_sink.f) {
            corr_emit_syscall(&g_sink.jb, e, name, fdmask, sockidx);
            ares_sink_emit(&g_sink);
        }
    } else if (h->type == CORR_EV_RETURN) {
        if (sz < sizeof(struct corr_return_event)) return 0;
        const struct corr_return_event *e = data;
        g_sum_returns_captured++; // SYM1 Phase 5c: tallied unconditionally so the summary survives -q.
        if (!g_quiet)
            // SYM1 Phase 4d: was printf(...).
            ts_print("[return]  > span=%llu retval=0x%llx elapsed=%lluns @ 0x%llx\n",
                   (unsigned long long)e->span, (unsigned long long)e->retval,
                   (unsigned long long)e->elapsed_ns, (unsigned long long)e->entry_addr);
        if (g_sink.f) {
            corr_emit_return(&g_sink.jb, e);
            ares_sink_emit(&g_sink);
        }
    } else if (h->type == CORR_EV_MAP) {
        if (sz < sizeof(struct lib_map_event)) return 0;
        const struct lib_map_event *e = data;
        char path[256];
        if (ares_libtrace_resolve_path(e->h.pid, e->start, e->name,
                                       path, sizeof(path)) != 0)
            snprintf(path, sizeof(path), "%s", e->name);
        // emit self-gates: console line unless -q, {"type":"lib"} when -o set.
        ares_libtrace_emit_lib(&g_sink, g_quiet, e, path, NULL);
    } else if (h->type == CORR_EV_UNMAP) {
        if (sz < sizeof(struct lib_unmap_event)) return 0;
        const struct lib_unmap_event *e = data;
        ares_libtrace_emit_unlib(&g_sink, g_quiet, e);
    }
    return 0;
}

// Scan /proc/<pid>/maps and attach the entry uprobe at every spec'd function.
struct corr_dedup_entry { char path[256]; unsigned long off; };

// Attach a single resolved custom-spec target, deduping via `done[]`. Shared
// by both the exact-match spec path and the bulk /regex/ func-match path
// (EPIC H12).
static void attach_custom_spec_target(struct ares_correlate *skel, pid_t pid,
                                       const char *path, probe_target_t tgt, int returns,
                                       struct corr_dedup_entry *done, int *ndone,
                                       int *attached, int *warned)
{
    int dup = 0;
    for (int d = 0; d < *ndone; d++)
        if (done[d].off == tgt.offset && strcmp(done[d].path, path) == 0) { dup = 1; break; }
    if (dup) return;
    if (*ndone < 256) {
        snprintf(done[*ndone].path, sizeof(done[*ndone].path), "%s", path);
        done[*ndone].off = tgt.offset;
        (*ndone)++;
    } else if (!*warned) {
        fprintf(stderr, "correlate: warning — dedup table full (256) for PID %d; "
                        "duplicate uprobes may be attached\n", pid);
        *warned = 1;
    }

    struct bpf_link *link = bpf_program__attach_uprobe(
        skel->progs.corr_uprobe_entry, false, pid, path, tgt.offset);
    const char *bname = strrchr(path, '/');
    bname = bname ? bname + 1 : path;
    if (link) {
        track_uprobe_link(link);
        printf("[spec] > %s!%s @ 0x%lx\n", bname,
               tgt.func_name[0] ? tgt.func_name : "?", tgt.offset);
        (*attached)++;
        if (returns) {
            struct bpf_link *rl = bpf_program__attach_uprobe(
                skel->progs.corr_uretprobe_ret, true, pid, path, tgt.offset);
            if (rl)
                track_uprobe_link(rl);
            else
                fprintf(stderr, "[spec] > RET FAILED: %s!%s @ 0x%lx\n", bname,
                        tgt.func_name[0] ? tgt.func_name : "?", tgt.offset);
        }
    } else {
        fprintf(stderr, "[spec] > FAILED: %s!%s @ 0x%lx\n", bname,
                tgt.func_name[0] ? tgt.func_name : "?", tgt.offset);
    }
}

static int attach_uprobes_for_pid(struct ares_correlate *skel, pid_t pid,
                                  const custom_probe_spec_t *specs, int nspec,
                                  int returns)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        fprintf(stderr, "correlate: cannot open %s: %s\n", maps_path, strerror(errno));
        return -1;
    }

    // Small dedup of (path,offset) already attached for this pid.
    struct corr_dedup_entry done[256];
    int ndone = 0, attached = 0, warned = 0;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        struct ares_map_line ml;
        if (!ares_parse_maps_line(line, &ml)) continue;
        if (ml.path[0] != '/' || !ml.exec) continue;
        const char *path = ml.path;

        for (int s = 0; s < nspec; s++) {
            // Multi-kind files (EPIC H11) may carry syscall:/lib:/mod: lines
            // meant for other engines -- only funcs-kind specs describe a
            // uprobe target.
            if (specs[s].kind != SPEC_KIND_FUNCS) continue;
            if (!custom_spec_matches_path(&specs[s], path)) continue;

            if (pm_is_regex(specs[s].func)) {
                // Bulk match: one spec, potentially many symbols (EPIC H12,
                // replaces -i's "scan every symbol in a matched module" shape).
                probe_target_t matches[256];
                int n = resolve_custom_spec_matches_for_path(pid, path, &specs[s], matches, 256);
                if (n == 256)
                    fprintf(stderr, "correlate: warning — regex match cap (256) reached for %s!%s "
                                    "in %s; additional matches may exist and were ignored\n",
                            specs[s].mod, specs[s].func, path);
                for (int m = 0; m < n; m++)
                    attach_custom_spec_target(skel, pid, path, matches[m], returns,
                                               done, &ndone, &attached, &warned);
                continue;
            }

            probe_target_t tgt;
            if (resolve_custom_spec_for_path(pid, path, &specs[s], &tgt) != 0)
                continue;
            attach_custom_spec_target(skel, pid, path, tgt, returns,
                                       done, &ndone, &attached, &warned);
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

// -P timing: block briefly after launch until a spec'd/regex-matched library
// shows up mapped-executable in /proc/<pid>/maps, instead of a blind sleep(1)
// (which misses calls in the first second and over-waits once the lib is
// already up). Falls through on timeout — same worst case as the old sleep.
static void wait_for_target_mapped(pid_t pid, const custom_probe_spec_t *specs, int nspec)
{
    const int poll_ms = 10, timeout_ms = 2000;
    for (int waited = 0; waited < timeout_ms; waited += poll_ms) {
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
        FILE *f = fopen(maps_path, "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                struct ares_map_line ml;
                if (!ares_parse_maps_line(line, &ml)) continue;
                if (ml.path[0] != '/' || !ml.exec) continue;
                for (int s = 0; s < nspec; s++)
                    if (custom_spec_matches_path(&specs[s], ml.path)) { fclose(f); return; }
            }
            fclose(f);
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)poll_ms * 1000000L };
        nanosleep(&ts, NULL);
    }
}

// ---- argp parser ----------------------------------------------------------

static const char corr_doc[] =
    "Attach entry uprobes to spec'd functions + a span-gated syscall kprobe;\n"
    "emit each in-span syscall tagged with the enclosing function's span.\v"
    "Exactly one of -p or -P must be given. At least one of -e/-F is required.\n"
    "Example: ares correlate -P com.example.app -e 'libnative.so!Java_*' -o out.jsonl";
static const char corr_args_doc[] = "";

#define ARES_KEY_RETURNS 0x200   // correlate-local long-only key (--returns)

struct corr_args {
    struct common_args c;          // -o -v -q -J -b -Q (shared with funcs/syscalls)
    const char        *pkg;
    int                returns;
    struct target_args tgt;
    custom_probe_spec_t specs[64];
    int                nspec;
};

// Only the flags actually wired. -J/-b/-Q have nothing to attach here.
static const struct argp_option corr_options[] = {
    TARGET_ARGP_OPTIONS,
    { "package", 'P', "PACKAGE",   0, "Launch a package fresh and attach to it", 0 },
    { "spec",    'e', "SPEC",      0, "Probe spec MODULE!FUNC[(S|V,...)] (repeatable); MODULE/FUNC accept /regex/ for bulk matching", 0 },
    { "specs",   'F', "FILE",      0, "Load probe specs from a file (one per line, # = comment)", 0 },
    COMMON_ARGP_OPTIONS,
    { "returns", ARES_KEY_RETURNS, NULL, 0,
      "Also attach uretprobes: return value + exact span timing (LOUD: adds a "
      "stack trampoline, a 2nd detection surface beyond the entry BRK)", 0 },
    { 0 }
};

static error_t corr_parse_opt(int key, char *arg, struct argp_state *state)
{
    struct corr_args *a = state->input;
    switch (key) {
    case 'P': a->pkg = arg; break;
    case 'o': case 'v': case 'q': case 'J': case 'b': case 'Q':
        return parse_common_arg(key, arg, state, &a->c);
    case ARES_KEY_RETURNS: a->returns = 1; break;
    case 'p': case ARES_KEY_SIBLINGS: case ARES_KEY_NO_FOLLOW:
        return parse_target_arg(key, arg, state, &a->tgt);
    case 'e':
        if (a->nspec >= 64)
            fprintf(stderr, "correlate: warning — spec cap (64) reached; '%s' ignored\n", arg);
        else if (parse_custom_probe_spec(arg, &a->specs[a->nspec], log_stderr) == 0)
            a->nspec++;
        break;
    case 'F':
        if (load_probe_spec_file(arg, a->specs, 64, &a->nspec, log_stderr) != 0)
            argp_error(state, "cannot open spec file '%s'", arg);
        break;
    case ARGP_KEY_END:
        validate_pid_or_package(state, a->tgt.n, a->pkg);
        validate_have_selector(state, a->nspec, "-e SPEC or -F FILE");
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp corr_argp = { corr_options, corr_parse_opt, corr_args_doc, corr_doc, 0, 0, 0 };

// ---- four-phase driver -----------------------------------------------------
// correlate_setup arms everything that doesn't need the target PID; the caller
// (standalone cmd_correlate, or trace's coordinator) owns the single app launch
// and calls correlate_attach(pid) right after it succeeds, matching the other
// four engines' "setup arms, caller launches" contract (AA3/GA2) — the one
// correlate-specific wrinkle is that uprobe attach needs the launched PID, only
// known post-launch, so that one step is a 5th public function instead of living
// inside correlate_run/_teardown. In -p attach mode the PID(s) are already known
// at setup time, so setup attaches immediately and correlate_attach is a no-op.

// Cross-phase state: published by correlate_setup, consumed by run/teardown/attach.
static struct ares_correlate *g_skel;
static struct bpf_link        *g_kp;
static struct bpf_link        *g_ff;
static struct bpf_link        *g_map_kp;    // shared lib_trace uprobe_mmap kprobe
static struct bpf_link        *g_unmap_kp;  // shared lib_trace uprobe_munmap kprobe
static struct ring_buffer     *g_rb;
static int                     g_total;
static const char             *g_pkg;       // non-NULL in launch mode (-P); NULL in -p mode
static int                      g_uid;      // resolved UID, valid when g_pkg is set
// ponytail: promoted from correlate_setup's old function-local static so
// correlate_attach can reach the same specs/tgt state after setup returns.
static struct corr_args         g_ca = { .c = COMMON_ARGS_INIT };

// Attach the shared lib_trace kprobes (uprobe_mmap / uprobe_munmap) that emit the
// {"type":"lib"}/{"type":"unlib"} records. Attached before launch in -P mode (like
// the UID install) so the target's startup library maps are captured, not just
// later dlopens.
static int attach_lib_kprobes(struct ares_correlate *skel)
{
    g_map_kp = bpf_program__attach(skel->progs.on_uprobe_mmap);
    if (!g_map_kp) { fprintf(stderr, "correlate: attach uprobe_mmap kprobe failed\n"); return -1; }
    g_unmap_kp = bpf_program__attach(skel->progs.on_uprobe_munmap);
    if (!g_unmap_kp) { fprintf(stderr, "correlate: attach uprobe_munmap kprobe failed\n"); return -1; }
    return 0;
}

int correlate_setup(int argc, char **argv, const struct ares_run_ctx *rc)
{
    ares_sysindex_build(&g_sysidx, ares_syscall_table, ares_syscall_table_count);
    // Coordinator pre-fill (mirrors lib/dump/syscalls/funcs): lets trace drive
    // -P mode without repeating -P in the --correlate argv section.
    if (rc && rc->pkg)
        g_ca.pkg = rc->pkg;
    if (argp_parse(&corr_argp, argc, argv, ARGP_NO_EXIT, NULL, &g_ca) != 0)
        return 1;

    g_quiet   = g_ca.c.quiet; // SYM1 Phase 1: -o no longer forces quiet; file and stdout are independent channels

    if (g_ca.c.output_file && ares_sink_open(&g_sink, g_ca.c.output_file, "event", 1) != 0) {
        fprintf(stderr, "correlate: cannot open %s: %s\n", g_ca.c.output_file, strerror(errno));
        return 1;
    }

    libbpf_set_print(ares_libbpf_quiet);

    struct ares_correlate *skel = ares_correlate__open();
    if (!skel) { fprintf(stderr, "correlate: open skeleton failed\n"); goto err_file; }
    bpf_program__set_autoattach(skel->progs.corr_uretprobe_ret, false);
    if (ares_correlate__load(skel)) {
        fprintf(stderr, "correlate: BPF load failed (eBPF privileges / SELinux permissive?)\n");
        goto err_skel;
    }
    install_arg_types(bpf_map__fd(skel->maps.arg_types));
    install_sock_args(bpf_map__fd(skel->maps.sock_args));

    if (g_ca.pkg) {
        // Launch mode (-P, standalone or coordinator): arm everything that
        // doesn't need the target PID. Install UID before launch so the kprobe
        // gates from the start. The launch itself, and the post-launch uprobe
        // attach, are the caller's job now — see correlate_attach() below.
        g_uid = ares_resolve_uid(g_ca.pkg);
        if (g_uid < 0) { fprintf(stderr, "correlate: cannot resolve UID for %s\n", g_ca.pkg); goto err_skel; }
        if (install_uid(skel, g_uid) != 0) { fprintf(stderr, "correlate: install UID failed\n"); goto err_skel; }
        // Attach lib_trace kprobes before launch so startup maps are captured.
        if (attach_lib_kprobes(skel) != 0) goto err_skel;
        g_pkg = g_ca.pkg;
    } else {
        // -p: arm target_pids for each PID; arm target_uids only if --siblings.
        __u8 one = 1;
        for (int i = 0; i < g_ca.tgt.n; i++) {
            __u32 tgid = (__u32)g_ca.tgt.pids[i];
            bpf_map_update_elem(bpf_map__fd(skel->maps.target_pids), &tgid, &one, BPF_ANY);
            if (g_ca.tgt.siblings) {
                int uid = ares_get_pid_uid(g_ca.tgt.pids[i]);
                if (uid > 0 && install_uid(skel, uid) != 0)
                    fprintf(stderr, "correlate: install UID for PID %d failed\n", g_ca.tgt.pids[i]);
            }
        }
        if (!g_ca.tgt.no_follow) {
            g_ff = bpf_program__attach(skel->progs.ares_follow_fork);
            if (!g_ff) fprintf(stderr, "correlate: follow-fork attach failed (non-fatal)\n");
        }
        // Already-running target: catches future maps/unmaps (dlopen/dlclose).
        if (attach_lib_kprobes(skel) != 0) goto err_skel;
    }

    // Span-gated syscall kprobe (one, shared) — doesn't depend on the PID, so
    // it's armed here regardless of mode.
    struct bpf_link *kp = bpf_program__attach(skel->progs.corr_on_svc);
    if (!kp) { fprintf(stderr, "correlate: attach do_el0_svc kprobe failed\n"); goto err_skel; }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "correlate: ring buffer failed\n"); bpf_link__destroy(kp); goto err_skel; }

    g_skel    = skel;
    g_kp      = kp;
    g_rb      = rb;
    g_returns = g_ca.returns;

    int total = 0;
    if (!g_ca.pkg) {
        // -p mode: PIDs already known, attach uprobes now (launch mode defers
        // this to correlate_attach, once the launched PID is known).
        for (int i = 0; i < g_ca.tgt.n; i++) {
            int n = attach_uprobes_for_pid(skel, g_ca.tgt.pids[i], g_ca.specs, g_ca.nspec, g_ca.returns);
            if (n > 0) total += n;
        }
        if (total == 0)
            fprintf(stderr, "correlate: warning — no uprobes attached (no spec'd functions found)\n");
        if (g_ca.returns && total > 0)
            fprintf(stderr, "correlate: --returns active - uretprobe trampoline on the "
                            "target stack is a 2nd detection surface (beyond the entry BRK)\n");
    }
    g_total = total;
    return 0;

err_skel:
    // AA11 fix: g_ff (attached earlier in setup, if reached) isn't touched by
    // destroy_uprobe_links() — destroy it explicitly, same as funcs' teardown-reuse.
    if (g_ff) {
        bpf_link__destroy(g_ff);
        g_ff = NULL;
    }
    destroy_uprobe_links();
    ares_correlate__destroy(skel);
err_file:
    if (g_sink.f) {
        ares_sink_close(&g_sink);
        ares_sink_report(&g_sink);
    }
    return 1;
}

// Post-launch uprobe attach for -P (launch) mode: the caller (standalone
// cmd_correlate, or trace's coordinator) calls this right after its single
// ares_launch_app succeeds, since uprobe attach needs the launched PID. No-op
// if correlate_setup ran in -p attach mode (PIDs were already known and
// attached during setup).
int correlate_attach(pid_t pid)
{
    if (!g_pkg) return 0;

    wait_for_target_mapped(pid, g_ca.specs, g_ca.nspec);
    g_ca.tgt.pids[g_ca.tgt.n++] = pid;

    int n = attach_uprobes_for_pid(g_skel, pid, g_ca.specs, g_ca.nspec, g_ca.returns);
    if (n > 0) g_total += n;
    if (g_total == 0)
        fprintf(stderr, "correlate: warning — no uprobes attached (no spec'd functions found)\n");
    if (g_ca.returns && g_total > 0)
        fprintf(stderr, "correlate: --returns active - uretprobe trampoline on the "
                        "target stack is a 2nd detection surface (beyond the entry BRK)\n");
    return 0;
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
    if (g_map_kp)   { bpf_link__destroy(g_map_kp);   g_map_kp = NULL; }
    if (g_unmap_kp) { bpf_link__destroy(g_unmap_kp); g_unmap_kp = NULL; }
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
        cov.decode_partial = 0;   // string/fd/sockaddr/flags decode wired (see corr_emit.c)
        if (g_returns) {
            cov.returns_mode      = 1;
            cov.spans_opened      = ares_coverage_read(covfd, COV_SPAN_OPEN);
            cov.returns_captured  = ares_coverage_read(covfd, COV_URET_FIRED);
        }
        ares_coverage_report(&g_sink, &cov);
        // SYM1 Phase 5c: end-of-run content summary, same slot as coverage
        // (sink must still be open for emit_summary's JSON line).
        corr_print_summary();
        corr_emit_summary(&g_sink);
        ares_correlate__destroy(g_skel);
        g_skel = NULL;
    }
    if (g_sink.f) { ares_sink_close(&g_sink); ares_sink_report(&g_sink); }
}

// ---- entry point (thin standalone wrapper) --------------------------------

int cmd_correlate(int argc, char **argv)
{
    // MT1: argp_parse(ARGP_NO_EXIT) inside correlate_setup returns 0 on --help/
    // --usage (it only prints), so control would otherwise fall through into
    // attach/run.
    if (ares_wants_help(argc, argv)) {
        argp_help(&corr_argp, stdout, ARGP_HELP_STD_HELP, argv[0]);
        return 0;
    }

    if (correlate_setup(argc, argv, NULL) != 0)
        return 1;

    // Standalone: tracing is armed (UID installed in setup for -P mode); in -P
    // mode launch now and attach uprobes to the fresh PID, in -p mode setup
    // already attached everything.
    ares_install_stop_handler(&exiting);
    if (g_pkg) {
        ares_launch_banner(g_pkg, g_uid);
        pid_t p;
        if (ares_launch_app(g_pkg, NULL, &p) != 0) {
            fprintf(stderr, "correlate: launch failed for %s\n", g_pkg);
            correlate_teardown();
            return 1;
        }
        correlate_attach(p);
    }

    correlate_run(&exiting);
    correlate_teardown();
    return 0;
}
