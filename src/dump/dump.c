// SPDX-License-Identifier: GPL-2.0
// `ares dump` — launch an Android app fresh and dump a (possibly decrypted)
// native library from its live memory, rebuilt into a loadable ELF.
//
// Stealthy, kprobe-based (like `ares lib`): launch the package under a UID
// filter installed before launch, capture mappings with the shared lib_trace
// probe. Two triggers:
//   - default (dump-on-exit): record every app pid; at Ctrl-C/exit, rescan each
//     pid's /proc/<pid>/maps and dump every module matching <pattern> from the
//     still-live (post-decryption) image.
//   - --on-map: dump a matching module the instant it maps (catches transient /
//     short-lived libraries, at the cost of possibly dumping pre-decryption).
//
// The ELF capture + rebuild is src/dump/rebuild.c; capture/path-resolution is
// the shared src/common/lib_trace.*. The device/launch helpers are shared from
// src/common/launch.{c,h} as ares_*.
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "dump.skel.h"
#include "common/lib_trace.h"
#include "common/launch.h"
#include "common/engine_args.h"
#include "common/runtime.h"
#include "common/engine_driver.h"  // dump_setup/_run/_teardown (AA3)
#include "common/probe_resolve.h"
#include "common/probe_spec_loader.h"
#include "common/human_out.h"      // err_print: surface -F parse errors (was silently NULL)
#include "common/emit.h"           // SYM1 Phase 3: struct ares_sink, ares_sink_open/close/report
#include "common/coverage.h"       // SYM1 Phase 5b: explicit "exempt" coverage record
#include "dump/dump_args.h"
#include "rebuild.h"

const char *argp_program_bug_address = "<michael.windarta@binus.ac.id>";

static volatile sig_atomic_t exiting = 0;

static const char **g_patterns = NULL; // module patterns to dump (glob/substring); OR'd
static int g_npat = 0;
static const char *g_outdir  = ".";    // -d: output directory
static int g_on_map  = 0;              // --on-map: dump at map time, not on exit
static int g_quiet   = 0;              // -q: suppress progress chatter
static int g_now;                      // --now: pure /proc snapshot, no BPF
static int g_check;                    // --check: compare, don't write
static const unsigned long long *g_bases;
static int g_nbase;
static int g_tgt_pids[64];             // -p targets (for --now's direct rescan)
static int g_ntgt;

// Raw parsed specs (from -F), copied out of dump_setup's local `da` so both
// the before-run and after-run "ignoring non-lib: spec" warnings can read
// them (see print_ignored_kind_warning below).
static custom_probe_spec_t g_specs[64];
static int g_nspec;

// Per-pattern "did this lib: pattern ever match a module" tracking, index-
// aligned with g_patterns[]. Set at match time (handle_event's dump-on-map
// path and dump_pid_modules's dump-on-exit rescan); reported at end of run
// so a typo'd pattern that dumped nothing isn't silent (see
// print_never_matched_report below).
static int g_pat_hit[64];

// SYM1 Phase 3: machine channel — a {"type":"dump",...} manifest record per
// dumped module, mirroring every other engine's g_sink. Independent of
// g_quiet (dump never had an -o-implies-quiet coupling, unchanged by Phase 1).
static struct ares_sink g_sink;

// ---- dump-on-exit: record every app pid that maps anything ----------------
static __u32 *g_pids;
static size_t g_pids_n, g_pids_cap;
static void note_pid(__u32 pid)
{
	for (size_t i = 0; i < g_pids_n; i++)
		if (g_pids[i] == pid)
			return;
	if (g_pids_n == g_pids_cap) {
		size_t nc = g_pids_cap ? g_pids_cap * 2 : 16;
		__u32 *np = realloc(g_pids, nc * sizeof(*np));
		if (!np)
			return;
		g_pids = np;
		g_pids_cap = nc;
	}
	g_pids[g_pids_n++] = pid;
}

// ---- dump-on-map: dedup (pid,start) so a module is dumped once -------------
struct seen { __u32 pid; __u64 start; };
static struct seen *g_seen;
static size_t g_seen_n, g_seen_cap;
static int seen_add(__u32 pid, __u64 start)
{
	for (size_t i = 0; i < g_seen_n; i++)
		if (g_seen[i].pid == pid && g_seen[i].start == start)
			return 0;                  // already dumped
	if (g_seen_n == g_seen_cap) {
		size_t nc = g_seen_cap ? g_seen_cap * 2 : 16;
		struct seen *ns = realloc(g_seen, nc * sizeof(*ns));
		if (!ns)
			return 0;
		g_seen = ns;
		g_seen_cap = nc;
	}
	g_seen[g_seen_n].pid = pid;
	g_seen[g_seen_n].start = start;
	g_seen_n++;
	return 1;                              // newly recorded
}

// ---- ring-buffer event handling -------------------------------------------

static int handle_event(void *ctx, void *data, size_t sz)
{
	(void)ctx;
	if (sz < sizeof(struct lib_event_header))
		return 0;
	const struct lib_event_header *h = data;
	if (h->type != LIB_EV_MAP)
		return 0;
	if (sz < sizeof(struct lib_map_event))
		return 0;
	const struct lib_map_event *e = data;

	if (!g_on_map) {
		note_pid(h->pid);              // dump-on-exit: defer to the rescan
		return 0;
	}

	// dump-on-map: resolve, match, dump this module once.
	char path[256];
	const char *full = path;
	if (ares_libtrace_resolve_path(h->pid, e->start, e->name, path, sizeof(path)) != 0)
		full = e->name;
	if (!dump_name_matches_any_track(g_patterns, g_npat, full, g_pat_hit))
		return 0;
	if (!seen_add(h->pid, e->start))
		return 0;
	if (!g_quiet)
		printf("[dump] on-map: pid %u %s @0x%llx\n",
		       h->pid, full, (unsigned long long)e->start);
	dump_one_at((int)h->pid, e->start, full, g_outdir, &g_sink);
	return 0;
}

// ponytail: libbpf_print_fn removed; ares_libbpf_quiet from common/runtime.h used instead

// ---- argp parser ----------------------------------------------------------

static const char dump_doc[] =
    "Launch PACKAGE fresh and dump every native library whose basename matches"
    " PATTERN (glob, e.g. 'e_*') from live memory, rebuilding each into a"
    " loadable ELF (.so).\v"
    "PACKAGE, PATTERN, and ACTIVITY can be passed as flags or positionally.\n"
    "Example: ares dump -P com.example.app 'libsecret*' -d /tmp/dumps";
static const char dump_args_doc[] = "[PACKAGE PATTERN [ACTIVITY]]";

struct dump_args {
    const char *pkg;
    const char *patterns[64];  // -l (repeatable) + legacy positional
    int npat;
    const char *pat_pos;       // legacy single positional pattern, folded into patterns[] at END
    const char *activity;
    const char *outdir;
    const char *output_file;  // -o: SYM1 Phase 3 manifest JSONL path (NULL = none)
    int on_map;
    int now;                   // --now: snapshot -p targets, no BPF
    int check;                 // --check: compare instead of write
    unsigned long long bases[64];  // --base (repeatable)
    int nbase;
    int raw;
    int quiet;
    struct target_args tgt;
    custom_probe_spec_t specs[64];
    int nspec;
};

// Synthetic keys for long-only options (must be > 127 to avoid short-option collision).
// Use 0x200+ to avoid collision with ARES_KEY_SIBLINGS (0x100) / ARES_KEY_NO_FOLLOW (0x101).
enum { KEY_ON_MAP = 0x200, KEY_RAW, KEY_NOW, KEY_BASE, KEY_CHECK };

static const struct argp_option dump_options[] = {
    { "package",  'P',        "PACKAGE",  0, "App package to launch and dump", 0 },
    { "activity", 'A',        "ACTIVITY", 0, "Override launch activity component (default: auto-resolve)", 0 },
    { "dump-dir", 'd',        "DIR",      0, "Output directory (default: current dir)", 0 },
    { "output",   'o',        "FILE",     0, "Export a {\"type\":\"dump\",...} manifest JSONL record per dumped module (also prints console; -q silences that)", 0 },
    { "lib",      'l',        "PATTERN",  0, "Library basename pattern to dump (glob/substring); repeat for OR", 0 },
    { "on-map",   KEY_ON_MAP, NULL,       0, "Dump the instant a matching library maps (default: dump on exit, post-decryption)", 0 },
    { "now",      KEY_NOW,    NULL,       0, "Snapshot the -p target's currently-mapped modules immediately and exit (no BPF, no launch)", 0 },
    { "base",     KEY_BASE,   "ADDR",     0, "Dump the module at this exact load base (hex, 0x-prefixed); repeat for OR. Immune to per-run library renaming", 0 },
    { "check",    KEY_CHECK,  NULL,       0, "Compare each module's executable memory against its file on disk and emit modcmp records instead of dumping", 0 },
    { "raw",      KEY_RAW,    NULL,       0, "Emit the raw phdr-fixed image, skip ELF rebuild", 0 },
    { "quiet",    'q',        NULL,       0, "Suppress progress chatter", 0 },
    { "spec-file", 'F',       "FILE",     0, "Load probe specs from a file (one per line, # = comment); a lib: line supplies PATTERN when none is given positionally", 0 },
    TARGET_ARGP_OPTIONS,
    { 0 }
};

static error_t dump_parse_opt(int key, char *arg, struct argp_state *state)
{
    struct dump_args *a = state->input;
    switch (key) {
    case 'P': a->pkg      = arg;  break;
    case 'A': a->activity = arg;  break;
    case 'd': a->outdir   = arg;  break;
    case 'o': a->output_file = arg; break;
    case 'l':
        if (a->npat < 64) a->patterns[a->npat++] = arg;
        else fprintf(stderr, "dump: warning — lib-pattern cap (64) reached; '%s' ignored\n", arg);
        break;
    case 'q': a->quiet    = 1;    break;
    case KEY_ON_MAP: a->on_map = 1; break;
    case KEY_NOW:   a->now   = 1; break;
    case KEY_CHECK: a->check = 1; break;
    case KEY_BASE: {
        if (a->nbase >= 64) {
            fprintf(stderr, "dump: warning - base cap (64) reached; '%s' ignored\n", arg);
            break;
        }
        char *end = NULL;
        unsigned long long v = strtoull(arg, &end, 0);
        if (!end || *end || end == arg)
            argp_error(state, "invalid --base address '%s' (expected hex, e.g. 0x7281a0000)", arg);
        a->bases[a->nbase++] = v;
        break;
    }
    case KEY_RAW:    a->raw    = 1; break;
    case 'F':
        if (load_probe_spec_file(arg, a->specs, 64, &a->nspec, err_print) != 0)
            argp_error(state, "cannot open spec file '%s'", arg);
        break;
    case 'p': case ARES_KEY_SIBLINGS: case ARES_KEY_NO_FOLLOW:
        return parse_target_arg(key, arg, state, &a->tgt);
    case ARGP_KEY_ARG:
        if      (!a->pkg && a->tgt.n == 0)  a->pkg      = arg;
        else if (!a->pat_pos)               a->pat_pos  = arg;
        else if (!a->activity)              a->activity = arg;
        else argp_error(state, "unexpected argument '%s'", arg);
        break;
    case ARGP_KEY_END:
        if (a->pat_pos && a->npat < 64) a->patterns[a->npat++] = a->pat_pos;
        if (a->npat == 0)               // pull ALL lib: specs, not just the first
            for (int i = 0; i < a->nspec && a->npat < 64; i++)
                if (a->specs[i].kind == SPEC_KIND_LIB) a->patterns[a->npat++] = a->specs[i].mod;
        {
            struct dump_trigger t = {
                .now = a->now, .check = a->check, .on_map = a->on_map,
                .has_pkg = a->pkg ? 1 : 0,
                .ntgt = a->tgt.n, .npat = a->npat, .nbase = a->nbase,
            };
            const char *err = dump_args_check(&t);
            if (err)
                argp_error(state, "%s", err);
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp dump_argp = { dump_options, dump_parse_opt, dump_args_doc, dump_doc, 0, 0, 0 };

// ---- three-phase driver ---------------------------------------------------
// dump_setup/run/teardown are kept global so a trace-style coordinator can drive
// `dump` alongside other engines from a single app launch. Cross-phase state lives
// in the file-static g_* above. (cmd_dump below is the thin standalone wrapper.)

// Cross-phase state: published by dump_setup, consumed by dump_run/dump_teardown.
static struct ares_dump  *g_skel;
static struct ring_buffer *g_rb;
static int                 g_uid;
static const char         *g_pkg;
static const char         *g_activity;
static struct bpf_link    *g_ff;

// Multi-kind spec files (EPIC H11) may carry funcs:/syscall:/mod: lines meant
// for other engines; dump only ever consumes SPEC_KIND_LIB specs (folded into
// g_patterns at dump_parse_opt's ARGP_KEY_END). Warn once so silence isn't
// mistaken for "the spec was applied" -- printed both before the run
// (dump_setup) and again at teardown (dump_teardown), matching funcs.c's
// print_ignored_kind_warning / syscalls.c's print_defaulted_kind_warning idiom.
static void print_ignored_kind_warning(void)
{
    int n = 0;
    for (int i = 0; i < g_nspec; i++)
        if (g_specs[i].kind != SPEC_KIND_LIB)
            n++;
    if (!n)
        return;
    fprintf(stderr, "dump: warning — ignoring %d spec(s) not applicable to this engine "
                     "(lib: only):", n);
    for (int i = 0; i < g_nspec; i++) {
        if (g_specs[i].kind == SPEC_KIND_LIB)
            continue;
        char desc[400];
        spec_describe(&g_specs[i], desc, sizeof desc);
        fprintf(stderr, " %s", desc);
    }
    fprintf(stderr, "\n");
}

// End-of-run: lib: patterns (-l / positional / spec-file lib: lines) that
// never matched a module anywhere this run. Previously silent -- a typo'd
// pattern just produced an empty (or partial) dump directory with no
// explanation. Printed both after the run (dump_run) and again at teardown
// (dump_teardown), same "don't lose the note" reasoning as the warning above.
static void print_never_matched_report(void)
{
    int n = 0;
    for (int i = 0; i < g_npat && i < 64; i++)
        if (!g_pat_hit[i])
            n++;
    if (!n)
        return;
    fprintf(stderr, "dump: warning — %d pattern(s) never matched any module this run:", n);
    for (int i = 0; i < g_npat && i < 64; i++) {
        if (g_pat_hit[i])
            continue;
        fprintf(stderr, " %s", g_patterns[i]);
    }
    fprintf(stderr, "\n");
}

int dump_setup(int argc, char **argv, const struct ares_run_ctx *rc)
{
    // ponytail: static so g_pkg/g_activity/g_patterns can alias da after setup returns.
    static struct dump_args da = { .outdir = "." };
    if (rc && rc->pkg) da.pkg = rc->pkg;
    if (argp_parse(&dump_argp, argc, argv, ARGP_NO_EXIT, NULL, &da) != 0)
        return 1;

    memcpy(g_specs, da.specs, sizeof g_specs);
    g_nspec = da.nspec;
    print_ignored_kind_warning(); // "before run"

    g_pkg      = da.pkg;
    g_activity = da.activity;
    g_patterns = da.patterns;
    g_npat     = da.npat;
    g_outdir   = da.outdir;
    g_on_map   = da.on_map;
    g_quiet    = da.quiet;
    if (da.raw) dump_set_raw(1);

    // SYM1 Phase 3: dump's machine channel. Always JSONL (noun "module") --
    // a brand-new sink with no legacy array-framing consumers, so there's no
    // -J flag to plumb.
    if (da.output_file && ares_sink_open(&g_sink, da.output_file, "module", 1) != 0) {
        fprintf(stderr, "dump: cannot open output file '%s': %s\n", da.output_file, strerror(errno));
        return 1;
    }

    g_now    = da.now;
    g_check  = da.check;
    g_bases  = da.bases;
    g_nbase  = da.nbase;

    // -p targets, copied out for --now's direct rescan. Must happen before the
    // early return below.
    g_ntgt = da.tgt.n < 64 ? da.tgt.n : 64;
    for (int i = 0; i < g_ntgt; i++)
        g_tgt_pids[i] = da.tgt.pids[i];

    // --now is a pure /proc read: no skeleton, no attach, no ring buffer, no
    // stop handler. dump_run does the whole job and cmd_dump exits 0. Skipping
    // BPF also keeps a snapshot maximally quiet - nothing is attached to the
    // target at all (see the detectability firewall).
    if (da.now) {
        g_uid = 0;   // display-only; PID mode never resolves a UID
        return 0;
    }

    if (da.tgt.n > 0) {
        g_uid = 0;  // ponytail: uid is display-only; BPF gate uses TGID in PID mode
    } else {
        g_uid = (rc && rc->uid > 0) ? rc->uid : ares_resolve_uid(g_pkg);
        if (g_uid < 0) {
            fprintf(stderr, "dump: could not resolve UID for '%s' (installed? run as root?)\n", g_pkg);
            if (g_sink.f) { ares_sink_close(&g_sink); ares_sink_report(&g_sink); }  // AUDIT.md #7d
            return 1;
        }
    }

    libbpf_set_print(ares_libbpf_quiet);

    struct ares_dump *skel = ares_dump__open();
    if (!skel) {
        fprintf(stderr, "dump: failed to open BPF skeleton\n");
        return 1;
    }
    if (ares_dump__load(skel)) {
        fprintf(stderr, "dump: failed to load BPF (need eBPF privileges / SELinux permissive?)\n");
        goto err_skel;
    }

    if (da.tgt.n > 0) {
        // -p mode: arm target_pids; target_uids only if --siblings.
        __u8 one = 1;
        for (int i = 0; i < da.tgt.n; i++) {
            __u32 tgid = (__u32)da.tgt.pids[i];
            bpf_map_update_elem(bpf_map__fd(skel->maps.target_pids), &tgid, &one, BPF_ANY);
            if (da.tgt.siblings) {
                int uid = ares_get_pid_uid(da.tgt.pids[i]);
                if (uid > 0) {
                    __u32 vuid = (__u32)uid;
                    bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY);
                }
            }
        }
    } else {
        // -P mode: arm target_uids.
        __u32 vuid = (__u32)g_uid; __u8 one = 1;
        if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY) != 0) {
            fprintf(stderr, "dump: failed to install target UID\n");
            goto err_skel;
        }
    }

    bpf_program__set_autoattach(skel->progs.ares_follow_fork, 0);

    if (ares_dump__attach(skel)) {
        fprintf(stderr, "dump: failed to attach (uprobe_mmap in kallsyms?)\n");
        goto err_skel;
    }

    if (da.tgt.n > 0 && !da.tgt.no_follow) {
        g_ff = bpf_program__attach(skel->progs.ares_follow_fork);
        if (!g_ff) fprintf(stderr, "dump: follow-fork attach failed (non-fatal)\n");
    }

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "dump: failed to create ring buffer\n");
        goto err_skel;
    }

    // Setup complete: publish live state to run/teardown phases. The caller
    // owns the app launch, which must happen AFTER this returns since the UID
    // filter is already armed.
    g_skel = skel;
    g_rb   = rb;
    return 0;

err_skel:
    ares_dump__destroy(skel);
    if (g_sink.f) { ares_sink_close(&g_sink); ares_sink_report(&g_sink); }  // AUDIT.md #7d
    return 1;
}

// "libA*" or "libA* (+2 more)" for banners when multiple -l patterns are given.
static char g_pat_banner[128];
static const char *pat_banner(void)
{
    if (g_npat > 1)
        snprintf(g_pat_banner, sizeof(g_pat_banner), "%s (+%d more)", g_patterns[0], g_npat - 1);
    else
        snprintf(g_pat_banner, sizeof(g_pat_banner), "%s", g_npat ? g_patterns[0] : "");
    return g_pat_banner;
}

int dump_run(volatile sig_atomic_t *stop)
{
    struct dump_sel sel = { .pats = g_patterns, .npat = g_npat, .hit = g_pat_hit,
                            .bases = g_bases, .nbase = g_nbase };

    // --now: the -p targets are already running and have already mapped
    // everything they are going to map, so there are no events to wait for.
    // Rescan their maps directly and return. (This is the whole reason --now
    // exists: dump-on-exit only rescans pids recorded from map events, so
    // attaching to an already-running process rescanned nothing.)
    if (g_now) {
        int total = 0;
        for (int i = 0; i < g_ntgt; i++) {
            int r = g_check ? dump_check_pid_modules(g_tgt_pids[i], &sel, &g_sink)
                            : dump_pid_modules_sel(g_tgt_pids[i], &sel, g_outdir, &g_sink);
            if (r > 0)
                total += r;
        }
        fprintf(stderr, "[dump] %s %d module%s in %d pid%s\n",
                g_check ? "checked" : "wrote", total, total == 1 ? "" : "s",
                g_ntgt, g_ntgt == 1 ? "" : "s");
        print_never_matched_report();
        return 0;
    }

    printf("tracing uid %d, dumping '%s' (%s) ... Ctrl-C to stop\n",
           g_uid, pat_banner(), g_on_map ? "on map" : "on exit");

    ares_rb_poll_until(g_rb, stop);

    // dump-on-exit: rescan each recorded pid's maps and dump matching modules.
    if (!g_on_map) {
        if (g_pids_n == 0)
            fprintf(stderr, "[dump] no app process mapped anything\n");
        int total = 0;
        for (size_t i = 0; i < g_pids_n; i++) {
            int d = dump_pid_modules((int)g_pids[i], g_patterns, g_npat, g_outdir, &g_sink, g_pat_hit);
            if (d > 0)
                total += d;
        }
        fprintf(stderr, "[dump] wrote %d module image%s matching '%s' to %s\n",
            total, total == 1 ? "" : "s", pat_banner(), g_outdir);
    }
    print_never_matched_report(); // "after run"
    return 0;
}

void dump_teardown(void)
{
    if (g_rb) {
        ring_buffer__free(g_rb);
        g_rb = NULL;
    }
    if (g_ff) {
        bpf_link__destroy(g_ff);
        g_ff = NULL;
    }
    if (g_skel) {
        ares_dump__destroy(g_skel);
        g_skel = NULL;
    }
    free(g_pids); g_pids = NULL; g_pids_n = g_pids_cap = 0;
    free(g_seen); g_seen = NULL; g_seen_n = g_seen_cap = 0;

    // Repeat both warnings so a long-scrolling console doesn't lose the note
    // (mirrors funcs.c's print_ignored_kind_warning / syscalls.c's
    // print_defaulted_kind_warning idiom -- printed once before/after the run
    // already, in dump_setup and dump_run respectively; this is the teardown repeat).
    print_never_matched_report();
    print_ignored_kind_warning();

    // SYM1 Phase 5b: explicit "not applicable" record instead of silence --
    // dump is a single-shot read, no run-long coverage to accumulate. Must
    // run before the sink closes below (matches every other engine).
    struct ares_coverage cov = { .engine = "dump", .exempt = 1,
        .exempt_reason = "single-shot read, no run-long coverage to accumulate" };
    ares_coverage_report(&g_sink, &cov);

    // SYM1 Phase 3: close + report the manifest sink, mirroring every other engine.
    if (g_sink.f) {
        ares_sink_close(&g_sink);
        ares_sink_report(&g_sink);
    }
}

// ---- entry point (thin standalone wrapper) --------------------------------

int cmd_dump(int argc, char **argv)
{
    // MT1: argp_parse(ARGP_NO_EXIT) inside dump_setup returns 0 on --help/--usage
    // (it only prints), so control would otherwise fall through into attach/run.
    if (ares_wants_help(argc, argv)) {
        argp_help(&dump_argp, stdout, ARGP_HELP_STD_HELP, argv[0]);
        return 0;
    }

    if (dump_setup(argc, argv, NULL) != 0)
        return 1;

    // Standalone: tracing is armed (UID installed in setup); install 2-stage
    // stop handler, launch, run, then teardown.
    ares_install_stop_handler(&exiting);
    if (g_pkg) {
        ares_launch_banner(g_pkg, g_uid);
        if (ares_launch_app(g_pkg, g_activity, NULL) != 0) {
            fprintf(stderr, "dump: launch failed for '%s' (activity resolvable? am available?)\n", g_pkg);
            dump_teardown();
            return 1;
        }
    }

    dump_run(&exiting);
    dump_teardown();
    return 0;
}
