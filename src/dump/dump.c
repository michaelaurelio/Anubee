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
#include "rebuild.h"

const char *argp_program_bug_address = "<michael.windarta@binus.ac.id>";

static volatile sig_atomic_t exiting = 0;

static const char *g_pattern = NULL;   // module pattern to dump (glob/substring)
static const char *g_outdir  = ".";    // -d: output directory
static int g_on_map  = 0;              // --on-map: dump at map time, not on exit
static int g_quiet   = 0;              // -q: suppress progress chatter

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
	if (!dump_name_matches(g_pattern, full))
		return 0;
	if (!seen_add(h->pid, e->start))
		return 0;
	if (!g_quiet)
		printf("[dump] on-map: pid %u %s @0x%llx\n",
		       h->pid, full, (unsigned long long)e->start);
	dump_one_at((int)h->pid, e->start, full, g_outdir);
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
    const char *pattern;
    const char *activity;
    const char *outdir;
    int on_map;
    int raw;
    int quiet;
};

// Synthetic keys for long-only options (must be > 127 to avoid short-option collision).
enum { KEY_ON_MAP = 256, KEY_RAW };

static const struct argp_option dump_options[] = {
    { "package",  'P',        "PACKAGE",  0, "App package to launch and dump", 0 },
    { "activity", 'A',        "ACTIVITY", 0, "Override launch activity component (default: auto-resolve)", 0 },
    { "dump-dir", 'd',        "DIR",      0, "Output directory (default: current dir)", 0 },
    { "on-map",   KEY_ON_MAP, NULL,       0, "Dump the instant a matching library maps (default: dump on exit, post-decryption)", 0 },
    { "raw",      KEY_RAW,    NULL,       0, "Emit the raw phdr-fixed image, skip ELF rebuild", 0 },
    { "quiet",    'q',        NULL,       0, "Suppress progress chatter", 0 },
    { 0 }
};

static error_t dump_parse_opt(int key, char *arg, struct argp_state *state)
{
    struct dump_args *a = state->input;
    switch (key) {
    case 'P': a->pkg      = arg;  break;
    case 'A': a->activity = arg;  break;
    case 'd': a->outdir   = arg;  break;
    case 'q': a->quiet    = 1;    break;
    case KEY_ON_MAP: a->on_map = 1; break;
    case KEY_RAW:    a->raw    = 1; break;
    case ARGP_KEY_ARG:
        if      (!a->pkg)     a->pkg     = arg;
        else if (!a->pattern) a->pattern = arg;
        else if (!a->activity) a->activity = arg;
        else argp_error(state, "unexpected argument '%s'", arg);
        break;
    case ARGP_KEY_END:
        if (!a->pkg)     argp_error(state, "package is required (-P PACKAGE or first positional)");
        if (!a->pattern) argp_error(state, "pattern is required (second positional)");
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

int dump_setup(int argc, char **argv, const struct ares_run_ctx *rc)
{
    // ponytail: static so g_pkg/g_activity/g_pattern can alias da after setup returns.
    static struct dump_args da = { .outdir = "." };
    if (rc && rc->pkg) da.pkg = rc->pkg;
    if (argp_parse(&dump_argp, argc, argv, 0, NULL, &da) != 0)
        return 1;

    g_pkg      = da.pkg;
    g_activity = da.activity;
    g_pattern  = da.pattern;
    g_outdir   = da.outdir;
    g_on_map   = da.on_map;
    g_quiet    = da.quiet;
    if (da.raw) dump_set_raw(1);

    g_uid = (rc && rc->uid > 0) ? rc->uid : ares_resolve_uid(g_pkg);
    if (g_uid < 0) {
        fprintf(stderr, "dump: could not resolve UID for '%s' (installed? run as root?)\n", g_pkg);
        return 1;
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

    __u32 vuid = (__u32)g_uid; __u8 one = 1;
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY) != 0) {
        fprintf(stderr, "dump: failed to install target UID\n");
        goto err_skel;
    }

    if (ares_dump__attach(skel)) {
        fprintf(stderr, "dump: failed to attach (uprobe_mmap in kallsyms?)\n");
        goto err_skel;
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
    return 1;
}

int dump_run(volatile sig_atomic_t *stop)
{
    printf("tracing uid %d, dumping '%s' (%s) ... Ctrl-C to stop\n",
           g_uid, g_pattern, g_on_map ? "on map" : "on exit");

    ares_rb_poll_until(g_rb, stop);

    // dump-on-exit: rescan each recorded pid's maps and dump matching modules.
    if (!g_on_map) {
        if (g_pids_n == 0)
            fprintf(stderr, "[dump] no app process mapped anything\n");
        int total = 0;
        for (size_t i = 0; i < g_pids_n; i++) {
            int d = dump_pid_modules((int)g_pids[i], g_pattern, g_outdir);
            if (d > 0)
                total += d;
        }
        fprintf(stderr, "[dump] wrote %d module image%s matching '%s' to %s\n",
            total, total == 1 ? "" : "s", g_pattern, g_outdir);
    }
    return 0;
}

void dump_teardown(void)
{
    if (g_rb) {
        ring_buffer__free(g_rb);
        g_rb = NULL;
    }
    if (g_skel) {
        ares_dump__destroy(g_skel);
        g_skel = NULL;
    }
    free(g_pids); g_pids = NULL; g_pids_n = g_pids_cap = 0;
    free(g_seen); g_seen = NULL; g_seen_n = g_seen_cap = 0;
}

// ---- entry point (thin standalone wrapper) --------------------------------

int cmd_dump(int argc, char **argv)
{
    if (dump_setup(argc, argv, NULL) != 0)
        return 1;

    // Standalone: tracing is armed (UID installed in setup); install 2-stage
    // stop handler, launch, run, then teardown.
    ares_install_stop_handler(&exiting);
    ares_launch_banner(g_pkg, g_uid);
    if (ares_launch_app(g_pkg, g_activity, NULL) != 0) {
        fprintf(stderr, "dump: launch failed for '%s' (activity resolvable? am available?)\n", g_pkg);
        dump_teardown();
        return 1;
    }

    dump_run(&exiting);
    dump_teardown();
    return 0;
}
