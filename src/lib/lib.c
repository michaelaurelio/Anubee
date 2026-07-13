// SPDX-License-Identifier: GPL-2.0
// `ares lib` — trace every native library (.so) an Android app loads.
//
// Launches the target package fresh under a UID filter installed before launch,
// so every mapping is caught from the process's first thread (including forked
// children of the same app UID). Capture + path resolution + output are the
// shared module in src/common/lib_trace.*; this file is just the loader and the
// fresh-launch driver.
//
// The device/launch helpers (sh_exec/resolve_uid/resolve_component) are shared
// from src/common/launch.{c,h} as ares_*; this module owns only library tracing.
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

#include "lib.skel.h"
#include "common/emit.h"
#include "common/lib_trace.h"
#include "common/launch.h"
#include "common/engine_args.h"
#include "common/runtime.h"
#include "common/engine_driver.h"  // lib_setup/_run/_teardown (AA3)
#include "common/coverage.h"       // SYM1 Phase 5b: explicit "exempt" coverage record

static volatile sig_atomic_t exiting = 0;

static struct ares_sink g_sink;
static int              g_quiet   = 0;
static int              g_verbose = 0;

// Cross-phase state: published by lib_setup, consumed by lib_run/lib_teardown.
static struct ares_lib   *g_skel;
static struct ring_buffer *g_rb;
static int                 g_uid;
static const char         *g_pkg;
static const char         *g_activity;
static struct bpf_link    *g_ff;

// ---- ring-buffer event handling ------------------------------------------

static int handle_event(void *ctx, void *data, size_t sz)
{
	(void)ctx;
	if (sz < sizeof(struct lib_event_header))
		return 0;
	const struct lib_event_header *h = data;

	if (h->type == LIB_EV_MAP) {
		if (sz < sizeof(struct lib_map_event))
			return 0;
		const struct lib_map_event *e = data;
		char path[256];
		const char *full = path;
		if (ares_libtrace_resolve_path(h->pid, e->start, e->name, path, sizeof(path)) != 0)
			full = e->name;     // fall back to the BPF-supplied basename
		ares_libtrace_emit_lib(&g_sink, g_quiet, e, full, NULL);
	} else if (h->type == LIB_EV_UNMAP) {
		if (sz < sizeof(struct lib_unmap_event))
			return 0;
		ares_libtrace_emit_unlib(&g_sink, g_quiet || !g_verbose, data);
	}
	return 0;
}

// ponytail: libbpf_print_fn removed; ares_libbpf_quiet from common/runtime.h used instead

// ---- argp parser ----------------------------------------------------------

static const char lib_doc[] =
    "Launch PACKAGE fresh and trace every native library (.so) it loads.\v"
    "PACKAGE and ACTIVITY can be passed as flags (-P/-A) or positionally.\n"
    "Example: ares lib -P com.example.app -o libs.jsonl";
static const char lib_args_doc[] = "[PACKAGE [ACTIVITY]]";

struct lib_args {
    const char      *pkg;
    const char      *activity;
    struct common_args c;   // -o/-v/-q
    struct target_args tgt; // -p / --siblings / --no-follow-fork
};

// Only advertise flags that are actually wired. -J/-b/-Q are NOT included:
// lib polls the ring buffer directly and has no worker queue to configure.
static const struct argp_option lib_options[] = {
    { "package",  'P', "PACKAGE",  0, "App package to launch and trace", 0 },
    { "activity", 'A', "ACTIVITY", 0, "Override launch activity component (default: auto-resolve)", 0 },
    { "output",   'o', "FILE",     0, "Write structured JSONL ({\"type\":\"lib\",...}) (also prints console; -q silences that)", 0 },
    { "verbose",  'v', NULL,       0, "Also print [unlib] unmap lines (default: [lib] only)", 0 },
    { "quiet",    'q', NULL,       0, "Suppress human-readable [lib] console lines", 0 },
    TARGET_ARGP_OPTIONS,
    { 0 }
};

static error_t lib_parse_opt(int key, char *arg, struct argp_state *state)
{
    struct lib_args *a = state->input;
    switch (key) {
    case 'P': a->pkg      = arg; break;
    case 'A': a->activity = arg; break;
    case 'p': case ARES_KEY_SIBLINGS: case ARES_KEY_NO_FOLLOW:
        return parse_target_arg(key, arg, state, &a->tgt);
    case ARGP_KEY_ARG:
        if      (!a->pkg && a->tgt.n == 0) a->pkg      = arg;
        else if (!a->activity)             a->activity = arg;
        else argp_error(state, "unexpected argument '%s'", arg);
        break;
    case ARGP_KEY_END:
        if (a->tgt.n > 0 && a->pkg)
            argp_error(state, "specify exactly one of -p or -P");
        if (!a->tgt.n && !a->pkg)
            argp_error(state, "specify -P PACKAGE or -p PID[,PID...]");
        break;
    default:
        return parse_common_arg(key, arg, state, &a->c);
    }
    return 0;
}

static const struct argp lib_argp = { lib_options, lib_parse_opt, lib_args_doc, lib_doc, 0, 0, 0 };

// ---- three-phase driver ---------------------------------------------------
// lib_setup/run/teardown are kept global so a trace-style coordinator can drive
// `lib` alongside other engines from a single app launch. Cross-phase state lives
// in the file-static g_* above. (cmd_lib below is the thin standalone wrapper.)

int lib_setup(int argc, char **argv, const struct ares_run_ctx *rc)
{
    // ponytail: static so g_pkg/g_activity can alias la after setup returns.
    static struct lib_args la = { .c = COMMON_ARGS_INIT };
    // Pre-fill package from coordinator so ARGP_KEY_END validation passes
    // without needing -P in the lib argv section.
    if (rc && rc->pkg)
        la.pkg = rc->pkg;
    if (argp_parse(&lib_argp, argc, argv, ARGP_NO_EXIT, NULL, &la) != 0)
        return 1;

    g_pkg      = la.pkg;
    g_activity = la.activity;
    g_quiet    = la.c.quiet; // SYM1 Phase 1: -o no longer forces quiet; file and stdout are independent channels
    g_verbose  = la.c.verbose;

    if (la.tgt.n > 0) {
        g_uid = 0;  // ponytail: uid is display-only; BPF gate uses TGID in PID mode
    } else {
        g_uid = (rc && rc->uid > 0) ? rc->uid : ares_resolve_uid(g_pkg);
        if (g_uid < 0) {
            fprintf(stderr, "lib: could not resolve UID for '%s' (installed? run as root?)\n", g_pkg);
            return 1;
        }
    }

    if (la.c.output_file && ares_sink_open(&g_sink, la.c.output_file, "lib", 1) != 0) {
        fprintf(stderr, "lib: cannot open '%s': %s\n", la.c.output_file, strerror(errno));
        return 1;
    }

    libbpf_set_print(ares_libbpf_quiet);

    struct ares_lib *skel = ares_lib__open();
    if (!skel) {
        fprintf(stderr, "lib: failed to open BPF skeleton\n");
        goto err_file;
    }
    if (ares_lib__load(skel)) {
        fprintf(stderr, "lib: failed to load BPF (need eBPF privileges / SELinux permissive?)\n");
        goto err_skel;
    }

    // Arm the filter BEFORE launching so the first mapping is caught.
    __u8 one = 1;
    if (la.tgt.n > 0) {
        // -p mode: arm target_pids; target_uids only if --siblings.
        for (int i = 0; i < la.tgt.n; i++) {
            __u32 tgid = (__u32)la.tgt.pids[i];
            bpf_map_update_elem(bpf_map__fd(skel->maps.target_pids), &tgid, &one, BPF_ANY);
            if (la.tgt.siblings) {
                int puid = ares_get_pid_uid(la.tgt.pids[i]);
                if (puid > 0) {
                    __u32 vuid = (__u32)puid;
                    bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY);
                }
            }
        }
    } else {
        __u32 vuid = (__u32)g_uid;
        if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY) != 0) {
            fprintf(stderr, "lib: failed to install target UID\n");
            goto err_skel;
        }
    }

    bpf_program__set_autoattach(skel->progs.ares_follow_fork, 0);

    if (ares_lib__attach(skel)) {
        fprintf(stderr, "lib: failed to attach (uprobe_mmap in kallsyms?)\n");
        goto err_skel;
    }

    if (la.tgt.n > 0 && !la.tgt.no_follow) {
        g_ff = bpf_program__attach(skel->progs.ares_follow_fork);
        if (!g_ff) fprintf(stderr, "lib: follow-fork attach failed (non-fatal)\n");
    }

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "lib: failed to create ring buffer\n");
        goto err_skel;
    }

    // Setup complete: publish live state to run/teardown phases. The caller
    // owns the app launch, which must happen AFTER this returns since the UID
    // filter is already armed.
    g_skel = skel;
    g_rb   = rb;
    return 0;

err_skel:
    ares_lib__destroy(skel);
err_file:
    if (g_sink.f) {
        ares_sink_close(&g_sink);
        ares_sink_report(&g_sink);
    }
    return 1;
}

int lib_run(volatile sig_atomic_t *stop)
{
    printf("tracing uid %d (library loads) ... Ctrl-C to stop\n", g_uid);
    // ponytail: no drops ticker — lib.bpf.c has no dropped map / worker queue.
    ares_rb_poll_until(g_rb, stop);
    return 0;
}

void lib_teardown(void)
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
        ares_lib__destroy(g_skel);
        g_skel = NULL;
    }
    // SYM1 Phase 5b: explicit "not applicable" record instead of silence --
    // lib has no drop map or snapshot path to report on. Must run before the
    // sink closes below (matches every other engine's ares_coverage_report
    // call, always before its own ares_sink_close).
    struct ares_coverage cov = { .engine = "lib", .exempt = 1,
        .exempt_reason = "no drop map or snapshot path for this engine" };
    ares_coverage_report(&g_sink, &cov);
    if (g_sink.f) { ares_sink_close(&g_sink); ares_sink_report(&g_sink); }
}

// ---- entry point (thin standalone wrapper) --------------------------------

int cmd_lib(int argc, char **argv)
{
    if (lib_setup(argc, argv, NULL) != 0)
        return 1;

    // Standalone: tracing is armed; in -P mode launch, in -p mode just run.
    ares_install_stop_handler(&exiting);
    if (g_pkg) {
        ares_launch_banner(g_pkg, g_uid);
        if (ares_launch_app(g_pkg, g_activity, NULL) != 0) {
            fprintf(stderr, "lib: launch failed for '%s' (activity resolvable? am available?)\n", g_pkg);
            lib_teardown();
            return 1;
        }
    }

    lib_run(&exiting);
    lib_teardown();
    return 0;
}
