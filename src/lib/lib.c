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
#include "common/lib_trace.h"
#include "common/launch.h"
#include "common/engine_args.h"

const char *argp_program_bug_address = "<michael.windarta@binus.ac.id>";

static volatile sig_atomic_t exiting = 0;
static void on_sigint(int sig) { (void)sig; exiting = 1; }

static FILE *g_jsonl   = NULL;   // structured JSONL sink (-o), or NULL
static int   g_quiet   = 0;      // suppress stdout text
static int   g_verbose = 0;      // -v: also print [unlib] unmap lines on stdout

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
		ares_libtrace_emit_lib(g_jsonl, g_quiet, e, full, NULL);
	} else if (h->type == LIB_EV_UNMAP) {
		if (sz < sizeof(struct lib_unmap_event))
			return 0;
		ares_libtrace_emit_unlib(g_jsonl, g_quiet || !g_verbose, data);
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, args);
}

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
};

// Only advertise flags that are actually wired. -J/-b/-Q are NOT included:
// lib polls the ring buffer directly and has no worker queue to configure.
static const struct argp_option lib_options[] = {
    { "package",  'P', "PACKAGE",  0, "App package to launch and trace", 0 },
    { "activity", 'A', "ACTIVITY", 0, "Override launch activity component (default: auto-resolve)", 0 },
    { "output",   'o', "FILE",     0, "Write structured JSONL ({\"type\":\"lib\",...}) (implies -q)", 0 },
    { "verbose",  'v', NULL,       0, "Also print [unlib] unmap lines (default: [lib] only)", 0 },
    { "quiet",    'q', NULL,       0, "Suppress human-readable [lib] console lines", 0 },
    { 0 }
};

static error_t lib_parse_opt(int key, char *arg, struct argp_state *state)
{
    struct lib_args *a = state->input;
    switch (key) {
    case 'P': a->pkg      = arg; break;
    case 'A': a->activity = arg; break;
    case ARGP_KEY_ARG:
        if      (!a->pkg)      a->pkg      = arg;
        else if (!a->activity) a->activity = arg;
        else argp_error(state, "unexpected argument '%s'", arg);
        break;
    case ARGP_KEY_END:
        if (!a->pkg)
            argp_error(state, "package is required (-P PACKAGE or first positional)");
        break;
    default:
        return parse_common_arg(key, arg, state, &a->c);
    }
    return 0;
}

static const struct argp lib_argp = { lib_options, lib_parse_opt, lib_args_doc, lib_doc, 0, 0, 0 };

// ---- entry point ----------------------------------------------------------

int cmd_lib(int argc, char **argv)
{
    struct lib_args la = { .c = COMMON_ARGS_INIT };
    if (argp_parse(&lib_argp, argc, argv, 0, NULL, &la) != 0)
        return 1;

    const char *pkg      = la.pkg;
    const char *activity = la.activity;
    g_quiet   = la.c.quiet || (la.c.output_file != NULL);
    g_verbose = la.c.verbose;

    int uid = ares_resolve_uid(pkg);
    if (uid < 0) {
        fprintf(stderr, "lib: could not resolve UID for '%s' (installed? run as root?)\n", pkg);
        return 1;
    }

    if (la.c.output_file) {
        g_jsonl = fopen(la.c.output_file, "w");
        if (!g_jsonl) {
            fprintf(stderr, "lib: cannot open '%s': %s\n", la.c.output_file, strerror(errno));
            return 1;
        }
    }

    libbpf_set_print(libbpf_print_fn);

    struct ares_lib *skel = ares_lib__open();
    if (!skel) {
        fprintf(stderr, "lib: failed to open BPF skeleton\n");
        goto err_file;
    }
    if (ares_lib__load(skel)) {
        fprintf(stderr, "lib: failed to load BPF (need eBPF privileges / SELinux permissive?)\n");
        goto err_skel;
    }

    // Install the target UID BEFORE launching, so the first mapping is caught.
    __u32 key = 0, vuid = (__u32)uid;
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uid), &key, &vuid, BPF_ANY) != 0) {
        fprintf(stderr, "lib: failed to install target UID\n");
        goto err_skel;
    }

    if (ares_lib__attach(skel)) {
        fprintf(stderr, "lib: failed to attach (uprobe_mmap in kallsyms?)\n");
        goto err_skel;
    }

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "lib: failed to create ring buffer\n");
        goto err_skel;
    }

    // Fresh start: kill any running instance, wait for it to die, then launch.
    // Tracing is already armed, so we catch the new process from its first mapping.
    ares_launch_banner(pkg, uid);
    if (ares_launch_app(pkg, activity) != 0) {
        fprintf(stderr, "lib: launch failed for '%s' (activity resolvable? am available?)\n", pkg);
        goto err_rb;
    }

    signal(SIGINT, on_sigint);
    printf("tracing uid %d (library loads) ... Ctrl-C to stop\n", uid);

    while (!exiting) {
        int err = ring_buffer__poll(rb, 200 /* ms */);
        if (err < 0 && err != -EINTR)
            break;
    }

    ring_buffer__free(rb);
    ares_lib__destroy(skel);
    if (g_jsonl) fclose(g_jsonl);
    return 0;

err_rb:
    ring_buffer__free(rb);
err_skel:
    ares_lib__destroy(skel);
err_file:
    if (g_jsonl) fclose(g_jsonl);
    return 1;
}
