// SPDX-License-Identifier: GPL-2.0
// `anubee lib` — trace every native library (.so) an Android app loads.
//
// Launches the target package fresh under a UID filter installed before launch,
// so every mapping is caught from the process's first thread (including forked
// children of the same app UID). Capture + path resolution + output are the
// shared module in src/common/lib_trace.*; this file is just the loader and the
// fresh-launch driver.
//
// The device/launch helpers (sh_exec/resolve_uid/resolve_component) are shared
// from src/common/launch.{c,h} as anubee_*; this module owns only library tracing.
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
#include "common/sym_apk.h"        // MT3: apk_list_sos, packed-native enumeration

static volatile sig_atomic_t exiting = 0;

static struct anubee_sink g_sink;
static int              g_quiet   = 0;
static int              g_verbose = 0;

// Cross-phase state: published by lib_setup, consumed by lib_run/lib_teardown.
static struct anubee_lib   *g_skel;
static struct ring_buffer *g_rb;
static int                 g_uid;
static const char         *g_pkg;
static const char         *g_activity;
static struct bpf_link    *g_ff;

// ---- ring-buffer event handling ------------------------------------------

// MT3: which base.apk paths we've already enumerated+emitted the packed
// native list for this run (once per APK, not once per mapped segment).
#define APK_SEEN_MAX 8
static char apk_seen[APK_SEEN_MAX][256];
static int  apk_seen_count;

static bool mark_apk_seen(const char *path)
{
	for (int i = 0; i < apk_seen_count; i++)
		if (strcmp(apk_seen[i], path) == 0)
			return false;
	if (apk_seen_count < APK_SEEN_MAX)
		snprintf(apk_seen[apk_seen_count++], sizeof(apk_seen[0]), "%s", path);
	// ponytail: beyond APK_SEEN_MAX distinct APKs in one run (unusual — an
	// app plus a handful of split APKs), re-enumeration just repeats output
	// (apk_get()'s own per-path cache keeps the ZIP parse itself cheap);
	// widen APK_SEEN_MAX if a real target needs more.
	return true;
}

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
		if (anubee_libtrace_resolve_path(h->pid, e->start, e->name, path, sizeof(path)) != 0)
			full = e->name;     // fall back to the BPF-supplied basename

		// MT3: extractNativeLibs=false apps map a stored .so straight out of
		// base.apk instead of a standalone file — recover the inner .so name
		// via the ZIP central directory (already parsed for symbolization,
		// common/sym_apk.c) and surface every packed native up front, not
		// just the one segment this particular event happens to be.
		const char *soname = NULL;
		size_t fl = strlen(full);
		if (fl >= 4 && !strcmp(full + fl - 4, ".apk")) {
			// e->pgoff is vm_pgoff: kernel-PAGE_SIZE units, not bytes, and
			// not necessarily 4K (16K-page devices exist) — multiply by the
			// runtime page size to get the byte offset the ZIP central
			// directory records as data_start. NOT `pgoff << 12`.
			unsigned long long off = (unsigned long long)e->pgoff *
			                         (unsigned long long)sysconf(_SC_PAGESIZE);
			struct apk_so_ref refs[32];
			int n = apk_list_sos(full, refs, 32);
			if (mark_apk_seen(full))
				for (int i = 0; i < n; i++)
					anubee_libtrace_emit_packed(&g_sink, g_quiet, full, &refs[i]);
			// This mmap event covers one ELF segment, whose file offset is
			// generally not the .so's own data_start (e.g. the exec segment
			// starts partway in) — range-match instead of exact-match.
			for (int i = 0; i < n; i++) {
				if (off >= refs[i].data_start && off < refs[i].data_start + refs[i].size) {
					soname = refs[i].name;
					break;
				}
			}
		}
		anubee_libtrace_emit_lib(&g_sink, g_quiet, e, full, soname);
	} else if (h->type == LIB_EV_UNMAP) {
		if (sz < sizeof(struct lib_unmap_event))
			return 0;
		anubee_libtrace_emit_unlib(&g_sink, g_quiet || !g_verbose, data);
	}
	return 0;
}

// ponytail: libbpf_print_fn removed; anubee_libbpf_quiet from common/runtime.h used instead

// ---- argp parser ----------------------------------------------------------

static const char lib_doc[] =
    "Launch PACKAGE fresh and trace every native library (.so) it loads.\v"
    "PACKAGE and ACTIVITY can be passed as flags (-P/-A) or positionally.\n"
    "Example: anubee lib -P com.example.app -o libs.jsonl";
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
    case 'p': case ANUBEE_KEY_SIBLINGS: case ANUBEE_KEY_NO_FOLLOW:
        return parse_target_arg(key, arg, state, &a->tgt);
    case ARGP_KEY_ARG:
        if      (!a->pkg && a->tgt.n == 0) a->pkg      = arg;
        else if (!a->activity)             a->activity = arg;
        else argp_error(state, "unexpected argument '%s'", arg);
        break;
    case ARGP_KEY_END:
        anubee_target_warn_noop(&a->tgt, "lib");
        if (a->tgt.n > 0 && a->activity)
            fprintf(stderr, "lib: warning - -A/--activity has no effect in -p mode; ignored\n");
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

int lib_setup(int argc, char **argv, const struct anubee_run_ctx *rc)
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
        g_uid = (rc && rc->uid > 0) ? rc->uid : anubee_resolve_uid(g_pkg);
        if (g_uid < 0) {
            fprintf(stderr, "lib: could not resolve UID for '%s' (installed? run as root?)\n", g_pkg);
            return 1;
        }
    }

    if (la.c.output_file && anubee_sink_open(&g_sink, la.c.output_file, "lib", 1) != 0) {
        fprintf(stderr, "lib: cannot open '%s': %s\n", la.c.output_file, strerror(errno));
        return 1;
    }

    libbpf_set_print(anubee_libbpf_quiet);

    struct anubee_lib *skel = anubee_lib__open();
    if (!skel) {
        fprintf(stderr, "lib: failed to open BPF skeleton\n");
        goto err_file;
    }
    if (anubee_lib__load(skel)) {
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
                int puid = anubee_get_pid_uid(la.tgt.pids[i]);
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

    bpf_program__set_autoattach(skel->progs.anubee_follow_fork, 0);

    if (anubee_lib__attach(skel)) {
        fprintf(stderr, "lib: failed to attach (uprobe_mmap in kallsyms?)\n");
        goto err_skel;
    }

    if (la.tgt.n > 0 && !la.tgt.no_follow) {
        g_ff = bpf_program__attach(skel->progs.anubee_follow_fork);
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
    anubee_lib__destroy(skel);
err_file:
    if (g_sink.f) {
        anubee_sink_close(&g_sink);
        anubee_sink_report(&g_sink);
    }
    return 1;
}

int lib_run(volatile sig_atomic_t *stop)
{
    printf("tracing uid %d (library loads) ... Ctrl-C to stop\n", g_uid);
    // ponytail: no drops ticker — lib.bpf.c has no dropped map / worker queue.
    anubee_rb_poll_until(g_rb, stop);
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
        anubee_lib__destroy(g_skel);
        g_skel = NULL;
    }
    // SYM1 Phase 5b: explicit "not applicable" record instead of silence --
    // lib has no drop map or snapshot path to report on. Must run before the
    // sink closes below (matches every other engine's anubee_coverage_report
    // call, always before its own anubee_sink_close).
    struct anubee_coverage cov = { .engine = "lib", .exempt = 1,
        .exempt_reason = "no drop map or snapshot path for this engine" };
    anubee_coverage_report(&g_sink, &cov);
    if (g_sink.f) { anubee_sink_close(&g_sink); anubee_sink_report(&g_sink); }
}

// ---- entry point (thin standalone wrapper) --------------------------------

int cmd_lib(int argc, char **argv)
{
    // MT1: argp_parse(ARGP_NO_EXIT) inside lib_setup returns 0 on --help/--usage
    // (it only prints), so control would otherwise fall through into attach/run.
    if (anubee_wants_help(argc, argv)) {
        argp_help(&lib_argp, stdout, ARGP_HELP_STD_HELP, argv[0]);
        return 0;
    }

    if (lib_setup(argc, argv, NULL) != 0)
        return 1;

    // Standalone: tracing is armed; in -P mode launch, in -p mode just run.
    anubee_install_stop_handler(&exiting);
    if (g_pkg) {
        anubee_launch_banner(g_pkg, g_uid);
        if (anubee_launch_app(g_pkg, g_activity, NULL) != 0) {
            fprintf(stderr, "lib: launch failed for '%s' (activity resolvable? am available?)\n", g_pkg);
            lib_teardown();
            return 1;
        }
    }

    lib_run(&exiting);
    lib_teardown();
    return 0;
}
