// SPDX-License-Identifier: GPL-2.0
// `ares mod` — dispatcher for named analyzers.
//
// Owns arg-parse, uid resolve, sink, stop handler, app launch, ring-poll,
// and teardown order. Each analyzer owns only its own BPF skeleton + event
// semantics. The registry below is the only place that enumerates analyzers.
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "common/analyzer.h"
#include "common/capabilities.h"
#include "common/emit.h"
#include "common/launch.h"
#include "common/runtime.h"
#include "common/engine_args.h"

static volatile sig_atomic_t exiting = 0;
static struct ares_sink g_sink;

// ---- analyzer registry -------------------------------------------------------

static const ares_analyzer_t *const registry[] = {
    &analyzer_proc_event,
    &analyzer_execve,
    &analyzer_prop_read,
    NULL,
};

static const ares_analyzer_t *find_analyzer(const char *name)
{
    for (int i = 0; registry[i]; i++)
        if (strcmp(registry[i]->name, name) == 0)
            return registry[i];
    return NULL;
}

static void list_analyzers(void)
{
    fprintf(stderr, "available analyzers:\n");
    for (int i = 0; registry[i]; i++)
        fprintf(stderr, "  %-16s %s\n", registry[i]->name, registry[i]->description);
}

// ---- argp parser -------------------------------------------------------------

static const char mod_doc[] =
    "Run an ares analyzer by name. Each analyzer is a self-contained specialized\n"
    "tracing package with its own BPF object.\v"
    "Run 'ares mod <name> --help' for per-analyzer detail.\n";
static const char mod_args_doc[] = "NAME [options]";

struct mod_args {
    const char *name;
    const char *pkg;
    const char *activity;
    struct common_args c;
    struct target_args tgt; // -p / --siblings / --no-follow-fork
};

// Only advertise flags that are actually wired. -J/-b/-Q are NOT included:
// mod polls the ring buffer directly (no queue) and the per-analyzer ring
// size is hardcoded; -J is redundant with -o. Mirrors lib.c:89-96.
static const struct argp_option mod_options[] = {
    { "package",  'P', "PACKAGE",  0, "App package to launch and trace", 0 },
    { "activity", 'A', "ACTIVITY", 0, "Override launch activity (default: auto-resolve)", 0 },
    { "output",   'o', "FILE",     0, "Export structured JSONL to FILE (implies -q)", 0 },
    { "verbose",  'v', NULL,       0, "Verbose output (execve: full backtrace frames)", 0 },
    { "quiet",    'q', NULL,       0, "Suppress per-event console output", 0 },
    TARGET_ARGP_OPTIONS,
    { 0 }
};

static error_t mod_parse_opt(int key, char *arg, struct argp_state *state)
{
    struct mod_args *a = state->input;
    switch (key) {
    case 'P': a->pkg      = arg; break;
    case 'A': a->activity = arg; break;
    case ARGP_KEY_ARG:
        if (!a->name) a->name = arg;
        else argp_error(state, "unexpected argument '%s'", arg);
        break;
    case 'p': case ARES_KEY_SIBLINGS: case ARES_KEY_NO_FOLLOW:
        return parse_target_arg(key, arg, state, &a->tgt);
    case ARGP_KEY_END:
        if (!a->name)
            argp_error(state, "analyzer name is required (first positional)");
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

static const struct argp mod_argp = { mod_options, mod_parse_opt, mod_args_doc, mod_doc, 0, 0, 0 };

// ---- entry point -------------------------------------------------------------

int cmd_mod(int argc, char **argv)
{
    struct mod_args ma = { .c = COMMON_ARGS_INIT };
    argp_parse(&mod_argp, argc, argv, 0, NULL, &ma);

    const ares_analyzer_t *an = find_analyzer(ma.name);
    if (!an) {
        fprintf(stderr, "mod: unknown analyzer '%s'\n", ma.name);
        list_analyzers();
        return 1;
    }

    // AA2 fix: classify + print loudness here, before anything below can load or
    // attach a BPF object — so a LOUD analyzer's uprobe is never live before the
    // operator sees the warning. ares_quiet_config_ok (not the direct
    // ares_object_writes_target call) so the one runtime-assertion helper in
    // capabilities.h has a real caller.
    char mod_key[64];
    snprintf(mod_key, sizeof(mod_key), "mod:%s", ma.name);
    const char *loaded[1] = { mod_key };
    if (!ares_quiet_config_ok(loaded, 1))
        printf("[mod]   > LOUD: %s uses uprobes (writes target memory)\n", ma.name);
    else
        printf("[mod]   > stealthy: %s uses kernel-only probes\n", ma.name);

    int uid;
    if (ma.tgt.n > 0) {
        // ponytail: siblings → grab UID from first PID; precise → uid=0 (BPF gate uses TGID)
        uid = ma.tgt.siblings ? ares_get_pid_uid(ma.tgt.pids[0]) : 0;
    } else {
        uid = ares_resolve_uid(ma.pkg);
        if (uid < 0) {
            fprintf(stderr, "mod: could not resolve UID for '%s' (installed? run as root?)\n", ma.pkg);
            return 1;
        }
    }

    if (ma.c.output_file && ares_sink_open(&g_sink, ma.c.output_file, "event", 1) != 0) {
        fprintf(stderr, "mod: cannot open '%s': %s\n", ma.c.output_file, strerror(errno));
        return 1;
    }

    int quiet = ma.c.quiet || (ma.c.output_file != NULL);
    struct ares_mod_ctx mc = {
        .sink    = ma.c.output_file ? &g_sink : NULL,
        .quiet   = quiet,
        .verbose = ma.c.verbose,
        .tgt     = &ma.tgt,
    };

    libbpf_set_print(ares_libbpf_quiet);

    struct ring_buffer *rb = an->setup(uid, &mc);
    if (!rb) {
        fprintf(stderr, "mod: analyzer '%s' setup failed\n", ma.name);
        if (ma.c.output_file) {
            ares_sink_close(&g_sink);
            ares_sink_report(&g_sink);
        }
        return 1;
    }

    ares_install_stop_handler(&exiting);
    if (ma.pkg) {
        ares_launch_banner(ma.pkg, uid);
        if (ares_launch_app(ma.pkg, ma.activity, NULL) != 0) {
            fprintf(stderr, "mod: launch failed for '%s' (activity resolvable? am available?)\n", ma.pkg);
            an->teardown();
            if (ma.c.output_file) {
                ares_sink_close(&g_sink);
                ares_sink_report(&g_sink);
            }
            return 1;
        }
    }

    printf("tracing uid %d (%s) ... Ctrl-C to stop\n", uid, ma.name);
    ares_rb_poll_until(rb, &exiting);

    // mod drop-telemetry parity: read the drop-map fd BEFORE teardown() destroys
    // the skeleton (fd goes with it). Task #10 upgrades this to ares_coverage_report.
    unsigned long long drops = an->drops ? an->drops() : 0;

    an->teardown();
    if (an->print_summary) an->print_summary();
    ares_drops_report(drops, 0);

    if (ma.c.output_file) {
        ares_sink_close(&g_sink);
        ares_sink_report(&g_sink);
    }

    return 0;
}
