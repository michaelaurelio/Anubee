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
};

static const struct argp_option mod_options[] = {
    { "package",  'P', "PACKAGE",  0, "App package to launch and trace", 0 },
    { "activity", 'A', "ACTIVITY", 0, "Override launch activity (default: auto-resolve)", 0 },
    COMMON_ARGP_OPTIONS,
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
    case ARGP_KEY_END:
        if (!a->name)
            argp_error(state, "analyzer name is required (first positional)");
        if (!a->pkg)
            argp_error(state, "package is required (-P PACKAGE)");
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

    int uid = ares_resolve_uid(ma.pkg);
    if (uid < 0) {
        fprintf(stderr, "mod: could not resolve UID for '%s' (installed? run as root?)\n", ma.pkg);
        return 1;
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
    };

    libbpf_set_print(ares_libbpf_quiet);

    struct ring_buffer *rb = an->setup(uid, &mc);
    if (!rb) {
        fprintf(stderr, "mod: analyzer '%s' setup failed\n", ma.name);
        if (ma.c.output_file) ares_sink_close(&g_sink);
        return 1;
    }

    char mod_key[64];
    snprintf(mod_key, sizeof(mod_key), "mod:%s", ma.name);
    int loud = ares_object_writes_target(mod_key);
    if (loud)
        printf("[mod]   > LOUD: %s uses uprobes (writes target memory)\n", ma.name);
    else
        printf("[mod]   > stealthy: %s uses kernel-only probes\n", ma.name);

    ares_install_stop_handler(&exiting);
    ares_launch_banner(ma.pkg, uid);

    if (ares_launch_app(ma.pkg, ma.activity, NULL) != 0) {
        fprintf(stderr, "mod: launch failed for '%s' (activity resolvable? am available?)\n", ma.pkg);
        an->teardown();
        if (ma.c.output_file) ares_sink_close(&g_sink);
        return 1;
    }

    printf("tracing uid %d (%s) ... Ctrl-C to stop\n", uid, ma.name);
    ares_rb_poll_until(rb, &exiting);

    an->teardown();
    if (an->print_summary) an->print_summary();

    if (ma.c.output_file) {
        ares_sink_close(&g_sink);
        ares_sink_report(&g_sink);
    }

    return 0;
}
