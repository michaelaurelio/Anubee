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
#include "common/coverage.h"
#include "common/emit.h"
#include "common/launch.h"
#include "common/runtime.h"
#include "common/engine_args.h"
#include "common/probe_resolve.h"
#include "common/probe_spec_loader.h"
#include "common/human_out.h"      // err_print: surface -F parse errors (was silently NULL)

static volatile sig_atomic_t exiting = 0;
static struct ares_sink g_sink;

// ---- analyzer registry -------------------------------------------------------

static const ares_analyzer_t *const registry[] = {
    &analyzer_proc_event,
    &analyzer_execve,
    &analyzer_prop_read,
    &analyzer_file_access,
    &analyzer_ransomware_burst,
    &analyzer_exfil_burst,
    &analyzer_a11y_abuse,
    &analyzer_fileless_exec,
    &analyzer_mediaproj_abuse,
    NULL,
};

static const ares_analyzer_t *find_analyzer(const char *name)
{
    for (int i = 0; registry[i]; i++)
        if (strcmp(registry[i]->name, name) == 0)
            return registry[i];
    return NULL;
}

// MT3: out to `out` so callers can choose stdout (explicit discovery: bare
// `ares mod`, --list, --help) vs stderr (error paths, e.g. unknown analyzer
// name). Loudness reuses the same capabilities.c lookup the dispatcher itself
// consults before running an analyzer (see the LOUD/stealthy print below) —
// one source of truth, not a second copy of the loud/quiet table.
static void list_analyzers(FILE *out)
{
    fprintf(out, "available analyzers — run 'ares mod <name>' "
                  "('ares mod <name> --help' for flags):\n\n");
    for (int i = 0; registry[i]; i++) {
        char mod_key[64];
        snprintf(mod_key, sizeof(mod_key), "mod:%s", registry[i]->name);
        fprintf(out, "  %-16s %s\n    %s\n\n", registry[i]->name,
                ares_object_writes_target(mod_key) ? "[LOUD]" : "[stealth]",
                registry[i]->description);
    }
}

// ---- argp parser -------------------------------------------------------------

static const char mod_doc[] =
    "Run an ares analyzer by name. Each analyzer is a self-contained specialized\n"
    "tracing package with its own BPF object.\v"
    "Run 'ares mod <name> --help' for per-analyzer detail.\n";
static const char mod_args_doc[] = "NAME [options]";

struct mod_args {
    const char *names[16]; // -m (repeatable) + positional; only 8 analyzers exist, 16 is headroom
    int nname;
    const char *pkg;
    const char *activity;
    struct common_args c;
    struct target_args tgt; // -p / --siblings / --no-follow-fork
    custom_probe_spec_t specs[64];
    int nspec;
};

// Only advertise flags that are actually wired. -J/-b/-Q are NOT included:
// mod polls the ring buffer directly (no queue) and the per-analyzer ring
// size is hardcoded; -J is redundant with -o. Mirrors lib.c:89-96.
static const struct argp_option mod_options[] = {
    { "package",  'P', "PACKAGE",  0, "App package to launch and trace", 0 },
    { "activity", 'A', "ACTIVITY", 0, "Override launch activity (default: auto-resolve)", 0 },
    { "output",   'o', "FILE",     0, "Export structured JSONL to FILE (also prints console output; -q silences that)", 0 },
    { "module",   'm', "NAME",     0, "Analyzer to run; repeat to run several concurrently", 0 },
    { "verbose",  'v', NULL,       0, "Verbose output (execve: full backtrace frames)", 0 },
    { "quiet",    'q', NULL,       0, "Suppress per-event console output", 0 },
    { "spec-file", 'F', "FILE", 0, "Load probe specs from a file (one per line, # = comment); a mod: NAME line supplies the analyzer name when none is given positionally", 0 },
    { "list",     'l', NULL,       0, "List available analyzers and exit", 0 },
    TARGET_ARGP_OPTIONS,
    { 0 }
};

static error_t mod_parse_opt(int key, char *arg, struct argp_state *state)
{
    struct mod_args *a = state->input;
    switch (key) {
    case 'P': a->pkg      = arg; break;
    case 'A': a->activity = arg; break;
    case 'm': if (a->nname < 16) a->names[a->nname++] = arg;
              else argp_error(state, "analyzer name cap (16) reached, '%s' rejected", arg); break;
    case 'l': break; // handled by the argc pre-scan in cmd_mod, before argp runs
    case 'F':
        if (load_probe_spec_file(arg, a->specs, 64, &a->nspec, err_print) != 0)
            argp_error(state, "cannot open spec file '%s'", arg);
        break;
    case ARGP_KEY_ARG:
        if (a->nname < 16) a->names[a->nname++] = arg;
        else argp_error(state, "unexpected argument '%s'", arg);
        break;
    case 'p': case ARES_KEY_SIBLINGS: case ARES_KEY_NO_FOLLOW:
        return parse_target_arg(key, arg, state, &a->tgt);
    case ARGP_KEY_END:
        if (a->nname == 0)               // pull ALL mod: specs, not just the first
            for (int i = 0; i < a->nspec && a->nname < 16; i++)
                if (a->specs[i].kind == SPEC_KIND_MOD) a->names[a->nname++] = a->specs[i].mod;
        if (a->nname == 0)
            argp_error(state, "analyzer name is required (positional or -m)");
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

// AA2-follow-up: a shared -F spec file may carry funcs:/syscall:/lib: lines
// alongside mod: lines; those are silently dropped by the ARGP_KEY_END filter
// above (it only populates a->names[] from SPEC_KIND_MOD entries). Warn once
// so the operator sees what mod ignored. Printed twice (before + after run,
// see call sites below) so a long-scrolling console doesn't lose the note.
// Same idiom as funcs.c's print_ignored_kind_warning().
static void print_ignored_kind_warning(const custom_probe_spec_t *specs, int nspec)
{
    int n = 0;
    for (int i = 0; i < nspec; i++)
        if (specs[i].kind != SPEC_KIND_MOD)
            n++;
    if (!n) return;
    fprintf(stderr, "mod: warning — ignoring %d spec(s) not applicable to this engine "
                     "(mod: only):", n);
    for (int i = 0; i < nspec; i++) {
        if (specs[i].kind == SPEC_KIND_MOD) continue;
        char desc[400];
        spec_describe(&specs[i], desc, sizeof desc);
        fprintf(stderr, " %s", desc);
    }
    fprintf(stderr, "\n");
}

// MT3: -l/--list needs to short-circuit before argp_parse, same reason
// ares_wants_help (engine_args.h) is pre-scanned rather than handled purely
// via argp's own dispatch — ARGP_KEY_END below rejects a run with no analyzer
// name, which --list-alone would otherwise trip.
static bool mod_wants_list(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--list"))
            return true;
    return false;
}

// ---- entry point -------------------------------------------------------------

int cmd_mod(int argc, char **argv)
{
    // MT2/MT3: bare `ares mod`, `ares mod --list`, and `ares mod --help` used
    // to give no reliable indication of what NAME can be (main.c's usage text
    // claims --help lists analyzers, but argp has no visibility into
    // registry[] to do that itself). List up front, to stdout since this is
    // explicit discovery, not an error path. For --help, argp still runs
    // afterward and prints its own usage/options.
    if (argc < 2 || mod_wants_list(argc, argv)) { list_analyzers(stdout); return 0; }
    if (ares_wants_help(argc, argv)) list_analyzers(stdout);

    struct mod_args ma = { .c = COMMON_ARGS_INIT };
    argp_parse(&mod_argp, argc, argv, 0, NULL, &ma);
    print_ignored_kind_warning(ma.specs, ma.nspec); // "before run"

    const ares_analyzer_t *ans[16];
    int nan = ma.nname;
    for (int i = 0; i < nan; i++) {
        ans[i] = find_analyzer(ma.names[i]);
        if (!ans[i]) {
            fprintf(stderr, "mod: unknown analyzer '%s'\n", ma.names[i]);
            list_analyzers(stderr);
            return 1;
        }
    }

    // AA2 fix: classify + print loudness here, before anything below can load or
    // attach a BPF object — so a LOUD analyzer's uprobe is never live before the
    // operator sees the warning. ares_quiet_config_ok (not the direct
    // ares_object_writes_target call) so the one runtime-assertion helper in
    // capabilities.h has a real caller.
    for (int i = 0; i < nan; i++) {
        char mod_key[64];
        snprintf(mod_key, sizeof(mod_key), "mod:%s", ans[i]->name);
        const char *loaded[1] = { mod_key };
        if (!ares_quiet_config_ok(loaded, 1))
            printf("[mod]   > LOUD: %s uses uprobes (writes target memory)\n", ans[i]->name);
        else
            printf("[mod]   > stealthy: %s uses kernel-only probes\n", ans[i]->name);
    }

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

    const char *pkg_for_ctx = ma.pkg;
    char resolved_pkg[256];
    if (!pkg_for_ctx && ma.tgt.n > 0) {
        if (ares_resolve_pkg_from_pid(ma.tgt.pids[0], resolved_pkg, sizeof(resolved_pkg)) == 0)
            pkg_for_ctx = resolved_pkg;
    }

    if (ma.c.output_file && ares_sink_open(&g_sink, ma.c.output_file, "event", 1) != 0) {
        fprintf(stderr, "mod: cannot open '%s': %s\n", ma.c.output_file, strerror(errno));
        return 1;
    }

    int quiet = ma.c.quiet; // SYM1 Phase 1: -o no longer forces quiet; file and stdout are independent channels
    struct ares_mod_ctx mc = {
        .sink    = ma.c.output_file ? &g_sink : NULL,
        .quiet   = quiet,
        .verbose = ma.c.verbose,
        .tgt     = &ma.tgt,
        .pkg     = pkg_for_ctx,
    };

    libbpf_set_print(ares_libbpf_quiet);

    struct ring_buffer *rbs[16];
    int nrb = 0;
    for (int i = 0; i < nan; i++) {
        rbs[nrb] = ans[i]->setup(uid, &mc);
        if (!rbs[nrb]) {
            fprintf(stderr, "mod: analyzer '%s' setup failed\n", ans[i]->name);
            for (int j = nrb - 1; j >= 0; j--)
                ans[j]->teardown();
            if (ma.c.output_file) {
                ares_sink_close(&g_sink);
                ares_sink_report(&g_sink);
            }
            return 1;
        }
        nrb++;
    }

    ares_install_stop_handler(&exiting);
    if (ma.pkg) {
        ares_launch_banner(ma.pkg, uid);
        if (ares_launch_app(ma.pkg, ma.activity, NULL) != 0) {
            fprintf(stderr, "mod: launch failed for '%s' (activity resolvable? am available?)\n", ma.pkg);
            for (int j = nrb - 1; j >= 0; j--)
                ans[j]->teardown();
            if (ma.c.output_file) {
                ares_sink_close(&g_sink);
                ares_sink_report(&g_sink);
            }
            return 1;
        }
    }

    printf("tracing uid %d (%d analyzer%s) ... Ctrl-C to stop\n",
           uid, nan, nan == 1 ? "" : "s");
    ares_rb_poll_multi(rbs, nrb, &exiting);

    for (int i = nan - 1; i >= 0; i--) {
        // mod drop-telemetry parity + CR5 coverage: read the drop-map fd BEFORE
        // teardown() destroys the skeleton (fd goes with it).
        unsigned long long drops = ans[i]->drops ? ans[i]->drops() : 0;

        ans[i]->teardown();
        if (ans[i]->print_summary) ans[i]->print_summary();
        if (ans[i]->emit_summary && g_sink.f) ans[i]->emit_summary(&g_sink);

        struct ares_coverage cov = { .engine = ans[i]->name };
        cov.ring_drops = drops;
        ares_coverage_report(&g_sink, &cov);
    }
    print_ignored_kind_warning(ma.specs, ma.nspec); // "after run" repeat, see the "before run" call above

    if (ma.c.output_file) {
        ares_sink_close(&g_sink);
        ares_sink_report(&g_sink);
    }

    return 0;
}
