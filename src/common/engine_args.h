// SPDX-License-Identifier: GPL-2.0
// Shared argument contract for flags that every engine accepts: output, verbosity,
// ring buffer size, and worker queue size. Including this header gives:
//   - struct common_args  — fields for the six shared flags
//   - COMMON_ARGS_INIT    — designated initializer with correct defaults
//   - COMMON_ARGP_OPTIONS — argp option entries to embed in each engine's table
//   - parse_common_arg()  — argp callback delegate for the shared keys
//
// Include in the engine's .c file (not in shared headers); it pulls <argp.h>.
#ifndef __ARES_ENGINE_ARGS_H
#define __ARES_ENGINE_ARGS_H

#include <argp.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

struct common_args {
    const char *output_file;  // -o: JSONL output path (NULL = none)
    int         verbose;      // -v
    int         quiet;        // -q: suppress per-event console output
    int         jsonl;        // -J: force JSON Lines framing
    int         bufmb;        // -b: kernel ring buffer MB (default 4)
    int         queue_mb;     // -Q: userspace worker queue MB (default 256)
};

#define COMMON_ARGS_INIT { .bufmb = 4, .queue_mb = 256 }

// Embed in an engine's argp_option table (before the terminating { 0 }).
#define COMMON_ARGP_OPTIONS \
    { "output",  'o', "FILE", 0, "Export structured JSONL to FILE (also prints to console; -q silences that)", 0 }, \
    { "verbose", 'v', NULL,   0, "Verbose debug output",                            0 }, \
    { "quiet",   'q', NULL,   0, "Suppress per-event console output",               0 }, \
    { "jsonl",   'J', NULL,   0, "Write JSON Lines (one record per line)",          0 }, \
    { "bufsize", 'b', "MB",   0, "Kernel ring buffer size in MB (default 4)",       0 }, \
    { "queue",   'Q', "MB",   0, "Userspace worker queue size in MB (default 256)", 0 }

// Call from each engine's parse_opts for the common keys.
// Returns 0 when handled, ARGP_ERR_UNKNOWN when not (so the caller handles
// engine-specific keys in the same switch).
static inline error_t parse_common_arg(int key, char *arg,
                                       struct argp_state *state,
                                       struct common_args *c)
{
    switch (key) {
        case 'o': c->output_file = arg;  return 0;
        case 'v': c->verbose = 1;        return 0;
        case 'q': c->quiet = 1;          return 0;
        case 'J': c->jsonl = 1;          return 0;
        case 'b':
            c->bufmb = atoi(arg);
            if (c->bufmb < 1 || c->bufmb > 4096)
                argp_error(state, "bufsize must be between 1 and 4096 MB");  // AUDIT.md #4
            return 0;
        case 'Q':
            c->queue_mb = atoi(arg);
            if (c->queue_mb < 1 || c->queue_mb > 4096)
                argp_error(state, "queue must be between 1 and 4096 MB");  // AUDIT.md #4
            return 0;
    }
    return ARGP_ERR_UNKNOWN;
}

// ---- Shared target-selection args (-p PID, --siblings, --no-follow-fork) --------
// Parallel to common_args; engines that support attach mode embed this in their
// local args struct and delegate to parse_target_arg() from their parse_opts switch.

#define ARES_KEY_SIBLINGS   0x100  // long-only key, high range to avoid engine short-key clashes
#define ARES_KEY_NO_FOLLOW  0x101

struct target_args {
    pid_t pids[64];   // parsed PIDs from -p
    int   n;          // count of valid pids[]
    int   siblings;   // --siblings: also arm target_uids with each PID's UID
    int   no_follow;  // --no-follow-fork: skip follow-fork attach in PID mode
};

// Embed in an engine's argp_option table (before the terminating { 0 }).
#define TARGET_ARGP_OPTIONS \
    { "pid",            'p',                 "PID[,PID...]", 0, \
      "Attach to running PID(s) (precise; use --siblings to widen to same-UID)", 0 }, \
    { "siblings",       ARES_KEY_SIBLINGS,   NULL,           0, \
      "With -p: also trace processes sharing the target PID's UID", 0 }, \
    { "no-follow-fork", ARES_KEY_NO_FOLLOW,  NULL,           0, \
      "With -p: don't follow forked children (default: follow)", 0 }

// Pure CSV-to-pid_t parser. Splits csv on commas, converts each token with atoi,
// writes at most max entries to out[]. Returns the count written (<= max).
// ponytail: atoi is fine here — invalid non-numeric input becomes 0, caught at attach.
static inline int ares_parse_pid_list(const char *csv, pid_t *out, int max)
{
    if (!csv || max <= 0) return 0;
    // strtok modifies its input; work on a copy
    char buf[512];
    int  blen = (int)strnlen(csv, sizeof(buf) - 1);
    __builtin_memcpy(buf, csv, (size_t)blen);
    buf[blen] = '\0';
    int n = 0;
    char *tok = strtok(buf, ",");
    while (tok && n < max) {
        out[n++] = (pid_t)atoi(tok);
        tok = strtok(NULL, ",");
    }
    return n;
}

// Call from each engine's parse_opts for the target keys.
// Returns 0 when handled, ARGP_ERR_UNKNOWN when not.
static inline error_t parse_target_arg(int key, char *arg,
                                       struct argp_state *state,
                                       struct target_args *t)
{
    (void)state;
    switch (key) {
        case 'p': {
            int got = ares_parse_pid_list(arg, t->pids, 64);
            if (got < 1)
                argp_error(state, "-p: no valid PID in '%s'", arg);
            if (got == 64) {
                // check if there were more tokens
                const char *p = arg;
                int commas = 0;
                while (*p) { if (*p++ == ',') commas++; }
                if (commas >= 64)
                    fprintf(stderr, "warn: more than 64 PIDs given; extras ignored\n");
            }
            t->n = got;
            return 0;
        }
        case ARES_KEY_SIBLINGS:   t->siblings   = 1; return 0;
        case ARES_KEY_NO_FOLLOW:  t->no_follow  = 1; return 0;
    }
    return ARGP_ERR_UNKNOWN;
}

// True if argv requests help/usage — argp prints these but (under ARGP_NO_EXIT)
// returns 0, so callers must detect + abort themselves. See MT1.
static inline bool ares_wants_help(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help") ||
            !strcmp(a, "-?") || !strcmp(a, "--usage"))
            return true;
    }
    return false;
}

#endif /* __ARES_ENGINE_ARGS_H */
