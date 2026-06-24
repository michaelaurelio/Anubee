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
    { "output",  'o', "FILE", 0, "Export structured JSONL to FILE (implies -q)",    0 }, \
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
            if (c->bufmb < 1) argp_error(state, "bufsize must be >= 1 MB");
            return 0;
        case 'Q':
            c->queue_mb = atoi(arg);
            if (c->queue_mb < 1) argp_error(state, "queue must be >= 1 MB");
            return 0;
    }
    return ARGP_ERR_UNKNOWN;
}

#endif /* __ARES_ENGINE_ARGS_H */
