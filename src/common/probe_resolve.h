// SPDX-License-Identifier: GPL-2.0
#ifndef __ARES_COMMON_PROBE_RESOLVE_H
#define __ARES_COMMON_PROBE_RESOLVE_H

#include <regex.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/types.h>

#define ARG_STR  0
#define ARG_VAL  1
#define ARG_NONE 2  // no return probe for this target
#define ARG_FD   3  // fd argument; resolved to path via /proc/PID/fd/<n> at display time
#define ARG_SOCKADDR 4  // sockaddr* argument; decoded to ip:port via decode_sockaddr at display time

typedef struct {
    pid_t pid;
    char mod_path[256];
    char func_name[256];
    unsigned long offset;
    __u64 runtime_entry_addr;
    int arg_count;       // -1 = use BPF heuristic, 0-8 manual spec
    uint8_t arg_types[8];
    uint8_t ret_type;    // ARG_VAL, ARG_STR, or ARG_NONE (no return probe)
    bool ret_only;       // true = -r match: uprobe_save_only + uretprobe, no CALL event
} probe_target_t;

typedef struct {
    char mod[256];
    char func[256];
    unsigned long offset; // 0 = resolve from symbol name
    int arg_count;
    uint8_t arg_types[8];
    uint8_t ret_type;    // ARG_VAL, ARG_STR, or ARG_NONE
    bool ret_only;       // true when '>' present but no '()': uretprobe only, no CALL event
} custom_probe_spec_t;

// Bundle of the probe-resolution state, so the resolver is reentrant and can be
// lifted into src/common. Fields point at the existing file-scope arrays
// — no storage is moved. Attach (skel->progs) stays in the funcs engine.
struct probe_resolve_ctx {
    regex_t              *mod_re;
    bool                 *mod_has_slash;
    int                   mod_re_count;
    regex_t              *func_re;
    int                   func_re_count;
    regex_t              *func_ret_re;
    int                   func_ret_re_count;
    probe_target_t       *targets;        // output array (base)
    int                  *target_count;   // output count (shared cursor)
    int                   targets_cap;
    const custom_probe_spec_t *custom_specs;
    int                   custom_spec_count;
    bool                  verbose;
    void (*log)(const char *fmt, ...);
};

bool mod_matches(const char *full_path, regex_t *re, bool *has_slash, int count);
bool is_duplicate(probe_target_t *targets, int count, const char *mod_path, unsigned long offset);
int  resolve_targets(const struct probe_resolve_ctx *ctx, pid_t pid,
                     probe_target_t *targets, int max_targets);
int  resolve_targets_for_file(const struct probe_resolve_ctx *ctx, pid_t pid, const char *path,
                              unsigned long map_start, unsigned long map_end,
                              probe_target_t *targets, int max_targets);
int  parse_custom_probe_spec(const char *input, custom_probe_spec_t *out,
                             void (*log)(const char *fmt, ...));
int  resolve_custom_spec_for_path(pid_t pid, const char *path,
                                  const custom_probe_spec_t *spec, probe_target_t *out);
bool custom_spec_matches_path(const custom_probe_spec_t *spec, const char *path);

// Segment descriptor for vaddr→file-offset conversion. Plain ints; no libelf
// types so it can be used in host tests without pulling in gelf.h.
struct load_seg { unsigned long vaddr, offset, filesz; };
// Sentinel: vaddr matched no PT_LOAD segment — caller must skip, not attach.
#define SEG_VADDR_BAD ((unsigned long)-1)
// Convert a symbol virtual address to its file offset using a PT_LOAD table.
// Returns SEG_VADDR_BAD if no segment contains the vaddr — the caller must
// skip the symbol rather than attach a uprobe at a wrong file offset.
unsigned long seg_vaddr_to_off(const struct load_seg *segs, int n,
                                unsigned long vaddr);

#endif /* __ARES_COMMON_PROBE_RESOLVE_H */
