// SPDX-License-Identifier: GPL-2.0
// `ares correlate` — span-gated function->syscall correlation.
//
// Attaches entry uprobes to spec'd functions (MODULE!FUNC) and a span-gated
// do_el0_svc kprobe; every syscall issued while a probed function is on the
// thread's stack is emitted carrying that function's span id. Reuses the shared
// launch (src/common/launch) and probe resolution (src/common/probe_resolve);
// the span stack lives in the BPF object (src/common/span_stack.bpf.h).
//
// v1 scope: custom specs (-e/-F) + -p (full) / -P (best-effort post-launch);
// SP-based span close by default, --returns opts a target into an authoritative
// uretprobe pop; syscall args get string/fd/sockaddr/flags decode (see corr_emit.c).
#include <errno.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "correlate.skel.h"
#include "correlate.h"
#include "common/emit.h"
#include "common/launch.h"
#include "common/probe_resolve.h"
#include "common/engine_args.h"
#include "common/runtime.h"
#include "common/maps.h"
#include "common/syscall_index.h"
#include "common/syscall_table.h"
#include "common/coverage.h"

const char *argp_program_bug_address = "<michael.windarta@binus.ac.id>";

// nr -> name table (generated for the device's arm64 ABI). R9 residual: table
// data now lives once in common/syscall_table.c, shared with syscalls.c.
static struct ares_sysindex g_sysidx;

static const char *syscall_name(long nr)
{
    const char *n = ares_sysindex_name(&g_sysidx, nr);
    return n ? n : "?";
}

// ---- syscall-arg decode tables (mirrors syscalls.c; correlate's per-event
// volume doesn't need that engine's dense by-nr cache, so these are a plain
// linear scan over a small table) ------------------------------------------

#define A0 (1u << 0)
#define A1 (1u << 1)
#define A2 (1u << 2)
#define A3 (1u << 3)
#define A4 (1u << 4)

// Which of args[0..3] are a const char* (path/string), per syscall. Copied
// verbatim from syscalls.c's g_str_args[].
static const struct { long nr; unsigned char mask; } g_str_args[] = {
#ifdef __NR_openat
    { __NR_openat, A1 },
#endif
#ifdef __NR_openat2
    { __NR_openat2, A1 },
#endif
#ifdef __NR_name_to_handle_at
    { __NR_name_to_handle_at, A1 },
#endif
#ifdef __NR_readlinkat
    { __NR_readlinkat, A1 },
#endif
#ifdef __NR_newfstatat
    { __NR_newfstatat, A1 },
#endif
#ifdef __NR_statx
    { __NR_statx, A1 },
#endif
#ifdef __NR_faccessat
    { __NR_faccessat, A1 },
#endif
#ifdef __NR_faccessat2
    { __NR_faccessat2, A1 },
#endif
#ifdef __NR_fchmodat
    { __NR_fchmodat, A1 },
#endif
#ifdef __NR_fchownat
    { __NR_fchownat, A1 },
#endif
#ifdef __NR_unlinkat
    { __NR_unlinkat, A1 },
#endif
#ifdef __NR_mkdirat
    { __NR_mkdirat, A1 },
#endif
#ifdef __NR_mknodat
    { __NR_mknodat, A1 },
#endif
#ifdef __NR_utimensat
    { __NR_utimensat, A1 },
#endif
#ifdef __NR_renameat
    { __NR_renameat, A1 | A3 },
#endif
#ifdef __NR_renameat2
    { __NR_renameat2, A1 | A3 },
#endif
#ifdef __NR_linkat
    { __NR_linkat, A1 | A3 },
#endif
#ifdef __NR_symlinkat
    { __NR_symlinkat, A0 | A2 },
#endif
#ifdef __NR_execve
    { __NR_execve, A0 },
#endif
#ifdef __NR_execveat
    { __NR_execveat, A1 },
#endif
#ifdef __NR_chdir
    { __NR_chdir, A0 },
#endif
#ifdef __NR_chroot
    { __NR_chroot, A0 },
#endif
#ifdef __NR_truncate
    { __NR_truncate, A0 },
#endif
#ifdef __NR_statfs
    { __NR_statfs, A0 },
#endif
#ifdef __NR_getxattr
    { __NR_getxattr, A0 | A1 },
#endif
#ifdef __NR_lgetxattr
    { __NR_lgetxattr, A0 | A1 },
#endif
#ifdef __NR_setxattr
    { __NR_setxattr, A0 | A1 },
#endif
#ifdef __NR_mount
    { __NR_mount, A0 | A1 | A2 },
#endif
#ifdef __NR_umount2
    { __NR_umount2, A0 },
#endif
#ifdef __NR_pivot_root
    { __NR_pivot_root, A0 | A1 },
#endif
};

static void install_arg_types(int fd)
{
    for (size_t i = 0; i < sizeof(g_str_args) / sizeof(g_str_args[0]); i++) {
        __u32 k = (__u32)g_str_args[i].nr;
        __u8 v = g_str_args[i].mask;
        if (k < 512)
            bpf_map_update_elem(fd, &k, &v, BPF_ANY);
    }
}

// Which arg holds a sockaddr* (the addrlen is the next arg); connect/bind at
// arg1, sendto at arg4. Copied verbatim from syscalls.c's g_sock_args[].
static const struct { long nr; int arg; } g_sock_args[] = {
#ifdef __NR_connect
    { __NR_connect, 1 },
#endif
#ifdef __NR_bind
    { __NR_bind, 1 },
#endif
#ifdef __NR_sendto
    { __NR_sendto, 4 },
#endif
};

static void install_sock_args(int fd)
{
    for (size_t i = 0; i < sizeof(g_sock_args) / sizeof(g_sock_args[0]); i++) {
        __u32 k = (__u32)g_sock_args[i].nr;
        __u8 v = (__u8)(g_sock_args[i].arg + 1);
        if (k < 512)
            bpf_map_update_elem(fd, &k, &v, BPF_ANY);
    }
}

static int arg_sock_index(unsigned long long nr)
{
    for (size_t i = 0; i < sizeof(g_sock_args) / sizeof(g_sock_args[0]); i++)
        if ((unsigned long long)g_sock_args[i].nr == nr)
            return g_sock_args[i].arg;
    return -1;
}

static const struct { long nr; unsigned char mask; } g_fd_args[] = {
#ifdef __NR_read
    { __NR_read, A0 },
#endif
#ifdef __NR_write
    { __NR_write, A0 },
#endif
#ifdef __NR_pread64
    { __NR_pread64, A0 },
#endif
#ifdef __NR_pwrite64
    { __NR_pwrite64, A0 },
#endif
#ifdef __NR_readv
    { __NR_readv, A0 },
#endif
#ifdef __NR_writev
    { __NR_writev, A0 },
#endif
#ifdef __NR_close
    { __NR_close, A0 },
#endif
#ifdef __NR_fstat
    { __NR_fstat, A0 },
#endif
#ifdef __NR_fstatfs
    { __NR_fstatfs, A0 },
#endif
#ifdef __NR_lseek
    { __NR_lseek, A0 },
#endif
#ifdef __NR_fsync
    { __NR_fsync, A0 },
#endif
#ifdef __NR_fdatasync
    { __NR_fdatasync, A0 },
#endif
#ifdef __NR_ftruncate
    { __NR_ftruncate, A0 },
#endif
#ifdef __NR_fcntl
    { __NR_fcntl, A0 },
#endif
#ifdef __NR_ioctl
    { __NR_ioctl, A0 },
#endif
#ifdef __NR_getdents64
    { __NR_getdents64, A0 },
#endif
#ifdef __NR_flock
    { __NR_flock, A0 },
#endif
#ifdef __NR_fchdir
    { __NR_fchdir, A0 },
#endif
#ifdef __NR_fchmod
    { __NR_fchmod, A0 },
#endif
#ifdef __NR_fchown
    { __NR_fchown, A0 },
#endif
#ifdef __NR_dup
    { __NR_dup, A0 },
#endif
#ifdef __NR_dup3
    { __NR_dup3, A0 },
#endif
#ifdef __NR_sendto
    { __NR_sendto, A0 },
#endif
#ifdef __NR_recvfrom
    { __NR_recvfrom, A0 },
#endif
#ifdef __NR_sendmsg
    { __NR_sendmsg, A0 },
#endif
#ifdef __NR_recvmsg
    { __NR_recvmsg, A0 },
#endif
#ifdef __NR_connect
    { __NR_connect, A0 },
#endif
#ifdef __NR_getsockopt
    { __NR_getsockopt, A0 },
#endif
#ifdef __NR_setsockopt
    { __NR_setsockopt, A0 },
#endif
#ifdef __NR_epoll_ctl
    { __NR_epoll_ctl, A0 | A4 },
#endif
#ifdef __NR_mmap
    { __NR_mmap, A4 },
#endif
    // *at family: arg0 is the dirfd.
#ifdef __NR_openat
    { __NR_openat, A0 },
#endif
#ifdef __NR_openat2
    { __NR_openat2, A0 },
#endif
#ifdef __NR_newfstatat
    { __NR_newfstatat, A0 },
#endif
#ifdef __NR_readlinkat
    { __NR_readlinkat, A0 },
#endif
#ifdef __NR_faccessat
    { __NR_faccessat, A0 },
#endif
#ifdef __NR_faccessat2
    { __NR_faccessat2, A0 },
#endif
#ifdef __NR_fchmodat
    { __NR_fchmodat, A0 },
#endif
#ifdef __NR_fchownat
    { __NR_fchownat, A0 },
#endif
#ifdef __NR_unlinkat
    { __NR_unlinkat, A0 },
#endif
#ifdef __NR_mkdirat
    { __NR_mkdirat, A0 },
#endif
#ifdef __NR_utimensat
    { __NR_utimensat, A0 },
#endif
#ifdef __NR_statx
    { __NR_statx, A0 },
#endif
#ifdef __NR_name_to_handle_at
    { __NR_name_to_handle_at, A0 },
#endif
#ifdef __NR_execveat
    { __NR_execveat, A0 },
#endif
};

static unsigned arg_fd_mask(unsigned long long nr)
{
    for (size_t i = 0; i < sizeof(g_fd_args) / sizeof(g_fd_args[0]); i++)
        if ((unsigned long long)g_fd_args[i].nr == nr)
            return g_fd_args[i].mask;
    return 0;
}

static volatile sig_atomic_t exiting = 0;

static struct ares_sink g_sink;
static int              g_quiet = 0;
static int              g_returns = 0;  // --returns: attach a uretprobe per target too

// -I/-i regex targeting (mirrors funcs.c). Resolved targets accumulate here
// across attach_uprobes_for_pid calls so resolve_targets_for_file's dedup
// (ctx->targets/target_count) sees everything attached so far.
static regex_t        g_mod_re[32];
static bool            g_mod_has_slash[32];
static int             g_mod_re_count = 0;
static regex_t         g_func_re[32];
static int             g_func_re_count = 0;
static probe_target_t  g_regex_targets[1024];
static int             g_regex_target_count = 0;

// Tracked uprobe links so teardown can bpf_link__destroy them (the syscall
// kprobe is tracked separately via g_kp). Grown on demand; on OOM we drop
// tracking for the new link — it stays attached and is reaped at process exit.
static struct bpf_link **g_uprobe_links = NULL;
static int g_uprobe_nlinks = 0, g_uprobe_cap = 0;

static void track_uprobe_link(struct bpf_link *link)
{
    if (g_uprobe_nlinks == g_uprobe_cap) {
        int ncap = g_uprobe_cap ? g_uprobe_cap * 2 : 64;
        struct bpf_link **n = realloc(g_uprobe_links, (size_t)ncap * sizeof(*n));
        if (!n) return;
        g_uprobe_links = n;
        g_uprobe_cap = ncap;
    }
    g_uprobe_links[g_uprobe_nlinks++] = link;
}

static void destroy_uprobe_links(void)
{
    for (int i = 0; i < g_uprobe_nlinks; i++)
        bpf_link__destroy(g_uprobe_links[i]);
    free(g_uprobe_links);
    g_uprobe_links = NULL;
    g_uprobe_nlinks = g_uprobe_cap = 0;
}

static void log_stderr(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

// ponytail: libbpf_print_fn removed; ares_libbpf_quiet from common/runtime.h used instead

static int handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct trace_event_header))
        return 0;
    const struct trace_event_header *h = data;

    if (h->type == CORR_EV_FUNC) {
        if (sz < sizeof(struct corr_func_event)) return 0;
        const struct corr_func_event *e = data;
        if (!g_quiet)
            printf("[func]    > span=%llu parent=%llu pid=%u tid=%u @ 0x%llx\n",
                   (unsigned long long)e->span, (unsigned long long)e->parent_span,
                   e->h.pid, e->h.tid, (unsigned long long)e->entry_addr);
        if (g_sink.f) {
            corr_emit_func(&g_sink.jb, e);
            ares_sink_emit(&g_sink);
        }
    } else if (h->type == CORR_EV_SYSCALL) {
        if (sz < sizeof(struct corr_syscall_event)) return 0;
        const struct corr_syscall_event *e = data;
        const char *name = syscall_name((long)e->nr);
        if (!g_quiet)
            printf("[syscall] > span=%llu pid=%u tid=%u %s (nr=%llu)\n",
                   (unsigned long long)e->span, e->h.pid, e->h.tid, name,
                   (unsigned long long)e->nr);
        if (g_sink.f) {
            unsigned fdmask = arg_fd_mask(e->nr);
            int sockidx = arg_sock_index(e->nr);
            corr_emit_syscall(&g_sink.jb, e, name, fdmask, sockidx);
            ares_sink_emit(&g_sink);
        }
    } else if (h->type == CORR_EV_RETURN) {
        if (sz < sizeof(struct corr_return_event)) return 0;
        const struct corr_return_event *e = data;
        if (!g_quiet)
            printf("[return]  > span=%llu retval=0x%llx elapsed=%lluns @ 0x%llx\n",
                   (unsigned long long)e->span, (unsigned long long)e->retval,
                   (unsigned long long)e->elapsed_ns, (unsigned long long)e->entry_addr);
        if (g_sink.f) {
            corr_emit_return(&g_sink.jb, e);
            ares_sink_emit(&g_sink);
        }
    } else if (h->type == CORR_EV_MAP) {
        if (sz < sizeof(struct lib_map_event)) return 0;
        const struct lib_map_event *e = data;
        char path[256];
        if (ares_libtrace_resolve_path(e->h.pid, e->start, e->name,
                                       path, sizeof(path)) != 0)
            snprintf(path, sizeof(path), "%s", e->name);
        // emit self-gates: console line unless -q, {"type":"lib"} when -o set.
        ares_libtrace_emit_lib(&g_sink, g_quiet, e, path, NULL);
    } else if (h->type == CORR_EV_UNMAP) {
        if (sz < sizeof(struct lib_unmap_event)) return 0;
        const struct lib_unmap_event *e = data;
        ares_libtrace_emit_unlib(&g_sink, g_quiet, e);
    }
    return 0;
}

// Scan /proc/<pid>/maps and attach the entry uprobe at every spec'd function.
static int attach_uprobes_for_pid(struct ares_correlate *skel, pid_t pid,
                                  const custom_probe_spec_t *specs, int nspec,
                                  int returns)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        fprintf(stderr, "correlate: cannot open %s: %s\n", maps_path, strerror(errno));
        return -1;
    }

    // Small dedup of (path,offset) already attached for this pid.
    struct { char path[256]; unsigned long off; } done[256];
    int ndone = 0, attached = 0, warned = 0;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        struct ares_map_line ml;
        if (!ares_parse_maps_line(line, &ml)) continue;
        if (ml.path[0] != '/' || !ml.exec) continue;
        const char *path = ml.path;

        for (int s = 0; s < nspec; s++) {
            if (!custom_spec_matches_path(&specs[s], path)) continue;
            probe_target_t tgt;
            if (resolve_custom_spec_for_path(pid, path, &specs[s], &tgt) != 0)
                continue;

            int dup = 0;
            for (int d = 0; d < ndone; d++)
                if (done[d].off == tgt.offset && strcmp(done[d].path, path) == 0) { dup = 1; break; }
            if (dup) continue;
            if (ndone < 256) {
                snprintf(done[ndone].path, sizeof(done[ndone].path), "%s", path);
                done[ndone].off = tgt.offset;
                ndone++;
            } else if (!warned) {
                fprintf(stderr, "correlate: warning — dedup table full (256) for PID %d; "
                                "duplicate uprobes may be attached\n", pid);
                warned = 1;
            }

            struct bpf_link *link = bpf_program__attach_uprobe(
                skel->progs.corr_uprobe_entry, false, pid, path, tgt.offset);
            const char *bname = strrchr(path, '/');
            bname = bname ? bname + 1 : path;
            if (link) {
                track_uprobe_link(link);
                printf("[spec] > %s!%s @ 0x%lx\n", bname,
                       tgt.func_name[0] ? tgt.func_name : "?", tgt.offset);
                attached++;
                if (returns) {
                    struct bpf_link *rl = bpf_program__attach_uprobe(
                        skel->progs.corr_uretprobe_ret, true, pid, path, tgt.offset);
                    if (rl)
                        track_uprobe_link(rl);
                    else
                        fprintf(stderr, "[spec] > RET FAILED: %s!%s @ 0x%lx\n", bname,
                                tgt.func_name[0] ? tgt.func_name : "?", tgt.offset);
                }
            } else {
                fprintf(stderr, "[spec] > FAILED: %s!%s @ 0x%lx\n", bname,
                        tgt.func_name[0] ? tgt.func_name : "?", tgt.offset);
            }
        }

        // -I/-i regex targeting: resolve symbols in this mapping, attach each
        // (mirrors funcs.c's mmap-triggered resolve_targets_for_file path).
        if ((g_mod_re_count > 0 || g_func_re_count > 0) &&
            mod_matches(path, g_mod_re, g_mod_has_slash, g_mod_re_count)) {
            struct probe_resolve_ctx rctx = {
                .mod_re = g_mod_re, .mod_has_slash = g_mod_has_slash, .mod_re_count = g_mod_re_count,
                .func_re = g_func_re, .func_re_count = g_func_re_count,
                .func_ret_re = NULL, .func_ret_re_count = 0,
                .targets = g_regex_targets, .target_count = &g_regex_target_count,
                .targets_cap = (int)(sizeof(g_regex_targets) / sizeof(g_regex_targets[0])),
                .custom_specs = NULL, .custom_spec_count = 0,
                .verbose = 0, .log = log_stderr,
            };
            int max = (int)(sizeof(g_regex_targets) / sizeof(g_regex_targets[0])) - g_regex_target_count;
            int resolved = (max > 0) ? resolve_targets_for_file(&rctx, pid, path,
                                (unsigned long)ml.start, (unsigned long)ml.end,
                                g_regex_targets + g_regex_target_count, max) : 0;

            for (int i = g_regex_target_count; i < g_regex_target_count + (resolved > 0 ? resolved : 0); i++) {
                probe_target_t *tgt = &g_regex_targets[i];
                int dup = 0;
                for (int d = 0; d < ndone; d++)
                    if (done[d].off == tgt->offset && strcmp(done[d].path, path) == 0) { dup = 1; break; }
                if (dup) continue;
                if (ndone < 256) {
                    snprintf(done[ndone].path, sizeof(done[ndone].path), "%s", path);
                    done[ndone].off = tgt->offset;
                    ndone++;
                }

                const char *bname = strrchr(path, '/');
                bname = bname ? bname + 1 : path;
                struct bpf_link *link = bpf_program__attach_uprobe(
                    skel->progs.corr_uprobe_entry, false, pid, path, tgt->offset);
                if (link) {
                    track_uprobe_link(link);
                    printf("[regex] > %s!%s @ 0x%lx\n", bname, tgt->func_name, tgt->offset);
                    attached++;
                } else {
                    fprintf(stderr, "[regex] > FAILED: %s!%s @ 0x%lx\n", bname, tgt->func_name, tgt->offset);
                }

                if (link && g_returns) {
                    struct bpf_link *rlink = bpf_program__attach_uprobe(
                        skel->progs.corr_uretprobe_ret, true, pid, path, tgt->offset);
                    if (rlink)
                        track_uprobe_link(rlink);
                    else
                        fprintf(stderr, "[regex] > FAILED ret: %s!%s @ 0x%lx\n", bname, tgt->func_name, tgt->offset);
                }
            }
            if (resolved > 0) g_regex_target_count += resolved;
        }
    }
    fclose(f);
    return attached;
}

static int install_uid(struct ares_correlate *skel, int uid)
{
    if (uid <= 0) return -1;
    __u32 vuid = (__u32)uid, one = 1;
    return bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY);
}

// -P timing: block briefly after launch until a spec'd/regex-matched library
// shows up mapped-executable in /proc/<pid>/maps, instead of a blind sleep(1)
// (which misses calls in the first second and over-waits once the lib is
// already up). Falls through on timeout — same worst case as the old sleep.
static void wait_for_target_mapped(pid_t pid, const custom_probe_spec_t *specs, int nspec)
{
    const int poll_ms = 10, timeout_ms = 2000;
    for (int waited = 0; waited < timeout_ms; waited += poll_ms) {
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
        FILE *f = fopen(maps_path, "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                struct ares_map_line ml;
                if (!ares_parse_maps_line(line, &ml)) continue;
                if (ml.path[0] != '/' || !ml.exec) continue;
                for (int s = 0; s < nspec; s++)
                    if (custom_spec_matches_path(&specs[s], ml.path)) { fclose(f); return; }
                if ((g_mod_re_count > 0 || g_func_re_count > 0) &&
                    mod_matches(ml.path, g_mod_re, g_mod_has_slash, g_mod_re_count)) {
                    fclose(f);
                    return;
                }
            }
            fclose(f);
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)poll_ms * 1000000L };
        nanosleep(&ts, NULL);
    }
}

// ---- argp parser ----------------------------------------------------------

static const char corr_doc[] =
    "Attach entry uprobes to spec'd functions + a span-gated syscall kprobe;\n"
    "emit each in-span syscall tagged with the enclosing function's span.\v"
    "Exactly one of -p or -P must be given. At least one of -e/-F or -I/-i is required.\n"
    "Example: ares correlate -P com.example.app -e 'libnative.so!Java_*' -o out.jsonl";
static const char corr_args_doc[] = "";

#define ARES_KEY_RETURNS 0x200   // correlate-local long-only key (--returns)

struct corr_args {
    const char        *pkg;
    const char        *out_path;
    int                quiet;
    int                returns;
    struct target_args tgt;
    custom_probe_spec_t specs[64];
    int                nspec;
    char               mod_patterns[32][256];
    int                mod_pattern_count;
    char               func_patterns[32][256];
    int                func_pattern_count;
};

// Only the flags actually wired. -J/-b/-Q have nothing to attach here.
static const struct argp_option corr_options[] = {
    TARGET_ARGP_OPTIONS,
    { "package", 'P', "PACKAGE",   0, "Launch a package fresh and attach to it", 0 },
    { "spec",    'e', "SPEC",      0, "Probe spec MODULE!FUNC[(S|V,...)] (repeatable)", 0 },
    { "specs",   'F', "FILE",      0, "Load probe specs from a file (one per line, # = comment)", 0 },
    { "include-module", 'I', "MODULE", 0, "Target module to trace (regex, repeatable)", 0 },
    { "include", 'i', "FUNCTION",  0, "Target function to trace (regex, repeatable)", 0 },
    { "output",  'o', "FILE",      0, "Write structured JSONL (implies -q)", 0 },
    { "quiet",   'q', NULL,        0, "Suppress per-event console output", 0 },
    { "returns", ARES_KEY_RETURNS, NULL, 0,
      "Also attach uretprobes: return value + exact span timing (LOUD: adds a "
      "stack trampoline, a 2nd detection surface beyond the entry BRK)", 0 },
    { 0 }
};

static error_t corr_parse_opt(int key, char *arg, struct argp_state *state)
{
    struct corr_args *a = state->input;
    switch (key) {
    case 'P': a->pkg      = arg; break;
    case 'o': a->out_path = arg; break;
    case 'q': a->quiet    = 1;   break;
    case ARES_KEY_RETURNS: a->returns = 1; break;
    case 'I':
        if (a->mod_pattern_count < 32)
            snprintf(a->mod_patterns[a->mod_pattern_count++], 256, "%s", arg);
        else
            fprintf(stderr, "correlate: warning — module pattern cap (32) reached; '%s' ignored\n", arg);
        break;
    case 'i':
        if (a->func_pattern_count < 32)
            snprintf(a->func_patterns[a->func_pattern_count++], 256, "%s", arg);
        else
            fprintf(stderr, "correlate: warning — function pattern cap (32) reached; '%s' ignored\n", arg);
        break;
    case 'p': case ARES_KEY_SIBLINGS: case ARES_KEY_NO_FOLLOW:
        return parse_target_arg(key, arg, state, &a->tgt);
    case 'e':
        if (a->nspec >= 64)
            fprintf(stderr, "correlate: warning — spec cap (64) reached; '%s' ignored\n", arg);
        else if (parse_custom_probe_spec(arg, &a->specs[a->nspec], log_stderr) == 0)
            a->nspec++;
        break;
    case 'F': {
        FILE *sf = fopen(arg, "r");
        if (!sf) argp_error(state, "cannot open '%s': %s", arg, strerror(errno));
        char line[512];
        while (fgets(line, sizeof(line), sf) && a->nspec < 64) {
            char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
            if (line[0] == '\0' || line[0] == '#') continue;
            if (parse_custom_probe_spec(line, &a->specs[a->nspec], log_stderr) == 0) a->nspec++;
        }
        if (a->nspec >= 64 && !feof(sf))
            fprintf(stderr, "correlate: warning — spec cap (64) reached; "
                            "remaining lines in '%s' ignored\n", arg);
        fclose(sf);
        break;
    }
    case ARGP_KEY_END:
        if ((a->tgt.n == 0 && !a->pkg) || (a->tgt.n > 0 && a->pkg))
            argp_error(state, "specify exactly one of -p or -P");
        if (a->nspec == 0 && a->mod_pattern_count == 0 && a->func_pattern_count == 0)
            argp_error(state, "no probe targets given (-e SPEC, -F FILE, or -I/-i regex)");
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp corr_argp = { corr_options, corr_parse_opt, corr_args_doc, corr_doc, 0, 0, 0 };

// ---- three-phase driver ---------------------------------------------------
// correlate_setup/run/teardown are kept global for signature parity with the
// other engines. rc is plumbed through for future coordinator use but is not
// consumed: correlate's -P launch stays inside setup because uprobe attach needs
// the child PID (only known post-launch) before setup returns.
// ponytail: correlate stays standalone — trace --correlate is deferred; the
// coordinator would need a post-launch correlate_attach(pid) step (5th public fn).

// Cross-phase state: published by correlate_setup, consumed by run/teardown.
static struct ares_correlate *g_skel;
static struct bpf_link        *g_kp;
static struct bpf_link        *g_ff;
static struct bpf_link        *g_map_kp;    // shared lib_trace uprobe_mmap kprobe
static struct bpf_link        *g_unmap_kp;  // shared lib_trace uprobe_munmap kprobe
static struct ring_buffer     *g_rb;
static int                     g_total;

// Attach the shared lib_trace kprobes (uprobe_mmap / uprobe_munmap) that emit the
// {"type":"lib"}/{"type":"unlib"} records. Attached before launch in -P mode (like
// the UID install) so the target's startup library maps are captured, not just
// later dlopens.
static int attach_lib_kprobes(struct ares_correlate *skel)
{
    g_map_kp = bpf_program__attach(skel->progs.on_uprobe_mmap);
    if (!g_map_kp) { fprintf(stderr, "correlate: attach uprobe_mmap kprobe failed\n"); return -1; }
    g_unmap_kp = bpf_program__attach(skel->progs.on_uprobe_munmap);
    if (!g_unmap_kp) { fprintf(stderr, "correlate: attach uprobe_munmap kprobe failed\n"); return -1; }
    return 0;
}

int correlate_setup(int argc, char **argv, const struct ares_run_ctx *rc)
{
    ares_sysindex_build(&g_sysidx, ares_syscall_table, ares_syscall_table_count);
    (void)rc;  // plumbed for parity; trace --correlate wiring deferred (post-launch attach)
    // ponytail: static so specs/pkg strings (pointing into argv) outlive setup.
    static struct corr_args ca = { 0 };
    if (argp_parse(&corr_argp, argc, argv, 0, NULL, &ca) != 0)
        return 1;

    g_quiet   = ca.quiet || (ca.out_path != NULL);

    for (int i = 0; i < ca.mod_pattern_count; i++) {
        g_mod_has_slash[i] = strchr(ca.mod_patterns[i], '/') != NULL;
        if (regcomp(&g_mod_re[i], ca.mod_patterns[i], REG_EXTENDED | REG_NOSUB) != 0) {
            fprintf(stderr, "correlate: invalid -I regex: %s\n", ca.mod_patterns[i]);
            return 1;
        }
        g_mod_re_count++;
    }
    for (int i = 0; i < ca.func_pattern_count; i++) {
        if (regcomp(&g_func_re[i], ca.func_patterns[i], REG_EXTENDED | REG_NOSUB) != 0) {
            fprintf(stderr, "correlate: invalid -i regex: %s\n", ca.func_patterns[i]);
            return 1;
        }
        g_func_re_count++;
    }
    if (ca.out_path && ares_sink_open(&g_sink, ca.out_path, "event", 1) != 0) {
        fprintf(stderr, "correlate: cannot open %s: %s\n", ca.out_path, strerror(errno));
        return 1;
    }

    libbpf_set_print(ares_libbpf_quiet);

    struct ares_correlate *skel = ares_correlate__open();
    if (!skel) { fprintf(stderr, "correlate: open skeleton failed\n"); goto err_file; }
    bpf_program__set_autoattach(skel->progs.corr_uretprobe_ret, false);
    if (ares_correlate__load(skel)) {
        fprintf(stderr, "correlate: BPF load failed (eBPF privileges / SELinux permissive?)\n");
        goto err_skel;
    }
    install_arg_types(bpf_map__fd(skel->maps.arg_types));
    install_sock_args(bpf_map__fd(skel->maps.sock_args));

    // -P: install UID before launch so the kprobe gates from the start.
    if (ca.pkg) {
        int uid = ares_resolve_uid(ca.pkg);
        if (uid < 0) { fprintf(stderr, "correlate: cannot resolve UID for %s\n", ca.pkg); goto err_skel; }
        if (install_uid(skel, uid) != 0) { fprintf(stderr, "correlate: install UID failed\n"); goto err_skel; }
        ares_launch_banner(ca.pkg, uid);
        // Attach lib_trace kprobes before launch so startup maps are captured.
        if (attach_lib_kprobes(skel) != 0) goto err_skel;
        pid_t p;
        if (ares_launch_app(ca.pkg, NULL, &p) != 0) {
            fprintf(stderr, "correlate: launch failed for %s\n", ca.pkg); goto err_skel;
        }
        wait_for_target_mapped(p, ca.specs, ca.nspec);
        ca.tgt.pids[ca.tgt.n++] = p;
    } else {
        // -p: arm target_pids for each PID; arm target_uids only if --siblings.
        __u8 one = 1;
        for (int i = 0; i < ca.tgt.n; i++) {
            __u32 tgid = (__u32)ca.tgt.pids[i];
            bpf_map_update_elem(bpf_map__fd(skel->maps.target_pids), &tgid, &one, BPF_ANY);
            if (ca.tgt.siblings) {
                int uid = ares_get_pid_uid(ca.tgt.pids[i]);
                if (uid > 0 && install_uid(skel, uid) != 0)
                    fprintf(stderr, "correlate: install UID for PID %d failed\n", ca.tgt.pids[i]);
            }
        }
        if (!ca.tgt.no_follow) {
            g_ff = bpf_program__attach(skel->progs.ares_follow_fork);
            if (!g_ff) fprintf(stderr, "correlate: follow-fork attach failed (non-fatal)\n");
        }
        // Already-running target: catches future maps/unmaps (dlopen/dlclose).
        if (attach_lib_kprobes(skel) != 0) goto err_skel;
    }

    // Span-gated syscall kprobe (one, shared).
    struct bpf_link *kp = bpf_program__attach(skel->progs.corr_on_svc);
    if (!kp) { fprintf(stderr, "correlate: attach do_el0_svc kprobe failed\n"); goto err_skel; }

    int total = 0;
    for (int i = 0; i < ca.tgt.n; i++) {
        int n = attach_uprobes_for_pid(skel, ca.tgt.pids[i], ca.specs, ca.nspec, ca.returns);
        if (n > 0) total += n;
    }
    if (total == 0)
        fprintf(stderr, "correlate: warning — no uprobes attached (no spec'd functions found)\n");
    if (ca.returns && total > 0)
        fprintf(stderr, "correlate: --returns active - uretprobe trampoline on the "
                        "target stack is a 2nd detection surface (beyond the entry BRK)\n");

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "correlate: ring buffer failed\n"); bpf_link__destroy(kp); goto err_skel; }

    g_skel  = skel;
    g_kp    = kp;
    g_rb    = rb;
    g_total = total;
    g_returns = ca.returns;
    return 0;

err_skel:
    // AA11 fix: g_ff (attached earlier in setup, if reached) isn't touched by
    // destroy_uprobe_links() — destroy it explicitly, same as funcs' teardown-reuse.
    if (g_ff) {
        bpf_link__destroy(g_ff);
        g_ff = NULL;
    }
    destroy_uprobe_links();
    ares_correlate__destroy(skel);
err_file:
    if (g_sink.f) {
        ares_sink_close(&g_sink);
        ares_sink_report(&g_sink);
    }
    return 1;
}

int correlate_run(volatile sig_atomic_t *stop)
{
    printf("correlating %d uprobe(s) -> syscalls ... Ctrl-C to stop\n", g_total);
    ares_rb_poll_until(g_rb, stop);
    return 0;
}

void correlate_teardown(void)
{
    if (g_rb) {
        ring_buffer__free(g_rb);
        g_rb = NULL;
    }
    if (g_kp) {
        bpf_link__destroy(g_kp);
        g_kp = NULL;
    }
    if (g_ff) {
        bpf_link__destroy(g_ff);
        g_ff = NULL;
    }
    if (g_map_kp)   { bpf_link__destroy(g_map_kp);   g_map_kp = NULL; }
    if (g_unmap_kp) { bpf_link__destroy(g_unmap_kp); g_unmap_kp = NULL; }
    destroy_uprobe_links();
    if (g_skel) {
        // Always report the final tally, so "no message" never means "didn't
        // check". Subsumes the old ares_drops_report: ring/queue drops are
        // coverage fields here. No worker queue in correlate (ring drained
        // inline) -> queue_drops = 0.
        struct ares_coverage cov = { .engine = "correlate" };
        int covfd = bpf_map__fd(g_skel->maps.coverage_stats);
        cov.depth_capped   = ares_coverage_read(covfd, COV_DEPTH_CAP);
        cov.ring_drops     = ares_drops_read(bpf_map__fd(g_skel->maps.dropped));
        cov.queue_drops    = 0;
        cov.decode_partial = 0;   // string/fd/sockaddr/flags decode wired (see corr_emit.c)
        if (g_returns) {
            cov.returns_mode      = 1;
            cov.spans_opened      = ares_coverage_read(covfd, COV_SPAN_OPEN);
            cov.returns_captured  = ares_coverage_read(covfd, COV_URET_FIRED);
        }
        ares_coverage_report(&g_sink, &cov);
        ares_correlate__destroy(g_skel);
        g_skel = NULL;
    }
    if (g_sink.f) { ares_sink_close(&g_sink); ares_sink_report(&g_sink); }
}

// ---- entry point (thin standalone wrapper) --------------------------------

int cmd_correlate(int argc, char **argv)
{
    if (correlate_setup(argc, argv, NULL) != 0)
        return 1;

    ares_install_stop_handler(&exiting);
    correlate_run(&exiting);
    correlate_teardown();
    return 0;
}
