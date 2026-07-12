// syscalls.c
//
// Userspace loader for syscalls.bpf.c. Traces the syscalls of a single Android
// app, emitting only those whose user backtrace passes through a chosen native
// library (e.g. a RASP .so).
//
//   usage: syscalls -P <package> -l <lib-selector> [options]
//   where <lib-selector> is a substring or glob (* ? []) of the library name.
//   e.g.   syscalls -P com.example.app -l librasp.so
//          syscalls -P com.example.app -l 'e_[0-9]*'
//          syscalls -P com.example.app -a -s openat,read -o out.jsonl
//
// What it does, in order:
//   1. Resolves the package's app-UID by stat'ing its data dir.
//   2. Loads + attaches the BPF programs and installs the UID *before* the app
//      is (re)launched, so tracing is armed from the app's first syscall.
//   3. force-stops then launches the package via the native am/cmd tools.
//   4. Arms the in-kernel library filter from uprobe_mmap events (event-driven):
//      as soon as the target library's mapping is delivered off the ring, its
//      range is pushed into the BPF filter, on the drain thread, ahead of the
//      queue. This is NOT race-free — the push happens after an asynchronous
//      kernel-to-userspace round trip, so syscalls the library issues in that
//      window are dropped in-kernel (CR2 pre-arm window; see COV_PREARM /
//      prearm_drops). Backtrace symbolization (every frame, all libs) is
//      handled separately in symbolize.c via /proc/<pid>/maps + each ELF .dynsym.
//   5. Prints each filtered syscall (name + raw args + symbolized backtrace).
//
// Intended to run as root from a plain `adb shell` on a rooted device.

#include "common/emit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <fnmatch.h>               // glob match for the target-library name
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>            // __NR_* for the generated table
#include <linux/types.h>
#include <stdint.h>
#include <pthread.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common/runtime.h"
#include "common/evqueue.h"

#include "syscalls.h"
#include "syscalls.skel.h"
#include "common/symbolize.h"
#include "common/stack_snapshot.h"
#include "common/art_nterp.h"
#include "syscalls/snapshot_gate.h"
#include "common/decode.h"
#include "common/lib_trace.h"
#include "common/launch.h"
#include "common/engine_args.h"
#include "common/managed_frame.h"
#include "common/syscall_index.h"
#include "common/syscall_table.h"
#include "common/coverage.h"
#include "common/art_buildid.h"
#include "common/maps.h"
#include "common/probe_resolve.h"
#include "common/probe_spec_loader.h"
#include "common/syscall_argtypes.h"
#include "common/human_out.h"      // SYM1 Phase 4a: shared stdout formatter
#include "syscalls/lib_seed.h"

// ---- syscall name table (numbers resolved by the cross compiler) ---------
// R9 residual: table data now lives once in common/syscall_table.c, shared
// with correlate.c (previously each compiled its own copy of syscalls_gen.h).

static struct ares_sysindex g_sysidx;

// compat: 1 = 32-bit/AArch32 syscall (do_el0_svc_compat) — a distinct EABI
// number namespace ares_sysindex_name doesn't cover, so these render
// numerically rather than risk naming them against the wrong (arm64) table.
// ponytail: numeric-only naming for compat syscalls; add an ARM-EABI
// {nr,name} table (mirrors common/syscall_table.c) if compat naming matters —
// vendoring ~400 rows was out of proportion for closing CR2's visibility gap.
static const char *sysname(unsigned long long nr, int compat)
{
	static char buf[32];
	if (compat) {
		snprintf(buf, sizeof(buf), "compat_syscall_%llu", nr);
		return buf;
	}
	const char *n = ares_sysindex_name(&g_sysidx, (long)nr);
	if (n)
		return n;
	snprintf(buf, sizeof(buf), "sys_%llu", nr);
	return buf;
}

// Per-syscall argument count (arm64 ABI), so we print only the real arguments
// instead of leftover register values. Unknown syscalls show all 6.
static const struct { long nr; int count; } g_argc[] = {
#include "syscall_argc.h"
};
static const int g_nargc = (int)(sizeof(g_argc) / sizeof(g_argc[0]));

// by_nr[512] dense indexes (AA7), mirroring ares_sysindex_build's scatter pattern
// for syscall_name() (R9). Each attribute table keeps its own array/sentinel since
// the payload types differ (count/mask/index); build_arg_tables() runs once at
// setup, before the worker thread starts.
#define ARG_TBL_CAP 512

static int           g_argc_by_nr[ARG_TBL_CAP];
static unsigned char g_fdmask_by_nr[ARG_TBL_CAP];
static signed char   g_sockidx_by_nr[ARG_TBL_CAP];

static int arg_count(unsigned long long nr)
{
	if (nr < ARG_TBL_CAP) return g_argc_by_nr[nr];
	for (int i = 0; i < g_nargc; i++)
		if ((unsigned long long)g_argc[i].nr == nr)
			return g_argc[i].count;
	return SYSC_SYSCALL_NARGS;
}

// Syscall name -> number (reverse of the generated table), or -1 if unknown.
static long sysnr(const char *name)
{
	for (size_t i = 0; i < ares_syscall_table_count; i++)
		if (!strcmp(ares_syscall_table[i].name, name))
			return ares_syscall_table[i].nr;
	return -1;
}

// Flag each comma-separated syscall name in `list` in the syscall_filter map.
// Returns the count flagged; warns on unknown names.
static int install_syscall_filter(int fd, const char *list)
{
	char buf[1024];
	snprintf(buf, sizeof(buf), "%s", list);
	int count = 0;
	char *save = NULL;
	for (char *tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		while (*tok == ' ')
			tok++;
		if (!*tok)
			continue;
		long nr = sysnr(tok);
		if (nr < 0 || nr >= 512) {
			fprintf(stderr, "warning: unknown syscall '%s' (ignored)\n", tok);
			continue;
		}
		__u32 k = (__u32)nr;
		__u8 v = 1;
		bpf_map_update_elem(fd, &k, &v, BPF_ANY);
		count++;
	}
	return count;
}

// ---- globals -------------------------------------------------------------

static const char *g_pkg;
static const char *g_lib;
static int g_lib_ranges_fd = -1;
static int g_verbose;
static int g_quiet;                             // suppress per-event console output
static volatile sig_atomic_t exiting;
// Stop flag the run loop is draining against. In standalone this is &exiting; under
// the `trace` coordinator it is the coordinator's flag. enqueue_event honors it so
// the ring drain bails promptly on stop even when `exiting` was never set.
static volatile sig_atomic_t *g_stopp;

static unsigned long long g_next_id = 1;       // monotonic per-syscall id
static int g_jsonl;                             // 1 = JSON Lines (one record/line); set during setup
static struct ares_sink g_sink;                 // output file sink (inactive when g_sink.f == NULL)
static FILE *g_stacks;                          // stack-snapshot sidecar, or NULL
static unsigned long long g_stack_count;        // snapshots written so far

// Coverage-health record (CR5). Mutated only from process_event() / the CFI
// walk it drives, which run exclusively on the worker thread (see the comment
// on process_event); read at teardown only after pthread_join(g_worker, ...)
// has returned, so the worker is no longer running - no lock needed.
static struct ares_coverage g_cov = { .engine = "syscalls" };

// ---- engine state shared across setup / run / teardown -------------------
// Promoted from cmd_syscalls locals so the engine can be driven in three phases
// (standalone via cmd_syscalls, or by the `trace` coordinator). See syscalls.h.
static struct syscalls *g_skel;
static struct ring_buffer *g_rb;
static struct bpf_link *g_ff;
static struct bpf_link *g_compat;    // do_el0_svc_compat, NULL if not attached (optional)
static pthread_t g_worker;
static int g_worker_started;
static int g_dropfd = -1;
static int g_uid;
static int g_capture_all;
static const char *g_activity;                  // optional launcher activity

// Device launch/UID helpers (sh_exec / resolve_uid / resolve_component) now live
// in src/common/launch.{c,h} as ares_*; shared with funcs/correlate/dump/lib.

// Symbolization (every frame: target lib + libc + others) is delegated to
// symbolize.c, which reads /proc/<pid>/maps for module ranges/paths and parses
// each ELF's .dynsym. We use sym_resolve() wherever we render a backtrace. The
// in-kernel filter below remains purely event-driven.

// ---- target library -> BPF filter ----------------------------------------

// Does a mapped library's basename match the target-library selector g_lib? A
// selector containing glob metacharacters (* ? [) is matched with fnmatch;
// otherwise it's a substring match (backward compatible). This mirrors dump.c's
// name_matches so the same pattern (e.g. 'e_*' / 'e_[0-9]*' for a protector
// payload loaded under a randomized per-run name) selects the library for both
// syscall tracing and dumping.
static int lib_name_matches(const char *name)
{
	return lib_selector_matches_name(name, g_lib);
}

// Push a newly seen executable range of the target library into lib_ranges[tgid]
// so the syscall hook starts matching it. Read-modify-write of the per-tgid set.
// `name` is the matched library's basename (which, under a glob selector, is the
// concrete per-run name — reported so the user sees what actually armed).
static void push_lib_range(__u32 tgid, __u64 start, __u64 end, const char *name)
{
	struct syscalls_lib_ranges lr;
	memset(&lr, 0, sizeof(lr));
	bpf_map_lookup_elem(g_lib_ranges_fd, &tgid, &lr);    // ENOENT leaves it zeroed

	for (__u32 i = 0; i < lr.count && i < SYSC_MAX_RANGES; i++)
		if (lr.r[i].start == start && lr.r[i].end == end)
			return;                                       // already known

	if (lr.count >= SYSC_MAX_RANGES)
		return;

	lr.r[lr.count].start = start;
	lr.r[lr.count].end = end;
	lr.count++;

	if (bpf_map_update_elem(g_lib_ranges_fd, &tgid, &lr, BPF_ANY) == 0)
		printf("[+] %s mapped in pid %u: [0x%llx, 0x%llx) — filter armed (%u range%s)\n",
		       name, tgid, (unsigned long long)start, (unsigned long long)end,
		       lr.count, lr.count == 1 ? "" : "s");
}

// Seed lib_ranges from a one-time /proc/<tgid>/maps scan (lib-filter attribution
// defect, BACKLOG.md): libc.so et al. are mapped once in the zygote and
// inherited by the forked app via COW, so no uprobe_mmap ever fires for them in
// the child and the event-driven arming above never catches them — every
// syscall they issue then fails the issuer check. Called once the target pid is
// known (attach or just-launched), before the event loop starts, so already-
// mapped matches are armed immediately; later live mmaps still arm anything
// mapped after this scan. Best-effort: silent if maps is unreadable.
static void seed_lib_ranges_from_maps(__u32 tgid)
{
	if (!g_lib[0] || g_lib_ranges_fd < 0)
		return;

	char path[64];
	snprintf(path, sizeof(path), "/proc/%u/maps", tgid);
	FILE *f = fopen(path, "r");
	if (!f)
		return;

	char line[512];
	while (fgets(line, sizeof(line), f)) {
		struct ares_map_line ml;
		if (!ares_parse_maps_line(line, &ml))
			continue;
		if (!lib_seed_line_arms(&ml, g_lib))
			continue;
		const char *base = strrchr(ml.path, '/');
		base = base ? base + 1 : ml.path;
		push_lib_range(tgid, ml.start, ml.end, base);
	}
	fclose(f);
}

// ---- string-argument types -----------------------------------------------
//
// g_str_args[]/install_arg_types() now live in common/syscall_argtypes.{h,c}
// (EPIC I2) - shared verbatim with correlate.c instead of duplicated here.

static const char *arg_string(const struct syscalls_syscall_event *e, int i)
{
	if (i < SYSC_STR_SLOTS && (e->str_present & (1u << i)))
		return e->str[i];
	return NULL;
}

// ---- file-descriptor arguments -------------------------------------------
//
// g_fd_args[] now lives in common/syscall_argtypes.{h,c} (EPIC I2) - shared
// verbatim with correlate.c. arg_fd_mask() below keeps its dense by-nr cache
// fast path (AA7), falling back past ARG_TBL_CAP to the shared table via
// g_fd_args_count (an extern array of unknown bound is an incomplete type,
// so sizeof(g_fd_args) no longer compiles in this TU).
static unsigned arg_fd_mask(unsigned long long nr)
{
	if (nr < ARG_TBL_CAP) return g_fdmask_by_nr[nr];
	for (size_t i = 0; i < g_fd_args_count; i++)
		if ((unsigned long long)g_fd_args[i].nr == nr)
			return g_fd_args[i].mask;
	return 0;
}

// ---- sockaddr arguments --------------------------------------------------
//
// g_sock_args[] now lives in common/syscall_argtypes.{h,c} (EPIC I2) - shared
// verbatim with correlate.c. Same dense-cache-then-shared-fallback shape as
// arg_fd_mask() above.
static int arg_sock_index(unsigned long long nr)
{
	if (nr < ARG_TBL_CAP) return g_sockidx_by_nr[nr];
	for (size_t i = 0; i < g_sock_args_count; i++)
		if ((unsigned long long)g_sock_args[i].nr == nr)
			return g_sock_args[i].arg;
	return -1;
}

// Scatter all three sparse tables into their dense by_nr[] arrays (AA7). Must
// run once at setup, before the worker thread starts reading arg_count/
// arg_fd_mask/arg_sock_index.
static void build_arg_tables(void)
{
	for (int i = 0; i < ARG_TBL_CAP; i++) {
		g_argc_by_nr[i]    = SYSC_SYSCALL_NARGS;   // default: unknown -> all 6
		g_fdmask_by_nr[i]  = 0;                    // default: unknown -> no fd args
		g_sockidx_by_nr[i] = -1;                   // default: unknown -> no sockaddr arg
	}
	for (int i = 0; i < g_nargc; i++)
		if (g_argc[i].nr >= 0 && g_argc[i].nr < ARG_TBL_CAP)
			g_argc_by_nr[g_argc[i].nr] = g_argc[i].count;
	for (size_t i = 0; i < g_fd_args_count; i++)
		if (g_fd_args[i].nr >= 0 && g_fd_args[i].nr < ARG_TBL_CAP)
			g_fdmask_by_nr[g_fd_args[i].nr] = g_fd_args[i].mask;
	for (size_t i = 0; i < g_sock_args_count; i++)
		if (g_sock_args[i].nr >= 0 && g_sock_args[i].nr < ARG_TBL_CAP)
			g_sockidx_by_nr[g_sock_args[i].nr] = (signed char)g_sock_args[i].arg;
}

// Render argument i of a syscall: string > fd > decoded flags/enum > raw hex.
// fdm/sockidx are precomputed once per event by the caller (AA7) — arg_fd_mask/
// arg_sock_index are invariant across a syscall's arguments, so a per-argument
// loop shouldn't re-call them (even O(1) lookups are pure waste repeated N times).
static void render_arg(const struct syscalls_syscall_event *e, int i, unsigned fdm,
			int sockidx, char *out, size_t outsz)
{
	const char *s = arg_string(e, i);
	if (s) {
		// Bound the string to what fits between the quotes (outsz - 2 quotes -
		// NUL) so the format provably can't overflow; long traced strings are
		// truncated for display, same as before but without the truncation warning.
		snprintf(out, outsz, "\"%.*s\"", (int)(outsz - 3), s);
		return;
	}
	if (fdm & (1u << i)) {
		render_fd((int)e->h.pid, e->args[i], out, outsz);
		return;
	}
	if (i == sockidx && e->sock_len > 0 &&
	    decode_sockaddr((const unsigned char *)e->sock, (unsigned)e->sock_len, out, outsz))
		return;
	// compat: e->nr is an EABI number, not an arm64 one — arm64's flags/enum
	// table would be a namespace mismatch (CR2), so skip straight to raw hex.
	if (!e->compat && flags_decode_arg((long)e->nr, i, e->args[i], out, outsz))
		return;
	snprintf(out, outsz, "0x%llx", (unsigned long long)e->args[i]);
}

// Render a syscall return value: decimal, with errno name for small negatives.
static void render_ret(long long ret, char *out, size_t outsz)
{
	if (ret < 0 && ret >= -4095)
		snprintf(out, outsz, "%lld (%s)", ret, strerror((int)-ret));
	else
		snprintf(out, outsz, "%lld", ret);
}

// ---- JSON export ---------------------------------------------------------
//
// Records are built into a growable in-memory buffer with hand-rolled formatting
// (no per-field fprintf, which locks the FILE and re-parses a format string on
// every call), then written with a single fwrite. This is the dominant per-event
// cost on the drain path once symbolization is cached.

// Write one stack snapshot to the sidecar stream. Delegates serialisation to
// the shared ares_stack_snapshot_emit_json; owns only the file write.
// After writing the raw snapshot, emit a companion cfi_stack record.
static void emit_cfi_backtrace(const struct ares_stack_snapshot *s);

static void json_emit_stack(const struct ares_stack_snapshot *s)
{
	if (!g_stacks)
		return;
	struct jbuf *j = &g_sink.jb;
	j->len = 0;
	ares_stack_snapshot_emit_json(j, s);
	if (j->b && j->len)
		fwrite(j->b, 1, j->len, g_stacks);
	g_stack_count++;
	emit_cfi_backtrace(s);
}


static void emit_cfi_backtrace(const struct ares_stack_snapshot *s)
{
	if (!g_stacks) return;
	uint64_t pcs[64];
	uint64_t sps[64];
	static int dbg = -1;
	if (dbg < 0) dbg = getenv("ARES_CFI_DEBUG") ? 1 : 0;
	struct cfi_step_diag diags[64];
	memset(diags, 0, sizeof(diags));
	// diags is always passed now (not just under ARES_CFI_DEBUG): the
	// coverage-health record (CR5) needs the terminal stop_reason of every
	// walk, regardless of debug mode. The memset must run unconditionally:
	// cfi_unwind_snapshot's own early-exit break paths (frame cap, maps
	// miss) do not always write out_diags[n-1].stop_reason, so a gated
	// memset left the terminal slot as uninitialized stack garbage that
	// could alias a valid enum value and silently corrupt g_cov.cfi_stop[].
	// Zero-init means an unwritten terminal reads as CFI_OK (0).
	int n = cfi_unwind_snapshot((int)s->h.pid, s, pcs, 64, sps, diags);
	if (n <= 0) return;

	g_cov.snaps_total++;
	g_cov.cfi_walks++;
	int stop_reason = diags[n - 1].stop_reason;
	if (stop_reason >= 0 && stop_reason < ARES_CFI_STOP_N)
		g_cov.cfi_stop[stop_reason]++;

	// AA9: resolve each frame once and share it with both emitters below
	// (they previously each re-resolved the same n symbols).
	char sym_store[64][320];
	const char *syms[64];
	int nsym = n < 64 ? n : 64;
	for (int i = 0; i < nsym; i++) {
		sym_resolve((int)s->h.pid, pcs[i], sym_store[i], sizeof(sym_store[i]));
		syms[i] = sym_store[i];
	}

	struct jbuf *j = &g_sink.jb; j->len = 0;
	ares_emit_cfi_stack_json(j, (int)s->h.pid, s, pcs, sps, n, syms, dbg ? diags : NULL);
	if (j->b && j->len) fwrite(j->b, 1, j->len, g_stacks);

	char frag[208];
	if (ares_managed_chain((int)s->h.pid, s, pcs, sps, n, syms, frag, sizeof(frag)) > 0)
		ares_jcache_put(s->stack_id, frag);
}

static void json_emit(const struct syscalls_syscall_event *e, unsigned long long id,
		      int has_ret, long long ret)
{
	struct jbuf *j = &g_sink.jb;
	j->len = 0;
	jb_c(j, '{');

	// Discriminator for the unified ares trace schema: every record carries a
	// "type". Syscall events are "syscall"; stack snapshots are "stack" (see
	// json_emit_stack). Future ares-funcs structured events use "call"/"return"/
	// "map"/"prop"/etc. — see DOCUMENTATION.md "Unified trace schema".
	jb_s(j, "\"type\":\"syscall\",");
	jb_s(j, "\"id\":");        jb_u64(j, id);
	jb_s(j, ",\"pid\":");      jb_u64(j, e->h.pid);
	jb_s(j, ",\"tid\":");      jb_u64(j, e->h.tid);
	jb_s(j, ",\"syscall_nr\":"); jb_u64(j, e->nr);
	jb_s(j, ",\"syscall\":\""); jb_s(j, sysname(e->nr, e->compat)); jb_c(j, '"');
	jb_s(j, ",\"ktime\":");     jb_u64(j, e->ktime); // EPIC C3: boot-monotonic entry time

	// compat: e->nr is an EABI number, so arg_count/arg_fd_mask/flags_decode_arg
	// (all arm64-nr-keyed) would be a namespace mismatch (CR2) — show every raw
	// argument slot instead and skip the decode sections below.
	int nargs = e->compat ? SYSC_SYSCALL_NARGS : arg_count(e->nr);
	jb_s(j, ",\"args\":[");
	for (int i = 0; i < nargs; i++) {
		if (i) jb_c(j, ',');
		jb_c(j, '"'); jb_hex(j, e->args[i]); jb_c(j, '"');
	}
	jb_s(j, "],\"retval\":");
	if (has_ret) jb_i64(j, ret); else jb_s(j, "null");

	jb_s(j, ",\"string_args\":{");
	for (int i = 0, first = 1; i < SYSC_STR_SLOTS; i++) {
		const char *s = arg_string(e, i);
		if (!s) continue;
		if (!first)
			jb_c(j, ',');
		first = 0;
		jb_c(j, '"'); jb_u64(j, i); jb_s(j, "\":\""); jb_esc(j, s); jb_c(j, '"');
	}
	jb_s(j, "},\"fd_args\":{");
	unsigned fdm = e->compat ? 0u : arg_fd_mask(e->nr);
	for (int i = 0, first = 1; i < SYSC_SYSCALL_NARGS; i++) {
		if (!(fdm & (1u << i))) continue;
		char fdbuf[320];
		render_fd((int)e->h.pid, e->args[i], fdbuf, sizeof(fdbuf));
		if (!first)
			jb_c(j, ',');
		first = 0;
		jb_c(j, '"'); jb_u64(j, i); jb_s(j, "\":\""); jb_esc(j, fdbuf); jb_c(j, '"');
	}
	jb_s(j, "},\"decoded_args\":{");
	for (int i = 0, first = 1; !e->compat && i < nargs; i++) {
		char dec[256];
		if (arg_string(e, i) || (fdm & (1u << i)))
			continue;
		if (!flags_decode_arg((long)e->nr, i, e->args[i], dec, sizeof(dec)))
			continue;
		if (!first)
			jb_c(j, ',');
		first = 0;
		jb_c(j, '"'); jb_u64(j, i); jb_s(j, "\":\""); jb_esc(j, dec); jb_c(j, '"');
	}
	jb_c(j, '}');

	if (e->sock_len > 0) {
		char sockbuf[128];
		if (decode_sockaddr((const unsigned char *)e->sock, (unsigned)e->sock_len, sockbuf, sizeof(sockbuf))) {
			jb_s(j, ",\"sock_addr\":\""); jb_esc(j, sockbuf); jb_c(j, '"');
		}
	}

	if (e->stack_id) {
		jb_s(j, ",\"stack_id\":"); jb_u64(j, e->stack_id);
		char js[208];
		if (ares_jcache_get(e->stack_id, js, sizeof(js))) { jb_s(j, ",\"java_stack\":"); jb_s(j, js); }
	}

	jb_s(j, ",\"backtrace\":[");
	int n = e->stack_sz / (int)sizeof(__u64);
	char sym[320];
	for (int i = 0, first = 1; i < n && i < SYSC_MAX_STACK_DEPTH; i++) {
		if (e->stack[i] == 0) break;
		sym_resolve(e->h.pid, e->stack[i], sym, sizeof(sym));
		if (!first)
			jb_c(j, ',');
		first = 0;
		jb_s(j, "{\"frame\":"); jb_u64(j, i);
		jb_s(j, ",\"addr\":\""); jb_hex(j, e->stack[i]);
		jb_s(j, "\",\"symbol\":\""); jb_esc(j, sym); jb_c(j, '"');
		if (ares_is_interp_frame(sym))
			jb_s(j, ",\"java\":\"interpreted (managed frame elided)\"");
		// The frame-pointer chain cannot cross the JNI trampoline: the managed
		// caller above it does not keep an AAPCS [fp,lr] frame, so the next
		// bpf_get_stack frame is ART quick-frame data misread as fp/lr (a garbage
		// [unmapped]/non-canonical address). Mark this frame as the FP-unwind
		// boundary and stop — the crossed managed caller, when recoverable, is in
		// the companion cfi_stack record (correlated by stack_id).
		int fp_boundary = strstr(sym, "jni_trampoline") != NULL;
		if (fp_boundary)
			jb_s(j, ",\"fp_unwind_end\":\"jni-trampoline (managed caller in cfi_stack)\"");
		jb_c(j, '}');
		if (fp_boundary)
			break;
	}
	jb_s(j, "]}");
	ares_sink_emit(&g_sink);
}

// ---- entry/return pairing ------------------------------------------------
//
// The entry line is printed immediately (live), but the JSON record is held
// until its return arrives so it can carry the retval. Entries are paired with
// returns by tid (syscalls are serialized per thread). An entry whose return is
// never seen (interrupted, or stopped while blocked) is flushed without a retval.

struct pend_entry {
	int used;
	__u32 tid;
	unsigned long long id;
	struct syscalls_syscall_event ev;
};

static struct pend_entry *g_pend;
static size_t g_pend_n, g_pend_cap;

static struct pend_entry *pend_find(__u32 tid)
{
	for (size_t i = 0; i < g_pend_n; i++)
		if (g_pend[i].used && g_pend[i].tid == tid)
			return &g_pend[i];
	return NULL;
}

static void pend_store(const struct syscalls_syscall_event *e, unsigned long long id)
{
	struct pend_entry *p = pend_find(e->h.tid);
	if (p) {
		if (g_sink.f)                   // previous syscall on this tid never returned
			json_emit(&p->ev, p->id, 0, 0);
	} else {
		for (size_t i = 0; i < g_pend_n; i++)
			if (!g_pend[i].used) { p = &g_pend[i]; break; }
		if (!p) {
			if (g_pend_n == g_pend_cap) {
				size_t nc = g_pend_cap ? g_pend_cap * 2 : 64;
				struct pend_entry *np = realloc(g_pend, nc * sizeof(*np));
				if (!np)
					return;
				g_pend = np;
				g_pend_cap = nc;
			}
			p = &g_pend[g_pend_n++];
		}
	}
	p->used = 1;
	p->tid = e->h.tid;
	p->id = id;
	p->ev = *e;
}

static void pend_flush_all(void)
{
	for (size_t i = 0; i < g_pend_n; i++)
		if (g_pend[i].used) {
			if (g_sink.f)
				json_emit(&g_pend[i].ev, g_pend[i].id, 0, 0);
			g_pend[i].used = 0;
		}
}

// ---- ring buffer handling ------------------------------------------------

static void handle_syscall(const struct syscalls_syscall_event *e)
{
	unsigned long long id = g_next_id++;

	// In quiet mode skip all console rendering (printing + symbolization + fd
	// readlinks): the heavy work that limits drain throughput. The JSON record
	// is still produced (and symbolized) once the return arrives.
	if (!g_quiet) {
		char arg[320];
		// compat: arg_count/arg_fd_mask/arg_sock_index are arm64-nr-keyed
		// tables, a namespace mismatch for EABI numbers (CR2) — show all raw
		// argument slots instead of guessing counts/fds/sockaddr from them.
		int nargs = e->compat ? SYSC_SYSCALL_NARGS : arg_count(e->nr);
		unsigned fdm = e->compat ? 0u : arg_fd_mask(e->nr);
		int sockidx = e->compat ? 0 : arg_sock_index(e->nr);
		// SYM1 Phase 4a: shared human_out skeleton (timestamp + own "syscall"
		// tag), args/stack as human_detail continuation lines -- was inline
		// "==> #id [pid/tid] name(args)" + bare "      #n sym" prints.
		ts_print("[syscall] > [CALL] #%llu PID:%u TID:%u %s\n",
		         id, e->h.pid, e->h.tid, sysname(e->nr, e->compat));
		for (int i = 0; i < nargs; i++) {
			render_arg(e, i, fdm, sockidx, arg, sizeof(arg));
			human_detail("syscall", "args[%d] %s\n", i, arg);
		}

		int n = e->stack_sz / (int)sizeof(__u64);
		char sym[320];
		for (int i = 0; i < n && i < SYSC_MAX_STACK_DEPTH; i++) {
			if (e->stack[i] == 0)
				break;
			sym_resolve(e->h.pid, e->stack[i], sym, sizeof(sym));
			human_detail("syscall", "#%d %s\n", i, sym);
		}
		fflush(stdout);
	}

	pend_store(e, id);          // JSON emitted once the return value arrives
}

static void handle_return(const struct syscalls_return_event *r)
{
	struct pend_entry *p = pend_find(r->h.tid);
	if (!p)
		return;
	if (!g_quiet) {
		char rb[160];
		render_ret(r->retval, rb, sizeof(rb));
		// SYM1 Phase 4a: was "<== #id name = ret".
		ts_print("[syscall] > [RET]  #%llu PID:%u %s -> %s\n",
		         p->id, r->h.pid, sysname(p->ev.nr, p->ev.compat), rb);
		fflush(stdout);
	}
	if (g_sink.f)
		json_emit(&p->ev, p->id, 1, r->retval);
#ifdef __NR_close
	if (p->ev.nr == __NR_close && r->retval == 0)
		fdc_drop((int)p->ev.h.pid, (int)p->ev.args[0]);   // fd may be reused
#endif
	p->used = 0;
}

// Process one event — the heavy path (symbolization + JSON). Runs ONLY on the
// worker thread, so all the caches/pending state it touches stay single-threaded.
static void process_event(const void *data, size_t sz)
{
	if (sz < sizeof(struct trace_event_header))
		return;
	const struct trace_event_header *h = data;

	switch (h->type) {
	case SYSC_EV_MAP: {
		if (sz < sizeof(struct lib_map_event))
			return;
		const struct lib_map_event *m = data;
		if (g_verbose)
			// SYM1 Phase 4a: was bare "    map  pid ...".
			ts_print("[syscall] > [MAP] pid %u %s [0x%llx,0x%llx) off=0x%llx\n",
			       m->h.pid, m->name, (unsigned long long)m->start,
			       (unsigned long long)m->end, (unsigned long long)m->pgoff);
		// Range is armed on the drain thread (enqueue_event, below) the moment
		// the event arrives — this worker-side case only handles the verbose
		// print, to close as much of the pre-arm window (CR2) as possible.
		break;
	}
	case SYSC_EV_UNMAP: {
		if (sz < sizeof(struct lib_unmap_event))
			return;
		const struct lib_unmap_event *u = data;
		sym_flush_pid(u->h.pid);          // force a /proc maps reread on next resolve
		break;
	}
	case SYSC_EV_SYSCALL:
		if (sz < sizeof(struct syscalls_syscall_event))
			return;
		handle_syscall(data);
		break;
	case SYSC_EV_RETURN:
		if (sz < sizeof(struct syscalls_return_event))
			return;
		handle_return(data);
		break;
	case SYSC_EV_STACK:
		if (sz < sizeof(struct ares_stack_snapshot))
			return;
		json_emit_stack(data);
		break;
	}
}

// ---- decoupled drain: fast drain thread -> queue -> worker thread ---------
//
// The ring_buffer callback (drain thread) does only a memcpy into a large
// userspace byte-queue, so the kernel ring stays empty regardless of how slow
// symbolization/JSON is. The worker thread drains the queue and does the heavy
// per-event work. This absorbs bursts in ordinary RAM (the queue can be far
// bigger than a kernel ring) and parallelizes copy vs processing.

static struct ares_evq g_q;

// ring_buffer callback (drain thread): copy the raw event into the queue. Also
// arms the target-library range here, synchronously, for SYSC_EV_MAP events —
// rather than waiting for the worker thread to reach it off the queue — to
// shrink the pre-arm window (CR2): any syscall the library issues before its
// range is armed is dropped in-kernel (see COV_PREARM), and the queue hop was
// pure added latency on top of the unavoidable kernel-to-userspace delivery
// delay. push_lib_range/lib_name_matches are only ever called from this drain
// thread, so this stays single-writer with no new locking.
static int enqueue_event(void *ctx, void *data, size_t sz)
{
	(void)ctx;
	if (exiting || (g_stopp && *g_stopp))
		return -1;                          // bail the drain promptly on Ctrl+C / stop
	if (sz >= sizeof(struct trace_event_header)) {
		const struct trace_event_header *h = data;
		if (h->type == SYSC_EV_MAP && sz >= sizeof(struct lib_map_event)) {
			const struct lib_map_event *m = data;
			if (lib_name_matches(m->name))
				push_lib_range(m->h.pid, m->start, m->end, m->name);
		}
	}
	ares_evq_push(&g_q, data, sz);
	return 0;
}

static void *worker_main(void *arg)
{
	(void)arg;
	// Sized to the largest record (the stack snapshot), so nothing is truncated.
	static char rec[sizeof(struct ares_stack_snapshot) + 64];
	unsigned long flushed = 0;
	size_t sz;
	while (ares_evq_pop(&g_q, rec, sizeof(rec), &sz)) {
		process_event(rec, sz);
		// Periodic flush so a hard-kill loses little (JSONL stays valid).
		if (g_sink.f && (++flushed & ARES_FLUSH_MASK) == 0)
			ares_sink_flush(&g_sink);
	}
	return NULL;
}

// ---- main ----------------------------------------------------------------

// Syscalls we attach classic kretprobes to for return values. Focused on the
// file / proc / memory / process calls relevant to RASP analysis. Most are
// non-blocking, so the default per-function kretprobe maxactive suffices;
// heavily-blocking calls (futex/poll/epoll/nanosleep) are deliberately omitted
// to avoid silently dropping returns. Entry events are captured regardless.
static const char *g_ret_syscalls[] = {
	"openat", "openat2", "close", "read", "write", "pread64", "pwrite64",
	"readv", "writev", "lseek", "fstat", "newfstatat", "statx", "statfs", "fstatfs",
	"faccessat", "faccessat2", "readlinkat", "unlinkat", "mkdirat",
	"renameat2", "mknodat", "fchmodat", "fchownat", "symlinkat", "linkat",
	"getdents64", "fchdir", "getcwd", "name_to_handle_at",
	"fcntl", "ioctl", "dup", "dup3", "pipe2", "eventfd2", "memfd_create",
	"mmap", "munmap", "mprotect", "madvise", "mremap", "mlock", "msync",
	"prctl", "ptrace", "process_vm_readv", "process_vm_writev",
	"socket", "connect", "bind", "sendto", "recvfrom", "getsockopt", "setsockopt",
	"getsockname", "execve", "execveat", "clone", "clone3", "kill", "tgkill",
	"getrandom",
};

// Attach the return-value program as a classic kretprobe to each syscall above.
// Returns the count that attached. Links are intentionally left to the process
// lifetime (detached on exit). Missing functions on this ABI are skipped quietly.
static int attach_return_probes(struct syscalls *skel)
{
	libbpf_print_fn_t prev = libbpf_set_print(NULL);    // hush per-function misses
	int n = 0;
	for (size_t i = 0; i < sizeof(g_ret_syscalls) / sizeof(g_ret_syscalls[0]); i++) {
		char fn[64];
		snprintf(fn, sizeof(fn), "__arm64_sys_%s", g_ret_syscalls[i]);
		struct bpf_link *l =
			bpf_program__attach_kprobe(skel->progs.on_sys_exit, true /* retprobe */, fn);
		if (!l || libbpf_get_error(l))
			continue;
		n++;
	}
	libbpf_set_print(prev);
	return n;
}

static void copy_str(char *dst, const char *src, size_t n)
{
	size_t len = strnlen(src, n - 1);
	memcpy(dst, src, len);
	dst[len] = '\0';
}

// ---- argp-based argument parser ------------------------------------------

struct sysc_args {
	struct common_args c;        // -o -v -q -J -b -Q (shared with funcs)
	char package_name[256];      // -P
	char lib_sel[256];           // -l: library selector (substring or glob)
	char activity[256];          // -A: optional launch activity override
	int  capture_all;            // -a
	int  want_snap;              // --snapshot
	const char *syscall_list;    // value of -s or -x
	int  syscall_mode;           // 0=off 1=allowlist 2=denylist
	struct target_args tgt;      // -p / --siblings / --no-follow-fork
	custom_probe_spec_t specs[64]; // -e / -F: syscall:/lib: kind lines (funcs:/mod: ignored)
	int  nspec;
};

const char *argp_program_bug_address = "<michael.windarta@binus.ac.id>";

static const struct argp_option sysc_options[] = {
	{ "package",     'P', "PACKAGE",  0, "App package to trace (required in standalone mode)", 0 },
	{ "lib",         'l', "SELECTOR", 0, "Library selector: substring or glob (e.g. 'e_*')",  0 },
	{ "activity",    'A', "ACTIVITY", 0, "Override launch activity component",                 0 },
	COMMON_ARGP_OPTIONS,
	{ "all",         'a', NULL,       0, "Capture all syscalls (no library filter)",           0 },
	{ "snapshot",     1,  NULL,       0, "Capture stack snapshots for off-device unwinding",   0 },
	{ "no-snapshot",  2,  NULL,       0, "Disable snapshots (default)",                        0 },
	{ "syscall",     's', "LIST",     0, "Allowlist: comma-separated syscall names",           0 },
	{ "exclude",     'x', "LIST",     0, "Denylist: comma-separated syscall names",            0 },
	{ "spec",        'e', "SPEC",     0, "Probe spec: syscall:[!]NAME or lib:[!]PATTERN (repeatable)", 0 },
	{ "specs",       'F', "FILE",     0, "Load probe specs from a file (one per line, # = comment)", 0 },
	TARGET_ARGP_OPTIONS,
	{ 0 }
};

static error_t parse_sysc_opts(int key, char *arg, struct argp_state *state)
{
	struct sysc_args *a = state->input;
	switch (key) {
	case 'P': copy_str(a->package_name, arg, sizeof(a->package_name)); break;
	case 'l': copy_str(a->lib_sel,      arg, sizeof(a->lib_sel));      break;
	case 'A': copy_str(a->activity,     arg, sizeof(a->activity));     break;
	case 'a': a->capture_all = 1; break;
	case  1 : a->want_snap = 1;   break;
	case  2 : a->want_snap = 0;   break;
	case 's':
		if (a->syscall_mode == 2) argp_error(state, "use either -s or -x, not both");
		a->syscall_list = arg; a->syscall_mode = 1;
		break;
	case 'x':
		if (a->syscall_mode == 1) argp_error(state, "use either -s or -x, not both");
		a->syscall_list = arg; a->syscall_mode = 2;
		break;
	case 'e':
		if (a->nspec >= 64)
			fprintf(stderr, "syscalls: warning — spec cap (64) reached; '%s' ignored\n", arg);
		else if (parse_custom_probe_spec(arg, &a->specs[a->nspec], NULL) == 0)
			a->nspec++;
		break;
	case 'F':
		if (load_probe_spec_file(arg, a->specs, 64, &a->nspec, NULL) != 0)
			argp_error(state, "cannot open spec file '%s'", arg);
		break;
	case 'p': case ARES_KEY_SIBLINGS: case ARES_KEY_NO_FOLLOW:
		return parse_target_arg(key, arg, state, &a->tgt);
	case ARGP_KEY_END:
		if (a->tgt.n > 0 && a->package_name[0])
			argp_error(state, "specify exactly one of -p or -P");
		if (!a->tgt.n && !a->package_name[0])
			argp_error(state, "specify -P PACKAGE or -p PID[,PID...]");
		{
			int spec_deny = 0, spec_allow = 0;
			for (int i = 0; i < a->nspec; i++)
				if (a->specs[i].kind == SPEC_KIND_SYSCALL) {
					if (a->specs[i].deny) spec_deny = 1; else spec_allow = 1;
				}
			if (spec_deny && spec_allow)
				argp_error(state, "spec file mixes syscall: allow and syscall:! deny lines; use one or the other");
			if (a->syscall_mode == 1 && spec_deny)
				argp_error(state, "-s (allowlist) conflicts with syscall:! deny lines in spec");
			if (a->syscall_mode == 2 && spec_allow)
				argp_error(state, "-x (denylist) conflicts with syscall: allow lines in spec");
			if (a->syscall_mode == 0) {
				if (spec_deny) a->syscall_mode = 2;
				else if (spec_allow) a->syscall_mode = 1;
			}
			if (!a->lib_sel[0])
				for (int i = 0; i < a->nspec; i++)
					if (a->specs[i].kind == SPEC_KIND_LIB) {
						copy_str(a->lib_sel, a->specs[i].mod, sizeof(a->lib_sel));
						break;
					}
		}
		if (!a->capture_all && a->lib_sel[0] == '\0')
			argp_error(state, "-l <lib-selector> is required (or use -a to capture all)");
		break;
	default:
		return parse_common_arg(key, arg, state, &a->c);
	}
	return 0;
}

static const struct argp sysc_argp = {
	.options = sysc_options,
	.parser  = parse_sysc_opts,
	.doc     = "Syscall tracer for a single Android app.\v"
	           "  e.g. ares syscalls -P com.example.app -l librasp.so\n"
	           "       ares syscalls -P com.example.app -l 'e_[0-9]*' -o out.jsonl\n"
	           "       ares syscalls -P com.example.app -a -s openat,read\n",
};

// ---- engine driver, split into setup / run / teardown --------------------
// cmd_syscalls below is a thin standalone wrapper; the `trace` coordinator drives
// the same three phases so the kprobe engine runs alongside the uprobe engine
// from a single app launch. Cross-phase state lives in the file-static g_* above.
int syscalls_setup(int argc, char **argv, const struct ares_run_ctx *rc)
{
	ares_sysindex_build(&g_sysidx, ares_syscall_table, ares_syscall_table_count);
	build_arg_tables();
	// ponytail: g_pkg/g_lib/g_activity alias into sa; static so they stay valid
	// through the run/launch phases after setup returns. setup runs once per process.
	static struct sysc_args sa = { .c = COMMON_ARGS_INIT };
	// Pre-fill package from coordinator so ARGP_KEY_END validation passes
	// without needing -P in the syscalls argv section.
	if (rc && rc->pkg)
		copy_str(sa.package_name, rc->pkg, sizeof(sa.package_name));
	if (argp_parse(&sysc_argp, argc, argv, ARGP_NO_EXIT, NULL, &sa) != 0)
		return 1;

	g_pkg      = sa.package_name;
	g_lib      = sa.capture_all ? "" : sa.lib_sel;
	g_activity = sa.activity[0] ? sa.activity : NULL;
	g_verbose  = sa.c.verbose;
	g_quiet    = sa.c.quiet; // SYM1 Phase 1: -o no longer forces quiet; file and stdout are independent channels
	g_jsonl    = 1; // SYM1 Phase 5a: JSONL always, matches lib/mod/correlate
	int capture_all      = sa.capture_all;
	int want_snap        = sa.want_snap;
	int bufmb            = sa.c.bufmb;
	int queue_mb         = sa.c.queue_mb;
	const char *json_path    = sa.c.output_file;
	const char *syscall_list = sa.syscall_list;
	int syscall_mode         = sa.syscall_mode;

	int uid;
	if (sa.tgt.n > 0) {
		uid = 0;  // ponytail: uid is display-only; BPF gate uses TGID in PID mode
	} else {
		uid = (rc && rc->uid > 0) ? rc->uid : ares_resolve_uid(g_pkg);
		if (uid < 0) {
			fprintf(stderr, "could not resolve UID for '%s' (installed? run as root?)\n", g_pkg);
			return 1;
		}
	}
	g_uid = uid;
	g_capture_all = capture_all;
	if (sa.tgt.n > 0)
		printf("pid mode: %d pid(s), capturing %s\n", sa.tgt.n, capture_all ? "ALL syscalls" : g_lib);
	else if (capture_all)
		printf("package %s -> uid %d, capturing ALL syscalls\n", g_pkg, uid);
	else
		printf("package %s -> uid %d, target lib '%s'\n", g_pkg, uid, g_lib);

	// Round the requested ring buffer size up to a power of two (a ringbuf
	// requirement). Uses the same helper as funcs.
	size_t bufbytes = ares_round_pow2((unsigned long)bufmb << 20);

	libbpf_set_print(ares_libbpf_quiet);

	struct syscalls *skel = syscalls__open();
	if (!skel) {
		fprintf(stderr, "open failed (run as root? SELinux permissive?)\n");
		return 1;
	}
	// Stack snapshots: opt-in (--snapshot), only when writing JSON (the snapshots
	// go to a <out>.stacks sidecar for off-device CFI unwinding of obfuscated
	// native frames — Java frames are resolved on-device by the symbolizer).
	// W6-A: decoupled from library-filter mode so JNI-originated (capture-all)
	// stacks get snapshotted and can cross art_jni_trampoline. Capture-all with no
	// syscall filter is a firehose (a 32 KB snapshot per distinct stack across all
	// syscalls) — warn and proceed so the user can bound it with -s/-x.
	int want_snapshots = sysc_want_snapshots(want_snap, json_path != NULL);
	if (want_snapshots &&
	    sysc_snapshot_firehose_warn(want_snap, capture_all, syscall_mode))
		fprintf(stderr,
			"syscalls: warning — --snapshot with -a and no syscall filter ships a "
			"32 KB snapshot per distinct stack across ALL syscalls; expect heavy "
			"ring traffic. Add -s/-x to bound it.\n");
	skel->rodata->capture_all = capture_all;
	skel->rodata->syscall_filter_mode = syscall_mode;
	skel->rodata->snapshot_enabled = want_snapshots;
	bpf_map__set_max_entries(skel->maps.events, bufbytes);
	if (syscalls__load(skel)) {
		fprintf(stderr, "load failed (run as root? SELinux permissive?)\n");
		syscalls__destroy(skel);
		return 1;
	}
	printf("ring buffer: %zu MB%s\n", bufbytes >> 20, g_quiet ? ", console output suppressed" : "");

	if (syscall_mode) {
		int nf = 0;
		if (syscall_list)
			nf += install_syscall_filter(bpf_map__fd(skel->maps.syscall_filter), syscall_list);
		for (int i = 0; i < sa.nspec; i++)
			if (sa.specs[i].kind == SPEC_KIND_SYSCALL)
				nf += install_syscall_filter(bpf_map__fd(skel->maps.syscall_filter), sa.specs[i].mod);
		printf("syscall filter: %s %d syscall(s)\n",
		       syscall_mode == 1 ? "only" : "excluding", nf);
	}

	g_lib_ranges_fd = bpf_map__fd(skel->maps.lib_ranges);

	if (json_path) {
		if (ares_sink_open(&g_sink, json_path, "syscall", g_jsonl) != 0) {
			fprintf(stderr, "cannot open '%s': %s\n", json_path, strerror(errno));
			goto out;
		}
	}

	// Stack-snapshot sidecar (JSON Lines) next to the trace, for the off-device
	// unwinder. Failing to open it is non-fatal — we just lose the snapshots.
	if (want_snapshots && json_path) {
		char sp[1024];
		snprintf(sp, sizeof(sp), "%s.stacks", json_path);
		g_stacks = fopen(sp, "w");
		if (!g_stacks)
			fprintf(stderr, "warning: cannot open snapshot sidecar '%s': %s\n",
				sp, strerror(errno));
		else {
			setvbuf(g_stacks, malloc(8u << 20), _IOFBF, 8u << 20);
			printf("stack snapshots: %s\n", sp);
		}
	}

	// Tell the hook which syscall args are strings, and arm the UID filter —
	// both BEFORE the app is launched so the very first syscalls are decoded.
	install_arg_types(bpf_map__fd(skel->maps.arg_types));
	install_sock_args(bpf_map__fd(skel->maps.sock_args));

	__u8 one = 1;
	if (sa.tgt.n > 0) {
		// -p mode: arm target_pids; target_uids only if --siblings. Also seed
		// the lib-filter from the attach-time maps snapshot (lib-filter
		// attribution defect) — attaching to an already-running process means
		// its libraries mapped long ago and will never fire a live mmap event.
		for (int i = 0; i < sa.tgt.n; i++) {
			__u32 tgid = (__u32)sa.tgt.pids[i];
			bpf_map_update_elem(bpf_map__fd(skel->maps.target_pids), &tgid, &one, BPF_ANY);
			seed_lib_ranges_from_maps(tgid);
			if (sa.tgt.siblings) {
				int puid = ares_get_pid_uid(sa.tgt.pids[i]);
				if (puid > 0) {
					__u32 vuid = (__u32)puid;
					bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY);
				}
			}
		}
	} else {
		__u32 vuid = (__u32)uid;
		if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY) != 0) {
			fprintf(stderr, "failed to set target uid: %s\n", strerror(errno));
			goto out;
		}
	}

	// We attach the return probe ourselves (classic kretprobes, per function),
	// so disable its autoattach. Also disable follow-fork autoattach; it is
	// attached manually below only in PID mode. Same for the 32-bit compat
	// hook (CR2): kernels without CONFIG_COMPAT have no do_el0_svc_compat
	// symbol, and syscalls__attach() below fails as a whole if any autoattach
	// program can't attach — so it's attached manually, non-fatally, after.
	bpf_program__set_autoattach(skel->progs.on_sys_exit, false);
	bpf_program__set_autoattach(skel->progs.ares_follow_fork, 0);
	bpf_program__set_autoattach(skel->progs.on_svc_enter_compat, false);

	if (syscalls__attach(skel)) {
		fprintf(stderr, "attach failed (do_el0_svc / uprobe_mmap present in kallsyms?)\n");
		goto out;
	}

	g_compat = bpf_program__attach(skel->progs.on_svc_enter_compat);
	if (!g_compat)
		fprintf(stderr, "syscalls: do_el0_svc_compat attach failed (non-fatal; "
				"no CONFIG_COMPAT? continuing without 32-bit coverage)\n");

	if (sa.tgt.n > 0 && !sa.tgt.no_follow) {
		g_ff = bpf_program__attach(skel->progs.ares_follow_fork);
		if (!g_ff) fprintf(stderr, "syscalls: follow-fork attach failed (non-fatal)\n");
	}

	int nret = attach_return_probes(skel);
	if (nret == 0)
		fprintf(stderr, "warning: no return-value probes attached; "
				"continuing without return values\n");
	else
		printf("return-value probes attached to %d syscalls\n", nret);

	struct ring_buffer *rb =
		ring_buffer__new(bpf_map__fd(skel->maps.events), enqueue_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new failed\n");
		goto out;
	}

	// Decoupled processing: a worker thread drains the in-RAM queue and does all
	// the heavy per-event work, so this (drain) thread only copies events out of
	// the kernel ring. The queue absorbs bursts the kernel ring can't.
	if (ares_evq_init(&g_q, (size_t)queue_mb << 20) != 0) {
		fprintf(stderr, "cannot allocate %d MB queue\n", queue_mb);
		goto out_rb;
	}
	pthread_t worker;
	if (pthread_create(&worker, NULL, worker_main, NULL) != 0) {
		fprintf(stderr, "cannot start worker thread\n");
		ares_evq_destroy(&g_q);
		goto out_rb;
	}
	printf("queue: %d MB, worker thread started\n", queue_mb);

	// Setup complete: hand the live state to the run/teardown phases. The caller
	// (cmd_syscalls standalone, or the trace coordinator) owns the app launch,
	// which must happen AFTER this returns since the UID filter is already armed.
	g_skel = skel;
	g_rb = rb;
	g_worker = worker;
	g_worker_started = 1;
	g_dropfd = bpf_map__fd(skel->maps.dropped);
	return 0;

out_rb:
	ring_buffer__free(rb);
out:
	// Setup failed: clean up the partial state and report failure. teardown is
	// NOT called for this path (globals were never published), so g_ff/g_compat
	// (attached just above, if reached) must be destroyed here explicitly — AA11 fix.
	if (g_ff) {
		bpf_link__destroy(g_ff);
		g_ff = NULL;
	}
	if (g_compat) {
		bpf_link__destroy(g_compat);
		g_compat = NULL;
	}
	pend_flush_all();
	ares_sink_close(&g_sink);
	ares_sink_report(&g_sink);
	if (g_stacks) {
		fclose(g_stacks);
		g_stacks = NULL;
	}
	free(g_pend);
	g_pend = NULL;
	syscalls__destroy(skel);
	return 1;
}

// ~every second: surface drops live (kernel ring + userspace queue).
static int g_drop_ticks;
static unsigned long long g_last_drops;
static void syscalls_drops_tick(void *ctx)
{
	(void)ctx;
	if (++g_drop_ticks < 5)            // ~1s at 200ms/tick
		return;
	g_drop_ticks = 0;
	pthread_mutex_lock(&g_q.m);
	unsigned long long qd = g_q.dropped;
	pthread_mutex_unlock(&g_q.m);
	unsigned long long d = ares_drops_read(g_dropfd) + qd;
	if (d > g_last_drops) {
		fprintf(stderr, "[drops] %llu event(s) dropped so far\n", d);
		g_last_drops = d;
	}
}

int syscalls_run(volatile sig_atomic_t *stop)
{
	g_stopp = stop;
	if (g_capture_all)
		printf("tracing uid %d (all syscalls) ... Ctrl-C to stop\n", g_uid);
	else
		printf("tracing uid %d (waiting for '%s' to load) ... Ctrl-C to stop\n", g_uid, g_lib);

	g_drop_ticks = 0;
	g_last_drops = 0;
	ares_rb_poll_until_cb(g_rb, stop, syscalls_drops_tick, NULL);
	return 0;
}

void syscalls_teardown(void)
{
	if (g_worker_started) {
		// Stop the worker and let it drain whatever is still queued.
		pthread_mutex_lock(&g_q.m);
		g_q.done = 1;
		pthread_cond_signal(&g_q.cv);
		pthread_mutex_unlock(&g_q.m);
		pthread_join(g_worker, NULL);
		g_worker_started = 0;

		// Always report the final tally, so "no message" never means "didn't check".
		// Subsumes the old ares_drops_report: ring/queue drops are coverage fields.
		int covfd = bpf_map__fd(g_skel->maps.coverage_stats);
		g_cov.snaps_truncated = ares_coverage_read(covfd, COV_TRUNC);
		g_cov.depth_capped    = ares_coverage_read(covfd, COV_DEPTH_CAP);
		g_cov.prearm_drops    = ares_coverage_read(covfd, COV_PREARM);
		g_cov.ring_drops      = ares_drops_read(g_dropfd);
		g_cov.queue_drops     = g_q.dropped;
		g_cov.managed_naming_off = ares_art_naming_disabled();
		ares_coverage_report(&g_sink, &g_cov);
		ares_evq_destroy(&g_q);
	}

	if (g_rb) {
		ring_buffer__free(g_rb);
		g_rb = NULL;
	}

	pend_flush_all();                       // emit any entries whose return we never saw
	ares_sink_close(&g_sink);
	ares_sink_report(&g_sink);
	if (g_stacks) {
		fclose(g_stacks);
		fprintf(stderr, "wrote %llu stack snapshot%s to %s.stacks\n",
		        g_stack_count, g_stack_count == 1 ? "" : "s", g_sink.path);
		g_stacks = NULL;
	}
	free(g_pend);
	g_pend = NULL;
	if (g_ff) {
		bpf_link__destroy(g_ff);
		g_ff = NULL;
	}
	if (g_compat) {
		bpf_link__destroy(g_compat);
		g_compat = NULL;
	}
	if (g_skel) {
		syscalls__destroy(g_skel);
		g_skel = NULL;
	}
}

int cmd_syscalls(int argc, char **argv)
{
	if (syscalls_setup(argc, argv, NULL) != 0)
		return 1;

	// Standalone: tracing is armed; in -P mode launch, in -p mode just run.
	ares_install_stop_handler(&exiting);
	if (g_pkg[0]) {
		ares_launch_banner(g_pkg, g_uid);
		pid_t pid;
		if (ares_launch_app(g_pkg, g_activity, &pid) != 0) {
			fprintf(stderr, "launch failed for '%s' (could not resolve activity? pass it explicitly)\n", g_pkg);
			syscalls_teardown();
			return 1;
		}
		// Seed the lib-filter from the just-launched process's maps (lib-filter
		// attribution defect): inherited libraries (libc.so et al., mapped in
		// the zygote before fork) never fire a live uprobe_mmap in the child.
		seed_lib_ranges_from_maps((__u32)pid);
	}

	syscalls_run(&exiting);
	syscalls_teardown();
	return 0;
}
