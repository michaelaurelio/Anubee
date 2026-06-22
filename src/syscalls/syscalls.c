// syscalls.c
//
// Userspace loader for syscalls.bpf.c. Traces the syscalls of a single Android
// app, emitting only those whose user backtrace passes through a chosen native
// library (e.g. a RASP .so).
//
//   usage: syscalls <package> <lib> [activity]
//   where <lib> is a substring of the native library's mapped name, or a glob
//   (* ? []) over it for a randomized per-run name (e.g. 'e_[0-9]*').
//   e.g.   syscalls com.example.app librasp.so
//          syscalls com.example.app 'e_[0-9]*'
//          syscalls com.example.app libtoyguard.so com.example.app.MainActivity
//
// What it does, in order:
//   1. Resolves the package's app-UID by stat'ing its data dir.
//   2. Loads + attaches the BPF programs and installs the UID *before* the app
//      is (re)launched, so tracing is armed from the app's first syscall.
//   3. force-stops then launches the package via the native am/cmd tools.
//   4. Arms the in-kernel library filter from uprobe_mmap events (event-driven,
//      race-free): the moment the target library is mapped, its range is pushed
//      into the BPF filter. Backtrace symbolization (every frame, all libs) is
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

#include "syscalls.h"
#include "syscalls.skel.h"
#include "symbolize.h"
#include "common/decode.h"
#include "common/lib_trace.h"
#include "common/launch.h"

// ---- syscall name table (numbers resolved by the cross compiler) ---------

static const struct sysent { long nr; const char *name; } g_sys[] = {
#include "syscalls_gen.h"
};
static const int g_nsys = (int)(sizeof(g_sys) / sizeof(g_sys[0]));

static const char *sysname(unsigned long long nr)
{
	static char buf[32];
	for (int i = 0; i < g_nsys; i++)
		if ((unsigned long long)g_sys[i].nr == nr)
			return g_sys[i].name;
	snprintf(buf, sizeof(buf), "sys_%llu", nr);
	return buf;
}

// Per-syscall argument count (arm64 ABI), so we print only the real arguments
// instead of leftover register values. Unknown syscalls show all 6.
static const struct { long nr; int count; } g_argc[] = {
#include "syscall_argc.h"
};
static const int g_nargc = (int)(sizeof(g_argc) / sizeof(g_argc[0]));

static int arg_count(unsigned long long nr)
{
	for (int i = 0; i < g_nargc; i++)
		if ((unsigned long long)g_argc[i].nr == nr)
			return g_argc[i].count;
	return SYSC_SYSCALL_NARGS;
}

// Syscall name -> number (reverse of the generated table), or -1 if unknown.
static long sysnr(const char *name)
{
	for (int i = 0; i < g_nsys; i++)
		if (!strcmp(g_sys[i].name, name))
			return g_sys[i].nr;
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

static unsigned long long g_next_id = 1;       // monotonic per-syscall id
static FILE *g_json;                            // JSON output stream, or NULL
static unsigned long long g_json_count;         // objects written so far
static int g_jsonl;                             // 1 = JSON Lines (one record/line)
static FILE *g_stacks;                          // stack-snapshot sidecar, or NULL
static unsigned long long g_stack_count;        // snapshots written so far

// ---- engine state shared across setup / run / teardown -------------------
// Promoted from cmd_syscalls locals so the engine can be driven in three phases
// (standalone via cmd_syscalls, or by the `trace` coordinator). See syscalls.h.
static struct syscalls *g_skel;
static struct ring_buffer *g_rb;
static pthread_t g_worker;
static int g_worker_started;
static int g_dropfd = -1;
static int g_uid;
static int g_capture_all;
static const char *g_activity;                  // optional launcher activity
static const char *g_json_path;                 // for the teardown "wrote N" line

static void on_sigint(int s)
{
	(void)s;
	if (exiting)            // second Ctrl+C: force quit even if stuck in a write()
		_exit(130);
	exiting = 1;
}

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
	if (!g_lib[0])
		return 0;
	if (strpbrk(g_lib, "*?["))
		return fnmatch(g_lib, name, 0) == 0;
	return strstr(name, g_lib) != NULL;
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

// ---- string-argument types -----------------------------------------------

// Which of args[0..3] are a const char* (path/string), per syscall. Bit i set
// => args[i] is a string. arm64 uses the generic syscall ABI, so the legacy
// open/stat/... numbers don't exist — only the *at variants do.
#define A0 (1u << 0)
#define A1 (1u << 1)
#define A2 (1u << 2)
#define A3 (1u << 3)

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

// Mirror the table into the kernel arg_types map so the hook knows which
// arguments to dereference. Must be done before the app is launched.
static void install_arg_types(int fd)
{
	for (size_t i = 0; i < sizeof(g_str_args) / sizeof(g_str_args[0]); i++) {
		__u32 k = (__u32)g_str_args[i].nr;
		__u8 v = g_str_args[i].mask;
		if (k < 512)
			bpf_map_update_elem(fd, &k, &v, BPF_ANY);
	}
}

static const char *arg_string(const struct syscalls_syscall_event *e, int i)
{
	if (i < SYSC_STR_SLOTS && (e->str_present & (1u << i)))
		return e->str[i];
	return NULL;
}

// ---- file-descriptor arguments -------------------------------------------

// Which args are a file descriptor (or *at dirfd) per syscall: bit i => args[i]
// is an fd. Resolved to a path at print time via /proc/<pid>/fd/<n>.
#define A4 (1u << 4)

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

// ---- sockaddr arguments --------------------------------------------------

// Which arg holds a sockaddr* (the addrlen is the next arg). connect/bind take
// it at arg1; sendto at arg4. recvfrom/accept fill it at return, so not here.
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

static int arg_sock_index(unsigned long long nr)
{
	for (size_t i = 0; i < sizeof(g_sock_args) / sizeof(g_sock_args[0]); i++)
		if ((unsigned long long)g_sock_args[i].nr == nr)
			return g_sock_args[i].arg;
	return -1;
}

// Mirror the table into the BPF sock_args map (1-based index; 0 = none).
static void install_sock_args(int fd)
{
	for (size_t i = 0; i < sizeof(g_sock_args) / sizeof(g_sock_args[0]); i++) {
		__u32 k = (__u32)g_sock_args[i].nr;
		__u8 v = (__u8)(g_sock_args[i].arg + 1);
		if (k < 512)
			bpf_map_update_elem(fd, &k, &v, BPF_ANY);
	}
}

// Render argument i of a syscall: string > fd > decoded flags/enum > raw hex.
static void render_arg(const struct syscalls_syscall_event *e, int i, char *out, size_t outsz)
{
	const char *s = arg_string(e, i);
	if (s) {
		// Bound the string to what fits between the quotes (outsz - 2 quotes -
		// NUL) so the format provably can't overflow; long traced strings are
		// truncated for display, same as before but without the truncation warning.
		snprintf(out, outsz, "\"%.*s\"", (int)(outsz - 3), s);
		return;
	}
	if (arg_fd_mask(e->nr) & (1u << i)) {
		render_fd((int)e->h.pid, e->args[i], out, outsz);
		return;
	}
	if (i == arg_sock_index(e->nr) && e->sock_len > 0 &&
	    decode_sockaddr((const unsigned char *)e->sock, (unsigned)e->sock_len, out, outsz))
		return;
	if (flags_decode_arg((long)e->nr, i, e->args[i], out, outsz))
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

static struct jbuf g_jb;

// Write one stack snapshot (registers + base64 stack bytes) to the sidecar
// stream. Always JSON Lines — this is consumed by the off-device unwinder, not
// the main trace. Deduped in-kernel, so these are comparatively rare.
static void json_emit_stack(const struct syscalls_stack_snapshot *s)
{
	if (!g_stacks)
		return;
	struct jbuf *j = &g_jb;
	j->len = 0;

	jb_s(j, "{\"type\":\"stack\",\"pid\":"); jb_u64(j, s->h.pid);
	jb_s(j, ",\"tid\":");      jb_u64(j, s->h.tid);
	jb_s(j, ",\"stack_id\":"); jb_u64(j, s->stack_id);
	jb_s(j, ",\"pc\":\"");     jb_hex(j, s->pc); jb_c(j, '"');
	jb_s(j, ",\"sp\":\"");     jb_hex(j, s->sp); jb_c(j, '"');
	jb_s(j, ",\"fp\":\"");     jb_hex(j, s->fp); jb_c(j, '"');
	jb_s(j, ",\"lr\":\"");     jb_hex(j, s->lr); jb_c(j, '"');
	jb_s(j, ",\"snap_len\":"); jb_u64(j, s->snap_len);
	jb_s(j, ",\"snapshot\":\"");
	if (s->snap_len <= sizeof(s->snap))
		jb_b64(j, s->snap, s->snap_len);
	jb_s(j, "\"}\n");

	if (j->b && j->len)
		fwrite(j->b, 1, j->len, g_stacks);
	g_stack_count++;
}

// A frame inside one of ART's interpreter entrypoints means a Java method is
// being interpreted: there is no native frame for the managed method itself (it
// lives as a ShadowFrame in ART's managed stack), so the backtrace can't name
// it without an ART-internal stack walk. Flag it so the reader knows a Java
// frame was elided here rather than mistaking the bridge for the whole story.
static int is_interp_frame(const char *sym)
{
	return strstr(sym, "ToInterpreterBridge") ||      // art{Quick,Interpreter}ToInterpreterBridge
	       strstr(sym, "ExecuteNterpImpl")     ||      // nterp fast interpreter
	       strstr(sym, "ExecuteSwitchImpl")    ||      // switch interpreter
	       strstr(sym, "artInterpreterToCompiledCodeBridge");
}

static void json_emit(const struct syscalls_syscall_event *e, unsigned long long id,
		      int has_ret, long long ret)
{
	struct jbuf *j = &g_jb;
	j->len = 0;

	if (g_jsonl)
		jb_c(j, '{');
	else { jb_s(j, g_json_count ? "," : ""); jb_s(j, "\n  {"); }
	g_json_count++;

	// Discriminator for the unified ares trace schema: every record carries a
	// "type". Syscall events are "syscall"; stack snapshots are "stack" (see
	// json_emit_stack). Future ares-funcs structured events use "call"/"return"/
	// "map"/"prop"/etc. — see DOCUMENTATION.md "Unified trace schema".
	jb_s(j, "\"type\":\"syscall\",");
	jb_s(j, "\"id\":");        jb_u64(j, id);
	jb_s(j, ",\"pid\":");      jb_u64(j, e->h.pid);
	jb_s(j, ",\"tid\":");      jb_u64(j, e->h.tid);
	jb_s(j, ",\"syscall_nr\":"); jb_u64(j, e->nr);
	jb_s(j, ",\"syscall\":\""); jb_s(j, sysname(e->nr)); jb_c(j, '"');

	int nargs = arg_count(e->nr);
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
	unsigned fdm = arg_fd_mask(e->nr);
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
	for (int i = 0, first = 1; i < nargs; i++) {
		char dec[256];
		if (arg_string(e, i) || (arg_fd_mask(e->nr) & (1u << i)))
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

	if (e->stack_id)
		{ jb_s(j, ",\"stack_id\":"); jb_u64(j, e->stack_id); }

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
		if (is_interp_frame(sym))
			jb_s(j, ",\"java\":\"interpreted (managed frame elided)\"");
		jb_c(j, '}');
	}
	jb_s(j, g_jsonl ? "]}\n" : "]}");

	if (j->b && j->len)
		fwrite(j->b, 1, j->len, g_json);
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
		if (g_json)                     // previous syscall on this tid never returned
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
			if (g_json)
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
		int nargs = arg_count(e->nr);
		printf("==> #%llu [%u/%u] %s(", id, e->h.pid, e->h.tid, sysname(e->nr));
		for (int i = 0; i < nargs; i++) {
			if (i)
				printf(", ");
			render_arg(e, i, arg, sizeof(arg));
			fputs(arg, stdout);
		}
		printf(")\n");

		int n = e->stack_sz / (int)sizeof(__u64);
		char sym[320];
		for (int i = 0; i < n && i < SYSC_MAX_STACK_DEPTH; i++) {
			if (e->stack[i] == 0)
				break;
			sym_resolve(e->h.pid, e->stack[i], sym, sizeof(sym));
			printf("      #%-2d %s\n", i, sym);
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
		printf("<== #%llu %s = %s\n", p->id, sysname(p->ev.nr), rb);
		fflush(stdout);
	}
	if (g_json)
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
	if (sz < sizeof(struct syscalls_hdr))
		return;
	const struct syscalls_hdr *h = data;

	switch (h->type) {
	case SYSC_EV_MAP: {
		if (sz < sizeof(struct lib_map_event))
			return;
		const struct lib_map_event *m = data;
		if (g_verbose)
			printf("    map  pid %u %s [0x%llx,0x%llx) off=0x%llx\n",
			       m->h.pid, m->name, (unsigned long long)m->start,
			       (unsigned long long)m->end, (unsigned long long)m->pgoff);
		// The shared probe only emits executable mappings, so no is_exec test.
		if (lib_name_matches(m->name))
			push_lib_range(m->h.pid, m->start, m->end, m->name);
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
		if (sz < sizeof(struct syscalls_stack_snapshot))
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

struct queue {
	char *buf;
	size_t cap, head, tail, used;
	pthread_mutex_t m;
	pthread_cond_t cv;
	int done;
	unsigned long long qdropped;
};
static struct queue g_q;

static void q_in(struct queue *q, const void *src, size_t n)
{
	size_t f = q->cap - q->head;
	if (f > n) f = n;
	memcpy(q->buf + q->head, src, f);
	if (n > f) memcpy(q->buf, (const char *)src + f, n - f);
	q->head = (q->head + n) % q->cap;
	q->used += n;
}

static void q_out(struct queue *q, void *dst, size_t n)
{
	size_t f = q->cap - q->tail;
	if (f > n) f = n;
	memcpy(dst, q->buf + q->tail, f);
	if (n > f) memcpy((char *)dst + f, q->buf, n - f);
	q->tail = (q->tail + n) % q->cap;
	q->used -= n;
}

// ring_buffer callback (drain thread): copy the raw event into the queue.
static int enqueue_event(void *ctx, void *data, size_t sz)
{
	(void)ctx;
	if (exiting)
		return -1;                          // bail the drain promptly on Ctrl+C
	struct queue *q = &g_q;
	uint32_t s = (uint32_t)sz;
	size_t total = 4 + sz;
	pthread_mutex_lock(&q->m);
	if (q->cap - q->used < total) {
		q->qdropped++;                      // queue full: worker fell behind
	} else {
		q_in(q, &s, 4);
		q_in(q, data, sz);
		pthread_cond_signal(&q->cv);
	}
	pthread_mutex_unlock(&q->m);
	return 0;
}

static void *worker_main(void *arg)
{
	(void)arg;
	struct queue *q = &g_q;
	// Sized to the largest record (the stack snapshot), so nothing is truncated.
	static char rec[sizeof(struct syscalls_stack_snapshot) + 64];
	unsigned long flushed = 0;
	for (;;) {
		pthread_mutex_lock(&q->m);
		while (q->used == 0 && !q->done)
			pthread_cond_wait(&q->cv, &q->m);
		if (q->used == 0 && q->done) {
			pthread_mutex_unlock(&q->m);
			break;
		}
		uint32_t sz;
		q_out(q, &sz, 4);
		if (sz > sizeof(rec))
			sz = sizeof(rec);               // safety clamp
		q_out(q, rec, sz);
		pthread_mutex_unlock(&q->m);
		process_event(rec, sz);
		// Periodic flush so a hard-kill loses little (JSONL stays valid).
		if (g_json && (++flushed & 0x3fff) == 0)
			fflush(g_json);
	}
	return NULL;
}

// ---- main ----------------------------------------------------------------

static int libbpf_quiet(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG && !getenv("ARES_DEBUG"))
		return 0;
	return vfprintf(stderr, fmt, args);
}

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

static int ends_with(const char *s, const char *suf)
{
	size_t ls = strlen(s), lf = strlen(suf);
	return ls >= lf && !strcmp(s + ls - lf, suf);
}

// Sum the per-CPU dropped-event counters.
static unsigned long long read_dropped(int fd)
{
	int ncpu = libbpf_num_possible_cpus();
	if (ncpu < 1)
		ncpu = 1;
	__u64 *vals = calloc(ncpu, sizeof(__u64));
	if (!vals)
		return 0;
	__u32 k = 0;
	unsigned long long total = 0;
	if (bpf_map_lookup_elem(fd, &k, vals) == 0)
		for (int i = 0; i < ncpu; i++)
			total += vals[i];
	free(vals);
	return total;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [-o out.json] [-v] [-q] [-a] [-b MB] [-s list|-x list] <package> [lib-substring] [activity]\n"
		"  -a, --all           capture ALL syscalls of the app (no library filter)\n"
		"  -s, --syscall list  only these syscalls (comma-separated names, e.g. openat,read)\n"
		"  -x, --exclude list  all syscalls except these (comma-separated names)\n"
		"  -o, --json <file>   export captured syscalls to a JSON file (implies -q)\n"
		"  -J, --jsonl         write JSON Lines (one record/line; crash-safe, streamable).\n"
		"                      Auto-enabled when -o ends in .jsonl\n"
		"  -b, --bufsize MB    kernel ring buffer size in MB (default 4; rounded to power of 2)\n"
		"  -Q, --queue MB      userspace worker queue size in MB (default 256; absorbs bursts)\n"
		"  -q, --quiet         suppress per-event console output (much faster under load)\n"
		"  -v, --verbose       also log every executable mapping\n"
		"      --snapshot      capture per-syscall register+stack snapshots to a\n"
		"                      <out>.stacks sidecar for off-device CFI unwinding of\n"
		"                      packed/obfuscated native code (library-filtered mode; off by\n"
		"                      default — Java/JIT/OAT frames are symbolized on-device)\n"
		"\n"
		"  By default a <lib> selector is required and only syscalls whose backtrace\n"
		"  passes through that library are recorded. With -a it is optional/ignored.\n"
		"  <lib> is a substring of the mapped name, or a glob (* ? []) over it — e.g.\n"
		"  'e_*' / 'e_[0-9]*' for a protector payload loaded under a randomized name.\n"
		"  -s/-x further restrict which syscalls are kept (works with the default/-a modes).\n"
		"  e.g. %s com.example.app librasp.so\n"
		"       %s com.example.app 'e_[0-9]*'         # trace a randomized-name library\n"
		"       %s -a -s openat,read,close,newfstatat -o files.json com.example.app\n",
		argv0, argv0, argv0, argv0);
}

// ---- engine driver, split into setup / run / teardown --------------------
// cmd_syscalls below is a thin standalone wrapper; the `trace` coordinator drives
// the same three phases so the kprobe engine runs alongside the uprobe engine
// from a single app launch. Cross-phase state lives in the file-static g_* above.
int syscalls_setup(int argc, char **argv, const struct ares_run_ctx *rc)
{
	g_verbose = getenv("ARES_VERBOSE") != NULL;
	g_quiet = getenv("ARES_QUIET") != NULL;
	g_jsonl = getenv("ARES_JSONL") != NULL;
	int capture_all = getenv("ARES_ALL") != NULL;
	// Java frames are now symbolized on-device, so the off-device stack-snapshot
	// sidecar is opt-in (it remains the escape hatch for native CFI unwinding of
	// packed/obfuscated code). --snapshot / ARES_SNAPSHOT enables it.
	int want_snap = getenv("ARES_SNAPSHOT") != NULL;
	const char *json_path = getenv("ARES_JSON");
	const char *syscall_list = NULL;
	int syscall_mode = 0;                    // 0=off, 1=allowlist, 2=denylist
	int bufmb = 4;                           // kernel ring buffer size (MB)
	int queue_mb = 256;                      // userspace worker queue size (MB)

	int ai = 1;
	for (; ai < argc; ai++) {
		if (!strcmp(argv[ai], "-o") || !strcmp(argv[ai], "--json")) {
			if (ai + 1 >= argc) { usage(argv[0]); return 1; }
			json_path = argv[++ai];
		} else if (!strcmp(argv[ai], "-v") || !strcmp(argv[ai], "--verbose")) {
			g_verbose = 1;
		} else if (!strcmp(argv[ai], "-q") || !strcmp(argv[ai], "--quiet")) {
			g_quiet = 1;
		} else if (!strcmp(argv[ai], "-J") || !strcmp(argv[ai], "--jsonl")) {
			g_jsonl = 1;
		} else if (!strcmp(argv[ai], "-b") || !strcmp(argv[ai], "--bufsize")) {
			if (ai + 1 >= argc) { usage(argv[0]); return 1; }
			bufmb = atoi(argv[++ai]);
			if (bufmb < 1) { fprintf(stderr, "bufsize must be >= 1 MB\n"); return 1; }
		} else if (!strcmp(argv[ai], "-Q") || !strcmp(argv[ai], "--queue")) {
			if (ai + 1 >= argc) { usage(argv[0]); return 1; }
			queue_mb = atoi(argv[++ai]);
			if (queue_mb < 1) { fprintf(stderr, "queue must be >= 1 MB\n"); return 1; }
		} else if (!strcmp(argv[ai], "-a") || !strcmp(argv[ai], "--all")) {
			capture_all = 1;
		} else if (!strcmp(argv[ai], "--snapshot")) {
			want_snap = 1;
		} else if (!strcmp(argv[ai], "--no-snapshot")) {
			want_snap = 0;          // accepted for back-compat; off is the default
		} else if (!strcmp(argv[ai], "-s") || !strcmp(argv[ai], "--syscall")) {
			if (ai + 1 >= argc || syscall_mode == 2) {
				fprintf(stderr, "use either -s or -x, not both\n");
				usage(argv[0]); return 1;
			}
			syscall_list = argv[++ai];
			syscall_mode = 1;
		} else if (!strcmp(argv[ai], "-x") || !strcmp(argv[ai], "--exclude")) {
			if (ai + 1 >= argc || syscall_mode == 1) {
				fprintf(stderr, "use either -s or -x, not both\n");
				usage(argv[0]); return 1;
			}
			syscall_list = argv[++ai];
			syscall_mode = 2;
		} else if (argv[ai][0] == '-') {
			fprintf(stderr, "unknown option: %s\n", argv[ai]);
			usage(argv[0]);
			return 1;
		} else {
			break;
		}
	}
	// Need <package>; <lib-substring> is required only in the default
	// library-filtered mode (not with -a). In coordinator mode (rc->pkg set) the
	// package is supplied by `trace`, so the positionals are just [lib] [activity].
	int no_lib_needed = capture_all;
	int npos = argc - ai;
	const char *activity;
	if (rc && rc->pkg) {
		if (!no_lib_needed && npos < 1) { usage(argv[0]); return 1; }
		g_pkg = rc->pkg;
		if (no_lib_needed) {
			g_lib = "";
			activity = (npos > 0) ? argv[ai] : NULL;
		} else {
			g_lib = argv[ai];
			activity = (npos > 1) ? argv[ai + 1] : NULL;
		}
	} else {
		if (npos < 1 || (!no_lib_needed && npos < 2)) {
			usage(argv[0]);
			return 1;
		}
		g_pkg = argv[ai];
		if (no_lib_needed) {
			g_lib = "";                          // no library filter
			activity = (npos > 1) ? argv[ai + 1] : NULL;
		} else {
			g_lib = argv[ai + 1];
			activity = (npos > 2) ? argv[ai + 2] : NULL;
		}
	}

	g_activity = activity;
	int uid = (rc && rc->uid > 0) ? rc->uid : ares_resolve_uid(g_pkg);
	if (uid < 0) {
		fprintf(stderr, "could not resolve UID for '%s' (installed? run as root?)\n", g_pkg);
		return 1;
	}
	g_uid = uid;
	g_capture_all = capture_all;
	if (capture_all)
		printf("package %s -> uid %d, capturing ALL syscalls\n", g_pkg, uid);
	else
		printf("package %s -> uid %d, target lib '%s'\n", g_pkg, uid, g_lib);

	// Writing JSON => suppress the slow per-event console rendering by default.
	if (json_path)
		g_quiet = 1;
	// A .jsonl output path implies JSON Lines framing.
	if (json_path && ends_with(json_path, ".jsonl"))
		g_jsonl = 1;
	g_json_path = json_path;

	// Round the requested ring buffer size up to a power of two (a ringbuf
	// requirement).
	size_t bufbytes = (size_t)bufmb << 20;
	size_t p2 = 1;
	while (p2 < bufbytes)
		p2 <<= 1;
	bufbytes = p2;

	libbpf_set_print(libbpf_quiet);

	struct syscalls *skel = syscalls__open();
	if (!skel) {
		fprintf(stderr, "open failed (run as root? SELinux permissive?)\n");
		return 1;
	}
	// Stack snapshots: opt-in (--snapshot), library-filtered mode only (far too
	// heavy for the -a firehose), and only when writing JSON (the snapshots go to
	// a <out>.stacks sidecar for off-device CFI unwinding of obfuscated native
	// frames — Java frames are resolved on-device by the symbolizer).
	int want_snapshots = want_snap && !capture_all && json_path != NULL;
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
		int nf = install_syscall_filter(bpf_map__fd(skel->maps.syscall_filter), syscall_list);
		printf("syscall filter: %s %d syscall(s)\n",
		       syscall_mode == 1 ? "only" : "excluding", nf);
	}

	g_lib_ranges_fd = bpf_map__fd(skel->maps.lib_ranges);

	if (json_path) {
		g_json = fopen(json_path, "w");
		if (!g_json) {
			fprintf(stderr, "cannot open '%s': %s\n", json_path, strerror(errno));
			goto out;
		}
		// Large output buffer: batch the worker's writes into big flash writes
		// so it doesn't stall on small I/O during a burst.
		setvbuf(g_json, malloc(8u << 20), _IOFBF, 8u << 20);
		if (!g_jsonl)
			fputc('[', g_json);     // JSONL needs no array framing
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

	__u32 key = 0, vuid = (__u32)uid;
	if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uid), &key, &vuid, BPF_ANY) != 0) {
		fprintf(stderr, "failed to set target uid: %s\n", strerror(errno));
		goto out;
	}

	// We attach the return probe ourselves (classic kretprobes, per function),
	// so disable its autoattach.
	bpf_program__set_autoattach(skel->progs.on_sys_exit, false);

	if (syscalls__attach(skel)) {
		fprintf(stderr, "attach failed (do_el0_svc / uprobe_mmap present in kallsyms?)\n");
		goto out;
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
	g_q.cap = (size_t)queue_mb << 20;
	g_q.buf = malloc(g_q.cap);
	if (!g_q.buf) {
		fprintf(stderr, "cannot allocate %d MB queue\n", queue_mb);
		goto out_rb;
	}
	pthread_mutex_init(&g_q.m, NULL);
	pthread_cond_init(&g_q.cv, NULL);
	pthread_t worker;
	int worker_ok = (pthread_create(&worker, NULL, worker_main, NULL) == 0);
	if (!worker_ok) {
		fprintf(stderr, "cannot start worker thread\n");
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
	// NOT called for this path (globals were never published).
	pend_flush_all();
	if (g_json) {
		if (!g_jsonl)
			fputs("\n]\n", g_json);
		fclose(g_json);
		g_json = NULL;
	}
	if (g_stacks) {
		fclose(g_stacks);
		g_stacks = NULL;
	}
	free(g_pend);
	g_pend = NULL;
	syscalls__destroy(skel);
	return 1;
}

int syscalls_run(volatile sig_atomic_t *stop)
{
	if (g_capture_all)
		printf("tracing uid %d (all syscalls) ... Ctrl-C to stop\n", g_uid);
	else
		printf("tracing uid %d (waiting for '%s' to load) ... Ctrl-C to stop\n", g_uid, g_lib);

	unsigned long long last_drops = 0;
	int ticks = 0;
	while (!*stop) {
		int err = ring_buffer__poll(g_rb, 200 /* ms */);
		if (err < 0 && err != -EINTR)
			break;
		// ~every second: surface drops live (kernel ring + userspace queue).
		if (++ticks >= 5) {
			ticks = 0;
			pthread_mutex_lock(&g_q.m);
			unsigned long long qd = g_q.qdropped;
			pthread_mutex_unlock(&g_q.m);
			unsigned long long d = read_dropped(g_dropfd) + qd;
			if (d > last_drops) {
				fprintf(stderr, "[drops] %llu event(s) dropped so far\n", d);
				last_drops = d;
			}
		}
	}
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
		unsigned long long kdrops = read_dropped(g_dropfd), qdrops = g_q.qdropped;
		unsigned long long drops = kdrops + qdrops;
		if (drops)
			fprintf(stderr, "%llu event(s) dropped (%llu kernel ring, %llu queue) — "
					"trace is incomplete\n", drops, kdrops, qdrops);
		else
			fprintf(stderr, "no events dropped\n");
	}

	if (g_rb) {
		ring_buffer__free(g_rb);
		g_rb = NULL;
	}

	pend_flush_all();                       // emit any entries whose return we never saw
	if (g_json) {
		if (!g_jsonl)
			fputs("\n]\n", g_json);
		fclose(g_json);
		printf("wrote %llu %s record%s to %s\n",
		       g_json_count, "syscall",
		       g_json_count == 1 ? "" : "s", g_json_path);
		g_json = NULL;
	}
	if (g_stacks) {
		fclose(g_stacks);
		printf("wrote %llu stack snapshot%s to %s.stacks\n",
		       g_stack_count, g_stack_count == 1 ? "" : "s", g_json_path);
		g_stacks = NULL;
	}
	free(g_pend);
	g_pend = NULL;
	if (g_skel) {
		syscalls__destroy(g_skel);
		g_skel = NULL;
	}
}

int cmd_syscalls(int argc, char **argv)
{
	if (syscalls_setup(argc, argv, NULL) != 0)
		return 1;

	// Standalone: tracing is armed (UID installed in setup); launch and own SIGINT.
	signal(SIGINT, on_sigint);
	printf("launching: %s\n", g_pkg);
	if (ares_launch_app(g_pkg, g_activity) != 0) {
		fprintf(stderr, "launch failed for '%s' (could not resolve activity? pass it explicitly)\n", g_pkg);
		syscalls_teardown();
		return 1;
	}

	syscalls_run(&exiting);
	syscalls_teardown();
	return 0;
}
