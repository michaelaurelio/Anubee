// heimdall.c
//
// Userspace loader for heimdall.bpf.c. Traces the syscalls of a single Android
// app, emitting only those whose user backtrace passes through a chosen native
// library (e.g. a RASP .so).
//
//   usage: heimdall <package> <lib-substring> [activity]
//   e.g.   heimdall com.example.app librasp.so
//          heimdall com.example.app libguard.so com.example.app.MainActivity
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>            // __NR_* for the generated table
#include <linux/types.h>
#include <arpa/inet.h>              // inet_ntop / ntohs for sockaddr decode
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "heimdall.h"
#include "heimdall.skel.h"
#include "symbolize.h"
#include "flags.h"

extern char **environ;

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
	return HEIMDALL_SYSCALL_NARGS;
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

static void on_sigint(int s)
{
	(void)s;
	if (exiting)            // second Ctrl+C: force quit even if stuck in a write()
		_exit(130);
	exiting = 1;
}

// ---- running Android tools (no libc system(): /bin/sh is absent) ---------

// Run `cmd` via /system/bin/sh -c. If out != NULL, capture up to outsz-1 bytes
// of stdout. Returns the child's exit status, or -1 on spawn failure.
static int sh_exec(const char *cmd, char *out, size_t outsz)
{
	int pipefd[2] = { -1, -1 };
	if (out != NULL) {
		out[0] = '\0';
		if (pipe(pipefd) != 0)
			return -1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		if (out != NULL) { close(pipefd[0]); close(pipefd[1]); }
		return -1;
	}

	if (pid == 0) {
		if (out != NULL) {
			dup2(pipefd[1], STDOUT_FILENO);
			close(pipefd[0]);
			close(pipefd[1]);
		} else {
			int devnull = open("/dev/null", O_WRONLY);
			if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); close(devnull); }
		}
		char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, NULL };
		execve("/system/bin/sh", argv, environ);
		_exit(127);
	}

	if (out != NULL) {
		close(pipefd[1]);
		size_t off = 0;
		ssize_t n;
		while (off + 1 < outsz && (n = read(pipefd[0], out + off, outsz - 1 - off)) > 0)
			off += (size_t)n;
		out[off] = '\0';
		close(pipefd[0]);
	}

	int status = 0;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	return status;
}

// ---- package resolution --------------------------------------------------

// App UID = owner of the package's private data directory.
static int resolve_uid(const char *pkg)
{
	const char *roots[] = { "/data/data/%s", "/data/user/0/%s", "/data/user_de/0/%s" };
	for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
		char path[256];
		snprintf(path, sizeof(path), roots[i], pkg);
		struct stat st;
		if (stat(path, &st) == 0)
			return (int)st.st_uid;
	}
	return -1;
}

// Resolve "pkg/.Activity" launcher component via the native cmd tool.
static int resolve_component(const char *pkg, char *out, size_t outsz)
{
	char cmd[256], buf[1024];
	snprintf(cmd, sizeof(cmd), "cmd package resolve-activity --brief %s", pkg);
	if (sh_exec(cmd, buf, sizeof(buf)) < 0)
		return -1;

	out[0] = '\0';
	char *save = NULL;
	for (char *line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (strchr(line, '/') && strstr(line, pkg))     // last "pkg/..." line
			snprintf(out, outsz, "%s", line);
	}
	return out[0] ? 0 : -1;
}

// Symbolization (every frame: target lib + libc + others) is delegated to
// symbolize.c, which reads /proc/<pid>/maps for module ranges/paths and parses
// each ELF's .dynsym. We use sym_resolve() wherever we render a backtrace. The
// in-kernel filter below remains purely event-driven.

// ---- target library -> BPF filter ----------------------------------------

// Push a newly seen executable range of the target library into lib_ranges[tgid]
// so the syscall hook starts matching it. Read-modify-write of the per-tgid set.
static void push_lib_range(__u32 tgid, __u64 start, __u64 end)
{
	struct heimdall_lib_ranges lr;
	memset(&lr, 0, sizeof(lr));
	bpf_map_lookup_elem(g_lib_ranges_fd, &tgid, &lr);    // ENOENT leaves it zeroed

	for (__u32 i = 0; i < lr.count && i < HEIMDALL_MAX_RANGES; i++)
		if (lr.r[i].start == start && lr.r[i].end == end)
			return;                                       // already known

	if (lr.count >= HEIMDALL_MAX_RANGES)
		return;

	lr.r[lr.count].start = start;
	lr.r[lr.count].end = end;
	lr.count++;

	if (bpf_map_update_elem(g_lib_ranges_fd, &tgid, &lr, BPF_ANY) == 0)
		printf("[+] %s mapped in pid %u: [0x%llx, 0x%llx) — filter armed (%u range%s)\n",
		       g_lib, tgid, (unsigned long long)start, (unsigned long long)end,
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

static const char *arg_string(const struct heimdall_syscall_event *e, int i)
{
	if (i < HEIMDALL_STR_SLOTS && (e->str_present & (1u << i)))
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

// Decode a raw sockaddr (family + port + addr) to "ip:port" / "[ip6]:port" /
// "unix:/path". Returns 1 on success.
static int decode_sockaddr(const __u8 *sa, __u32 len, char *out, size_t outsz)
{
	if (len < 2)
		return 0;
	unsigned short fam;
	memcpy(&fam, sa, 2);                     // sa_family is host byte order
	if (fam == AF_INET && len >= 8) {
		unsigned short port;
		memcpy(&port, sa + 2, 2);
		char ip[INET_ADDRSTRLEN];
		if (!inet_ntop(AF_INET, sa + 4, ip, sizeof(ip)))
			return 0;
		snprintf(out, outsz, "%s:%u", ip, ntohs(port));
		return 1;
	}
	if (fam == AF_INET6 && len >= 24) {
		unsigned short port;
		memcpy(&port, sa + 2, 2);
		char ip[INET6_ADDRSTRLEN];
		if (!inet_ntop(AF_INET6, sa + 8, ip, sizeof(ip)))   // skip family+port+flowinfo
			return 0;
		snprintf(out, outsz, "[%s]:%u", ip, ntohs(port));
		return 1;
	}
	if (fam == AF_UNIX) {
		const char *path = (const char *)(sa + 2);
		__u32 plen = len - 2;
		if (plen == 0) {
			snprintf(out, outsz, "unix:<unnamed>");
		} else if (path[0] == '\0') {           // abstract namespace
			char buf[HEIMDALL_SOCK_MAX];
			__u32 m = plen - 1 < sizeof(buf) - 1 ? plen - 1 : (__u32)sizeof(buf) - 1;
			memcpy(buf, path + 1, m);
			buf[m] = '\0';
			snprintf(out, outsz, "unix:@%s", buf);
		} else {
			char buf[HEIMDALL_SOCK_MAX];
			__u32 m = plen < sizeof(buf) ? plen : (__u32)sizeof(buf) - 1;
			memcpy(buf, path, m);
			buf[m < sizeof(buf) ? m : sizeof(buf) - 1] = '\0';
			snprintf(out, outsz, "unix:%s", buf);
		}
		return 1;
	}
	snprintf(out, outsz, "family=%u", fam);
	return 1;
}

// Render an fd value: "AT_FDCWD", "fd=199 </proc/self/maps>", or "fd=5".
static void render_fd(int pid, unsigned long long val, char *out, size_t outsz)
{
	int fd = (int)val;
	if (fd == -100) {                       // AT_FDCWD
		snprintf(out, outsz, "AT_FDCWD");
		return;
	}
	if (fd < 0) {
		snprintf(out, outsz, "%d", fd);
		return;
	}
	char p[64], tgt[256];
	snprintf(p, sizeof(p), "/proc/%d/fd/%d", pid, fd);
	ssize_t k = readlink(p, tgt, sizeof(tgt) - 1);
	if (k > 0) {
		tgt[k] = '\0';
		snprintf(out, outsz, "fd=%d <%s>", fd, tgt);
	} else {
		snprintf(out, outsz, "fd=%d", fd);
	}
}

// Render argument i of a syscall: string > fd > decoded flags/enum > raw hex.
static void render_arg(const struct heimdall_syscall_event *e, int i, char *out, size_t outsz)
{
	const char *s = arg_string(e, i);
	if (s) {
		snprintf(out, outsz, "\"%s\"", s);
		return;
	}
	if (arg_fd_mask(e->nr) & (1u << i)) {
		render_fd((int)e->h.pid, e->args[i], out, outsz);
		return;
	}
	if (i == arg_sock_index(e->nr) && e->sock_len > 0 &&
	    decode_sockaddr(e->sock, e->sock_len, out, outsz))
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

static void json_puts_escaped(FILE *f, const char *s)
{
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		switch (c) {
		case '"':  fputs("\\\"", f); break;
		case '\\': fputs("\\\\", f); break;
		case '\n': fputs("\\n", f);  break;
		case '\r': fputs("\\r", f);  break;
		case '\t': fputs("\\t", f);  break;
		default:
			if (c < 0x20)
				fprintf(f, "\\u%04x", c);
			else
				fputc(c, f);
		}
	}
}

static void json_emit(const struct heimdall_syscall_event *e, unsigned long long id,
		      int has_ret, long long ret)
{
	FILE *f = g_json;
	if (g_jsonl)
		fputc('{', f);                  // one self-contained object per line
	else
		fprintf(f, "%s\n  {", g_json_count ? "," : "");
	g_json_count++;
	fprintf(f, "\"id\":%llu,\"pid\":%u,\"tid\":%u,\"syscall_nr\":%llu,\"syscall\":\"%s\",",
		id, e->h.pid, e->h.tid, (unsigned long long)e->nr, sysname(e->nr));

	int nargs = arg_count(e->nr);
	fprintf(f, "\"args\":[");
	for (int i = 0; i < nargs; i++)
		fprintf(f, "%s\"0x%llx\"", i ? "," : "", (unsigned long long)e->args[i]);
	fprintf(f, "],");

	if (has_ret)
		fprintf(f, "\"retval\":%lld,", ret);
	else
		fprintf(f, "\"retval\":null,");

	fprintf(f, "\"string_args\":{");
	for (int i = 0, first = 1; i < HEIMDALL_STR_SLOTS; i++) {
		const char *s = arg_string(e, i);
		if (!s)
			continue;
		fprintf(f, "%s\"%d\":\"", first ? "" : ",", i);
		first = 0;
		json_puts_escaped(f, s);
		fputc('"', f);
	}
	fprintf(f, "},\"fd_args\":{");
	unsigned fdm = arg_fd_mask(e->nr);
	for (int i = 0, first = 1; i < HEIMDALL_SYSCALL_NARGS; i++) {
		if (!(fdm & (1u << i)))
			continue;
		char fdbuf[320];
		render_fd((int)e->h.pid, e->args[i], fdbuf, sizeof(fdbuf));
		fprintf(f, "%s\"%d\":\"", first ? "" : ",", i);
		first = 0;
		json_puts_escaped(f, fdbuf);
		fputc('"', f);
	}
	fprintf(f, "},\"decoded_args\":{");
	for (int i = 0, first = 1; i < nargs; i++) {
		char dec[256];
		if (arg_string(e, i) || (arg_fd_mask(e->nr) & (1u << i)))
			continue;                       // already in string_args / fd_args
		if (!flags_decode_arg((long)e->nr, i, e->args[i], dec, sizeof(dec)))
			continue;
		fprintf(f, "%s\"%d\":\"", first ? "" : ",", i);
		first = 0;
		json_puts_escaped(f, dec);
		fputc('"', f);
	}
	fprintf(f, "},");

	if (e->sock_len > 0) {
		char sockbuf[128];
		if (decode_sockaddr(e->sock, e->sock_len, sockbuf, sizeof(sockbuf))) {
			fprintf(f, "\"sock_addr\":\"");
			json_puts_escaped(f, sockbuf);
			fprintf(f, "\",");
		}
	}
	fprintf(f, "\"backtrace\":[");

	int n = e->stack_sz / (int)sizeof(__u64);
	char sym[320];
	for (int i = 0, first = 1; i < n && i < HEIMDALL_MAX_STACK_DEPTH; i++) {
		if (e->stack[i] == 0)
			break;
		sym_resolve(e->h.pid, e->stack[i], sym, sizeof(sym));
		fprintf(f, "%s{\"frame\":%d,\"addr\":\"0x%llx\",\"symbol\":\"",
			first ? "" : ",", i, (unsigned long long)e->stack[i]);
		first = 0;
		json_puts_escaped(f, sym);
		fputs("\"}", f);
	}
	fputs(g_jsonl ? "]}\n" : "]}", f);
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
	struct heimdall_syscall_event ev;
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

static void pend_store(const struct heimdall_syscall_event *e, unsigned long long id)
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

static void handle_syscall(const struct heimdall_syscall_event *e)
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
		for (int i = 0; i < n && i < HEIMDALL_MAX_STACK_DEPTH; i++) {
			if (e->stack[i] == 0)
				break;
			sym_resolve(e->h.pid, e->stack[i], sym, sizeof(sym));
			printf("      #%-2d %s\n", i, sym);
		}
		fflush(stdout);
	}

	pend_store(e, id);          // JSON emitted once the return value arrives
}

static void handle_return(const struct heimdall_return_event *r)
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
	p->used = 0;
}

static int handle_event(void *ctx, void *data, size_t sz)
{
	(void)ctx;
	// On Ctrl+C, abort the ring-buffer drain promptly instead of finishing the
	// whole backlog: a negative return makes ring_buffer__poll bail out.
	if (exiting)
		return -1;
	if (sz < sizeof(struct heimdall_hdr))
		return 0;
	const struct heimdall_hdr *h = data;

	switch (h->type) {
	case HEIMDALL_EV_MAP: {
		if (sz < sizeof(struct heimdall_map_event))
			return 0;
		const struct heimdall_map_event *m = data;
		if (g_verbose)
			printf("    map  pid %u %s [0x%llx,0x%llx) off=0x%llx\n",
			       m->h.pid, m->name, (unsigned long long)m->start,
			       (unsigned long long)m->end, (unsigned long long)m->pgoff);
		if (m->is_exec && g_lib[0] && strstr(m->name, g_lib))
			push_lib_range(m->h.pid, m->start, m->end);
		break;
	}
	case HEIMDALL_EV_UNMAP: {
		if (sz < sizeof(struct heimdall_unmap_event))
			return 0;
		const struct heimdall_unmap_event *u = data;
		sym_flush_pid(u->h.pid);          // force a /proc maps reread on next resolve
		break;
	}
	case HEIMDALL_EV_SYSCALL:
		if (sz < sizeof(struct heimdall_syscall_event))
			return 0;
		handle_syscall(data);
		break;
	case HEIMDALL_EV_RETURN:
		if (sz < sizeof(struct heimdall_return_event))
			return 0;
		handle_return(data);
		break;
	}
	return 0;
}

// ---- main ----------------------------------------------------------------

static int libbpf_quiet(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG && !getenv("HEIMDALL_DEBUG"))
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
static int attach_return_probes(struct heimdall *skel)
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
		"  -b, --bufsize MB    ring buffer size in MB (default 4; rounded up to a power of 2)\n"
		"  -q, --quiet         suppress per-event console output (much faster under load)\n"
		"  -v, --verbose       also log every executable mapping\n"
		"\n"
		"  By default a <lib-substring> is required and only syscalls whose backtrace\n"
		"  passes through that library are recorded. With -a it is optional/ignored.\n"
		"  -s/-x further restrict which syscalls are kept (works in either mode).\n"
		"  e.g. %s com.example.app librasp.so\n"
		"       %s -a -s openat,read,close,newfstatat -o files.json com.example.app\n",
		argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
	g_verbose = getenv("HEIMDALL_VERBOSE") != NULL;
	g_quiet = getenv("HEIMDALL_QUIET") != NULL;
	g_jsonl = getenv("HEIMDALL_JSONL") != NULL;
	int capture_all = getenv("HEIMDALL_ALL") != NULL;
	const char *json_path = getenv("HEIMDALL_JSON");
	const char *syscall_list = NULL;
	int syscall_mode = 0;                    // 0=off, 1=allowlist, 2=denylist
	int bufmb = 4;                           // ring buffer size (MB)

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
		} else if (!strcmp(argv[ai], "-a") || !strcmp(argv[ai], "--all")) {
			capture_all = 1;
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
	// Need <package>, plus <lib-substring> unless capturing all.
	int npos = argc - ai;
	if (npos < 1 || (!capture_all && npos < 2)) {
		usage(argv[0]);
		return 1;
	}
	g_pkg = argv[ai];
	const char *activity;
	if (capture_all) {
		g_lib = "";                          // no library filter
		activity = (npos > 1) ? argv[ai + 1] : NULL;
	} else {
		g_lib = argv[ai + 1];
		activity = (npos > 2) ? argv[ai + 2] : NULL;
	}

	int uid = resolve_uid(g_pkg);
	if (uid < 0) {
		fprintf(stderr, "could not resolve UID for '%s' (installed? run as root?)\n", g_pkg);
		return 1;
	}
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

	// Round the requested ring buffer size up to a power of two (a ringbuf
	// requirement).
	size_t bufbytes = (size_t)bufmb << 20;
	size_t p2 = 1;
	while (p2 < bufbytes)
		p2 <<= 1;
	bufbytes = p2;

	libbpf_set_print(libbpf_quiet);

	struct heimdall *skel = heimdall__open();
	if (!skel) {
		fprintf(stderr, "open failed (run as root? SELinux permissive?)\n");
		return 1;
	}
	skel->rodata->capture_all = capture_all;
	skel->rodata->syscall_filter_mode = syscall_mode;
	bpf_map__set_max_entries(skel->maps.events, bufbytes);
	if (heimdall__load(skel)) {
		fprintf(stderr, "load failed (run as root? SELinux permissive?)\n");
		heimdall__destroy(skel);
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
		if (!g_jsonl)
			fputc('[', g_json);     // JSONL needs no array framing
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

	if (heimdall__attach(skel)) {
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
		ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new failed\n");
		goto out;
	}

	// Fresh start: kill any running instance, then launch. Tracing is already
	// armed, so we catch the new process from its first syscall.
	char cmd[512], comp[256];
	snprintf(cmd, sizeof(cmd), "am force-stop %s", g_pkg);
	sh_exec(cmd, NULL, 0);

	if (activity)
		snprintf(comp, sizeof(comp), "%s/%s", g_pkg, activity);
	else if (resolve_component(g_pkg, comp, sizeof(comp)) != 0) {
		fprintf(stderr, "could not resolve launcher activity for '%s'; pass it explicitly\n", g_pkg);
		goto out_rb;
	}

	snprintf(cmd, sizeof(cmd), "am start -n %s", comp);
	printf("launching: %s\n", cmd);
	if (sh_exec(cmd, NULL, 0) < 0) {
		fprintf(stderr, "launch failed\n");
		goto out_rb;
	}

	signal(SIGINT, on_sigint);
	if (capture_all)
		printf("tracing uid %d (all syscalls) ... Ctrl-C to stop\n", uid);
	else
		printf("tracing uid %d (waiting for '%s' to load) ... Ctrl-C to stop\n", uid, g_lib);

	int dropfd = bpf_map__fd(skel->maps.dropped);
	unsigned long long last_drops = 0;
	int ticks = 0;
	while (!exiting) {
		int err = ring_buffer__poll(rb, 200 /* ms */);
		if (err < 0 && err != -EINTR)
			break;
		// ~every second: surface drops live, and flush the JSON stream so a
		// hard-kill loses at most ~1s of records (JSONL stays valid; the array
		// form is still only complete after a clean exit).
		if (++ticks >= 5) {
			ticks = 0;
			if (g_json)
				fflush(g_json);
			unsigned long long d = read_dropped(dropfd);
			if (d > last_drops) {
				fprintf(stderr, "[drops] %llu event(s) dropped so far (ring buffer full)\n", d);
				last_drops = d;
			}
		}
	}

	// Always report the final tally, so "no message" never means "didn't check".
	unsigned long long drops = read_dropped(dropfd);
	if (drops)
		fprintf(stderr, "%llu event(s) dropped (ring buffer full) — trace is incomplete\n", drops);
	else
		fprintf(stderr, "no events dropped\n");

out_rb:
	ring_buffer__free(rb);
out:
	pend_flush_all();                       // emit any entries whose return we never saw
	if (g_json) {
		if (!g_jsonl)
			fputs("\n]\n", g_json);
		fclose(g_json);
		printf("wrote %llu syscall record%s to %s\n",
		       g_json_count, g_json_count == 1 ? "" : "s", json_path);
	}
	free(g_pend);
	heimdall__destroy(skel);
	return 0;
}
