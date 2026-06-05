// heimdall.c
//
// Userspace loader for heimdall.bpf.c. Traces the syscalls of a single Android
// app, emitting only those whose user backtrace passes through a chosen native
// library (e.g. a RASP .so).
//
//   usage: heimdall <package> <lib-substring> [activity]
//   e.g.   heimdall com.example.app librasp.so
//          heimdall com.example.app libtoyguard.so com.example.app.MainActivity
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
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "heimdall.h"
#include "heimdall.skel.h"
#include "symbolize.h"

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

// ---- globals -------------------------------------------------------------

static const char *g_pkg;
static const char *g_lib;
static int g_lib_ranges_fd = -1;
static int g_verbose;
static volatile sig_atomic_t exiting;

static unsigned long long g_next_id = 1;       // monotonic per-syscall id
static FILE *g_json;                            // JSON output stream, or NULL
static unsigned long long g_json_count;         // objects written so far

static void on_sigint(int s) { (void)s; exiting = 1; }

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

static void json_emit(const struct heimdall_syscall_event *e, unsigned long long id)
{
	FILE *f = g_json;
	fprintf(f, "%s\n  {", g_json_count++ ? "," : "");
	fprintf(f, "\"id\":%llu,\"pid\":%u,\"tid\":%u,\"syscall_nr\":%llu,\"syscall\":\"%s\",",
		id, e->h.pid, e->h.tid, (unsigned long long)e->nr, sysname(e->nr));

	fprintf(f, "\"args\":[");
	for (int i = 0; i < HEIMDALL_SYSCALL_NARGS; i++)
		fprintf(f, "%s\"0x%llx\"", i ? "," : "", (unsigned long long)e->args[i]);
	fprintf(f, "],\"string_args\":{");
	for (int i = 0, first = 1; i < HEIMDALL_STR_SLOTS; i++) {
		const char *s = arg_string(e, i);
		if (!s)
			continue;
		fprintf(f, "%s\"%d\":\"", first ? "" : ",", i);
		first = 0;
		json_puts_escaped(f, s);
		fputc('"', f);
	}
	fprintf(f, "},\"backtrace\":[");

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
	fputs("]}", f);
}

// ---- ring buffer handling ------------------------------------------------

static void handle_syscall(const struct heimdall_syscall_event *e)
{
	unsigned long long id = g_next_id++;

	printf("==> #%llu [%u/%u] %s(", id, e->h.pid, e->h.tid, sysname(e->nr));
	for (int i = 0; i < HEIMDALL_SYSCALL_NARGS; i++) {
		const char *s = arg_string(e, i);
		if (i)
			printf(", ");
		if (s)
			printf("\"%s\"", s);
		else
			printf("0x%llx", (unsigned long long)e->args[i]);
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

	if (g_json)
		json_emit(e, id);
}

static int handle_event(void *ctx, void *data, size_t sz)
{
	(void)ctx;
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

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [-o out.json] [-v] <package> <lib-substring> [activity]\n"
		"  -o, --json <file>   export captured syscalls to a JSON file\n"
		"  -v, --verbose       also log every executable mapping\n"
		"  e.g. %s -o trace.json com.example.app librasp.so\n",
		argv0, argv0);
}

int main(int argc, char **argv)
{
	g_verbose = getenv("HEIMDALL_VERBOSE") != NULL;
	const char *json_path = getenv("HEIMDALL_JSON");

	int ai = 1;
	for (; ai < argc; ai++) {
		if (!strcmp(argv[ai], "-o") || !strcmp(argv[ai], "--json")) {
			if (ai + 1 >= argc) { usage(argv[0]); return 1; }
			json_path = argv[++ai];
		} else if (!strcmp(argv[ai], "-v") || !strcmp(argv[ai], "--verbose")) {
			g_verbose = 1;
		} else if (argv[ai][0] == '-') {
			fprintf(stderr, "unknown option: %s\n", argv[ai]);
			usage(argv[0]);
			return 1;
		} else {
			break;
		}
	}
	if (argc - ai < 2) {
		usage(argv[0]);
		return 1;
	}
	g_pkg = argv[ai];
	g_lib = argv[ai + 1];
	const char *activity = (argc - ai > 2) ? argv[ai + 2] : NULL;

	int uid = resolve_uid(g_pkg);
	if (uid < 0) {
		fprintf(stderr, "could not resolve UID for '%s' (installed? run as root?)\n", g_pkg);
		return 1;
	}
	printf("package %s -> uid %d, target lib '%s'\n", g_pkg, uid, g_lib);

	libbpf_set_print(libbpf_quiet);

	struct heimdall *skel = heimdall__open_and_load();
	if (!skel) {
		fprintf(stderr, "open_and_load failed (run as root? SELinux permissive?)\n");
		return 1;
	}

	g_lib_ranges_fd = bpf_map__fd(skel->maps.lib_ranges);

	if (json_path) {
		g_json = fopen(json_path, "w");
		if (!g_json) {
			fprintf(stderr, "cannot open '%s': %s\n", json_path, strerror(errno));
			goto out;
		}
		fputc('[', g_json);
	}

	// Tell the hook which syscall args are strings, and arm the UID filter —
	// both BEFORE the app is launched so the very first syscalls are decoded.
	install_arg_types(bpf_map__fd(skel->maps.arg_types));

	__u32 key = 0, vuid = (__u32)uid;
	if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uid), &key, &vuid, BPF_ANY) != 0) {
		fprintf(stderr, "failed to set target uid: %s\n", strerror(errno));
		goto out;
	}

	if (heimdall__attach(skel)) {
		fprintf(stderr, "attach failed (do_el0_svc / uprobe_mmap present in kallsyms?)\n");
		goto out;
	}

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
	printf("tracing uid %d (waiting for '%s' to load) ... Ctrl-C to stop\n", uid, g_lib);
	while (!exiting) {
		int err = ring_buffer__poll(rb, 200 /* ms */);
		if (err < 0 && err != -EINTR)
			break;
	}

out_rb:
	ring_buffer__free(rb);
out:
	if (g_json) {
		fputs("\n]\n", g_json);
		fclose(g_json);
		printf("wrote %llu syscall record%s to %s\n",
		       g_json_count, g_json_count == 1 ? "" : "s", json_path);
	}
	heimdall__destroy(skel);
	return 0;
}
