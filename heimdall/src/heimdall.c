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
//   4. Builds the process's executable module map purely from uprobe_mmap /
//      uprobe_munmap events — it never reads /proc/<pid>/maps. The moment the
//      target library is mapped, its range is pushed into the BPF filter.
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

// ---- event-driven module map (no /proc/<pid>/maps) -----------------------

struct module {
	__u32 tgid;
	__u64 start, end, pgoff;
	char  name[HEIMDALL_MAX_NAME];
};

static struct module *g_mods;
static size_t g_nmods, g_cap;

static void mod_add(__u32 tgid, __u64 start, __u64 end, __u64 pgoff, const char *name)
{
	for (size_t i = 0; i < g_nmods; i++)
		if (g_mods[i].tgid == tgid && g_mods[i].start == start) {
			g_mods[i].end = end;                  // refresh in place
			return;
		}

	if (g_nmods == g_cap) {
		size_t ncap = g_cap ? g_cap * 2 : 256;
		struct module *p = realloc(g_mods, ncap * sizeof(*p));
		if (!p)
			return;
		g_mods = p;
		g_cap = ncap;
	}

	struct module *m = &g_mods[g_nmods++];
	m->tgid = tgid;
	m->start = start;
	m->end = end;
	m->pgoff = pgoff;
	snprintf(m->name, sizeof(m->name), "%s", name);
}

static void mod_remove_range(__u32 tgid, __u64 start, __u64 end)
{
	for (size_t i = 0; i < g_nmods; ) {
		struct module *m = &g_mods[i];
		if (m->tgid == tgid && m->start < end && m->end > start)
			*m = g_mods[--g_nmods];               // swap-remove
		else
			i++;
	}
}

// Lowest start among segments of the same file in this process = load base.
static __u64 mod_base(__u32 tgid, const char *name)
{
	__u64 lo = ~0ULL;
	for (size_t i = 0; i < g_nmods; i++)
		if (g_mods[i].tgid == tgid && !strcmp(g_mods[i].name, name) && g_mods[i].start < lo)
			lo = g_mods[i].start;
	return (lo == ~0ULL) ? 0 : lo;
}

static void resolve(__u32 tgid, __u64 addr, char *out, size_t outsz)
{
	for (size_t i = 0; i < g_nmods; i++) {
		struct module *m = &g_mods[i];
		if (m->tgid == tgid && addr >= m->start && addr < m->end) {
			__u64 base = mod_base(tgid, m->name);
			snprintf(out, outsz, "%s+0x%llx", m->name,
				 (unsigned long long)(addr - base));
			return;
		}
	}
	// Unknown => mapped before tracing started (zygote-inherited libc/libart)
	// or an anonymous/JIT region. We deliberately do not fall back to
	// /proc/<pid>/maps.
	snprintf(out, outsz, "0x%llx", (unsigned long long)addr);
}

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

// ---- ring buffer handling ------------------------------------------------

static void handle_syscall(const struct heimdall_syscall_event *e)
{
	printf("==> [%u/%u] %s(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx)\n",
	       e->h.pid, e->h.tid, sysname(e->nr),
	       (unsigned long long)e->args[0], (unsigned long long)e->args[1],
	       (unsigned long long)e->args[2], (unsigned long long)e->args[3],
	       (unsigned long long)e->args[4], (unsigned long long)e->args[5]);

	int n = e->stack_sz / (int)sizeof(__u64);
	char sym[320];
	for (int i = 0; i < n && i < HEIMDALL_MAX_STACK_DEPTH; i++) {
		if (e->stack[i] == 0)
			break;
		resolve(e->h.pid, e->stack[i], sym, sizeof(sym));
		printf("      #%-2d %s\n", i, sym);
	}
	fflush(stdout);
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
		mod_add(m->h.pid, m->start, m->end, m->pgoff, m->name);
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
		mod_remove_range(u->h.pid, u->start, u->end);
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

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr,
			"usage: %s <package> <lib-substring> [activity]\n"
			"  e.g. %s com.example.app librasp.so\n",
			argv[0], argv[0]);
		return 1;
	}
	g_pkg = argv[1];
	g_lib = argv[2];
	const char *activity = (argc > 3) ? argv[3] : NULL;
	g_verbose = getenv("HEIMDALL_VERBOSE") != NULL;

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

	// Arm the UID filter BEFORE the app is launched.
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
	heimdall__destroy(skel);
	free(g_mods);
	return 0;
}
