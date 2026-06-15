// SPDX-License-Identifier: GPL-2.0
// `ares lib` — trace every native library (.so) an Android app loads.
//
// Launches the target package fresh under a UID filter installed before launch,
// so every mapping is caught from the process's first thread (including forked
// children of the same app UID). Capture + path resolution + output are the
// shared module in src/common/lib_trace.*; this file is just the loader and the
// fresh-launch driver.
//
// The device/launch helpers (sh_exec/resolve_uid/resolve_component) are copied
// from the syscalls engine on purpose: consolidating the device layer is a
// separate future pass (see DOCUMENTATION.md §7); this module owns only library
// tracing.
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "lib.skel.h"
#include "common/lib_trace.h"

extern char **environ;

static volatile sig_atomic_t exiting = 0;
static void on_sigint(int sig) { (void)sig; exiting = 1; }

static FILE *g_jsonl = NULL;   // structured JSONL sink (-o), or NULL
static int   g_quiet = 0;      // suppress stdout text
static int   g_verbose = 0;    // -v: also print [unlib] unmap lines on stdout

// ---- running Android tools (no libc system(): /bin/sh is absent) ---------

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

// ---- ring-buffer event handling ------------------------------------------

static int handle_event(void *ctx, void *data, size_t sz)
{
	(void)ctx;
	if (sz < sizeof(struct lib_event_header))
		return 0;
	const struct lib_event_header *h = data;

	if (h->type == LIB_EV_MAP) {
		if (sz < sizeof(struct lib_map_event))
			return 0;
		const struct lib_map_event *e = data;
		char path[256];
		const char *full = path;
		if (ares_libtrace_resolve_path(h->pid, e->start, e->name, path, sizeof(path)) != 0)
			full = e->name;     // fall back to the BPF-supplied basename
		ares_libtrace_emit_lib(g_jsonl, g_quiet, e, full, NULL);
	} else if (h->type == LIB_EV_UNMAP) {
		if (sz < sizeof(struct lib_unmap_event))
			return 0;
		ares_libtrace_emit_unlib(g_jsonl, g_quiet || !g_verbose, data);
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static void usage(void)
{
	fprintf(stderr,
		"usage: ares lib [options] <package> [activity]\n"
		"\n"
		"Launch <package> fresh and trace every native library (.so) it loads.\n"
		"\n"
		"options:\n"
		"  -o, --output FILE   also write structured JSONL ({\"type\":\"lib\",...})\n"
		"  -v, --verbose       also print [unlib] unmap lines (default: [lib] only)\n"
		"  -q, --quiet         suppress the human-readable [lib] lines on stdout\n"
		"  -h, --help          show this help\n");
}

int cmd_lib(int argc, char **argv)
{
	const char *pkg = NULL, *activity = NULL, *out_path = NULL;

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			usage();
			return 0;
		} else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
			g_quiet = 1;
		} else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) {
			g_verbose = 1;
		} else if (!strcmp(a, "-o") || !strcmp(a, "--output")) {
			if (++i >= argc) { fprintf(stderr, "lib: -o needs a FILE\n"); return 1; }
			out_path = argv[i];
		} else if (a[0] == '-') {
			fprintf(stderr, "lib: unknown option '%s'\n", a);
			usage();
			return 1;
		} else if (!pkg) {
			pkg = a;
		} else if (!activity) {
			activity = a;
		} else {
			fprintf(stderr, "lib: unexpected argument '%s'\n", a);
			return 1;
		}
	}

	if (!pkg) {
		usage();
		return 1;
	}

	int uid = resolve_uid(pkg);
	if (uid < 0) {
		fprintf(stderr, "lib: could not resolve UID for '%s' (installed? run as root?)\n", pkg);
		return 1;
	}

	if (out_path) {
		g_jsonl = fopen(out_path, "w");
		if (!g_jsonl) {
			fprintf(stderr, "lib: cannot open '%s': %s\n", out_path, strerror(errno));
			return 1;
		}
	}

	libbpf_set_print(libbpf_print_fn);

	struct ares_lib *skel = ares_lib__open();
	if (!skel) {
		fprintf(stderr, "lib: failed to open BPF skeleton\n");
		goto err_file;
	}
	if (ares_lib__load(skel)) {
		fprintf(stderr, "lib: failed to load BPF (need eBPF privileges / SELinux permissive?)\n");
		goto err_skel;
	}

	// Install the target UID BEFORE launching, so the first mapping is caught.
	__u32 key = 0, vuid = (__u32)uid;
	if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uid), &key, &vuid, BPF_ANY) != 0) {
		fprintf(stderr, "lib: failed to install target UID\n");
		goto err_skel;
	}

	if (ares_lib__attach(skel)) {
		fprintf(stderr, "lib: failed to attach (uprobe_mmap in kallsyms?)\n");
		goto err_skel;
	}

	struct ring_buffer *rb =
		ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "lib: failed to create ring buffer\n");
		goto err_skel;
	}

	// Fresh start: kill any running instance, then launch. Tracing is already
	// armed, so we catch the new process from its first mapping.
	char cmd[512], comp[256];
	snprintf(cmd, sizeof(cmd), "am force-stop %s", pkg);
	sh_exec(cmd, NULL, 0);

	if (activity)
		snprintf(comp, sizeof(comp), "%s/%s", pkg, activity);
	else if (resolve_component(pkg, comp, sizeof(comp)) != 0) {
		fprintf(stderr, "lib: could not resolve launcher activity for '%s'; pass it explicitly\n", pkg);
		goto err_rb;
	}

	snprintf(cmd, sizeof(cmd), "am start -n %s", comp);
	printf("launching: %s\n", cmd);
	if (sh_exec(cmd, NULL, 0) < 0) {
		fprintf(stderr, "lib: launch failed\n");
		goto err_rb;
	}

	signal(SIGINT, on_sigint);
	printf("tracing uid %d (library loads) ... Ctrl-C to stop\n", uid);

	while (!exiting) {
		int err = ring_buffer__poll(rb, 200 /* ms */);
		if (err < 0 && err != -EINTR)
			break;
	}

	ring_buffer__free(rb);
	ares_lib__destroy(skel);
	if (g_jsonl) fclose(g_jsonl);
	return 0;

err_rb:
	ring_buffer__free(rb);
err_skel:
	ares_lib__destroy(skel);
err_file:
	if (g_jsonl) fclose(g_jsonl);
	return 1;
}
