// SPDX-License-Identifier: GPL-2.0
// `ares dump` — launch an Android app fresh and dump a (possibly decrypted)
// native library from its live memory, rebuilt into a loadable ELF.
//
// Stealthy, kprobe-based (like `ares lib`): launch the package under a UID
// filter installed before launch, capture mappings with the shared lib_trace
// probe. Two triggers:
//   - default (dump-on-exit): record every app pid; at Ctrl-C/exit, rescan each
//     pid's /proc/<pid>/maps and dump every module matching <pattern> from the
//     still-live (post-decryption) image.
//   - --on-map: dump a matching module the instant it maps (catches transient /
//     short-lived libraries, at the cost of possibly dumping pre-decryption).
//
// The ELF capture + rebuild is src/dump/rebuild.c; capture/path-resolution is
// the shared src/common/lib_trace.*. The device/launch helpers are shared from
// src/common/launch.{c,h} as ares_*.
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

#include "dump.skel.h"
#include "common/lib_trace.h"
#include "common/launch.h"
#include "rebuild.h"

static volatile sig_atomic_t exiting = 0;
static void on_sigint(int sig) { (void)sig; exiting = 1; }

static const char *g_pattern = NULL;   // module pattern to dump (glob/substring)
static const char *g_outdir  = ".";    // -d: output directory
static int g_on_map  = 0;              // --on-map: dump at map time, not on exit
static int g_quiet   = 0;              // -q: suppress progress chatter

// ---- dump-on-exit: record every app pid that maps anything ----------------
static __u32 *g_pids;
static size_t g_pids_n, g_pids_cap;
static void note_pid(__u32 pid)
{
	for (size_t i = 0; i < g_pids_n; i++)
		if (g_pids[i] == pid)
			return;
	if (g_pids_n == g_pids_cap) {
		size_t nc = g_pids_cap ? g_pids_cap * 2 : 16;
		__u32 *np = realloc(g_pids, nc * sizeof(*np));
		if (!np)
			return;
		g_pids = np;
		g_pids_cap = nc;
	}
	g_pids[g_pids_n++] = pid;
}

// ---- dump-on-map: dedup (pid,start) so a module is dumped once -------------
struct seen { __u32 pid; __u64 start; };
static struct seen *g_seen;
static size_t g_seen_n, g_seen_cap;
static int seen_add(__u32 pid, __u64 start)
{
	for (size_t i = 0; i < g_seen_n; i++)
		if (g_seen[i].pid == pid && g_seen[i].start == start)
			return 0;                  // already dumped
	if (g_seen_n == g_seen_cap) {
		size_t nc = g_seen_cap ? g_seen_cap * 2 : 16;
		struct seen *ns = realloc(g_seen, nc * sizeof(*ns));
		if (!ns)
			return 0;
		g_seen = ns;
		g_seen_cap = nc;
	}
	g_seen[g_seen_n].pid = pid;
	g_seen[g_seen_n].start = start;
	g_seen_n++;
	return 1;                              // newly recorded
}

// Device launch/UID helpers (sh_exec / resolve_uid / resolve_component) now live
// in src/common/launch.{c,h} as ares_*; shared across all engines.

// ---- ring-buffer event handling -------------------------------------------

static int handle_event(void *ctx, void *data, size_t sz)
{
	(void)ctx;
	if (sz < sizeof(struct lib_event_header))
		return 0;
	const struct lib_event_header *h = data;
	if (h->type != LIB_EV_MAP)
		return 0;
	if (sz < sizeof(struct lib_map_event))
		return 0;
	const struct lib_map_event *e = data;

	if (!g_on_map) {
		note_pid(h->pid);              // dump-on-exit: defer to the rescan
		return 0;
	}

	// dump-on-map: resolve, match, dump this module once.
	char path[256];
	const char *full = path;
	if (ares_libtrace_resolve_path(h->pid, e->start, e->name, path, sizeof(path)) != 0)
		full = e->name;
	if (!dump_name_matches(g_pattern, full))
		return 0;
	if (!seen_add(h->pid, e->start))
		return 0;
	if (!g_quiet)
		printf("[dump] on-map: pid %u %s @0x%llx\n",
		       h->pid, full, (unsigned long long)e->start);
	dump_one_at((int)h->pid, e->start, full, g_outdir);
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
		"usage: ares dump [options] <package> <pattern> [activity]\n"
		"\n"
		"Launch <package> fresh and dump every loaded native library whose\n"
		"basename matches <pattern> (glob, e.g. 'e_*') from live memory,\n"
		"rebuilding each into a loadable ELF (.so).\n"
		"\n"
		"options:\n"
		"  -d, --dump-dir DIR  output directory (default: current dir)\n"
		"      --on-map        dump the instant a matching library maps\n"
		"                      (default: dump on exit, post-decryption)\n"
		"      --raw           emit the raw phdr-fixed image, skip ELF rebuild\n"
		"  -q, --quiet         suppress progress chatter\n"
		"  -h, --help          show this help\n");
}

int cmd_dump(int argc, char **argv)
{
	const char *pkg = NULL, *activity = NULL;

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			usage();
			return 0;
		} else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
			g_quiet = 1;
		} else if (!strcmp(a, "--on-map")) {
			g_on_map = 1;
		} else if (!strcmp(a, "--raw")) {
			dump_set_raw(1);
		} else if (!strcmp(a, "-d") || !strcmp(a, "--dump-dir")) {
			if (++i >= argc) { fprintf(stderr, "dump: -d needs a DIR\n"); return 1; }
			g_outdir = argv[i];
		} else if (a[0] == '-') {
			fprintf(stderr, "dump: unknown option '%s'\n", a);
			usage();
			return 1;
		} else if (!pkg) {
			pkg = a;
		} else if (!g_pattern) {
			g_pattern = a;
		} else if (!activity) {
			activity = a;
		} else {
			fprintf(stderr, "dump: unexpected argument '%s'\n", a);
			return 1;
		}
	}

	if (!pkg || !g_pattern) {
		usage();
		return 1;
	}

	int uid = ares_resolve_uid(pkg);
	if (uid < 0) {
		fprintf(stderr, "dump: could not resolve UID for '%s' (installed? run as root?)\n", pkg);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	struct ares_dump *skel = ares_dump__open();
	if (!skel) {
		fprintf(stderr, "dump: failed to open BPF skeleton\n");
		return 1;
	}
	if (ares_dump__load(skel)) {
		fprintf(stderr, "dump: failed to load BPF (need eBPF privileges / SELinux permissive?)\n");
		goto err_skel;
	}

	__u32 key = 0, vuid = (__u32)uid;
	if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uid), &key, &vuid, BPF_ANY) != 0) {
		fprintf(stderr, "dump: failed to install target UID\n");
		goto err_skel;
	}

	if (ares_dump__attach(skel)) {
		fprintf(stderr, "dump: failed to attach (uprobe_mmap in kallsyms?)\n");
		goto err_skel;
	}

	struct ring_buffer *rb =
		ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "dump: failed to create ring buffer\n");
		goto err_skel;
	}

	char cmd[512], comp[256];
	snprintf(cmd, sizeof(cmd), "am force-stop %s", pkg);
	ares_sh_exec(cmd, NULL, 0);

	if (activity)
		snprintf(comp, sizeof(comp), "%s/%s", pkg, activity);
	else if (ares_resolve_component(pkg, comp, sizeof(comp)) != 0) {
		fprintf(stderr, "dump: could not resolve launcher activity for '%s'; pass it explicitly\n", pkg);
		goto err_rb;
	}

	snprintf(cmd, sizeof(cmd), "am start -n %s", comp);
	printf("launching: %s\n", cmd);
	if (ares_sh_exec(cmd, NULL, 0) < 0) {
		fprintf(stderr, "dump: launch failed\n");
		goto err_rb;
	}

	signal(SIGINT, on_sigint);
	printf("tracing uid %d, dumping '%s' (%s) ... Ctrl-C to stop\n",
	       uid, g_pattern, g_on_map ? "on map" : "on exit");

	while (!exiting) {
		int err = ring_buffer__poll(rb, 200 /* ms */);
		if (err < 0 && err != -EINTR)
			break;
	}

	// dump-on-exit: rescan each recorded pid's maps and dump matching modules.
	if (!g_on_map) {
		if (g_pids_n == 0)
			fprintf(stderr, "[dump] no app process mapped anything\n");
		int total = 0;
		for (size_t i = 0; i < g_pids_n; i++) {
			int d = dump_pid_modules((int)g_pids[i], g_pattern, g_outdir);
			if (d > 0)
				total += d;
		}
		fprintf(stderr, "[dump] wrote %d module image%s matching '%s' to %s\n",
			total, total == 1 ? "" : "s", g_pattern, g_outdir);
	}

	ring_buffer__free(rb);
	ares_dump__destroy(skel);
	free(g_pids);
	free(g_seen);
	return 0;

err_rb:
	ring_buffer__free(rb);
err_skel:
	ares_dump__destroy(skel);
	free(g_pids);
	free(g_seen);
	return 1;
}
