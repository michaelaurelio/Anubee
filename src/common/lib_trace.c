// SPDX-License-Identifier: GPL-2.0
// Shared userspace side of native-library load tracing: /proc/<pid>/maps
// full-path resolution (with a basename->path fallback cache) and the unified
// "[lib]" text / JSONL emitter. See lib_trace.h for the public API.
#include "common/lib_trace.h"

#include <stdio.h>
#include <string.h>

// ---- /proc/<pid>/maps full-path resolution --------------------------------

static int find_path_in_maps(pid_t pid, unsigned long long start, char *out, size_t outsz)
{
	char maps_path[64];
	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	FILE *f = fopen(maps_path, "r");
	if (!f)
		return -1;

	char line[512];
	while (fgets(line, sizeof(line), f)) {
		char perms[5], path[256] = "";
		unsigned long long start_addr;

		if (sscanf(line, "%llx-%*x %4s %*x %*s %*d %255s", &start_addr, perms, path) < 2)
			continue;

		if (start_addr == start) {
			strncpy(out, path, outsz - 1);
			out[outsz - 1] = '\0';
			fclose(f);
			return 0;
		}
	}

	fclose(f);
	return -1;
}

// Small per-pid basename->fullpath cache, consulted when /proc/<pid>/maps is
// momentarily unreadable (a library can map and unmap faster than we can read).
#define PATH_CACHE_PIDS   16
#define PATH_CACHE_NAMES 256

typedef struct {
	char basename[128];
	char fullpath[256];
} path_cache_entry_t;

typedef struct {
	pid_t              pid;
	path_cache_entry_t names[PATH_CACHE_NAMES];
	int                count;
} pid_path_cache_t;

static pid_path_cache_t path_cache[PATH_CACHE_PIDS];
static int              path_cache_pid_count;

static pid_path_cache_t *path_cache_find_pid(pid_t pid)
{
	for (int i = 0; i < path_cache_pid_count; i++)
		if (path_cache[i].pid == pid)
			return &path_cache[i];
	return NULL;
}

static void path_cache_put(pid_t pid, const char *basename, const char *fullpath)
{
	pid_path_cache_t *c = path_cache_find_pid(pid);
	if (!c) {
		if (path_cache_pid_count >= PATH_CACHE_PIDS)
			return;
		c = &path_cache[path_cache_pid_count++];
		c->pid   = pid;
		c->count = 0;
	}
	for (int i = 0; i < c->count; i++) {
		if (strcmp(c->names[i].basename, basename) == 0) {
			strncpy(c->names[i].fullpath, fullpath, sizeof(c->names[i].fullpath) - 1);
			return;
		}
	}
	if (c->count >= PATH_CACHE_NAMES)
		return;
	strncpy(c->names[c->count].basename, basename, sizeof(c->names[c->count].basename) - 1);
	strncpy(c->names[c->count].fullpath, fullpath, sizeof(c->names[c->count].fullpath) - 1);
	c->count++;
}

static int path_cache_lookup(pid_t pid, const char *basename, char *out, size_t outsz)
{
	pid_path_cache_t *c = path_cache_find_pid(pid);
	if (!c)
		return -1;
	for (int i = 0; i < c->count; i++) {
		if (strcmp(c->names[i].basename, basename) == 0) {
			strncpy(out, c->names[i].fullpath, outsz - 1);
			out[outsz - 1] = '\0';
			return 0;
		}
	}
	return -1;
}

int ares_libtrace_resolve_path(pid_t pid, unsigned long long start,
                               const char *basename, char *out, size_t outsz)
{
	if (find_path_in_maps(pid, start, out, outsz) == 0) {
		const char *b = strrchr(out, '/');
		path_cache_put(pid, b ? b + 1 : out, out);
		return 0;
	}
	if (basename && basename[0] && path_cache_lookup(pid, basename, out, outsz) == 0)
		return 0;
	return -1;
}

// ---- unified emitter ------------------------------------------------------

static void json_write_str(FILE *f, const char *s)
{
	fputc('"', f);
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (c == '"' || c == '\\')
			fprintf(f, "\\%c", c);
		else if (c < 0x20)
			fprintf(f, "\\u%04x", c);
		else
			fputc(c, f);
	}
	fputc('"', f);
}

void ares_libtrace_format_lib(char *buf, size_t bufsz, const struct lib_map_event *e,
                              const char *fullpath, const char *soname)
{
	int n = snprintf(buf, bufsz,
	                 "[lib] pid %u %s [0x%llx, 0x%llx) off=0x%llx inode=%llu ppid=%d",
	                 e->h.pid, fullpath,
	                 (unsigned long long)e->start, (unsigned long long)e->end,
	                 (unsigned long long)e->pgoff, (unsigned long long)e->inode, e->ppid);
	if (soname && soname[0] && n > 0 && (size_t)n < bufsz)
		snprintf(buf + n, bufsz - (size_t)n, " -> %s", soname);
}

void ares_libtrace_emit_lib(FILE *jsonl, int quiet, const struct lib_map_event *e,
                            const char *fullpath, const char *soname)
{
	if (!quiet) {
		char line[512];
		ares_libtrace_format_lib(line, sizeof(line), e, fullpath, soname);
		printf("%s\n", line);
	}
	if (jsonl) {
		fprintf(jsonl, "{\"type\":\"lib\",\"pid\":%u,\"tid\":%u,\"ppid\":%d,\"library\":",
		        e->h.pid, e->h.tid, e->ppid);
		json_write_str(jsonl, fullpath);
		fprintf(jsonl,
		        ",\"start\":\"0x%llx\",\"end\":\"0x%llx\",\"pgoff\":%llu,\"inode\":%llu}\n",
		        (unsigned long long)e->start, (unsigned long long)e->end,
		        (unsigned long long)e->pgoff, (unsigned long long)e->inode);
		fflush(jsonl);
	}
}

void ares_libtrace_emit_unlib(FILE *jsonl, int quiet, const struct lib_unmap_event *e)
{
	if (!quiet)
		printf("[unlib] pid %u [0x%llx, 0x%llx)\n",
		       e->h.pid, (unsigned long long)e->start, (unsigned long long)e->end);
	if (jsonl) {
		fprintf(jsonl,
		        "{\"type\":\"unlib\",\"pid\":%u,\"tid\":%u,\"start\":\"0x%llx\",\"end\":\"0x%llx\"}\n",
		        e->h.pid, e->h.tid,
		        (unsigned long long)e->start, (unsigned long long)e->end);
		fflush(jsonl);
	}
}
