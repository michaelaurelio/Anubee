// SPDX-License-Identifier: GPL-2.0
// Shared userspace side of native-library load tracing: /proc/<pid>/maps
// full-path resolution (with a basename->path fallback cache) and the unified
// "[lib]" text / JSONL emitter. See lib_trace.h for the public API.
#include "common/lib_trace.h"
#include "common/emit.h"
#include "common/maps.h"
#include "common/human_out.h"      // SYM1 Phase 4b: shared stdout formatter

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
		struct anubee_map_line ml;
		if (!anubee_parse_maps_line(line, &ml))
			continue;
		if (ml.start == start) {
			snprintf(out, outsz, "%s", ml.path);
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

int anubee_libtrace_resolve_path(pid_t pid, unsigned long long start,
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

void anubee_libtrace_format_lib(char *buf, size_t bufsz, const struct lib_map_event *e,
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

void anubee_libtrace_emit_lib(struct anubee_sink *sink, int quiet, const struct lib_map_event *e,
                            const char *fullpath, const char *soname)
{
	if (!quiet) {
		char line[512];
		anubee_libtrace_format_lib(line, sizeof(line), e, fullpath, soname);
		ts_print("%s\n", line);  // SYM1 Phase 4b: was printf("%s\n", line)
	}
	if (sink && sink->f) {
		struct jbuf *j = &sink->jb;
		j->len = 0;
		jb_s(j, "{\"type\":\"lib\",\"pid\":"); jb_u64(j, e->h.pid);
		jb_s(j, ",\"tid\":");                  jb_u64(j, e->h.tid);
		jb_s(j, ",\"ppid\":");                 jb_i64(j, e->ppid);
		jb_s(j, ",\"library\":\"");            jb_esc(j, fullpath); jb_c(j, '"');
		jb_s(j, ",\"start\":\"");              jb_hex(j, e->start); jb_c(j, '"');
		jb_s(j, ",\"end\":\"");                jb_hex(j, e->end);   jb_c(j, '"');
		jb_s(j, ",\"pgoff\":");                jb_u64(j, e->pgoff);
		jb_s(j, ",\"inode\":");                jb_u64(j, e->inode);
		if (soname && soname[0]) {
			jb_s(j, ",\"soname\":\""); jb_esc(j, soname); jb_c(j, '"');
		}
		jb_c(j, '}');
		anubee_sink_emit(sink);
	}
}

void anubee_libtrace_emit_unlib(struct anubee_sink *sink, int quiet, const struct lib_unmap_event *e)
{
	if (!quiet)
		// SYM1 Phase 4b: was printf(...).
		ts_print("[unlib] pid %u [0x%llx, 0x%llx)\n",
		       e->h.pid, (unsigned long long)e->start, (unsigned long long)e->end);
	if (sink && sink->f) {
		struct jbuf *j = &sink->jb;
		j->len = 0;
		jb_s(j, "{\"type\":\"unlib\",\"pid\":"); jb_u64(j, e->h.pid);
		jb_s(j, ",\"tid\":");                    jb_u64(j, e->h.tid);
		jb_s(j, ",\"start\":\"");                jb_hex(j, e->start); jb_c(j, '"');
		jb_s(j, ",\"end\":\"");                  jb_hex(j, e->end);   jb_c(j, '"');
		jb_c(j, '}');
		anubee_sink_emit(sink);
	}
}

void anubee_libtrace_emit_packed(struct anubee_sink *sink, int quiet, const char *apk_path,
                               const struct apk_so_ref *ref)
{
	if (!quiet)
		ts_print("[lib-packed] %s -> %s @0x%llx (%llu b)\n", apk_path, ref->name,
		       (unsigned long long)ref->data_start, (unsigned long long)ref->size);
	if (sink && sink->f) {
		struct jbuf *j = &sink->jb;
		j->len = 0;
		jb_s(j, "{\"type\":\"lib_packed\",\"apk\":\""); jb_esc(j, apk_path); jb_c(j, '"');
		jb_s(j, ",\"soname\":\"");                       jb_esc(j, ref->name); jb_c(j, '"');
		jb_s(j, ",\"offset\":");                         jb_u64(j, ref->data_start);
		jb_s(j, ",\"size\":");                           jb_u64(j, ref->size);
		jb_c(j, '}');
		anubee_sink_emit(sink);
	}
}
