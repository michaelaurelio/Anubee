// SPDX-License-Identifier: GPL-2.0
// Shared Android native-library (.so) load tracing.
//
// One implementation of the mmap/munmap capture, /proc/<pid>/maps full-path
// resolution, and the unified "[lib]" emitter, used by all three engines:
//   - `ares lib`     (src/lib)      — standalone library-load tracer
//   - `ares syscalls`(src/syscalls) — feeds its lib_ranges stack-origin filter
//   - `ares funcs`   (src/funcs)    — triggers uprobe attachment on map
//
// The BPF probe lives in lib_trace.bpf.h (source-shared, compiled into each
// engine's own skeleton — the detectability firewall requires per-engine BPF
// objects). The userspace API below is linked once (build/common.part.o).
#ifndef ARES_COMMON_LIB_TRACE_H
#define ARES_COMMON_LIB_TRACE_H

#ifndef __bpf__
#include <linux/types.h>   // __u32/__u64/__s32 in userspace; BPF gets them from vmlinux.h
#endif

#define LIBTRACE_MAX_NAME 128
#define LIBTRACE_VM_EXEC  0x00000004UL   // Linux VMA flag for executable mappings

// Reuses the MAP=2 / UNMAP=4 discriminators already shared by both engines.
enum lib_event_type {
	LIB_EV_MAP   = 2,
	LIB_EV_UNMAP = 4,
};

struct lib_event_header {
	__u32 type;
	__u32 pid;   // thread-group id (process)
	__u32 tid;   // thread id
	__u32 _pad;
};

// An executable, file-backed mapping just appeared (from uprobe_mmap).
struct lib_map_event {
	struct lib_event_header h;
	__u64 start;
	__u64 end;
	__u64 pgoff;                    // file offset in pages
	__u64 vm_flags;
	__u64 inode;
	__u32 dev;
	__s32 ppid;                     // parent tgid
	char  name[LIBTRACE_MAX_NAME];  // BPF basename; fallback when /proc/maps unreadable
};

// A range was unmapped (from uprobe_munmap).
struct lib_unmap_event {
	struct lib_event_header h;
	__u64 start;
	__u64 end;
};

#ifndef __bpf__
#include <stdio.h>
#include <sys/types.h>

// Resolve the full on-disk path of a just-mapped region. Reads /proc/<pid>/maps
// by start address and caches basename->path; on an unreadable maps file, falls
// back to the cache keyed on the BPF-supplied basename. Returns 0 and fills
// `out` on success, -1 if the path could not be resolved.
int ares_libtrace_resolve_path(pid_t pid, unsigned long long start,
                               const char *basename, char *out, size_t outsz);

// Format the unified, MCP-compatible library-load text line (no trailing newline):
//   [lib] pid <N> <fullpath> [0x<start>, 0x<end>) off=0x<pgoff> inode=<N> ppid=<P>[ -> <soname>]
// For callers (e.g. the funcs engine) that route text through their own output
// plumbing rather than the printf-based emitter below. `soname` is an optional
// APK-embedded .so name (NULL to omit).
void ares_libtrace_format_lib(char *buf, size_t bufsz, const struct lib_map_event *e,
                              const char *fullpath, const char *soname);

// Emit one library-load record: the unified line (see format_lib) to stdout unless
// `quiet`; if `jsonl` != NULL also writes a {"type":"lib",...} record.
void ares_libtrace_emit_lib(FILE *jsonl, int quiet, const struct lib_map_event *e,
                            const char *fullpath, const char *soname);

// Emit one unmap record: "[unlib] pid <N> [0x<start>, 0x<end>)" unless `quiet`;
// {"type":"unlib",...} if `jsonl` != NULL.
void ares_libtrace_emit_unlib(FILE *jsonl, int quiet, const struct lib_unmap_event *e);
#endif /* __bpf__ */

#endif /* ARES_COMMON_LIB_TRACE_H */
