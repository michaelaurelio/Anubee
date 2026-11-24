// SPDX-License-Identifier: GPL-2.0
// Shared event structs for the anubee mod analyzers. Included by both BPF
// programs (after vmlinux.h, before any libc headers) and userspace analyzer
// files. Must NOT pull <linux/types.h> or libc headers — vmlinux.h already
// provides __u32/__u64; userspace callers include <linux/types.h> first.
//
// MOD_EV_* are BPF-side type tags local to the analyzers. Userspace emitters
// map them to TRACE_* (trace_schema.h) for the stable output schema.
#ifndef __ANUBEE_MOD_EVENTS_H
#define __ANUBEE_MOD_EVENTS_H

#include "common/trace_schema.h"   // struct trace_event_header, TRACE_*

#define TASK_COMM_LEN    32
#define MAX_ARGV_ENTRIES  8
#define MAX_ARGV_STR    128
#define STACK_DEPTH      16
#define PROP_NAME_LEN   128
#define PROP_VALUE_LEN   96
#define FILE_PATH_LEN   256
// RING_LEN > THRESHOLD is load-bearing (see massdelete_detect.bpf.c): the
// per-pid path ring never wraps before a window resets, so at emit time the
// first `touch_count` ring slots are always exactly this window's paths --
// no stale cross-window data, no wraparound bookkeeping needed. RING_LEN must
// also stay a power of two: the slot index is computed with a `& (RING_LEN-1)`
// mask (not `%`) because the BPF verifier can prove a constant-mask AND is
// bounded but can't range-track a non-power-of-2 modulo's multiply/shift
// codegen -- confirmed on-device (-EACCES "unbounded memory access" at 24).
#define MASSDELETE_DETECT_RING_LEN 32
#define MASSDELETE_DETECT_THRESHOLD           20

// Per-pid ring of distinct sensitive files opened while exfil-detect's
// byte-volume window is armed (see exfil_detect.bpf.c). Unlike
// MASSDELETE_DETECT_RING_LEN, there is no threshold-vs-ring-size guarantee
// here: exfil-detect's trigger is bytes-sent, not read-count, so a scan
// touching more distinct sensitive files than this ring holds will wrap and
// lose the earliest entries (see paths_truncated on the event). Sized to
// match MASSDELETE_DETECT_RING_LEN for consistency. Same power-of-two
// requirement as that constant (slot index uses `& (RING_LEN-1)`).
#define EXFIL_DETECT_RING_LEN 32

// Truncated capture buffer for the fileless-detect analyzer's anon_name field
// (see fileless_detect.bpf.c). Not a ring/threshold pair like the burst
// analyzers above -- this is a single fixed-size string buffer, sized to
// comfortably hold ART's own tags (e.g. "dalvik-jit-code-cache" is 22
// bytes) plus headroom for whatever a non-ART caller might have set.
#define FILELESS_DETECT_TAG_LEN 32

// Grace window between an anon+exec mmap candidate landing in pending_map
// and (absent a suppressing dalvik-tagged prctl) graduating into an alert.
// See fileless_detect.bpf.c's two-hook mmap+prctl correlate/suppress design.
#define FILELESS_DETECT_GRACE_NS (250ULL * 1000000ULL)

// BPF map key/value for fileless-detect's pending-alert map: mmap-time state
// that gets suppressed if a matching dalvik-tagged
// prctl(PR_SET_VMA_ANON_NAME) follows within FILELESS_DETECT_GRACE_NS, or
// graduates into an alert if not. Shared between fileless_detect.bpf.c
// (writer, both hooks) and fileless_detect.c (dispatcher-tick reader).
struct fileless_pending_key {
    __u32 pid;
    __u32 _pad;
    __u64 addr;
};

struct fileless_pending_val {
    __u64 ts_ns;
    __u64 size;
    char  comm[TASK_COMM_LEN];
};

// BPF-side event type discriminators (set in h.type by each .bpf.c program).
enum {
    MOD_EV_SPAWN      = 1,
    MOD_EV_PROC_EXIT  = 2,
    MOD_EV_EXECVE     = 3,
    MOD_EV_PROP_GET   = 4,
    MOD_EV_PROP_FIND  = 5,
    MOD_EV_PROP_SCAN  = 6,
    MOD_EV_PROP_READ  = 7,
    MOD_EV_FILE_ACCESS = 8,
    MOD_EV_MASSDELETE_DETECT = 9,
    MOD_EV_EXFIL_DETECT = 10,
    MOD_EV_ACCESSIBILITY_DETECT = 11,
    MOD_EV_FILELESS_DETECT = 12,
    MOD_EV_SCREENCAPTURE_DETECT = 13,
    MOD_EV_BINDER_API = 14,
    MOD_EV_DEXLOAD_DETECT = 15,
};

struct spawn_event {
    struct trace_event_header h;
    __u64 ts_ns;
    __u32 child_pid;
    char  comm[TASK_COMM_LEN];
};

struct proc_exit_event {
    struct trace_event_header h;
    __u64 ts_ns;
    char comm[TASK_COMM_LEN];
    int  exit_code;
};

struct execve_event {
    struct trace_event_header h;
    __u64 ts_ns;
    __u32 argc;
    __u32 stack_depth;
    char  comm[TASK_COMM_LEN];
    char  filename[128];
    char  argv[MAX_ARGV_ENTRIES][MAX_ARGV_STR];
    __u64 call_stack[STACK_DEPTH];
};

struct prop_event {
    struct trace_event_header h;
    __u64 ts_ns;
    char comm[TASK_COMM_LEN];
    char name[PROP_NAME_LEN];
    char value[PROP_VALUE_LEN];
    __u8 is_ret;
    __u8 found;
    __u8 _pad[2];
};

struct file_access_event {
    struct trace_event_header h;
    __u64 ts_ns;
    char  comm[TASK_COMM_LEN];
    char  path[FILE_PATH_LEN];
    __u32 flags;
    __u8  _pad[4];
};

struct massdelete_detect_event {
    struct trace_event_header h;
    __u64  ts_ns;
    char   comm[TASK_COMM_LEN];
    __u32  touch_count;
    __u32  window_ms;
    char   paths[MASSDELETE_DETECT_RING_LEN][FILE_PATH_LEN];
    char   sample_path[FILE_PATH_LEN];
};

struct exfil_detect_event {
    struct trace_event_header h;
    __u64  ts_ns;
    char   comm[TASK_COMM_LEN];
    __u64  bytes_sent;
    __u32  window_ms;
    char   sample_path[FILE_PATH_LEN];
    char   sensitive_paths[EXFIL_DETECT_RING_LEN][FILE_PATH_LEN];
    __u32  sensitive_path_count;
    __u8   paths_truncated;
    unsigned char dest[28];   // raw sockaddr (in/in6) of the peer the tripping send went to
    __u32  dest_len;          // sizeof(dest) when set; 0 only if no outbound send was recorded
};

// First call of each IAccessibilityServiceConnection method by a process (see
// accessibility_detect.bpf.c); repeats are counted in a11y_counts.
struct accessibility_detect_event {
    struct trace_event_header h;
    __u64  ts_ns;
    char   comm[TASK_COMM_LEN];
    __u32  code;
    __u32  _pad;
};
struct a11y_key { __u32 tgid, code; };

struct fileless_detect_event {
    struct trace_event_header h;
    __u64  ts_ns;
    char   comm[TASK_COMM_LEN];
    __u64  start;
    __u64  size;
    char   anon_name[FILELESS_DETECT_TAG_LEN];
};

// First call of each watched (interface, method) by a process (see
// screencapture_detect.bpf.c); also built in userspace for the dumpsys stage.
struct screencapture_detect_event {
    struct trace_event_header h;
    __u64  ts_ns;
    char   comm[TASK_COMM_LEN];
    __u64  token_hash;
    __u32  code;
    __u32  _pad;
};

// binder-api: first outbound transaction of a given (process, interface,
// method) -- or every call, for interfaces userspace put in
// binder_api_always (IContentProvider: the URI differs per call). The kernel
// counts every call (binder_api_counts); userspace decodes the interface
// token and any content:// URI from raw[] (the start of the Parcel) and names
// the method from code.
#define BINDER_API_RAW 1024    // power of two (BPF index masking); room for a content:// URI after the token + AttributionSource
struct binder_api_event {
    struct trace_event_header h;
    __u64  ts_ns;
    __u64  token_hash;        // FNV-1a over the token's UTF-16 bytes; 0 = no token found
    __u32  code;              // transaction code (FIRST_CALL_TRANSACTION + n for AIDL)
    __u32  flags;             // TF_ONE_WAY = 0x01
    __u32  data_size;         // full Parcel size
    __u32  raw_len;           // bytes valid in raw[]
    char   comm[TASK_COMM_LEN];
    unsigned char raw[BINDER_API_RAW];
};

// binder_api_counts key/value (shared by BPF and userspace).
struct binder_api_key {
    __u32 tgid;
    __u32 code;
    __u64 token_hash;
};
struct binder_api_val {
    __u64 count;
    __u64 first_ts_ns;
};

// dexload-detect: a file whose first bytes written are a DEX/CDEX/ZIP/ELF
// header (drop), that file being mapped by any process (load), and unlinked
// (delete) -- see dexload_detect.bpf.c. comp[] is the file's path, leaf
// first, one component per slot (dexload_detect_parse.c joins it).
#define DEXLOAD_COMP_N   16   // power of two (BPF index masking)
#define DEXLOAD_COMP_LEN 48
enum { DEXLOAD_STAGE_DROP = 1, DEXLOAD_STAGE_LOAD = 2, DEXLOAD_STAGE_DELETE = 3 };
struct dexload_detect_event {
    struct trace_event_header h;
    __u64  ts_ns;
    __u64  ino;
    __u32  dev;
    __u8   stage;
    __u8   exec;              // load: mapped with PROT_EXEC
    __u8   ncomp;             // valid comp[] slots (0 for delete)
    __u8   truncated;         // path walk stopped before the root
    unsigned char head[8];    // drop: first bytes written
    char   comm[TASK_COMM_LEN];
    char   comp[DEXLOAD_COMP_N][DEXLOAD_COMP_LEN];
};

// dexload_files map: one entry per dropped payload file.
struct dexload_key { __u64 ino; __u32 dev; __u32 _pad; };
struct dexload_val {
    __u64 drop_ts_ns;
    __u32 pid;
    __u8  loaded, deleted, _p[2];
};

#endif /* __ANUBEE_MOD_EVENTS_H */
