// SPDX-License-Identifier: GPL-2.0
// BPF object for the exfil-burst analyzer: trace openat/openat2 (gated to
// media/credential-classified reads -- arms detection, doesn't count),
// connect (tracks which (tgid,fd) pairs are non-loopback outbound sockets),
// sendto/write/writev (byte-volume accumulation once armed+primed), and
// close (untracks fds). Flags a per-process byte-volume burst to any
// destination shortly after a sensitive-file read -- the syscall-level
// signature for bulk media/credential exfiltration. Unlike
// ransomware_burst, classification is entirely in-kernel: crossing the byte
// threshold IS the detection decision (see design doc for the full
// signal-model rationale -- why byte-volume not distinct-destination-count,
// why a single read arms rather than requiring its own burst).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 * 1024 * 1024);
} events_rb SEC(".maps");

#include "common/uid_filter.bpf.h"
#include "common/pid_filter.bpf.h"
#include "common/follow_fork.bpf.h"
#include "common/path_gate.bpf.h"
#include "common/bpf_drop.bpf.h"
#include "modules/mod_events.h"

#define EXFIL_WINDOW_NS      (30ULL * 1000000000ULL)
#define EXFIL_BYTE_THRESHOLD (512u * 1024u)

// Linux AF_* values -- no <sys/socket.h> in a BPF compile unit, and
// vmlinux.h (BTF-generated) carries types, not macro constants.
#define BPF_AF_INET  2
#define BPF_AF_INET6 10

// Two-stage gate, same shape as file_access.bpf.c's path_is_interesting:
// cheap outer prefix check first (unfiltered openat() is enormous), fine
// substring check only within paths that already pass it. Ported from
// file_access_classify.c's FA_MEDIA_SUBDIR/FA_CREDENTIAL_PATTERN pattern
// lists -- a second, independent copy (BPF can't call the userspace
// classifier); a future change to one must remember the other exists.
// Simplification vs the userspace classifier: the credential-pattern check
// here matches anywhere in the path, not just the basename
// (file_access_classify.c's classify_path() checks the basename only) --
// acceptable because this only gates arming (a soft precondition), not the
// actual byte-volume detection decision.
static __always_inline int path_is_sensitive(const char *path)
{
    int under_storage =
        path_has_prefix(path, "/storage/emulated/", 18) ||
        path_has_prefix(path, "/sdcard/", 8);
    int under_data =
        path_has_prefix(path, "/data/data/", 11) ||
        path_has_prefix(path, "/data/user/", 11);
    if (!under_storage && !under_data)
        return 0;

    if (under_storage) {
        if (path_has_component(path, "/DCIM/", 6))       return 1;
        if (path_has_component(path, "/Download/", 10))  return 1;
        if (path_has_component(path, "/Documents/", 11)) return 1;
        if (path_has_component(path, "/WhatsApp/", 10))  return 1;
        if (path_has_component(path, "/Telegram/", 10))  return 1;
        if (path_has_component(path, "/Pictures/", 10))  return 1;
    }

    if (path_has_component(path, ".keystore", 9)) return 1;
    if (path_has_component(path, "wallet", 6))    return 1;
    if (path_has_component(path, "id_rsa", 6))    return 1;
    if (path_has_component(path, ".pem", 4))      return 1;
    if (path_has_component(path, "cookies", 7))   return 1;
    if (path_has_component(path, "seed", 4))      return 1;

    return 0;
}

struct exfil_state {
    __u64 window_start_ns;
    __u8  primed;
    __u8  _pad[7];
    __u64 bytes_sent;
    char  sample_path[FILE_PATH_LEN];
    unsigned char dest[28];
    __u32 dest_len;
};

// Per-pid exfil state. Only uid/pid-filtered processes that have triggered
// the read-side gate ever get an entry.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, __u32);
	__type(value, struct exfil_state);
} exfil_map SEC(".maps");

// Zero-template seed, same idiom as ransomware_burst.bpf.c's burst_zero --
// struct exfil_state is too large for a safe BPF stack local.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exfil_state);
} exfil_zero SEC(".maps");

// key: (tgid << 32) | fd -> value: 1 ("this fd is a tracked outbound
// socket, opened via a non-loopback connect() observed while this analyzer
// was attached"). Consulted by on_write/on_writev (generic fd syscalls);
// not needed by on_sendto (fd is inherently a socket for that syscall).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, __u8);
} sock_fds SEC(".maps");

// sa is a 28-byte buffer already copied from user memory (sockaddr_in or
// sockaddr_in6, family-tagged in its first 2 bytes -- same "sa_family is
// host byte order" fact decode_sockaddr relies on, common/decode.c).
static __always_inline int sockaddr_is_loopback(const unsigned char *sa)
{
    __u16 fam;
    __builtin_memcpy(&fam, sa, 2);
    if (fam == BPF_AF_INET)
        return sa[4] == 127; // 127.0.0.0/8: first octet is at offset 4 (network order)
    if (fam == BPF_AF_INET6) {
        #pragma unroll
        for (int i = 0; i < 15; i++)
            if (sa[8 + i] != 0)
                return 0;
        return sa[8 + 15] == 1; // ::1
    }
    return 0; // AF_UNIX and anything else: not loopback, no incentive to exclude
}

// Record `n` bytes sent for the current process, once armed+primed. Emits
// an exfil_burst_event and resets the window when the byte threshold trips.
static __always_inline void record_bytes(__u64 n)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 now = bpf_ktime_get_ns();

    struct exfil_state *st = bpf_map_lookup_elem(&exfil_map, &pid);
    if (!st)
        return; // never primed by a sensitive read -- nothing to accumulate

    if (now - st->window_start_ns > EXFIL_WINDOW_NS) {
        // Stale window: the sensitive read that primed this is too old.
        st->primed = 0;
        st->bytes_sent = 0;
        return;
    }
    if (!st->primed)
        return;

    st->bytes_sent += n;
    if (st->bytes_sent < EXFIL_BYTE_THRESHOLD)
        return;

    struct exfil_burst_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e) {
        bump_dropped();
        st->primed = 0;
        st->bytes_sent = 0;
        return;
    }

    __u64 id = bpf_get_current_pid_tgid();
    e->h.type = MOD_EV_EXFIL_BURST;
    e->h.pid  = (__u32)(id >> 32);
    e->h.tid  = (__u32)id;
    e->h._pad = 0;
    e->bytes_sent = st->bytes_sent;
    e->window_ms  = (__u32)((now - st->window_start_ns) / 1000000ULL);
    __builtin_memcpy(e->sample_path, st->sample_path, FILE_PATH_LEN);
    __builtin_memcpy(e->dest, st->dest, sizeof(e->dest));
    e->dest_len = st->dest_len;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    st->primed = 0;
    st->bytes_sent = 0;
}

// Shared body for openat/openat2: gate already checked by caller. Arms (or
// re-arms a stale window on) the per-pid exfil_state, stashes the
// triggering path as the event's eventual sample_path.
static __always_inline void arm_on_sensitive_read(const char *path)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 now = bpf_ktime_get_ns();

    struct exfil_state *st = bpf_map_lookup_elem(&exfil_map, &pid);
    if (!st) {
        __u32 zk = 0;
        struct exfil_state *tmpl = bpf_map_lookup_elem(&exfil_zero, &zk);
        if (!tmpl)
            return;
        if (bpf_map_update_elem(&exfil_map, &pid, tmpl, BPF_NOEXIST) != 0)
            return;
        st = bpf_map_lookup_elem(&exfil_map, &pid);
        if (!st)
            return;
        st->window_start_ns = now;
    } else if (now - st->window_start_ns > EXFIL_WINDOW_NS) {
        st->window_start_ns = now;
        st->bytes_sent = 0;
    }

    st->primed = 1;
    bpf_probe_read_kernel_str(st->sample_path, sizeof(st->sample_path), path);
}

// openat(dirfd, pathname, flags, mode): regs[1]=pathname.
SEC("kprobe/__arm64_sys_openat")
int BPF_KPROBE(on_openat, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    unsigned long path_ptr = BPF_CORE_READ(regs, regs[1]) & 0x00FFFFFFFFFFFFFFul;
    char path[FILE_PATH_LEN];
    long n = bpf_probe_read_user_str(path, sizeof(path), (void *)path_ptr);
    if (n <= 0 || !path_is_sensitive(path))
        return 0;

    arm_on_sensitive_read(path);
    return 0;
}

// openat2(dirfd, pathname, how, size): regs[1]=pathname.
SEC("kprobe/__arm64_sys_openat2")
int BPF_KPROBE(on_openat2, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    unsigned long path_ptr = BPF_CORE_READ(regs, regs[1]) & 0x00FFFFFFFFFFFFFFul;
    char path[FILE_PATH_LEN];
    long n = bpf_probe_read_user_str(path, sizeof(path), (void *)path_ptr);
    if (n <= 0 || !path_is_sensitive(path))
        return 0;

    arm_on_sensitive_read(path);
    return 0;
}

// connect(sockfd, addr, addrlen): regs[0]=sockfd, regs[1]=addr. Entry-only
// -- non-blocking sockets return -EINPROGRESS immediately, so gating on a
// success return would miss most real connects.
SEC("kprobe/__arm64_sys_connect")
int BPF_KPROBE(on_connect, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(id >> 32);
    __s32 fd = (__s32)BPF_CORE_READ(regs, regs[0]);

    unsigned long addr_ptr = BPF_CORE_READ(regs, regs[1]) & 0x00FFFFFFFFFFFFFFul;
    unsigned char sa[28] = {};
    if (bpf_probe_read_user(sa, sizeof(sa), (void *)addr_ptr) != 0)
        return 0;
    if (sockaddr_is_loopback(sa))
        return 0; // exfil has no reason to target itself -- never armed

    __u64 key = ((__u64)tgid << 32) | (__u32)fd;
    __u8 one = 1;
    bpf_map_update_elem(&sock_fds, &key, &one, BPF_ANY);

    struct exfil_state *st = bpf_map_lookup_elem(&exfil_map, &tgid);
    if (st) {
        __builtin_memcpy(st->dest, sa, sizeof(sa));
        st->dest_len = sizeof(sa);
    }
    return 0;
}

// sendto(sockfd, buf, len, flags, dest_addr, addrlen): regs[0]=sockfd,
// regs[2]=len, regs[4]=dest_addr. fd is inherently a socket for this
// syscall (no sock_fds check needed), but unlike write/writev -- which
// only ever run on an fd armed by a prior non-loopback connect() --
// sendto can target an unconnected UDP socket directly via its own
// dest_addr, so the loopback exclusion has to be re-checked here against
// ITS OWN destination, not inherited from sock_fds. dest_addr is optional
// (NULL when reusing an already-connected socket's destination); a NULL
// or unreadable dest_addr counts rather than being excluded -- silently
// under-counting a real exfil send is worse than missing the narrow
// loopback-on-an-already-connected-socket case.
SEC("kprobe/__arm64_sys_sendto")
int BPF_KPROBE(on_sendto, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    unsigned long addr_ptr = BPF_CORE_READ(regs, regs[4]) & 0x00FFFFFFFFFFFFFFul;
    if (addr_ptr) {
        unsigned char sa[28] = {};
        if (bpf_probe_read_user(sa, sizeof(sa), (void *)addr_ptr) == 0 &&
            sockaddr_is_loopback(sa))
            return 0;
    }

    __u64 len = BPF_CORE_READ(regs, regs[2]);
    record_bytes(len);
    return 0;
}

// write(fd, buf, count): regs[0]=fd, regs[2]=count. Generic fd syscall --
// gate on sock_fds first (files/pipes must not count).
SEC("kprobe/__arm64_sys_write")
int BPF_KPROBE(on_write, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(id >> 32);
    __s32 fd = (__s32)BPF_CORE_READ(regs, regs[0]);
    __u64 key = ((__u64)tgid << 32) | (__u32)fd;
    if (!bpf_map_lookup_elem(&sock_fds, &key))
        return 0;

    __u64 count = BPF_CORE_READ(regs, regs[2]);
    record_bytes(count);
    return 0;
}

// writev(fd, iov, iovcnt): regs[0]=fd, regs[1]=iov, regs[2]=iovcnt. Sums
// iov_len across up to 8 entries (bounded, unrolled -- typical writev calls
// use far fewer; extra entries beyond 8 are a documented undercount, not a
// correctness bug).
SEC("kprobe/__arm64_sys_writev")
int BPF_KPROBE(on_writev, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(id >> 32);
    __s32 fd = (__s32)BPF_CORE_READ(regs, regs[0]);
    __u64 key = ((__u64)tgid << 32) | (__u32)fd;
    if (!bpf_map_lookup_elem(&sock_fds, &key))
        return 0;

    unsigned long iov_ptr = BPF_CORE_READ(regs, regs[1]) & 0x00FFFFFFFFFFFFFFul;
    __u64 iovcnt = BPF_CORE_READ(regs, regs[2]);

    __u64 total = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (i >= iovcnt)
            break;
        struct iovec iov;
        if (bpf_probe_read_user(&iov, sizeof(iov),
                                 (void *)(iov_ptr + i * sizeof(struct iovec))) != 0)
            break;
        total += iov.iov_len;
    }
    record_bytes(total);
    return 0;
}

// close(fd): regs[0]=fd. Untrack -- prevents a stale armed entry from
// wrongly gating an unrelated future fd after number reuse. No-op (harmless)
// if the fd was never armed.
SEC("kprobe/__arm64_sys_close")
int BPF_KPROBE(on_close, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(id >> 32);
    __s32 fd = (__s32)BPF_CORE_READ(regs, regs[0]);
    __u64 key = ((__u64)tgid << 32) | (__u32)fd;
    bpf_map_delete_elem(&sock_fds, &key);
    return 0;
}
