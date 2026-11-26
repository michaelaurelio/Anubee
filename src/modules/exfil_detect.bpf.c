// SPDX-License-Identifier: GPL-2.0
// BPF object for the exfil-detect analyzer: trace openat/openat2 (gated to
// media/credential-classified reads -- arms detection, doesn't count) and
// sendto/write/writev/sendmsg/sendmmsg/sendfile (byte-volume accumulation
// once armed+primed, counted
// only when the fd is a socket whose kernel-side peer is a non-loopback
// IPv4/IPv6 address -- see fd_outbound_peer). Flags a per-process byte-volume burst to any
// destination shortly after a sensitive-file read -- the syscall-level
// signature for bulk media/credential exfiltration. Unlike
// massdelete_detect, classification is entirely in-kernel: crossing the byte
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
#include "modules/exfil_detect_addr.h"

#define EXFIL_WINDOW_NS      (30ULL * 1000000000ULL)
#define EXFIL_BYTE_THRESHOLD (512u * 1024u)
// How recent a sensitive-file open must be, relative to the alert firing,
// to be reported as evidence -- narrower than EXFIL_WINDOW_NS (which only
// governs whether an alert fires at all, not what gets reported). Keeps
// the reported file list to plausible candidates for *this* burst instead
// of every sensitive open across the full 30s arming window. See
// docs/analyzers.md's Gotchas entry for what this field does and doesn't
// prove -- it narrows false attribution, it doesn't eliminate it.
#define EXFIL_RECENT_NS       (3ULL * 1000000000ULL)

// <sys/stat.h> file-type bits -- macro constants, not in vmlinux.h.
#define EXFIL_S_IFMT   0170000
#define EXFIL_S_IFSOCK 0140000

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
    char  sensitive_paths[EXFIL_DETECT_RING_LEN][FILE_PATH_LEN];
    __u64 sensitive_ts_ns[EXFIL_DETECT_RING_LEN]; // per-entry open time, kernel-side only -- not exposed in exfil_detect_event
    __u32 sensitive_path_count;
    __u8  paths_truncated;
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

// Zero-template seed, same idiom as massdelete_detect.bpf.c's burst_zero --
// struct exfil_state is too large for a safe BPF stack local.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exfil_state);
} exfil_zero SEC(".maps");

// Resolve fd to its kernel socket and, if the connected peer is a non-loopback
// IPv4/IPv6 address (exfil_addr_is_outbound), fill sa with that peer as a raw
// sockaddr_in/sockaddr_in6 and return 1. Anything else -- not a socket,
// AF_UNIX (logd's logdw gets every Log.* line), unconnected, loopback --
// returns 0 and must not count. Reading the peer from struct sock (the same
// fd -> file -> socket walk Tracee's get_struct_file_from_fd does) instead of
// remembering connect() calls means: sockets connected before the analyzer
// attached (pooled keep-alive connections, -p attach) are still seen, and
// the reported dest is the socket the bytes actually went to.
static __always_inline int fd_outbound_peer(__s32 fd, unsigned char *sa)
{
    if (fd < 0)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
    if (!fdt)
        return 0;
    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    if ((unsigned int)fd >= max_fds)
        return 0;
    struct file **fdarr = BPF_CORE_READ(fdt, fd);
    struct file *f = NULL;
    if (bpf_probe_read_kernel(&f, sizeof(f), &fdarr[fd]) != 0 || !f)
        return 0;
    umode_t mode = BPF_CORE_READ(f, f_inode, i_mode);
    if ((mode & EXFIL_S_IFMT) != EXFIL_S_IFSOCK)
        return 0;
    struct socket *sock = (struct socket *)BPF_CORE_READ(f, private_data);
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    __u16 fam   = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);   // network order, as sin_port
    __builtin_memset(sa, 0, 28);
    if (fam == EXFIL_AF_INET) {
        __be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        if (!exfil_addr_is_outbound(fam, (const unsigned char *)&daddr))
            return 0;
        __builtin_memcpy(sa, &fam, 2);
        __builtin_memcpy(sa + 2, &dport, 2);
        __builtin_memcpy(sa + 4, &daddr, 4);
        return 1;
    }
    if (fam == EXFIL_AF_INET6) {
        struct in6_addr a6;
        BPF_CORE_READ_INTO(&a6, sk, __sk_common.skc_v6_daddr);
        if (!exfil_addr_is_outbound(fam, (const unsigned char *)&a6))
            return 0;
        __builtin_memcpy(sa, &fam, 2);
        __builtin_memcpy(sa + 2, &dport, 2);
        __builtin_memcpy(sa + 8, &a6, 16);
        return 1;
    }
    return 0;
}

// Record `n` bytes sent to outbound peer `sa` (raw sockaddr) for the current
// process, once armed+primed. Emits an exfil_detect_event and resets the
// window when the byte threshold trips; dest is the peer of the send that
// tripped it.
static __always_inline void record_bytes(__u64 n, const unsigned char *sa)
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
    __builtin_memcpy(st->dest, sa, sizeof(st->dest));
    st->dest_len = sizeof(st->dest);
    if (st->bytes_sent < EXFIL_BYTE_THRESHOLD)
        return;

    struct exfil_detect_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e) {
        bump_dropped();
        st->primed = 0;
        st->bytes_sent = 0;
        return;
    }

    __u64 id = bpf_get_current_pid_tgid();
    e->h.type = MOD_EV_EXFIL_DETECT;
    e->h.pid  = (__u32)(id >> 32);
    e->h.tid  = (__u32)id;
    e->h._pad = 0;
    e->ts_ns  = now;
    e->bytes_sent = st->bytes_sent;
    e->window_ms  = (__u32)((now - st->window_start_ns) / 1000000ULL);
    __builtin_memcpy(e->sample_path, st->sample_path, FILE_PATH_LEN);
    // Only report ring entries opened within EXFIL_RECENT_NS of this alert
    // -- older opens get blanked out rather than copied, so the reported
    // evidence stays scoped to plausible candidates for *this* burst
    // instead of every sensitive open across the full 30s arming window.
    // Both read and write use the same compile-time-constant loop index i
    // (never a runtime-computed one) so this stays trivially unrollable/
    // verifier-safe -- an earlier version used a separate, data-dependent
    // output index to pack surviving entries densely, which failed to
    // unroll and blew the verifier's instruction budget by exactly one
    // instruction across on_sendto/on_write/on_writev. sensitive_paths[]
    // can now have blanks at any position, not just a trailing range;
    // consumers (exfil_detect.c, mod_emit.c) iterate the full
    // EXFIL_DETECT_RING_LEN range and skip blank entries rather than
    // trusting sensitive_path_count as a compact-prefix bound.
    __u32 recent_count = 0;
    #pragma unroll
    for (int i = 0; i < EXFIL_DETECT_RING_LEN; i++) {
        if (now - st->sensitive_ts_ns[i] <= EXFIL_RECENT_NS) {
            __builtin_memcpy(e->sensitive_paths[i], st->sensitive_paths[i], FILE_PATH_LEN);
            recent_count++;
        } else {
            e->sensitive_paths[i][0] = '\0';
        }
    }
    e->sensitive_path_count = recent_count;
    e->paths_truncated = st->paths_truncated;
    __builtin_memcpy(e->dest, st->dest, sizeof(e->dest));
    e->dest_len = st->dest_len;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    st->primed = 0;
    st->bytes_sent = 0;
    // Note: sensitive_path_count, paths_truncated, and the ring are deliberately NOT reset here.
    // They reset only on a stale-window in arm_on_sensitive_read; within-window alerts report
    // window-cumulative file count alongside since-last-emit byte count.
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
        st->sensitive_path_count = 0;
        st->paths_truncated = 0;
    }

    st->primed = 1;
    bpf_probe_read_kernel_str(st->sample_path, sizeof(st->sample_path), path);

    __u32 slot = st->sensitive_path_count & (EXFIL_DETECT_RING_LEN - 1);
    bpf_probe_read_kernel_str(st->sensitive_paths[slot], sizeof(st->sensitive_paths[slot]), path);
    st->sensitive_ts_ns[slot] = now;
    if (st->sensitive_path_count >= EXFIL_DETECT_RING_LEN)
        st->paths_truncated = 1;
    st->sensitive_path_count++;
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

// sendto(sockfd, buf, len, flags, dest_addr, addrlen): regs[0]=sockfd,
// regs[2]=len, regs[4]=dest_addr, regs[5]=addrlen. An explicit outbound
// dest_addr (unconnected UDP) counts toward that destination. Otherwise --
// NULL dest_addr (send() on a connected socket), or a local one (AF_UNIX /
// loopback datagram, or one the kernel ignores on a connected stream) -- the
// socket's own connected peer decides, same as write/writev.
SEC("kprobe/__arm64_sys_sendto")
int BPF_KPROBE(on_sendto, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    __s32 fd  = (__s32)BPF_CORE_READ(regs, regs[0]);
    __u64 len = BPF_CORE_READ(regs, regs[2]);
    unsigned char sa[28] = {};

    unsigned long addr_ptr = BPF_CORE_READ(regs, regs[4]) & 0x00FFFFFFFFFFFFFFul;
    if (addr_ptr) {
        // Bounded read sized to the caller's addrlen (masked to a
        // verifier-provable ceiling, clamped to the buffer) so a short
        // sockaddr_in near a page boundary doesn't fault the read.
        __u32 cnt = (__u32)BPF_CORE_READ(regs, regs[5]) & 31;
        if (cnt > sizeof(sa))
            cnt = sizeof(sa);
        if (cnt && bpf_probe_read_user(sa, cnt, (void *)addr_ptr) == 0 &&
            exfil_sockaddr_is_outbound(sa)) {
            record_bytes(len, sa);
            return 0;
        }
    }

    if (!fd_outbound_peer(fd, sa))
        return 0;
    record_bytes(len, sa);
    return 0;
}

// write(fd, buf, count): regs[0]=fd, regs[2]=count. Generic fd syscall --
// only an outbound socket counts (files/pipes/AF_UNIX must not).
SEC("kprobe/__arm64_sys_write")
int BPF_KPROBE(on_write, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    __s32 fd = (__s32)BPF_CORE_READ(regs, regs[0]);
    unsigned char sa[28];
    if (!fd_outbound_peer(fd, sa))
        return 0;

    __u64 count = BPF_CORE_READ(regs, regs[2]);
    record_bytes(count, sa);
    return 0;
}

// Sum of iov_len across up to 8 entries of a user iovec array (bounded,
// unrolled -- typical calls use far fewer; extra entries beyond 8 are a
// documented undercount, not a correctness bug).
static __always_inline __u64 iov_total(unsigned long iov_ptr, __u64 iovcnt)
{
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
    return total;
}

// writev(fd, iov, iovcnt): regs[0]=fd, regs[1]=iov, regs[2]=iovcnt.
SEC("kprobe/__arm64_sys_writev")
int BPF_KPROBE(on_writev, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    __s32 fd = (__s32)BPF_CORE_READ(regs, regs[0]);
    unsigned char sa[28];
    if (!fd_outbound_peer(fd, sa))
        return 0;

    unsigned long iov_ptr = BPF_CORE_READ(regs, regs[1]) & 0x00FFFFFFFFFFFFFFul;
    __u64 iovcnt = BPF_CORE_READ(regs, regs[2]);
    record_bytes(iov_total(iov_ptr, iovcnt), sa);
    return 0;
}

// Destination of a user msghdr: its msg_name if that is an outbound
// IPv4/IPv6 address (unconnected UDP), else the socket's connected peer.
static __always_inline int msghdr_dest(__s32 fd, const struct user_msghdr *m, unsigned char *sa)
{
    unsigned long name = (unsigned long)m->msg_name & 0x00FFFFFFFFFFFFFFul;
    if (name) {
        __u32 cnt = (__u32)m->msg_namelen & 31;
        if (cnt > 28)
            cnt = 28;
        __builtin_memset(sa, 0, 28);
        if (cnt && bpf_probe_read_user(sa, cnt, (void *)name) == 0 &&
            exfil_sockaddr_is_outbound(sa))
            return 1;
    }
    return fd_outbound_peer(fd, sa);
}

// sendmsg(fd, msg, flags): regs[0]=fd, regs[1]=struct user_msghdr *.
SEC("kprobe/__arm64_sys_sendmsg")
int BPF_KPROBE(on_sendmsg, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    __s32 fd = (__s32)BPF_CORE_READ(regs, regs[0]);
    unsigned long mp = BPF_CORE_READ(regs, regs[1]) & 0x00FFFFFFFFFFFFFFul;
    struct user_msghdr m;
    if (bpf_probe_read_user(&m, sizeof(m), (void *)mp) != 0)
        return 0;
    unsigned char sa[28];
    if (!msghdr_dest(fd, &m, sa))
        return 0;
    record_bytes(iov_total((unsigned long)m.msg_iov & 0x00FFFFFFFFFFFFFFul, m.msg_iovlen), sa);
    return 0;
}

// sendmmsg(fd, msgvec, vlen, flags): regs[0]=fd, regs[1]=struct mmsghdr *,
// regs[2]=vlen. Sums up to 8 messages (same undercount bound as writev's
// iovecs); the destination is the first message's.
SEC("kprobe/__arm64_sys_sendmmsg")
int BPF_KPROBE(on_sendmmsg, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    __s32 fd = (__s32)BPF_CORE_READ(regs, regs[0]);
    unsigned long vp = BPF_CORE_READ(regs, regs[1]) & 0x00FFFFFFFFFFFFFFul;
    __u32 vlen = (__u32)BPF_CORE_READ(regs, regs[2]);
    struct mmsghdr mm;
    if (!vlen || bpf_probe_read_user(&mm, sizeof(mm), (void *)vp) != 0)
        return 0;
    unsigned char sa[28];
    if (!msghdr_dest(fd, &mm.msg_hdr, sa))
        return 0;

    __u64 total = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (i >= vlen)
            break;
        if (i && bpf_probe_read_user(&mm, sizeof(mm), (void *)(vp + i * sizeof(struct mmsghdr))) != 0)
            break;
        total += iov_total((unsigned long)mm.msg_hdr.msg_iov & 0x00FFFFFFFFFFFFFFul,
                           mm.msg_hdr.msg_iovlen);
    }
    record_bytes(total, sa);
    return 0;
}

// sendfile(out_fd, in_fd, offset, count): regs[0]=out_fd, regs[3]=count --
// a file streamed to a socket without passing through user memory.
SEC("kprobe/__arm64_sys_sendfile64")
int BPF_KPROBE(on_sendfile, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    __s32 fd = (__s32)BPF_CORE_READ(regs, regs[0]);
    unsigned char sa[28];
    if (!fd_outbound_peer(fd, sa))
        return 0;
    record_bytes(BPF_CORE_READ(regs, regs[3]), sa);
    return 0;
}
