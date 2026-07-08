// SPDX-License-Identifier: GPL-2.0
// Single-process rename+unlink burst trigger for the `mod ransomware-burst`
// device smoke test (scripts/device-test.sh). Deliberately does the 25
// touches itself rather than forking mv/rm per file: burst_map in
// ransomware_burst.bpf.c keys per calling PID, so touches split across many
// short-lived subprocesses never accumulate to BURST_THRESHOLD.
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "/sdcard/.ares_burst_test";
    mkdir(dir, 0777);
    sleep(3); // give the caller time to attach kprobes before the burst
    for (int i = 1; i <= 25; i++) {
        char f[256], f2[256];
        snprintf(f, sizeof(f), "%s/f%d.txt", dir, i);
        snprintf(f2, sizeof(f2), "%s/f%d.txt.locked", dir, i);
        int fd = open(f, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) { write(fd, "x", 1); close(fd); }
        rename(f, f2);
        unlink(f2);
    }
    return 0;
}
