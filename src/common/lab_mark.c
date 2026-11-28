// SPDX-License-Identifier: GPL-2.0
// `anubee mark`: userspace-only (no BPF, writes nothing into any target), so it
// is quiet by construction. A lab harness calls it to timestamp analyst actions
// (launch, grant-begin:<kind>, grant-end:<kind>, stop) for later correlation
// with tracer output. Label convention is the harness's; we only escape it.
#include "common/lab_mark.h"
#include "common/emit.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int lab_mark_format(char *buf, size_t n, unsigned long long ts_ns, const char *label)
{
	if (!label || !*label || !n)
		return -1;
	struct jbuf j = {0};
	jb_s(&j, "{\"type\":\"lab_mark\",\"ts_ns\":");
	jb_u64(&j, ts_ns);
	jb_s(&j, ",\"label\":\"");
	jb_esc(&j, label);
	jb_s(&j, "\"}\n");
	int rc = -1;
	if (!j.err && j.len < n) {
		memcpy(buf, j.b, j.len);
		buf[j.len] = 0;
		rc = (int)j.len;
	}
	free(j.b);
	return rc;
}

static void mark_usage(void)
{
	fprintf(stderr,
		"usage: anubee mark <label> --file PATH\n"
		"  append one {\"type\":\"lab_mark\",...} line stamped with CLOCK_MONOTONIC\n");
}

int cmd_mark(int argc, char **argv)
{
	const char *label = NULL, *path = NULL;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--file") && i + 1 < argc)
			path = argv[++i];
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			mark_usage();
			return 0;
		} else if (argv[i][0] != '-' && !label)
			label = argv[i];
		else {
			mark_usage();
			return 2;
		}
	}
	if (!label || !*label || !path) {
		mark_usage();
		return 2;
	}

	// CLOCK_MONOTONIC is the base bpf_ktime_get_ns() uses, so marks line up
	// with every tracer record's ts_ns without any conversion.
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	unsigned long long ns = (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;

	char line[1024];
	int len = lab_mark_format(line, sizeof line, ns, label);
	if (len < 0) {
		fprintf(stderr, "mark: label too long\n");
		return 2;
	}
	int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
	if (fd < 0) {
		fprintf(stderr, "mark: open %s: %s\n", path, strerror(errno));
		return 1;
	}
	ssize_t w = write(fd, line, (size_t)len);
	int werr = (w != len) ? (w < 0 ? errno : EIO) : 0;
	if (close(fd) < 0 && !werr)
		werr = errno;
	if (werr) {
		fprintf(stderr, "mark: write %s: %s\n", path, strerror(werr));
		return 1;
	}
	return 0;
}
