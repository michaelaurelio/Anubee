// SPDX-License-Identifier: GPL-2.0
#include "common/launch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern char **environ;

int ares_sh_exec(const char *cmd, char *out, size_t outsz)
{
    int pipefd[2] = { -1, -1 };
	if (out != NULL) {
		out[0] = '\0';
		if (pipe(pipefd) != 0)
			return -1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		if (out != NULL) { close(pipefd[0]); close(pipefd[1]); }
		return -1;
	}

    if (pid == 0) {
		if (out != NULL) {
			dup2(pipefd[1], STDOUT_FILENO);
			close(pipefd[0]);
			close(pipefd[1]);
		} else {
			int devnull = open("/dev/null", O_WRONLY);
			if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); close(devnull); }
		}
		char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, NULL };
		execve("/system/bin/sh", argv, environ);
		_exit(127);
	}

    if (out != NULL) {
		close(pipefd[1]);
		size_t off = 0;
		ssize_t n;
		while (off + 1 < outsz && (n = read(pipefd[0], out + off, outsz - 1 - off)) > 0)
			off += (size_t)n;
		out[off] = '\0';
		close(pipefd[0]);
	}

	int status = 0;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	return status;
}

int ares_resolve_uid(const char *pkg)
{
	const char *roots[] = { "/data/data/%s", "/data/user/0/%s", "/data/user_de/0/%s" };
	for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
		char path[256];
		snprintf(path, sizeof(path), roots[i], pkg);
		struct stat st;
		if (stat(path, &st) == 0)
			return (int)st.st_uid;
	}
	return -1;
}

int ares_get_pid_uid(pid_t pid)
{
	char path[64], line[128];
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	int uid = -1;
	while (fgets(line, sizeof(line), f)) {
		unsigned int ruid;
		if (sscanf(line, "Uid:\t%u", &ruid) == 1) {
			uid = (int)ruid;
			break;
		}
	}
	fclose(f);
	return uid;
}

int ares_resolve_component(const char *pkg, char *out, size_t outsz)
{
	char cmd[512], buf[1024];
	snprintf(cmd, sizeof(cmd), "cmd package resolve-activity --brief %s", pkg);
	if (ares_sh_exec(cmd, buf, sizeof(buf)) < 0)
		return -1;

	out[0] = '\0';
	char *save = NULL;
	for (char *line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (strchr(line, '/') && strstr(line, pkg))     // Get the last "pkg/..." line
			snprintf(out, outsz, "%s", line);
	}
	return out[0] ? 0 : -1;
}

int ares_launch_app(const char *pkg, const char *activity, pid_t *out_pid)
{
	char cmd[512], comp[256];

	// Kill any running instance, then wait for it to actually die so the
	// relaunch starts from a clean state.
	snprintf(cmd, sizeof(cmd), "am force-stop %s", pkg);
	ares_sh_exec(cmd, NULL, 0);

	snprintf(cmd, sizeof(cmd), "pidof %s", pkg);
	for (int i = 0; i < 30; i++) {
		char pid_buf[32] = "";
		ares_sh_exec(cmd, pid_buf, sizeof(pid_buf));
		if (pid_buf[0] == '\0')
			break;
		usleep(100000);
	}

	// Resolve the launchable component (or use the caller-supplied activity).
	if (activity)
		snprintf(comp, sizeof(comp), "%s/%s", pkg, activity);
	else if (ares_resolve_component(pkg, comp, sizeof(comp)) != 0)
		return -1;

	snprintf(cmd, sizeof(cmd), "am start -S -n %s", comp);
	if (ares_sh_exec(cmd, NULL, 0) < 0)
		return -1;

	if (out_pid) {
		*out_pid = 0;
		snprintf(cmd, sizeof(cmd), "pidof %s", pkg);
		for (int i = 0; i < 30; i++) {
			char pid_buf[32] = "";
			ares_sh_exec(cmd, pid_buf, sizeof(pid_buf));
			pid_t p = (pid_t)atoi(pid_buf);
			if (p > 0) { *out_pid = p; return 0; }
			usleep(100000);
		}
		return -1;  // launched but PID never appeared in pidof
	}
	return 0;
}

void ares_launch_banner(const char *pkg, int uid)
{
	printf("launching %s (uid %d)\n", pkg, uid);
}
