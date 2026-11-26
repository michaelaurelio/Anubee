// SPDX-License-Identifier: GPL-2.0
// Follow-fork trigger for the `mod-follow-fork` device test
// (scripts/device-test.sh). In -p mode a tracked process's children are added
// to the BPF target_pids map (64 slots) when they fork. A thread creation
// fires the same sched_process_fork tracepoint, so a target that creates many
// threads must not use up those slots: this creates FORKFOLLOW_THREADS
// short-lived threads first -- more than the map holds -- and only then forks
// a child that execs /system/bin/true. The test asserts that exec is traced.
#include <pthread.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef FORKFOLLOW_THREADS
#define FORKFOLLOW_THREADS 100
#endif

static void *noop(void *arg) { return arg; }

int main(void)
{
    sleep(3); // give the caller time to attach before the threads/fork
    for (int i = 0; i < FORKFOLLOW_THREADS; i++) {
        pthread_t t;
        if (pthread_create(&t, NULL, noop, NULL) == 0)
            pthread_join(t, NULL);
    }
    pid_t pid = fork();
    if (pid == 0) {
        execl("/system/bin/true", "true", "anubee-forkfollow-child", (char *)NULL);
        _exit(127);
    }
    if (pid > 0)
        waitpid(pid, NULL, 0);
    sleep(2);
    return 0;
}
