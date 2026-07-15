// SPDX-License-Identifier: GPL-2.0
// See human_out.h. Moved verbatim out of src/funcs/funcs.c (funcs was the only
// caller); behavior unchanged — same lock, same "HH:MM:SS " timestamp format,
// same output bytes.
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include "common/human_out.h"

static pthread_mutex_t g_out_lock = PTHREAD_MUTEX_INITIALIZER; // stdout/stderr line serializer

// Sticky bottom line (drain progress). Guarded by g_out_lock, same as every
// printer below. stderr, never stdout: the bar is operational status, and
// keeping it off stdout means -q's per-event stdout suppression stays orthogonal
// to it, and a redirected stdout never gets ANSI in it.
static char g_progress[256];
static int  g_progress_on;

// Both require g_out_lock held.
static void progress_clear_locked(void)
{
    if (g_progress_on)
        fputs("\r\033[K", stderr);
}

static void progress_draw_locked(void)
{
    if (!g_progress_on)
        return;
    fflush(stdout);   // the line we just printed must land before the bar
    fputs(g_progress, stderr);
    fflush(stderr);
}

void human_progress_set(const char *line)
{
    pthread_mutex_lock(&g_out_lock);
    progress_clear_locked();
    if (line) {
        snprintf(g_progress, sizeof g_progress, "%s", line);
        g_progress_on = 1;
    } else {
        g_progress_on = 0;
        g_progress[0] = '\0';
    }
    progress_draw_locked();
    pthread_mutex_unlock(&g_out_lock);
}

void out_print(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    pthread_mutex_lock(&g_out_lock);
    progress_clear_locked();
    vprintf(fmt, ap);
    progress_draw_locked();
    pthread_mutex_unlock(&g_out_lock);
    va_end(ap);
}

void err_print(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    pthread_mutex_lock(&g_out_lock);
    progress_clear_locked();
    vfprintf(stderr, fmt, ap);
    progress_draw_locked();
    pthread_mutex_unlock(&g_out_lock);
    va_end(ap);
}

// Top-level event line, prepends "HH:MM:SS " to stdout.
void ts_print(const char *fmt, ...)
{
    time_t t; time(&t);
    char ts_buf[16];
    strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", localtime(&t));
    pthread_mutex_lock(&g_out_lock);
    progress_clear_locked();
    printf("%s ", ts_buf);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    progress_draw_locked();
    pthread_mutex_unlock(&g_out_lock);
}

void human_detail(const char *tag, const char *fmt, ...)
{
    pthread_mutex_lock(&g_out_lock);
    progress_clear_locked();
    printf("         [%s]   | ", tag);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    progress_draw_locked();
    pthread_mutex_unlock(&g_out_lock);
}
