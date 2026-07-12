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

void out_print(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    pthread_mutex_lock(&g_out_lock);
    vprintf(fmt, ap);
    pthread_mutex_unlock(&g_out_lock);
    va_end(ap);
}

void err_print(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    pthread_mutex_lock(&g_out_lock);
    vfprintf(stderr, fmt, ap);
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
    printf("%s ", ts_buf);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    pthread_mutex_unlock(&g_out_lock);
}

void human_detail(const char *tag, const char *fmt, ...)
{
    pthread_mutex_lock(&g_out_lock);
    printf("         [%s]   | ", tag);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    pthread_mutex_unlock(&g_out_lock);
}
