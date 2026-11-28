// SPDX-License-Identifier: GPL-2.0
// `anubee mark`: timestamped lab-action markers on the tracers' clock.
#ifndef __ANUBEE_LAB_MARK_H
#define __ANUBEE_LAB_MARK_H

#include <stddef.h>

// One JSON line {"type":"lab_mark","ts_ns":<ts>,"label":"<escaped>"}\n into buf.
// Returns bytes written (NUL-terminated), or -1 if label is empty or it won't fit.
int lab_mark_format(char *buf, size_t n, unsigned long long ts_ns, const char *label);

// anubee mark <label> --file PATH. 0 ok, 2 usage error, 1 write error.
int cmd_mark(int argc, char **argv);

#endif /* __ANUBEE_LAB_MARK_H */
