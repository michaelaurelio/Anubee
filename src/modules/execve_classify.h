// SPDX-License-Identifier: GPL-2.0
// The execve analyzer's classifier (src/modules/execve.c): what kind of
// command a process ran, from the binary path and argv -- including every
// command inside a `sh -c "..."` string. libc only -- host-testable.
#ifndef __ANUBEE_EXECVE_CLASSIFY_H
#define __ANUBEE_EXECVE_CLASSIFY_H

#include <stddef.h>

enum {
    EXF_ROOT    = 1 << 0,   // su, magisk, KernelSU/APatch daemons, busybox, resetprop
    EXF_RECON   = 1 << 1,   // getprop, id, pm list, dumpsys, settings get, which ...
    EXF_TAMPER  = 1 << 2,   // setenforce, mount, pm install/grant, settings put, iptables ...
    EXF_CONTROL = 1 << 3,   // am, input, screencap, cmd, svc, monkey ... (drives the device)
    EXF_SHELL   = 1 << 4,   // sh / bash / mksh
    EXF_APP_DIR = 1 << 5,   // binary in an app-writable folder (or a relative path)
    EXF_MEMFD   = 1 << 6,   // run from a file descriptor (/proc/self/fd/N, /dev/fd/N)
};

// Bitmask of EXF_*; 0 = nothing notable. argv may be NULL/argc 0.
unsigned ex_classify(const char *filename, const char *const *argv, int argc);

// "root,recon,..." in bit order (empty string for 0). Always NUL-terminated.
void ex_flag_names(unsigned flags, char *out, size_t cap);

#endif /* __ANUBEE_EXECVE_CLASSIFY_H */
