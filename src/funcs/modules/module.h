// SPDX-License-Identifier: GPL-2.0
#ifndef __MODULE_H
#define __MODULE_H

#include "../ares-tracer.h"
#include "../ares-tracer.skel.h"
#include <stddef.h>

typedef struct {
    const char *name;
    const char *description;
    // Called for EVERY module before ares_tracer_bpf__attach() — disables autoattach.
    void (*pre_attach)(struct ares_tracer_bpf *skel);
    // Called only for ACTIVE modules. Returns 0 ok, -1 fatal, -2 degraded (non-fatal).
    int  (*attach)(struct ares_tracer_bpf *skel);
    void (*detach)(void);
    void (*print_summary)(void);  // called once on exit; may be NULL
    // Returns 0 if handled, -1 if event type not recognised by this module.
    int  (*handle_event)(const struct trace_event_header *hdr, const void *data, size_t sz);
} ares_module_t;

extern ares_module_t module_proc_event;
extern ares_module_t module_execve;
extern ares_module_t module_prop_read;

#endif /* __MODULE_H */
