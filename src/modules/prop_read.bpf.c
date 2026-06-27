// SPDX-License-Identifier: GPL-2.0
// BPF object for the prop-read analyzer: trace all Android system property API calls.
// Standalone module with no dependency on the funcs engine.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 * 1024 * 1024);
} events_rb SEC(".maps");

#include "common/uid_filter.bpf.h"
#include "modules/mod_events.h"

// prop_read.bpf.c — BPF programs for all Android system property APIs.
//
// Hooks:
//   __system_property_get(name, buf)  → PROP_GET  CALL + RET
//   __system_property_find(name)      → PROP_FIND CALL + RET
//   __system_property_foreach(cb, ck) → PROP_SCAN CALL only
//   __system_property_read_callback   → PROP_READ (one per property in a foreach sweep)
//
// prop_info layout (Android 8+, bionic, stable API 26-35):
//   offset  0: atomic_uint_least32_t serial   (4 bytes)
//   offset  4: char value[92]                 (PROP_VALUE_MAX)
//   offset 96: char name[0]                   (flexible array)

struct prop_entry_ctx {
    __u64 name_ptr;   // arg0 (property name C string pointer)
    __u64 buf_ptr;    // arg1 (output buffer for _get); 0 for _find
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key,   __u32);                   // TID
    __type(value, struct prop_entry_ctx);
} prop_entry_map SEC(".maps");


// Strip ARM64 MTE heap tag and read name + value from a prop_info pointer.
static __always_inline void read_prop_info(
    __u64 pi_raw, char *name, __u32 nsz, char *value, __u32 vsz)
{
    unsigned long pi = pi_raw & 0x00FFFFFFFFFFFFFFul;
    bpf_probe_read_user_str(name,  nsz, (void *)(pi + 96));
    bpf_probe_read_user_str(value, vsz, (void *)(pi + 4));
}

// Reserve a prop_event slot and fill the common header fields.
// Returns NULL on ring buffer exhaustion. Caller must submit or discard.
static __always_inline struct prop_event *reserve_prop_event(__u32 type)
{
    struct prop_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return NULL;
    __u64 id  = bpf_get_current_pid_tgid();
    e->h.type = type;
    e->h.pid  = (__u32)(id >> 32);
    e->h.tid  = (__u32)id;
    e->h._pad = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->name[0]  = '\0';
    e->value[0] = '\0';
    e->is_ret   = 0;
    e->found    = 0;
    e->_pad[0]  = e->_pad[1] = 0;
    return e;
}


// ── __system_property_get(const char *name, char *value) ─────────────────────

SEC("uprobe")
int BPF_KPROBE(on_prop_get, const char *name, char *buf)
{
    if (!uid_matches()) return 0;

    __u64 tid = (__u32)bpf_get_current_pid_tgid();
    struct prop_entry_ctx ectx = { (unsigned long)name, (unsigned long)buf };
    bpf_map_update_elem(&prop_entry_map, &tid, &ectx, BPF_ANY);

    struct prop_event *e = reserve_prop_event(MOD_EV_PROP_GET);
    if (!e) return 0;
    unsigned long name_addr = (unsigned long)name & 0x00FFFFFFFFFFFFFFul;
    bpf_probe_read_user_str(e->name, sizeof(e->name), (void *)name_addr);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(on_prop_get_ret)
{
    if (!uid_matches()) return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct prop_entry_ctx *saved = bpf_map_lookup_elem(&prop_entry_map, &tid);
    if (!saved) return 0;

    struct prop_event *e = reserve_prop_event(MOD_EV_PROP_GET);
    if (!e) { bpf_map_delete_elem(&prop_entry_map, &tid); return 0; }

    e->is_ret = 1;
    unsigned long nptr = saved->name_ptr & 0x00FFFFFFFFFFFFFFul;
    unsigned long vptr = saved->buf_ptr  & 0x00FFFFFFFFFFFFFFul;
    bpf_probe_read_user_str(e->name,  sizeof(e->name),  (void *)nptr);
    bpf_probe_read_user_str(e->value, sizeof(e->value), (void *)vptr);
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&prop_entry_map, &tid);
    return 0;
}


// ── __system_property_find(const char *name) → prop_info* ────────────────────

SEC("uprobe")
int BPF_KPROBE(on_prop_find, const char *name)
{
    if (!uid_matches()) return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct prop_entry_ctx ectx = { (unsigned long)name, 0 };
    bpf_map_update_elem(&prop_entry_map, &tid, &ectx, BPF_ANY);

    struct prop_event *e = reserve_prop_event(MOD_EV_PROP_FIND);
    if (!e) return 0;
    unsigned long name_addr = (unsigned long)name & 0x00FFFFFFFFFFFFFFul;
    bpf_probe_read_user_str(e->name, sizeof(e->name), (void *)name_addr);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(on_prop_find_ret)
{
    if (!uid_matches()) return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct prop_entry_ctx *saved = bpf_map_lookup_elem(&prop_entry_map, &tid);
    if (!saved) return 0;

    struct prop_event *e = reserve_prop_event(MOD_EV_PROP_FIND);
    if (!e) { bpf_map_delete_elem(&prop_entry_map, &tid); return 0; }

    e->is_ret = 1;
    __u64 pi_raw = PT_REGS_RC(ctx);
    if (pi_raw) {
        e->found = 1;
        read_prop_info(pi_raw, e->name, sizeof(e->name), e->value, sizeof(e->value));
    } else {
        // Not found — show the name from the entry lookup
        unsigned long nptr = saved->name_ptr & 0x00FFFFFFFFFFFFFFul;
        bpf_probe_read_user_str(e->name, sizeof(e->name), (void *)nptr);
    }
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&prop_entry_map, &tid);
    return 0;
}


// ── __system_property_foreach(cb, cookie) ────────────────────────────────────

SEC("uprobe")
int BPF_KPROBE(on_prop_fore)
{
    if (!uid_matches()) return 0;
    struct prop_event *e = reserve_prop_event(MOD_EV_PROP_SCAN);
    if (!e) return 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}


// ── __system_property_read_callback(prop_info *pi, cb, cookie) ───────────────

SEC("uprobe")
int BPF_KPROBE(on_prop_read_callback, const void *pi)
{
    if (!uid_matches()) return 0;
    struct prop_event *e = reserve_prop_event(MOD_EV_PROP_READ);
    if (!e) return 0;
    read_prop_info((unsigned long)pi, e->name, sizeof(e->name), e->value, sizeof(e->value));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
