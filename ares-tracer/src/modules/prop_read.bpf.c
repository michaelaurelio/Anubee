// Intercepts __system_property_read_callback(prop_info *pi, cb, cookie) in bionic libc.
// Called once per property during a __system_property_foreach sweep.
//
// prop_info layout (Android 8+, bionic, stable across API 26-35):
//   offset  0: atomic_uint_least32_t serial   (4 bytes)
//   offset  4: char value[92]                 (PROP_VALUE_MAX)
//   offset 96: char name[0]                   (flexible array)
SEC("uprobe")
int BPF_KPROBE(on_prop_read_callback, const void *pi, void *cb, void *cookie)
{
    if (!uid_matches())
        return 0;

    struct prop_read_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 id  = bpf_get_current_pid_tgid();
    e->h.type = ARES_EVENT_PROP_READ;
    e->h.pid  = (__u32)(id >> 32);
    e->h.tid  = (__u32)id;
    e->h._pad = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Strip ARM64 MTE heap tag before any bpf_probe_read_user call
    unsigned long pi_addr = (unsigned long)pi & 0x00FFFFFFFFFFFFFFul;
    bpf_probe_read_user_str(e->name,  sizeof(e->name),  (void *)(pi_addr + 96));
    bpf_probe_read_user_str(e->value, sizeof(e->value), (void *)(pi_addr + 4));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
