# Graph Report - .  (2026-06-23)

## Corpus Check
- Large corpus: 185 files · ~1,024,087 words. Semantic extraction will be expensive (many Claude tokens). Consider running on a subfolder.

## Summary
- 2109 nodes · 5473 edges · 143 communities (130 shown, 13 thin omitted)
- Extraction: 82% EXTRACTED · 18% INFERRED · 0% AMBIGUOUS · INFERRED: 972 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 51|Community 51]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]
- [[_COMMUNITY_Community 54|Community 54]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 60|Community 60]]
- [[_COMMUNITY_Community 61|Community 61]]
- [[_COMMUNITY_Community 62|Community 62]]
- [[_COMMUNITY_Community 63|Community 63]]
- [[_COMMUNITY_Community 64|Community 64]]
- [[_COMMUNITY_Community 65|Community 65]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 67|Community 67]]
- [[_COMMUNITY_Community 68|Community 68]]
- [[_COMMUNITY_Community 69|Community 69]]
- [[_COMMUNITY_Community 70|Community 70]]
- [[_COMMUNITY_Community 71|Community 71]]
- [[_COMMUNITY_Community 72|Community 72]]
- [[_COMMUNITY_Community 73|Community 73]]
- [[_COMMUNITY_Community 74|Community 74]]
- [[_COMMUNITY_Community 75|Community 75]]
- [[_COMMUNITY_Community 76|Community 76]]
- [[_COMMUNITY_Community 77|Community 77]]
- [[_COMMUNITY_Community 78|Community 78]]
- [[_COMMUNITY_Community 81|Community 81]]
- [[_COMMUNITY_Community 83|Community 83]]
- [[_COMMUNITY_Community 84|Community 84]]
- [[_COMMUNITY_Community 85|Community 85]]
- [[_COMMUNITY_Community 87|Community 87]]
- [[_COMMUNITY_Community 88|Community 88]]
- [[_COMMUNITY_Community 95|Community 95]]
- [[_COMMUNITY_Community 96|Community 96]]

## God Nodes (most connected - your core abstractions)
1. `libbpf_err()` - 152 edges
2. `__u32` - 51 edges
3. `btf_type_by_id()` - 48 edges
4. `libbpf_err_errno()` - 40 edges
5. `__u32` - 40 edges
6. `btf__type_cnt()` - 39 edges
7. `__u32` - 38 edges
8. `bpf_map_lookup_elem()` - 34 edges
9. `libbpf_reallocarray()` - 34 edges
10. `libbpf_err_ptr()` - 34 edges

## Surprising Connections (you probably didn't know these)
- `on_proc_exit()` --calls--> `bpf_map_delete_elem()`  [INFERRED]
  src/funcs/modules/proc_event.bpf.c → third_party/libbpf/src/bpf.c
- `syscalls__destroy()` --calls--> `bpf_object__destroy_skeleton()`  [INFERRED]
  build/syscalls.skel.h → third_party/libbpf/src/libbpf.c
- `syscalls__open_opts()` --calls--> `bpf_object__open_skeleton()`  [INFERRED]
  build/syscalls.skel.h → third_party/libbpf/src/libbpf.c
- `syscalls__load()` --calls--> `bpf_object__load_skeleton()`  [INFERRED]
  build/syscalls.skel.h → third_party/libbpf/src/libbpf.c
- `syscalls__attach()` --calls--> `bpf_object__attach_skeleton()`  [INFERRED]
  build/syscalls.skel.h → third_party/libbpf/src/libbpf.c

## Import Cycles
- None detected.

## Communities (143 total, 13 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.06
Nodes (83): bpf_prog_linfo__free(), bpf_prog_linfo__lfind(), bpf_prog_linfo__lfind_addr_func(), bpf_prog_linfo__new(), dissect_jited_func(), add_data(), add_kfunc_btf_fd(), add_map_fd() (+75 more)

### Community 1 - "Community 1"
Cohesion: 0.03
Nodes (55): kallsyms_cb_t, add_jt_map(), __base_pr(), bpf_link__detach(), bpf_link__detach_fd(), bpf_link__fd(), bpf_link__unpin(), __bpf_map__iter() (+47 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (67): bpf_gen__record_extern(), bpf_gen__record_relo_core(), bpf_program_record_relos(), bpf_program__set_insns(), find_extern_btf_id(), btf_func_linkage(), libbpf_reallocarray(), libbpf_register_prog_handler() (+59 more)

### Community 3 - "Community 3"
Cohesion: 0.11
Nodes (62): btf_dump_printf_fn_t, btf__align_of(), btf_dump_add_emit_queue_id(), btf_dump_array_data(), btf_dump_base_type_check_zero(), btf_dump_bitfield_check_zero(), btf_dump_bitfield_data(), btf_dump_data_newline() (+54 more)

### Community 4 - "Community 4"
Cohesion: 0.10
Nodes (60): alloc_zero_tailing_info(), bpf_btf_get_fd_by_id(), bpf_btf_get_fd_by_id_opts(), bpf_btf_get_info_by_fd(), bpf_btf_get_next_id(), bpf_btf_load(), bpf_enable_stats(), bpf_iter_create() (+52 more)

### Community 5 - "Community 5"
Cohesion: 0.07
Nodes (49): GElf_Nhdr, GElf_Shdr, str_hash_fn(), elf_close(), elf_find_func_offset(), elf_find_func_offset_from_file(), elf_find_next_scn_by_type(), elf_get_vername() (+41 more)

### Community 6 - "Community 6"
Cohesion: 0.09
Nodes (53): __dump_nlmsg_t, libbpf_dump_nlmsg_t, qdisc_config_t, alloc_iov(), attach_point_to_config(), __bpf_set_link_xdp_fd_replace(), bpf_tc_attach(), __bpf_tc_detach() (+45 more)

### Community 7 - "Community 7"
Cohesion: 0.09
Nodes (54): btf__add_decl_attr(), btf_add_type_idx_entry(), btf_add_type_offs_mem(), btf_compat_array(), btf_compat_enum(), btf_compat_fnproto(), btf_dedup_clear_hypot_map(), btf_dedup_identical_types() (+46 more)

### Community 8 - "Community 8"
Cohesion: 0.05
Nodes (53): adjust_ringbuf_sz(), array_map_mmap_sz(), bpf_map__btf_key_type_id(), bpf_map__btf_value_type_id(), bpf_map__ifindex(), bpf_map__key_size(), bpf_map__map_flags(), bpf_map_mmap_resize() (+45 more)

### Community 9 - "Community 9"
Cohesion: 0.09
Nodes (49): Elf64_Rel, Elf_Data, add_dummy_ksym_var(), bpf_object__add_programs(), bpf_object_bswap_progs(), bpf_object__collect_externs(), bpf_object__collect_map_relos(), bpf_object__collect_prog_relos() (+41 more)

### Community 10 - "Community 10"
Cohesion: 0.08
Nodes (47): ERR_PTR(), IS_ERR(), IS_ERR_OR_NULL(), PTR_ERR(), PTR_ERR_OR_ZERO(), btf_check_sorted(), btf_dedup_strings(), btf_ext__free() (+39 more)

### Community 11 - "Community 11"
Cohesion: 0.08
Nodes (38): btf_enum64_value(), btf_int_bits(), btf_int_encoding(), btf_int_offset(), btf_is_any_enum(), btf_is_array(), btf_is_composite(), btf_is_const() (+30 more)

### Community 12 - "Community 12"
Cohesion: 0.08
Nodes (38): btf_enum64_value(), btf_int_bits(), btf_int_encoding(), btf_int_offset(), btf_is_any_enum(), btf_is_array(), btf_is_composite(), btf_is_const() (+30 more)

### Community 13 - "Community 13"
Cohesion: 0.10
Nodes (20): check(), main(), _body_desc(), _build_events(), _clamp(), _collect_loops(), _errname(), _find_runs() (+12 more)

### Community 14 - "Community 14"
Cohesion: 0.10
Nodes (40): off_t, Elf64_Shdr, add_symbols(), arena_add(), art_get(), art_locate(), art_refresh(), art_reset() (+32 more)

### Community 15 - "Community 15"
Cohesion: 0.07
Nodes (42): perf_buffer_event_fn, bpf_gen__record_attach_target(), attach_iter(), attach_kprobe(), attach_lsm(), attach_raw_tp(), attach_tp(), attach_trace() (+34 more)

### Community 16 - "Community 16"
Cohesion: 0.16
Nodes (42): btf__add_array(), btf__add_btf(), btf_add_composite(), btf__add_const(), btf__add_datasec(), btf__add_datasec_var_info(), btf_add_decl_tag(), btf_add_distilled_types() (+34 more)

### Community 17 - "Community 17"
Cohesion: 0.06
Nodes (42): btf__fd(), bpf_map__attach_struct_ops(), bpf_map__destroy(), bpf_map__init_kern_struct_ops(), bpf_map__initial_value(), bpf_map__inner_map(), bpf_map__is_internal(), bpf_map__is_struct_ops() (+34 more)

### Community 18 - "Community 18"
Cohesion: 0.10
Nodes (39): libbpf_print_fn_t, bpf_program__attach_kprobe(), libbpf_set_print(), sig_atomic_t, __u32, __u64, arg_count(), arg_fd_mask() (+31 more)

### Community 19 - "Community 19"
Cohesion: 0.12
Nodes (36): bpf_map_create(), bpf_prog_load(), bump_rlimit_memlock(), probe_sys_bpf_ext(), sys_bpf_ext(), sys_bpf_ext_fd(), sys_bpf_prog_load(), feat_supported() (+28 more)

### Community 20 - "Community 20"
Cohesion: 0.17
Nodes (35): bpf_core_types_are_compat(), bpf_core_types_match(), bpf_object__resolve_ksym_var_btf_id(), bpf_core_calc_enumval_relo(), bpf_core_calc_field_relo(), bpf_core_calc_relo(), bpf_core_calc_relo_insn(), bpf_core_calc_type_relo() (+27 more)

### Community 21 - "Community 21"
Cohesion: 0.10
Nodes (36): __s32, btf__add_enum64(), btf__add_struct(), btf__add_union(), btf_bswap_hdr(), btf_bswap_type_base(), btf_bswap_type_rest(), btf_dedup_compact_types() (+28 more)

### Community 22 - "Community 22"
Cohesion: 0.06
Nodes (32): diff_traces(), distinct_backtraces(), dump_library(), errors(), files(), get_event(), hot_loops(), load_trace() (+24 more)

### Community 23 - "Community 23"
Cohesion: 0.11
Nodes (32): bpf_link, add_kprobe_event_legacy(), add_uprobe_event_legacy(), append_to_file(), arch_specific_syscall_pfx(), attach_ksyscall(), attach_uprobe(), bpf_link_perf_detach() (+24 more)

### Community 24 - "Community 24"
Cohesion: 0.15
Nodes (27): btf_add_distilled_type_ids(), btf__base_btf(), btf_dedup_remap_types(), btf_ext_visit_str_offs(), btf_ext_visit_type_ids(), btf_for_each_str_off(), btf_header(), btf_set_base_btf() (+19 more)

### Community 25 - "Community 25"
Cohesion: 0.10
Nodes (19): ex_attach(), ex_detach(), ex_pre_attach(), pe_attach(), pe_detach(), pe_pre_attach(), find_symbol_in_elf(), is_rasp_prop() (+11 more)

### Community 26 - "Community 26"
Cohesion: 0.12
Nodes (22): ns_elapsed_timespec(), ring__avail_data_size(), ring_buffer__consume(), ring_buffer__consume_n(), ring_buffer__poll(), ring__consume(), ring__consume_n(), ring__consumer_pos() (+14 more)

### Community 27 - "Community 27"
Cohesion: 0.18
Nodes (24): apk_cache_t, error_t, apk_cache_get(), apk_resolve_offset(), apply_custom_specs_for_file(), cmd_funcs(), copy_str(), err_print() (+16 more)

### Community 28 - "Community 28"
Cohesion: 0.14
Nodes (26): bpf_link_create(), bpf_link_update(), bpf_prog_assoc_struct_ops(), libbpf_set_memlock_rlim(), bpf_link__update_map(), bpf_link__update_program(), bpf_map__delete_elem(), bpf_map__get_next_key() (+18 more)

### Community 29 - "Community 29"
Cohesion: 0.15
Nodes (22): _adb(), _adb_shell(), aggregate_libraries(), _check_pkg(), _clamp_seconds(), _diagnose(), dump_library(), _elf_info() (+14 more)

### Community 30 - "Community 30"
Cohesion: 0.15
Nodes (19): body_oneline(), ev_callsite(), ev_token(), find_runs(), fold(), fold_once(), load_trace(), main() (+11 more)

### Community 31 - "Community 31"
Cohesion: 0.17
Nodes (19): ares_correlate__attach(), ares_correlate__create_skeleton(), ares_correlate__destroy(), ares_correlate__detach(), ares_correlate__elf_bytes(), ares_correlate__load(), ares_correlate__open(), ares_correlate__open_and_load() (+11 more)

### Community 32 - "Community 32"
Cohesion: 0.19
Nodes (16): bpf_load_and_run(), close(), skel_closenz(), skel_finalize_map_data(), skel_free_map_data(), skel_link_create(), skel_map_create(), skel_map_delete_elem() (+8 more)

### Community 33 - "Community 33"
Cohesion: 0.15
Nodes (20): hashmap_equal_fn, hashmap_hash_fn, btf__dedup(), btf_dedup_fill_unique_names_map(), btf_dedup_free(), btf_dedup_new(), btf_dedup_prim_types(), btf_dedup_ref_types() (+12 more)

### Community 34 - "Community 34"
Cohesion: 0.19
Nodes (16): bpf_load_and_run(), close(), skel_closenz(), skel_finalize_map_data(), skel_free_map_data(), skel_link_create(), skel_map_create(), skel_map_delete_elem() (+8 more)

### Community 35 - "Community 35"
Cohesion: 0.13
Nodes (20): libbpf_ensure_mem(), attach_kprobe_multi(), attach_kprobe_session(), avail_kallsyms_cb(), bpf_core_essential_name_len(), bpf_core_is_flavor_sep(), bpf_object__resolve_ksym_func_btf_id(), bpf_object__resolve_ksyms_btf_id() (+12 more)

### Community 36 - "Community 36"
Cohesion: 0.16
Nodes (15): bpf_usdt_arg(), bpf_usdt_arg_cnt(), bpf_usdt_arg_size(), bpf_usdt_cookie(), __bpf_usdt_spec_id(), __always_inline, __u64, ares_drops_read() (+7 more)

### Community 37 - "Community 37"
Cohesion: 0.21
Nodes (19): bpf_obj_pin(), bpf_link__pin(), bpf_map__name(), bpf_map__pin(), bpf_map__set_pin_path(), bpf_map__unpin(), bpf_object__pin(), bpf_object__pin_maps() (+11 more)

### Community 38 - "Community 38"
Cohesion: 0.20
Nodes (16): ares_dump__attach(), ares_dump__create_skeleton(), ares_dump__destroy(), ares_dump__detach(), ares_dump__elf_bytes(), ares_dump__load(), ares_dump__open(), ares_dump__open_and_load() (+8 more)

### Community 39 - "Community 39"
Cohesion: 0.20
Nodes (16): ares_lib__attach(), ares_lib__create_skeleton(), ares_lib__destroy(), ares_lib__detach(), ares_lib__elf_bytes(), ares_lib__load(), ares_lib__open(), ares_lib__open_and_load() (+8 more)

### Community 40 - "Community 40"
Cohesion: 0.20
Nodes (16): attach(), destroy(), detach(), elf_bytes(), load(), open(), open_and_load(), syscalls__attach() (+8 more)

### Community 41 - "Community 41"
Cohesion: 0.16
Nodes (13): BPF_KPROBE(), BPF_KRETPROBE(), bump_dropped(), is_user_ptr(), uid_matches(), BPF_KPROBE(), on_proc_exit(), on_execve (+5 more)

### Community 42 - "Community 42"
Cohesion: 0.20
Nodes (16): ares_tracer_bpf__attach(), ares_tracer_bpf__create_skeleton(), ares_tracer_bpf__destroy(), ares_tracer_bpf__detach(), ares_tracer_bpf__elf_bytes(), ares_tracer_bpf__load(), ares_tracer_bpf__open(), ares_tracer_bpf__open_and_load() (+8 more)

### Community 43 - "Community 43"
Cohesion: 0.14
Nodes (17): libbpf_print_fn(), LLVMFuzzerTestOneInput(), bpf_gen__free(), bpf_object__close(), bpf_object__elf_finish(), bpf_object__elf_init(), bpf_object_fixup_btf(), bpf_object__init_prog() (+9 more)

### Community 44 - "Community 44"
Cohesion: 0.14
Nodes (18): adjust_prog_btf_ext_info(), append_subprog_relos(), bpf_object__append_subprog_code(), bpf_object__free_relocs(), bpf_object__load_progs(), bpf_object__next_program(), bpf_object__prev_program(), bpf_object__reloc_code() (+10 more)

### Community 45 - "Community 45"
Cohesion: 0.12
Nodes (18): arch_specific_lib_paths(), attach_usdt(), bpf_object__btf(), bpf_object__find_map_by_name(), bpf_object__find_map_fd_by_name(), bpf_object__find_program_by_name(), bpf_object__name(), bpf_object__open_skeleton() (+10 more)

### Community 46 - "Community 46"
Cohesion: 0.26
Nodes (15): bits_str(), dec_bits(), dec_clone(), dec_enum(), dec_mode(), dec_open(), dec_signal(), dec_socktype() (+7 more)

### Community 47 - "Community 47"
Cohesion: 0.27
Nodes (16): copy_str(), custom_spec_matches_path(), func_matches(), is_duplicate(), mod_matches(), parse_custom_probe_spec(), resolve_custom_spec_for_path(), resolve_targets() (+8 more)

### Community 48 - "Community 48"
Cohesion: 0.24
Nodes (15): basename_of(), build_shdrs(), dump_name_matches(), dump_one(), dump_one_at(), dump_pid_modules(), dyn_tag_is_ptr(), load_base_of() (+7 more)

### Community 49 - "Community 49"
Cohesion: 0.28
Nodes (9): jb_b64(), jb_c(), jb_esc(), jb_hex(), jb_i64(), jb_need(), jb_raw(), jb_s() (+1 more)

### Community 50 - "Community 50"
Cohesion: 0.18
Nodes (14): BPF_KPROBE(), BPF_KRETPROBE(), read_prop_info(), reserve_prop_event(), on_prop_find, on_prop_find_ret, on_prop_fore, on_prop_get (+6 more)

### Community 51 - "Community 51"
Cohesion: 0.30
Nodes (13): on_svc_enter, on_sys_exit, __always_inline, __u32, __u64, BPF_KPROBE(), BPF_KRETPROBE(), bump_dropped() (+5 more)

### Community 52 - "Community 52"
Cohesion: 0.20
Nodes (10): bpf_tail_call_static(), bpf_usdt_arg(), bpf_usdt_arg_cnt(), bpf_usdt_arg_size(), bpf_usdt_cookie(), __bpf_usdt_spec_id(), __always_inline, __u32 (+2 more)

### Community 53 - "Community 53"
Cohesion: 0.20
Nodes (11): attach_uprobes_for_pid(), cmd_correlate(), handle_event(), install_uid(), libbpf_print_fn(), syscall_name(), usage(), custom_probe_spec_t (+3 more)

### Community 54 - "Community 54"
Cohesion: 0.32
Nodes (12): ares_libtrace_emit_lib(), ares_libtrace_emit_unlib(), ares_libtrace_format_lib(), ares_libtrace_resolve_path(), find_path_in_maps(), json_write_str(), path_cache_find_pid(), path_cache_lookup() (+4 more)

### Community 55 - "Community 55"
Cohesion: 0.41
Nodes (12): span_depth_set(), span_next_id(), span_stack_clear(), span_stack_pop(), span_stack_push(), span_stack_reconcile(), span_stack_top_id(), bpf_map_delete_elem() (+4 more)

### Community 56 - "Community 56"
Cohesion: 0.19
Nodes (13): perf_buffer_lost_fn, perf_buffer_sample_fn, bpf_map_get_info_by_fd(), bpf_get_map_info_from_fdinfo(), bpf_map__reuse_fd(), bpf_object__reuse_map(), map_is_reuse_compat(), parse_cpu_mask_file() (+5 more)

### Community 57 - "Community 57"
Cohesion: 0.23
Nodes (9): cmd_dump(), handle_event(), libbpf_print_fn(), note_pid(), seen_add(), usage(), __u32, __u64 (+1 more)

### Community 58 - "Community 58"
Cohesion: 0.23
Nodes (9): cmd_lib(), libbpf_print_fn(), usage(), ring_buffer_sample_fn, va_list, ring_buffer__add(), ring_buffer__free(), ring_buffer__new() (+1 more)

### Community 59 - "Community 59"
Cohesion: 0.30
Nodes (11): bpf_object__new(), get_debian_kernel_version(), get_kernel_version(), get_ubuntu_kernel_version(), libbpf_probe_bpf_helper(), libbpf_probe_bpf_map_type(), libbpf_probe_bpf_prog_type(), load_local_storage_btf() (+3 more)

### Community 60 - "Community 60"
Cohesion: 0.36
Nodes (10): elf_find_func_offset_from_archive(), check_access(), find_cd(), get_entry_at_offset(), local_file_header_at_offset(), try_parse_end_of_cd(), zip_archive_close(), zip_archive_find_entry() (+2 more)

### Community 61 - "Community 61"
Cohesion: 0.18
Nodes (12): info_rec_bswap_fn, btf_ext_bswap_hdr(), btf_ext_bswap_info(), btf_ext_bswap_info_sec(), btf_ext__new(), btf_ext_parse(), btf_ext_parse_info(), btf_ext_parse_sec_info() (+4 more)

### Community 62 - "Community 62"
Cohesion: 0.56
Nodes (9): device-test.sh script, ares(), fail(), forcestop(), info(), kill_ares(), test_funcs_structured(), test_lib() (+1 more)

### Community 63 - "Community 63"
Cohesion: 0.22
Nodes (8): build-fuzzers.sh script, CC, CFLAGS, CXX, CXXFLAGS, LIB_FUZZING_ENGINE, OUT, SKIP_LIBELF_REBUILD

### Community 64 - "Community 64"
Cohesion: 0.43
Nodes (5): sync-kernel.sh script, cd_to(), cherry_pick_commits(), cleanup(), usage()

### Community 65 - "Community 65"
Cohesion: 0.43
Nodes (5): ares_get_pid_uid(), ares_launch_app(), ares_resolve_component(), ares_sh_exec(), pid_t

### Community 66 - "Community 66"
Cohesion: 0.33
Nodes (5): corr_on_svc, corr_uprobe_entry, BPF_KPROBE(), uid_matches(), __always_inline

### Community 67 - "Community 67"
Cohesion: 0.47
Nodes (5): bpf_perf_event_print_t, ring_buffer_read_head(), ring_buffer_write_tail(), perf_event_read_simple(), __u64

### Community 70 - "Community 70"
Cohesion: 0.60
Nodes (4): corr_emit_func(), corr_emit_syscall(), emit_hex_args(), __u64

### Community 72 - "Community 72"
Cohesion: 0.70
Nodes (4): debian.sh script, docker_exec(), error(), info()

### Community 73 - "Community 73"
Cohesion: 0.60
Nodes (3): mailmap-update.sh script, grep_lines(), usage()

### Community 74 - "Community 74"
Cohesion: 0.50
Nodes (3): bpf_tail_call_static(), __always_inline, __u32

### Community 75 - "Community 75"
Cohesion: 0.50
Nodes (3): DEBIAN_FRONTEND, TZ, build-in-docker.sh script

### Community 77 - "Community 77"
Cohesion: 0.50
Nodes (3): BPF_KPROBE(), on_uprobe_mmap, on_uprobe_munmap

## Knowledge Gaps
- **96 isolated node(s):** `deploy.sh script`, `build.sh script`, `coverity.sh script`, `PATH`, `build-fuzzers.sh script` (+91 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **13 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `libbpf_err()` connect `Community 28` to `Community 0`, `Community 1`, `Community 2`, `Community 3`, `Community 4`, `Community 6`, `Community 7`, `Community 8`, `Community 10`, `Community 15`, `Community 16`, `Community 17`, `Community 19`, `Community 21`, `Community 25`, `Community 26`, `Community 31`, `Community 33`, `Community 37`, `Community 43`, `Community 45`, `Community 53`, `Community 56`, `Community 58`, `Community 59`, `Community 67`?**
  _High betweenness centrality (0.109) - this node is a cross-community bridge._
- **Why does `bpf_map_lookup_elem()` connect `Community 36` to `Community 66`, `Community 4`, `Community 41`, `Community 50`, `Community 51`, `Community 52`, `Community 18`, `Community 55`?**
  _High betweenness centrality (0.043) - this node is a cross-community bridge._
- **Why does `bpf_map_update_elem()` connect `Community 4` to `Community 0`, `Community 1`, `Community 5`, `Community 17`, `Community 50`, `Community 51`, `Community 18`, `Community 53`, `Community 55`, `Community 56`, `Community 57`, `Community 58`, `Community 27`, `Community 28`?**
  _High betweenness centrality (0.039) - this node is a cross-community bridge._
- **Are the 151 inferred relationships involving `libbpf_err()` (e.g. with `bpf_btf_get_fd_by_id_opts()` and `bpf_btf_load()`) actually correct?**
  _`libbpf_err()` has 151 INFERRED edges - model-reasoned connections that need verification._
- **Are the 24 inferred relationships involving `btf_type_by_id()` (e.g. with `btf_mark_embedded_composite_type_ids()` and `btf_relocate_map_distilled_base()`) actually correct?**
  _`btf_type_by_id()` has 24 INFERRED edges - model-reasoned connections that need verification._
- **Are the 39 inferred relationships involving `libbpf_err_errno()` (e.g. with `bpf_btf_get_fd_by_id_opts()` and `bpf_btf_load()`) actually correct?**
  _`libbpf_err_errno()` has 39 INFERRED edges - model-reasoned connections that need verification._
- **What connects `deploy.sh script`, `build.sh script`, `Accept either a single JSON array or JSONL (one record per line).     Malformed` to the rest of the system?**
  _136 weakly-connected nodes found - possible documentation gaps or missing edges._