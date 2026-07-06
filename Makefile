# ares — unified Android RASP / malware-analysis tracer.
#
# Single static aarch64 binary with two tracing engines (syscalls = kprobe,
# funcs = uprobe) behind a subcommand dispatcher. The BPF objects + skeletons are
# built with the HOST clang/bpftool (BPF is arch-neutral; CO-RE relocates against
# the device kernel at load time). The userspace loader is cross-compiled into a
# STATIC aarch64 binary you push to a rooted device.
#
# EASIEST BUILD (no host toolchain needed): ./scripts/build.sh  (runs this Makefile
# inside a container). Native build deps (Debian/Ubuntu) if you run `make` directly:
#   sudo apt install clang llvm bpftool gcc-aarch64-linux-gnu make git
#   sudo dpkg --add-architecture arm64 && sudo apt update
#   sudo apt install libelf-dev:arm64 zlib1g-dev:arm64 libzstd-dev:arm64 liblzma-dev:arm64
#   git submodule update --init --recursive      # vendored libbpf
#
#   make            # build build/ares
#   make push       # adb push to /data/local/tmp
#   make regen-vmlinux   # rebuild vmlinux.h from kernel BTF (ARES_VMLINUX_BTF)
#
# Why partial-link + objcopy: the two engines were independent programs that each
# own the global namespace (ares exposes bare globals like `verbose`, `skel`,
# `out_print`). We `ld -r` each engine's objects into one relocatable object and
# localize every symbol except its single `cmd_*` entry, so they coexist in one
# binary without collisions and with near-zero source edits.

ARCH        := arm64
BPF_CLANG   ?= clang
BPFTOOL     ?= bpftool

# make pre-defines CC/AR as built-ins; override ONLY when still the default so an
# explicit `make CC=...` or exported env var still wins.
ifeq ($(origin CC),default)
CC          := aarch64-linux-gnu-gcc
endif
ifeq ($(origin AR),default)
AR          := aarch64-linux-gnu-ar
endif
# Cross binutils for the partial-link + localize step. Assigned unconditionally
# (not ?=): make predefines LD=ld, so ?= would be a no-op and leak the HOST
# linker into `ld -r`, which then rejects the aarch64 (EM_183) objects with
# "Relocations in generic ELF". A command-line `make LD=...` still overrides this.
LD          := aarch64-linux-gnu-ld
OBJCOPY     := aarch64-linux-gnu-objcopy

# Compiler-generated header dependencies. -MMD writes a .d per object next to it;
# -MP adds phony targets for each header so a deleted/renamed header never breaks
# the build. Threaded into every compile below and -include'd at the tail. This is
# what keeps a shared *.bpf.h / struct-header edit from silently shipping a stale
# BPF object (BLD1).
DEPFLAGS := -MMD -MP

BUILD       := build
SRC         := src
LIBBPF_SRC  := third_party/libbpf/src
LIBBPF_DEST := $(abspath $(BUILD)/libbpf)
LIBBPF_A    := $(LIBBPF_DEST)/lib/libbpf.a
LIBBPF_INC  := $(LIBBPF_DEST)/include

BIN         := $(BUILD)/ares

# ---- BPF objects + skeletons ----------------------------------------------
SYSC_BPF_OBJ := $(BUILD)/syscalls.bpf.o
SYSC_SKEL    := $(BUILD)/syscalls.skel.h
FUNC_BPF_OBJ := $(BUILD)/funcs.bpf.o
FUNC_SKEL    := $(BUILD)/funcs.skel.h
LIB_BPF_OBJ  := $(BUILD)/lib.bpf.o
LIB_SKEL     := $(BUILD)/lib.skel.h
CORR_BPF_OBJ := $(BUILD)/correlate.bpf.o
CORR_SKEL    := $(BUILD)/correlate.skel.h
DUMP_BPF_OBJ := $(BUILD)/dump.bpf.o
DUMP_SKEL    := $(BUILD)/dump.skel.h
SYSCALLS_TBL := $(BUILD)/syscalls_gen.h
PROC_EVENT_BPF_OBJ := $(BUILD)/proc_event.bpf.o
PROC_EVENT_SKEL    := $(BUILD)/proc_event.skel.h
EXECVE_BPF_OBJ     := $(BUILD)/execve.bpf.o
EXECVE_SKEL        := $(BUILD)/execve.skel.h
PROP_READ_BPF_OBJ  := $(BUILD)/prop_read.bpf.o
PROP_READ_SKEL     := $(BUILD)/prop_read.skel.h

BPF_CFLAGS_COMMON := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I$(LIBBPF_INC) -I. $(DEPFLAGS)

# ---- userspace objects (compiled per engine, then localized) --------------
SYSC_CSRC := $(SRC)/syscalls/syscalls.c
FUNC_CSRC := $(SRC)/funcs/funcs.c $(SRC)/funcs/funcs_emit.c

# shared library-load tracing module (src/common), linked once; exports only its
# ares_libtrace_* API (everything else localized, like the engines).
COMMON_CSRC := $(SRC)/common/lib_trace.c $(SRC)/common/proc_mem.c $(SRC)/common/launch.c \
               $(SRC)/common/probe_resolve.c $(SRC)/common/trace_schema.c \
               $(SRC)/common/emit.c $(SRC)/common/decode.c $(SRC)/common/capabilities.c \
               $(SRC)/common/runtime.c $(SRC)/common/evqueue.c $(SRC)/common/symbolize.c \
               $(SRC)/common/maps.c $(SRC)/common/stack_snapshot.c \
               $(SRC)/common/cfi_unwind.c $(SRC)/common/dwarf.c \
               $(SRC)/common/dex.c $(SRC)/common/art_nterp.c \
               $(SRC)/common/managed_frame.c $(SRC)/common/art_buildid.c \
               $(SRC)/common/art_shadow.c \
               $(SRC)/common/sym_apk.c $(SRC)/common/sym_vdso.c $(SRC)/common/sym_jit.c \
               $(SRC)/common/sym_elf.c $(SRC)/common/sym_procmaps.c
COMMON_OBJ  := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(COMMON_CSRC))
COMMON_PART := $(BUILD)/common.part.o
COMMON_API  := ares_libtrace_resolve_path ares_libtrace_format_lib \
               ares_libtrace_emit_lib ares_libtrace_emit_unlib \
               proc_mem_open proc_mem_read nterp_name \
               ares_sh_exec ares_resolve_uid ares_get_pid_uid ares_resolve_component \
               ares_launch_app ares_launch_banner \
               mod_matches is_duplicate resolve_targets resolve_targets_for_file \
               parse_custom_probe_spec resolve_custom_spec_for_path custom_spec_matches_path \
               trace_type_name \
               jb_s jb_c jb_u64 jb_i64 jb_hex jb_esc jb_b64 \
               ares_sink_open ares_sink_emit ares_sink_flush \
               ares_sink_close ares_sink_report \
               ares_drops_report ares_install_stop_handler ares_round_pow2 \
               ares_evq_init ares_evq_push ares_evq_pop ares_evq_destroy \
               flags_decode_arg decode_sockaddr render_fd fdc_drop \
               ares_bpf_objects ares_object_writes_target ares_quiet_config_ok \
               seg_vaddr_to_off \
               sym_resolve sym_flush_pid cfi_unwind_snapshot \
               ares_parse_maps_line ares_module_base_idx ares_map_files_path \
               ares_stack_snapshot_emit_json \
               ares_managed_chain_build ares_jcache_put ares_jcache_get \
               ares_jcache_reset ares_managed_chain ares_emit_cfi_stack_json \
               ares_is_interp_frame

SYSC_OBJ := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(SYSC_CSRC))
FUNC_OBJ := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(FUNC_CSRC))

LIB_CSRC := $(SRC)/lib/lib.c
LIB_OBJ  := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(LIB_CSRC))

CORR_CSRC := $(SRC)/correlate/correlate.c $(SRC)/correlate/corr_emit.c
CORR_OBJ  := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(CORR_CSRC))
CORR_PART := $(BUILD)/correlate.part.o

DUMP_CSRC := $(SRC)/dump/dump.c $(SRC)/dump/rebuild.c
DUMP_OBJ  := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(DUMP_CSRC))
DUMP_PART := $(BUILD)/dump.part.o

# trace: thin coordinator, no BPF object of its own — it drives the syscalls and
# funcs engines' setup/run/teardown phases (kept global in their part-links below).
TRACE_CSRC := $(SRC)/trace/trace.c $(SRC)/trace/trace_args.c
TRACE_OBJ  := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(TRACE_CSRC))
TRACE_PART := $(BUILD)/trace.part.o

MOD_CSRC   := $(SRC)/modules/mod_emit.c $(SRC)/modules/proc_event.c $(SRC)/modules/execve.c $(SRC)/modules/prop_read.c $(SRC)/modules/mod.c
MOD_OBJ    := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(MOD_CSRC))
MOD_PART   := $(BUILD)/mod.part.o
MOD_CFLAGS := -O2 -Wall -Wextra -I$(SRC) -I$(SRC)/modules -I$(BUILD) -I$(LIBBPF_INC) $(DEPFLAGS)

SYSC_PART := $(BUILD)/syscalls.part.o
FUNC_PART := $(BUILD)/funcs.part.o
LIB_PART  := $(BUILD)/lib.part.o
MAIN_OBJ  := $(BUILD)/main.o

# -I$(SRC) lets engines and the common module resolve "common/lib_trace.h".
SYSC_CFLAGS := -O2 -Wall -Wextra -I$(SRC) -I$(SRC)/syscalls -I$(BUILD) -I$(LIBBPF_INC) $(DEPFLAGS)
FUNC_CFLAGS := -O2 -Wall -Wextra -I$(SRC) -I$(SRC)/funcs -I$(BUILD) -I$(LIBBPF_INC) $(DEPFLAGS)
LIB_CFLAGS  := -O2 -Wall -Wextra -I$(SRC) -I$(SRC)/lib -I$(BUILD) -I$(LIBBPF_INC) $(DEPFLAGS)
CORR_CFLAGS := -O2 -Wall -Wextra -I$(SRC) -I$(SRC)/correlate -I$(BUILD) -I$(LIBBPF_INC) $(DEPFLAGS)
DUMP_CFLAGS := -O2 -Wall -Wextra -I$(SRC) -I$(SRC)/dump -I$(BUILD) -I$(LIBBPF_INC) $(DEPFLAGS)
TRACE_CFLAGS := -O2 -Wall -Wextra -I$(SRC) -I$(SRC)/trace -I$(LIBBPF_INC) $(DEPFLAGS)
COMMON_CFLAGS := -O2 -Wall -Wextra -I$(SRC) -I$(LIBBPF_INC) $(DEPFLAGS)

# Static link: libelf (zstd-enabled) pulls in zstd+zlib; liblzma decodes
# .gnu_debugdata mini-debug-info in the symbolizer. Superset of both engines.
LINK_LIBS := $(LIBBPF_A) -lelf -lz -lzstd -llzma
LINK_FLAGS := -static -pthread

.PHONY: all push device-test test clean regen-vmlinux check-firewall capdump
all: $(BIN)

# ---- vmlinux.h (committed; regenerate manually only on kernel change) ------
# vmlinux.h is checked in and is the build input; no auto-rule regenerates it.
# Source BTF defaults to the host's live kernel. Override with a pulled device BTF:
#   make regen-vmlinux ARES_VMLINUX_BTF=./vmlinux-device.btf
# See DOCUMENTATION.md — "Regenerating vmlinux.h (kernel BTF)".
ARES_VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
regen-vmlinux:
	$(BPFTOOL) btf dump file $(ARES_VMLINUX_BTF) format c > vmlinux.h

# ---- vendored libbpf, cross-built static ----------------------------------
$(LIBBPF_A):
	@test -f $(LIBBPF_SRC)/libbpf.c || { echo "third_party/libbpf is empty — run: git submodule update --init --recursive"; exit 1; }
	mkdir -p $(LIBBPF_DEST)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_DEST)/obj DESTDIR=$(LIBBPF_DEST) \
		PREFIX= LIBDIR=/lib INCLUDEDIR=/include UAPIDIR=/include \
		CC=$(CC) AR=$(AR) install install_uapi_headers

# ---- BPF objects + skeletons (host clang) ---------------------------------
$(SYSC_BPF_OBJ): $(SRC)/syscalls/syscalls.bpf.c vmlinux.h $(LIBBPF_A)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC) -I$(SRC)/syscalls -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(SYSC_SKEL): $(SYSC_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name syscalls > $@

$(FUNC_BPF_OBJ): $(SRC)/funcs/funcs.bpf.c vmlinux.h $(LIBBPF_A)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC) -I$(SRC)/funcs -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(FUNC_SKEL): $(FUNC_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name funcs_bpf > $@

# lib engine BPF: minimal maps + uid gate, then #includes the shared probe.
$(LIB_BPF_OBJ): $(SRC)/lib/lib.bpf.c vmlinux.h $(LIBBPF_A)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC) -I$(SRC)/lib -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(LIB_SKEL): $(LIB_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name ares_lib > $@

# correlate engine BPF: span stack + entry uprobe + span-gated do_el0_svc kprobe.
$(CORR_BPF_OBJ): $(SRC)/correlate/correlate.bpf.c vmlinux.h $(LIBBPF_A)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC) -I$(SRC)/correlate -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(CORR_SKEL): $(CORR_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name ares_correlate > $@

# dump engine BPF: minimal maps + uid gate, then #includes the shared probe.
$(DUMP_BPF_OBJ): $(SRC)/dump/dump.bpf.c vmlinux.h $(LIBBPF_A)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC) -I$(SRC)/dump -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(DUMP_SKEL): $(DUMP_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name ares_dump > $@

# proc-event analyzer BPF: own ring buffer + uid gate + fork/exit tracepoints.
$(PROC_EVENT_BPF_OBJ): $(SRC)/modules/proc_event.bpf.c vmlinux.h $(LIBBPF_A)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC) -I$(SRC)/modules -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(PROC_EVENT_SKEL): $(PROC_EVENT_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name proc_event_bpf > $@

$(EXECVE_BPF_OBJ): $(SRC)/modules/execve.bpf.c vmlinux.h $(LIBBPF_A)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC) -I$(SRC)/modules -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(EXECVE_SKEL): $(EXECVE_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name execve_bpf > $@

$(PROP_READ_BPF_OBJ): $(SRC)/modules/prop_read.bpf.c vmlinux.h $(LIBBPF_A)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC) -I$(SRC)/modules -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(PROP_READ_SKEL): $(PROP_READ_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name prop_read_bpf > $@

# ---- arm64 syscall name table (numbers resolved by the cross compiler) -----
$(SYSCALLS_TBL):
	mkdir -p $(BUILD)
	@echo '#include <sys/syscall.h>' | $(CC) -E -dM -xc - \
	  | awk '/^#define __NR_[a-z0-9_]+ / && !/__NR_syscalls/ { n=$$2; sub(/^__NR_/,"",n); print "{ __NR_" n ", \"" n "\" }," }' \
	  | sort -u > $@
	@[ -s $@ ] || { echo '{ -1, "?" },' > $@; }
	@echo "generated $@ ($$(wc -l < $@) entries)"

# ---- userspace objects ----------------------------------------------------
# syscalls engine objects depend on the generated skeleton + syscall table.
$(BUILD)/syscalls/%.o: $(SRC)/syscalls/%.c $(SYSC_SKEL) $(SYSCALLS_TBL) $(LIBBPF_A)
	mkdir -p $(dir $@)
	$(CC) $(SYSC_CFLAGS) -c $< -o $@

$(BUILD)/funcs/%.o: $(SRC)/funcs/%.c $(FUNC_SKEL) $(LIBBPF_A)
	mkdir -p $(dir $@)
	$(CC) $(FUNC_CFLAGS) -c $< -o $@

$(BUILD)/common/%.o: $(SRC)/common/%.c $(LIBBPF_A)
	mkdir -p $(dir $@)
	$(CC) $(COMMON_CFLAGS) -c $< -o $@

$(BUILD)/lib/%.o: $(SRC)/lib/%.c $(LIB_SKEL) $(LIBBPF_A)
	mkdir -p $(dir $@)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

$(BUILD)/correlate/%.o: $(SRC)/correlate/%.c $(CORR_SKEL) $(SYSCALLS_TBL) $(LIBBPF_A)
	mkdir -p $(dir $@)
	$(CC) $(CORR_CFLAGS) -c $< -o $@

$(BUILD)/dump/%.o: $(SRC)/dump/%.c $(DUMP_SKEL) $(LIBBPF_A)
	mkdir -p $(dir $@)
	$(CC) $(DUMP_CFLAGS) -c $< -o $@

# trace has no BPF skeleton; it only needs the shared launch header + the engine
# driver symbols (resolved at the final link from the syscalls/funcs parts).
$(BUILD)/trace/%.o: $(SRC)/trace/%.c $(LIBBPF_A)
	mkdir -p $(dir $@)
	$(CC) $(TRACE_CFLAGS) -c $< -o $@

$(BUILD)/modules/%.o: $(SRC)/modules/%.c $(PROC_EVENT_SKEL) $(EXECVE_SKEL) $(PROP_READ_SKEL) $(LIBBPF_A)
	mkdir -p $(dir $@)
	$(CC) $(MOD_CFLAGS) -c $< -o $@

$(MAIN_OBJ): $(SRC)/main.c
	mkdir -p $(BUILD)
	$(CC) -O2 -Wall -Wextra $(DEPFLAGS) -c $< -o $@

# ---- partial-link each engine + localize all but its cmd_* entry ----------
# syscalls/funcs/lib also export their setup/run/teardown phases so a trace-style
# coordinator can drive multiple engines from one process (everything else localized).
$(SYSC_PART): $(SYSC_OBJ)
	$(LD) -r -o $@ $(SYSC_OBJ)
	$(OBJCOPY) --keep-global-symbol=cmd_syscalls \
	           --keep-global-symbol=syscalls_setup \
	           --keep-global-symbol=syscalls_run \
	           --keep-global-symbol=syscalls_teardown $@

$(FUNC_PART): $(FUNC_OBJ)
	$(LD) -r -o $@ $(FUNC_OBJ)
	$(OBJCOPY) --keep-global-symbol=cmd_funcs \
	           --keep-global-symbol=funcs_setup \
	           --keep-global-symbol=funcs_run \
	           --keep-global-symbol=funcs_teardown $@

$(COMMON_PART): $(COMMON_OBJ) Makefile
	$(LD) -r -o $@ $(COMMON_OBJ)
	$(OBJCOPY) $(foreach s,$(COMMON_API),--keep-global-symbol=$(s)) $@

$(LIB_PART): $(LIB_OBJ)
	$(LD) -r -o $@ $(LIB_OBJ)
	$(OBJCOPY) --keep-global-symbol=cmd_lib \
	           --keep-global-symbol=lib_setup \
	           --keep-global-symbol=lib_run \
	           --keep-global-symbol=lib_teardown $@

$(CORR_PART): $(CORR_OBJ)
	$(LD) -r -o $@ $(CORR_OBJ)
	$(OBJCOPY) --keep-global-symbol=cmd_correlate \
	           --keep-global-symbol=correlate_setup \
	           --keep-global-symbol=correlate_run \
	           --keep-global-symbol=correlate_teardown $@

$(DUMP_PART): $(DUMP_OBJ)
	$(LD) -r -o $@ $(DUMP_OBJ)
	$(OBJCOPY) --keep-global-symbol=cmd_dump \
	           --keep-global-symbol=dump_setup \
	           --keep-global-symbol=dump_run \
	           --keep-global-symbol=dump_teardown $@

$(TRACE_PART): $(TRACE_OBJ)
	$(LD) -r -o $@ $(TRACE_OBJ)
	$(OBJCOPY) --keep-global-symbol=cmd_trace $@

$(MOD_PART): $(MOD_OBJ)
	$(LD) -r -o $@ $(MOD_OBJ)
	$(OBJCOPY) --keep-global-symbol=cmd_mod $@

# ---- final link -----------------------------------------------------------
$(BIN): $(MAIN_OBJ) $(COMMON_PART) $(SYSC_PART) $(FUNC_PART) $(LIB_PART) $(CORR_PART) $(DUMP_PART) $(TRACE_PART) $(MOD_PART) $(LIBBPF_A)
	$(CC) $(LINK_FLAGS) $(MAIN_OBJ) $(COMMON_PART) $(SYSC_PART) $(FUNC_PART) $(LIB_PART) $(CORR_PART) $(DUMP_PART) $(TRACE_PART) $(MOD_PART) -o $@ $(LINK_LIBS)
	@echo "built $@"; file $@ 2>/dev/null || true

push: $(BIN)
	adb push $(BIN) /data/local/tmp/ares
	adb shell chmod 755 /data/local/tmp/ares

# Device-tier smoke: push fresh binary, assert each capability attaches + emits
# real output on the attached rooted device. ARES_TEST_PKG / ARES_TEST_TIMEOUT
# override target + window. See scripts/device-test.sh and the
# testing-ares-on-device skill.
device-test: $(BIN)
	scripts/device-test.sh $(CAP)

check-firewall: $(BIN) $(BUILD)/capdump
	scripts/check-firewall.sh
	scripts/check-firewall.sh --selftest

# Host unit tests: pure-logic checks compiled with the HOST cc (no device, no
# cross-toolchain). Self-contained — depends only on the C sources under test.
HOST_CC ?= cc
capdump: $(BUILD)/capdump
$(BUILD)/capdump: tools/capdump.c src/common/capabilities.c src/common/capabilities.h
	@mkdir -p $(BUILD)
	$(HOST_CC) -Wall -Wextra -Isrc tools/capdump.c src/common/capabilities.c -o $@

test:
	@mkdir -p $(BUILD)
	@if $(HOST_CC) -x c - -lelf -o /dev/null 2>/dev/null </dev/null; then \
	  $(HOST_CC) -Wall -Wextra -Isrc tests/test_probe_spec.c src/common/probe_resolve.c -o $(BUILD)/test_probe_spec -lelf && \
	  $(BUILD)/test_probe_spec; \
	 else \
	  echo "skip: libelf-dev not installed, skipping test_probe_spec (apt install libelf-dev)"; \
	 fi
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_trace_schema.c src/common/trace_schema.c -o $(BUILD)/test_trace_schema
	$(BUILD)/test_trace_schema
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_emit.c src/common/emit.c -o $(BUILD)/test_emit
	$(BUILD)/test_emit
	$(HOST_CC) -Wall -Wextra -fsanitize=address,undefined -g -Isrc tests/test_decode.c src/common/decode.c -o $(BUILD)/test_decode
	$(BUILD)/test_decode
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_funcs_emit.c src/funcs/funcs_emit.c src/common/emit.c src/common/trace_schema.c src/common/decode.c -o $(BUILD)/test_funcs_emit
	$(BUILD)/test_funcs_emit
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_corr_emit.c src/correlate/corr_emit.c src/common/emit.c src/common/decode.c src/common/trace_schema.c -o $(BUILD)/test_corr_emit
	$(BUILD)/test_corr_emit
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_lib_trace_emit.c src/common/lib_trace.c src/common/emit.c src/common/maps.c -o $(BUILD)/test_lib_trace_emit
	$(BUILD)/test_lib_trace_emit
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_capabilities.c src/common/capabilities.c -o $(BUILD)/test_capabilities
	$(BUILD)/test_capabilities
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_trace_args.c src/trace/trace_args.c -o $(BUILD)/test_trace_args
	$(BUILD)/test_trace_args
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_runtime.c src/common/runtime.c -o $(BUILD)/test_runtime
	$(BUILD)/test_runtime
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_evqueue.c src/common/evqueue.c -o $(BUILD)/test_evqueue -lpthread
	$(BUILD)/test_evqueue
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_unwind_regs.c src/common/stack_snapshot.c src/common/emit.c src/common/trace_schema.c -o $(BUILD)/test_unwind_regs
	$(BUILD)/test_unwind_regs
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_stack_snapshot.c src/common/stack_snapshot.c src/common/emit.c src/common/trace_schema.c -o $(BUILD)/test_stack_snapshot
	$(BUILD)/test_stack_snapshot
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_dwarf.c src/common/dwarf.c -o $(BUILD)/test_dwarf
	$(BUILD)/test_dwarf
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_cfi_parse.c src/common/cfi_unwind.c src/common/dwarf.c -o $(BUILD)/test_cfi_parse
	$(BUILD)/test_cfi_parse
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_cfi_step.c src/common/cfi_unwind.c src/common/dwarf.c -o $(BUILD)/test_cfi_step
	$(BUILD)/test_cfi_step
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_cfi_elf.c src/common/cfi_unwind.c src/common/dwarf.c -o $(BUILD)/test_cfi_elf
	$(BUILD)/test_cfi_elf tests/fixtures/debug_frame_sample.elf
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_cfi_eh.c src/common/cfi_unwind.c src/common/dwarf.c -o $(BUILD)/test_cfi_eh
	$(BUILD)/test_cfi_eh tests/fixtures/eh_frame_sample.so
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_cfi_load.c src/common/cfi_unwind.c src/common/dwarf.c -o $(BUILD)/test_cfi_load
	$(BUILD)/test_cfi_load tests/fixtures/eh_frame_sample.so tests/fixtures/debug_frame_sample.elf
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_dex.c src/common/dex.c -o $(BUILD)/test_dex
	$(BUILD)/test_dex tests/fixtures/sample.dex
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_art_nterp.c src/common/art_nterp.c src/common/art_buildid.c src/common/dex.c src/common/proc_mem.c src/common/maps.c -o $(BUILD)/test_art_nterp -lpthread
	$(BUILD)/test_art_nterp tests/fixtures/sample.dex
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_art_buildid.c src/common/art_buildid.c src/common/maps.c -o $(BUILD)/test_art_buildid
	$(BUILD)/test_art_buildid
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_art_shadow.c src/common/art_shadow.c src/common/art_nterp.c src/common/art_buildid.c src/common/dex.c src/common/maps.c src/common/proc_mem.c -o $(BUILD)/test_art_shadow -lpthread
	$(BUILD)/test_art_shadow tests/fixtures/sample.dex
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_snapshot_gate.c -o $(BUILD)/test_snapshot_gate
	$(BUILD)/test_snapshot_gate
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_managed_frame.c src/common/managed_frame.c src/common/emit.c -o $(BUILD)/test_managed_frame -lpthread
	$(BUILD)/test_managed_frame
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_maps.c src/common/maps.c -o $(BUILD)/test_maps
	$(BUILD)/test_maps
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_target_args.c -o $(BUILD)/test_target_args
	$(BUILD)/test_target_args
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_mod_emit.c src/modules/mod_emit.c src/common/emit.c src/common/trace_schema.c -o $(BUILD)/test_mod_emit
	$(BUILD)/test_mod_emit
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_file_access_classify.c src/modules/file_access_classify.c -o $(BUILD)/test_file_access_classify
	$(BUILD)/test_file_access_classify
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_syscall_index.c -o $(BUILD)/test_syscall_index
	$(BUILD)/test_syscall_index
	@if command -v python3 >/dev/null 2>&1 && python3 -c "import duckdb" 2>/dev/null; then \
	  python3 tools/ares-mcp/test_unified_ingest.py; \
	 else \
	  echo "skip: python3+duckdb not available for ares-mcp ingest test"; \
	 fi

clean:
	rm -rf $(BUILD)

# ---- auto-generated header deps (-MMD -MP) --------------------------------
# Absent on a clean build → -include (leading dash) keeps the first pass silent;
# the explicit source + generated-skeleton/table + vmlinux.h + libbpf.a prereqs
# above guarantee correct first-build ordering. Thereafter these carry every
# fine-grained header dependency, so a shared *.bpf.h / struct-header edit rebuilds
# exactly the objects that include it, all the way to $(BIN).
ALL_OBJS     := $(SYSC_OBJ) $(FUNC_OBJ) $(COMMON_OBJ) $(LIB_OBJ) $(CORR_OBJ) \
                $(DUMP_OBJ) $(TRACE_OBJ) $(MOD_OBJ) $(MAIN_OBJ)
ALL_BPF_OBJS := $(SYSC_BPF_OBJ) $(FUNC_BPF_OBJ) $(LIB_BPF_OBJ) $(CORR_BPF_OBJ) \
                $(DUMP_BPF_OBJ) $(PROC_EVENT_BPF_OBJ) $(EXECVE_BPF_OBJ) $(PROP_READ_BPF_OBJ)
-include $(ALL_OBJS:.o=.d) $(ALL_BPF_OBJS:.o=.d)
