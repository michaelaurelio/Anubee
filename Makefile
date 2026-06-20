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
#   make regen-vmlinux   # rebuild vmlinux.h from vmlinux.btf
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

BUILD       := build
SRC         := src
LIBBPF_SRC  := third_party/libbpf/src
LIBBPF_DEST := $(abspath $(BUILD)/libbpf)
LIBBPF_A    := $(LIBBPF_DEST)/lib/libbpf.a
LIBBPF_INC  := $(LIBBPF_DEST)/include

BIN         := $(BUILD)/ares

# ---- BPF objects + skeletons ----------------------------------------------
SYSC_BPF_OBJ := $(BUILD)/heimdall.bpf.o
SYSC_SKEL    := $(BUILD)/heimdall.skel.h
FUNC_BPF_OBJ := $(BUILD)/ares-tracer.bpf.o
# funcs skeleton lives next to its source: ares-tracer.c and modules/*.c include
# it via "ares-tracer.skel.h" / "../ares-tracer.skel.h".
FUNC_SKEL    := $(SRC)/funcs/ares-tracer.skel.h
LIB_BPF_OBJ  := $(BUILD)/lib.bpf.o
LIB_SKEL     := $(BUILD)/lib.skel.h
CORR_BPF_OBJ := $(BUILD)/correlate.bpf.o
CORR_SKEL    := $(BUILD)/correlate.skel.h
DUMP_BPF_OBJ := $(BUILD)/dump.bpf.o
DUMP_SKEL    := $(BUILD)/dump.skel.h
SYSCALLS_TBL := $(BUILD)/syscalls_gen.h

BPF_CFLAGS_COMMON := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I$(LIBBPF_INC) -I.

# ---- userspace objects (compiled per engine, then localized) --------------
SYSC_CSRC := $(SRC)/syscalls/heimdall.c $(SRC)/syscalls/symbolize.c \
             $(SRC)/syscalls/flags.c
FUNC_CSRC := $(SRC)/funcs/ares-tracer.c \
             $(SRC)/funcs/modules/proc_event.c $(SRC)/funcs/modules/execve.c \
             $(SRC)/funcs/modules/prop_read.c

# shared library-load tracing module (src/common), linked once; exports only its
# ares_libtrace_* API (everything else localized, like the engines).
COMMON_CSRC := $(SRC)/common/lib_trace.c $(SRC)/common/proc_mem.c $(SRC)/common/launch.c \
               $(SRC)/common/probe_resolve.c
COMMON_OBJ  := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(COMMON_CSRC))
COMMON_PART := $(BUILD)/common.part.o
COMMON_API  := ares_libtrace_resolve_path ares_libtrace_format_lib \
               ares_libtrace_emit_lib ares_libtrace_emit_unlib \
               proc_mem_open proc_mem_read \
               ares_sh_exec ares_resolve_uid ares_get_pid_uid ares_resolve_component \
               mod_matches is_duplicate resolve_targets resolve_targets_for_file \
               parse_custom_probe_spec resolve_custom_spec_for_path custom_spec_matches_path

SYSC_OBJ := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(SYSC_CSRC))
FUNC_OBJ := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(FUNC_CSRC))

LIB_CSRC := $(SRC)/lib/lib.c
LIB_OBJ  := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(LIB_CSRC))

CORR_CSRC := $(SRC)/correlate/correlate.c
CORR_OBJ  := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(CORR_CSRC))
CORR_PART := $(BUILD)/correlate.part.o

DUMP_CSRC := $(SRC)/dump/dump.c $(SRC)/dump/rebuild.c
DUMP_OBJ  := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(DUMP_CSRC))
DUMP_PART := $(BUILD)/dump.part.o

SYSC_PART := $(BUILD)/syscalls.part.o
FUNC_PART := $(BUILD)/funcs.part.o
LIB_PART  := $(BUILD)/lib.part.o
MAIN_OBJ  := $(BUILD)/main.o

# -I$(SRC) lets engines and the common module resolve "common/lib_trace.h".
SYSC_CFLAGS := -O2 -Wall -Wextra -I$(SRC) -I$(SRC)/syscalls -I$(BUILD) -I$(LIBBPF_INC)
FUNC_CFLAGS := -O2 -Wall -I$(SRC) -I$(SRC)/funcs -I$(LIBBPF_INC)
LIB_CFLAGS  := -O2 -Wall -Wextra -I$(SRC) -I$(SRC)/lib -I$(BUILD) -I$(LIBBPF_INC)
CORR_CFLAGS := -O2 -Wall -Wextra -I$(SRC) -I$(SRC)/correlate -I$(BUILD) -I$(LIBBPF_INC)
DUMP_CFLAGS := -O2 -Wall -Wextra -I$(SRC) -I$(SRC)/dump -I$(BUILD) -I$(LIBBPF_INC)
COMMON_CFLAGS := -O2 -Wall -Wextra -I$(SRC) -I$(LIBBPF_INC)

# Static link: libelf (zstd-enabled) pulls in zstd+zlib; liblzma decodes
# .gnu_debugdata mini-debug-info in the symbolizer. Superset of both engines.
LINK_LIBS := $(LIBBPF_A) -lelf -lz -lzstd -llzma
LINK_FLAGS := -static -pthread

.PHONY: all push device-test test clean regen-vmlinux
all: $(BIN)

# ---- vmlinux.h (committed; regenerate only on kernel change) ---------------
vmlinux.h:
	$(BPFTOOL) btf dump file vmlinux.btf format c > $@
regen-vmlinux:
	$(BPFTOOL) btf dump file vmlinux.btf format c > vmlinux.h

# ---- vendored libbpf, cross-built static ----------------------------------
$(LIBBPF_A):
	@test -f $(LIBBPF_SRC)/libbpf.c || { echo "third_party/libbpf is empty — run: git submodule update --init --recursive"; exit 1; }
	mkdir -p $(LIBBPF_DEST)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_DEST)/obj DESTDIR=$(LIBBPF_DEST) \
		PREFIX= LIBDIR=/lib INCLUDEDIR=/include UAPIDIR=/include \
		CC=$(CC) AR=$(AR) install install_uapi_headers

# ---- BPF objects + skeletons (host clang) ---------------------------------
$(SYSC_BPF_OBJ): $(SRC)/syscalls/heimdall.bpf.c $(SRC)/syscalls/heimdall.h vmlinux.h $(LIBBPF_A) \
                 $(SRC)/common/lib_trace.h $(SRC)/common/lib_trace.bpf.h
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC) -I$(SRC)/syscalls -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(SYSC_SKEL): $(SYSC_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name heimdall > $@

# ares-tracer.bpf.c #includes its module .bpf.c files and the shared lib_trace
# probe; one compilation unit.
$(FUNC_BPF_OBJ): $(SRC)/funcs/ares-tracer.bpf.c $(SRC)/funcs/ares-tracer.h vmlinux.h $(LIBBPF_A) \
                 $(SRC)/common/lib_trace.h $(SRC)/common/lib_trace.bpf.h \
                 $(SRC)/common/span_stack.bpf.h \
                 $(wildcard $(SRC)/funcs/modules/*.bpf.c)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC) -I$(SRC)/funcs -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(FUNC_SKEL): $(FUNC_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name ares_tracer_bpf > $@

# lib engine BPF: minimal maps + uid gate, then #includes the shared probe.
$(LIB_BPF_OBJ): $(SRC)/lib/lib.bpf.c $(SRC)/common/lib_trace.h $(SRC)/common/lib_trace.bpf.h vmlinux.h $(LIBBPF_A)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC) -I$(SRC)/lib -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(LIB_SKEL): $(LIB_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name ares_lib > $@

# correlate engine BPF: span stack + entry uprobe + span-gated do_el0_svc kprobe.
$(CORR_BPF_OBJ): $(SRC)/correlate/correlate.bpf.c $(SRC)/correlate/correlate.h $(SRC)/common/span_stack.bpf.h vmlinux.h $(LIBBPF_A)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC) -I$(SRC)/correlate -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(CORR_SKEL): $(CORR_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name ares_correlate > $@

# dump engine BPF: minimal maps + uid gate, then #includes the shared probe.
$(DUMP_BPF_OBJ): $(SRC)/dump/dump.bpf.c $(SRC)/common/lib_trace.h $(SRC)/common/lib_trace.bpf.h vmlinux.h $(LIBBPF_A)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC) -I$(SRC)/dump -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(DUMP_SKEL): $(DUMP_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name ares_dump > $@

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

$(BUILD)/common/%.o: $(SRC)/common/%.c $(SRC)/common/lib_trace.h $(SRC)/common/proc_mem.h $(SRC)/common/launch.h $(SRC)/common/probe_resolve.h $(LIBBPF_A)
	mkdir -p $(dir $@)
	$(CC) $(COMMON_CFLAGS) -c $< -o $@

$(BUILD)/lib/%.o: $(SRC)/lib/%.c $(LIB_SKEL) $(SRC)/common/lib_trace.h $(LIBBPF_A)
	mkdir -p $(dir $@)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

$(BUILD)/correlate/%.o: $(SRC)/correlate/%.c $(CORR_SKEL) $(SYSCALLS_TBL) $(SRC)/common/launch.h $(SRC)/common/probe_resolve.h $(SRC)/correlate/correlate.h $(LIBBPF_A)
	mkdir -p $(dir $@)
	$(CC) $(CORR_CFLAGS) -c $< -o $@

$(BUILD)/dump/%.o: $(SRC)/dump/%.c $(DUMP_SKEL) $(SRC)/common/proc_mem.h $(SRC)/common/lib_trace.h $(LIBBPF_A)
	mkdir -p $(dir $@)
	$(CC) $(DUMP_CFLAGS) -c $< -o $@

$(MAIN_OBJ): $(SRC)/main.c
	mkdir -p $(BUILD)
	$(CC) -O2 -Wall -Wextra -c $< -o $@

# ---- partial-link each engine + localize all but its cmd_* entry ----------
$(SYSC_PART): $(SYSC_OBJ)
	$(LD) -r -o $@ $(SYSC_OBJ)
	$(OBJCOPY) --keep-global-symbol=cmd_syscalls $@

$(FUNC_PART): $(FUNC_OBJ)
	$(LD) -r -o $@ $(FUNC_OBJ)
	$(OBJCOPY) --keep-global-symbol=cmd_funcs $@

$(COMMON_PART): $(COMMON_OBJ)
	$(LD) -r -o $@ $(COMMON_OBJ)
	$(OBJCOPY) $(foreach s,$(COMMON_API),--keep-global-symbol=$(s)) $@

$(LIB_PART): $(LIB_OBJ)
	$(LD) -r -o $@ $(LIB_OBJ)
	$(OBJCOPY) --keep-global-symbol=cmd_lib $@

$(CORR_PART): $(CORR_OBJ)
	$(LD) -r -o $@ $(CORR_OBJ)
	$(OBJCOPY) --keep-global-symbol=cmd_correlate $@

$(DUMP_PART): $(DUMP_OBJ)
	$(LD) -r -o $@ $(DUMP_OBJ)
	$(OBJCOPY) --keep-global-symbol=cmd_dump $@

# ---- final link -----------------------------------------------------------
$(BIN): $(MAIN_OBJ) $(COMMON_PART) $(SYSC_PART) $(FUNC_PART) $(LIB_PART) $(CORR_PART) $(DUMP_PART) $(LIBBPF_A)
	$(CC) $(LINK_FLAGS) $(MAIN_OBJ) $(COMMON_PART) $(SYSC_PART) $(FUNC_PART) $(LIB_PART) $(CORR_PART) $(DUMP_PART) -o $@ $(LINK_LIBS)
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

# Host unit tests: pure-logic checks compiled with the HOST cc (no device, no
# cross-toolchain). Self-contained — depends only on the C sources under test.
HOST_CC ?= cc
test:
	@mkdir -p $(BUILD)
	$(HOST_CC) -Wall -Wextra -Isrc tests/test_probe_spec.c src/common/probe_resolve.c -o $(BUILD)/test_probe_spec -lelf
	$(BUILD)/test_probe_spec

clean:
	rm -rf $(BUILD) $(FUNC_SKEL)
