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
SYSCALLS_TBL := $(BUILD)/syscalls_gen.h

BPF_CFLAGS_COMMON := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I$(LIBBPF_INC) -I.

# ---- userspace objects (compiled per engine, then localized) --------------
SYSC_CSRC := $(SRC)/syscalls/heimdall.c $(SRC)/syscalls/symbolize.c \
             $(SRC)/syscalls/flags.c $(SRC)/syscalls/dump.c
FUNC_CSRC := $(SRC)/funcs/ares-tracer.c $(SRC)/funcs/so_repair.c \
             $(SRC)/funcs/modules/proc_event.c $(SRC)/funcs/modules/execve.c \
             $(SRC)/funcs/modules/prop_read.c

SYSC_OBJ := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(SYSC_CSRC))
FUNC_OBJ := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(FUNC_CSRC))

SYSC_PART := $(BUILD)/syscalls.part.o
FUNC_PART := $(BUILD)/funcs.part.o
MAIN_OBJ  := $(BUILD)/main.o

SYSC_CFLAGS := -O2 -Wall -Wextra -I$(SRC)/syscalls -I$(BUILD) -I$(LIBBPF_INC)
FUNC_CFLAGS := -O2 -Wall -I$(SRC)/funcs -I$(LIBBPF_INC)

# Static link: libelf (zstd-enabled) pulls in zstd+zlib; liblzma decodes
# .gnu_debugdata mini-debug-info in the symbolizer. Superset of both engines.
LINK_LIBS := $(LIBBPF_A) -lelf -lz -lzstd -llzma
LINK_FLAGS := -static -pthread

.PHONY: all push clean regen-vmlinux
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
$(SYSC_BPF_OBJ): $(SRC)/syscalls/heimdall.bpf.c $(SRC)/syscalls/heimdall.h vmlinux.h $(LIBBPF_A)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC)/syscalls -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(SYSC_SKEL): $(SYSC_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name heimdall > $@

# ares-tracer.bpf.c #includes its module .bpf.c files; one compilation unit.
$(FUNC_BPF_OBJ): $(SRC)/funcs/ares-tracer.bpf.c $(SRC)/funcs/ares-tracer.h vmlinux.h $(LIBBPF_A) \
                 $(wildcard $(SRC)/funcs/modules/*.bpf.c)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS_COMMON) -I$(SRC)/funcs -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true
$(FUNC_SKEL): $(FUNC_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name ares_tracer_bpf > $@

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

# ---- final link -----------------------------------------------------------
$(BIN): $(MAIN_OBJ) $(SYSC_PART) $(FUNC_PART) $(LIBBPF_A)
	$(CC) $(LINK_FLAGS) $(MAIN_OBJ) $(SYSC_PART) $(FUNC_PART) -o $@ $(LINK_LIBS)
	@echo "built $@"; file $@ 2>/dev/null || true

push: $(BIN)
	adb push $(BIN) /data/local/tmp/ares
	adb shell chmod 755 /data/local/tmp/ares

clean:
	rm -rf $(BUILD) $(FUNC_SKEL)
