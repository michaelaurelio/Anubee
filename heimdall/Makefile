# Heimdall — host cross-build.
#
# The BPF object + skeleton are built with the HOST clang/bpftool (BPF is an
# arch-neutral ISA; CO-RE relocates against the device kernel at load time).
# The userspace loader is cross-compiled into a STATIC aarch64 binary you push
# to the device and run from a rooted `adb shell` — no eadb chroot needed.
#
# One-time host deps (Debian/Ubuntu):
#   sudo apt install clang llvm bpftool gcc-aarch64-linux-gnu
#   sudo dpkg --add-architecture arm64 && sudo apt update
#   sudo apt install libelf-dev:arm64 zlib1g-dev:arm64 libzstd-dev:arm64
# libbpf itself is vendored at third_party/libbpf and built here.
#
#   make            # build build/heimdall
#   make push       # adb push to /data/local/tmp
#   make regen-vmlinux   # rebuild vmlinux.h from vmlinux.btf

ARCH        := arm64
BPF_CLANG   ?= clang
BPFTOOL     ?= bpftool

# make pre-defines CC=cc / AR=ar as built-ins, so `?=` would never pick our
# cross tools. Override ONLY when the value is make's built-in default; an
# explicit `make CC=...` or an exported env var still wins.
ifeq ($(origin CC),default)
CC          := aarch64-linux-gnu-gcc
endif
ifeq ($(origin AR),default)
AR          := aarch64-linux-gnu-ar
endif

BUILD       := build
SRC         := src
LIBBPF_SRC  := third_party/libbpf/src
LIBBPF_DEST := $(abspath $(BUILD)/libbpf)
LIBBPF_A    := $(LIBBPF_DEST)/lib/libbpf.a
LIBBPF_INC  := $(LIBBPF_DEST)/include

BIN         := $(BUILD)/heimdall
BPF_OBJ     := $(BUILD)/heimdall.bpf.o
SKEL        := $(BUILD)/heimdall.skel.h
SYSCALLS    := $(BUILD)/syscalls_gen.h

# Headers used to compile the BPF object (staged from libbpf).
BPF_CFLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
               -I$(LIBBPF_INC) -I$(SRC) -I.

LOADER_CFLAGS := -O2 -Wall -Wextra -static \
                 -I$(BUILD) -I$(SRC) -I$(LIBBPF_INC)
# Static link: libelf (built with zstd support) pulls in zstd + zlib, so they
# must follow -lelf on the line.
LOADER_LIBS   := $(LIBBPF_A) -lelf -lz -lzstd

.PHONY: all push clean regen-vmlinux
all: $(BIN)

# ---- vmlinux.h (committed; regenerate only on kernel change) --------------
vmlinux.h:
	$(BPFTOOL) btf dump file vmlinux.btf format c > $@
regen-vmlinux:
	$(BPFTOOL) btf dump file vmlinux.btf format c > vmlinux.h

# ---- vendored libbpf, cross-built static ----------------------------------
$(LIBBPF_A):
	mkdir -p $(LIBBPF_DEST)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_DEST)/obj DESTDIR=$(LIBBPF_DEST) \
		PREFIX= LIBDIR=/lib INCLUDEDIR=/include UAPIDIR=/include \
		CC=$(CC) AR=$(AR) install install_uapi_headers

# ---- BPF object + skeleton (host) -----------------------------------------
$(BPF_OBJ): $(SRC)/heimdall.bpf.c $(SRC)/heimdall.h vmlinux.h $(LIBBPF_A)
	mkdir -p $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name heimdall > $@

# ---- arm64 syscall name table (numbers resolved by the cross compiler) ----
$(SYSCALLS):
	mkdir -p $(BUILD)
	@echo '#include <sys/syscall.h>' | $(CC) -E -dM -xc - \
	  | awk '/^#define __NR_[a-z0-9_]+ / && !/__NR_syscalls/ { n=$$2; sub(/^__NR_/,"",n); print "{ __NR_" n ", \"" n "\" }," }' \
	  | sort -u > $@
	@[ -s $@ ] || { echo '{ -1, "?" },' > $@; }
	@echo "generated $@ ($$(wc -l < $@) entries)"

# ---- userspace loader (cross, static) -------------------------------------
$(BIN): $(SRC)/heimdall.c $(SRC)/heimdall.h $(SKEL) $(SYSCALLS) $(LIBBPF_A)
	$(CC) $(LOADER_CFLAGS) $(SRC)/heimdall.c -o $@ $(LOADER_LIBS)
	@echo "built $@"; file $@ 2>/dev/null || true

push: $(BIN)
	adb push $(BIN) /data/local/tmp/heimdall
	adb shell chmod 755 /data/local/tmp/heimdall

clean:
	rm -rf $(BUILD)
