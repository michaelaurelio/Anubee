# Hermetic cross-compile environment for ares (static aarch64).
#
# Base is Debian bookworm because its elfutils still ships a self-contained
# static libelf.a. (Newer Debian/sid/trixie split helpers into an internal
# `libeu` that isn't packaged, so static libelf fails to link with undefined
# `eu_search_tree_*`.) bookworm's default clang (14) is too old for the BPF
# objects, so we install a modern clang from the official LLVM apt repo.
#
# Pin exactly for reproducible builds by replacing the tag with a digest:
#   FROM debian:bookworm-slim@sha256:<digest>
FROM debian:bookworm-slim

ARG LLVM_VERSION=19

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates wget gnupg \
 && wget -qO /usr/share/keyrings/llvm.asc https://apt.llvm.org/llvm-snapshot.gpg.key \
 && echo "deb [signed-by=/usr/share/keyrings/llvm.asc] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-${LLVM_VERSION} main" \
        > /etc/apt/sources.list.d/llvm.list \
 && dpkg --add-architecture arm64 \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        gcc-aarch64-linux-gnu \
        binutils-aarch64-linux-gnu \
        libelf-dev:arm64 \
        zlib1g-dev:arm64 \
        libzstd-dev:arm64 \
        liblzma-dev:arm64 \
        clang-${LLVM_VERSION} \
        llvm-${LLVM_VERSION} \
        bpftool \
        make \
        git \
 && ln -sf /usr/bin/llvm-strip-${LLVM_VERSION} /usr/local/bin/llvm-strip \
 && rm -rf /var/lib/apt/lists/*

# Make the Makefile pick up the modern clang for the BPF objects (BPF_CLANG ?= clang).
ENV BPF_CLANG=clang-${LLVM_VERSION}

WORKDIR /workspace
# `make` is the single source of build truth; args after the image name go to it.
ENTRYPOINT ["make"]
