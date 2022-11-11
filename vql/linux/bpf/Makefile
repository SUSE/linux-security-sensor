GIT ?= git
BPFTOOL ?= bpftool
CLANG ?= clang
STRIP ?= llvm-strip

LIBBPFGO_DIR := $(abspath ../../../third_party/libbpfgo)
LIBBPFGO_OUTPUT := $(LIBBPFGO_DIR)/output
LIBBPF := $(LIBBPFGO_OUTPUT)/libbpf.a
VMLINUX_H := $(LIBBPFGO_OUTPUT)/vmlinux.h

ifeq ($(GOARCH), amd64)
	CLANGARCH=x86_64
	BPFARCH=x86
else ifeq ($(GOARCH), arm64)
	CLANGARCH=aarch64
	BPFARCH=arm64
else ifeq ($(GOARCH), ppc64le)
	CLANGARCH=ppc64
	BPFARCH=powerpc
else ifeq ($(GOARCH), s390x)
	CLANGARCH=s390x
	BPFARCH=s390
else ifneq ($(GOARCH),)
$(error Unsupported architecture `$(GOARCH)')
endif

.PHONY: all
all:
	$(warning This Makefile is intended to be invoked by either 'go generate' or the main magefile.)

CFLAGS := -g -O2 -Wall -I${LIBBPFGO_OUTPUT} -I${LIBBPFGO_DIR}/include/uapi

%.bpf.o : %.bpf.c $(LIBBPF) $(VMLINUX_H)
	@if test -z "$(GOARCH)"; then \
		echo "GOARCH='' -- BPF Modules are expected to be built using 'go generate'" >&2; \
		exit 1; \
	fi
	${CLANG} $(CFLAGS) -target bpf -D__TARGET_ARCH_${BPFARCH} -D__${CLANGARCH}__ -c $< -o $@
	${STRIP} -g "$@"

$(LIBBPFGO_DIR)/go.mod:
	echo "INFO: updating submodule 'libbpfgo'"
	$(GIT) submodule update --init --recursive "$(LIBBPFGO_DIR)"

$(LIBBPF): $(LIBBPFGO_DIR)/go.mod
	make -C $(LIBBPFGO_DIR) libbpfgo-static

$(VMLINUX_H):
	mkdir -p $(LIBBPFGO_OUTPUT)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp
	mv $@.tmp $@

clean:
	-make -C $(LIBBPFGO_DIR) clean
	rm -f */*.bpf.o
