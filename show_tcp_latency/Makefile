# Makefile for libbpf-based tools

APP = show_tcp_latency

# You might need to install: libbpf-dev clang llvm libelf-dev
# This Makefile assumes vmlinux.h is available or generated.
# If you don't have bpftool to generate vmlinux.h, you might need to install it.

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

INCLUDES := -I.
CFLAGS := -g -O2 -Wall
LIBS := -lbpf -lelf -lz

# Source files
C_SRC := $(APP).c
BPF_SRC := $(APP).bpf.c

# Output files
BPF_OBJ := $(APP).bpf.o
SKEL_H := $(APP).skel.h
BINARY := $(APP)

.PHONY: all clean vmlinux

all: $(BINARY)

vmlinux.h:
	@echo "Using local vmlinux.h"

$(BPF_OBJ): $(BPF_SRC) show_tcp_latency.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(BPF_SRC) -o $@

$(SKEL_H): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $@

$(BINARY): $(C_SRC) $(SKEL_H) show_tcp_latency.h
	$(CLANG) $(CFLAGS) $(INCLUDES) $(C_SRC) -o $@ $(LIBS)

clean:
	rm -f $(BINARY) $(BPF_OBJ) $(SKEL_H)
