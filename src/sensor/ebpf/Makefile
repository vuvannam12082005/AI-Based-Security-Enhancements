BPF_CLANG ?= clang
CC ?= gcc

INCDIR := include
SRCDIR := src
BUILDDIR := build
LOADERDIR := loader

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I$(INCDIR)

VMLINUX_H := $(INCDIR)/vmlinux.h

BPF_OBJ := $(BUILDDIR)/syscall_monitor.bpf.o
SKEL_H := $(BUILDDIR)/syscall_monitor.skel.h
LOADER_BIN := $(BUILDDIR)/syscall_loader

.PHONY: all clean
all: $(LOADER_BIN)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(VMLINUX_H):
	@echo "Generating vmlinux.h from /sys/kernel/btf/vmlinux"
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

$(BPF_OBJ): $(SRCDIR)/syscall_monitor.bpf.c $(VMLINUX_H) | $(BUILDDIR)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL_H): $(BPF_OBJ) | $(BUILDDIR)
	bpftool gen skeleton $< > $@

$(LOADER_BIN): $(LOADERDIR)/syscall_loader.c $(SKEL_H) | $(BUILDDIR)
	$(CC) -O2 -g -I$(BUILDDIR) -I$(INCDIR) -I. $< -o $@ $$(pkg-config --cflags --libs libbpf) -lelf -lz

clean:
	rm -rf $(BUILDDIR)
