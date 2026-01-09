# Makefile for libbpf-based monitor

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# 依赖库
LIBS := -lbpf -lelf -lz

# 目标文件
TARGET := monitor
BPF_OBJ := $(TARGET).bpf.o
SKEL_OBJ := $(TARGET).skel.h

.PHONY: all clean vmlinux

all: $(TARGET)

# 1. 生成 vmlinux.h (如果不存在)
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. 编译 BPF 内核代码 -> .o
$(BPF_OBJ): $(TARGET).bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c $(TARGET).bpf.c -o $@

# 3. 生成 Skeleton 头文件 -> .skel.h
$(SKEL_OBJ): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL_OBJ)

# 4. 编译用户态程序
$(TARGET): $(TARGET).c $(SKEL_OBJ)
	$(CLANG) -g -O2 -Wall -I. $(TARGET).c -o $@ $(LIBS)

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(SKEL_OBJ) vmlinux.h
