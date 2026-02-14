


# =============================================================================
# 文件: ebpf/Makefile
# 描述: eBPF 程序编译
# =============================================================================

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
GO ?= go

# 编译目标
TARGETS := xdp_phantom.o tc_phantom.o

# 编译选项
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS := -O2 -g -Wall -Werror
CFLAGS += -target bpf
CFLAGS += -D__TARGET_ARCH_$(ARCH)
CFLAGS += -I/usr/include/$(shell uname -m)-linux-gnu

# 内核头文件
KERNEL_HEADERS := $(shell find /usr/include -name "bpf_helpers.h" -printf "%h" 2>/dev/null | head -1)
ifneq ($(KERNEL_HEADERS),)
CFLAGS += -I$(KERNEL_HEADERS)
endif

# libbpf 头文件
LIBBPF_HEADERS := $(shell pkg-config --cflags libbpf 2>/dev/null)
ifneq ($(LIBBPF_HEADERS),)
CFLAGS += $(LIBBPF_HEADERS)
endif

.PHONY: all clean vmlinux generate install

all: vmlinux.h $(TARGETS)
	@echo "✅ eBPF 程序编译完成"

# 生成 vmlinux.h (BTF)
vmlinux.h:
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "📦 生成 vmlinux.h..."; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	else \
		echo "⚠️  BTF 不可用，创建最小头文件"; \
		echo "// Minimal vmlinux.h" > $@; \
	fi

# 编译 XDP 程序
xdp_phantom.o: xdp_phantom.c phantom_common.h vmlinux.h
	@echo "🔨 编译 $<..."
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "  ✓ $@"

# 编译 TC 程序
tc_phantom.o: tc_phantom.c phantom_common.h vmlinux.h
	@echo "🔨 编译 $<..."
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "  ✓ $@"

# 生成 Go 绑定
generate: $(TARGETS)
	@echo "📦 生成 Go 绑定..."
	$(GO) generate ./...

# 安装到系统
install: $(TARGETS)
	@echo "📦 安装 eBPF 程序..."
	sudo mkdir -p /opt/phantom/ebpf
	sudo cp $(TARGETS) /opt/phantom/ebpf/
	sudo cp phantom_common.h /opt/phantom/ebpf/
	@echo "✅ 安装完成"

# 加载 XDP 程序 (测试用)
load-xdp: xdp_phantom.o
	@echo "📦 加载 XDP 程序到 eth0..."
	sudo ip link set dev eth0 xdp obj $< sec xdp

# 卸载 XDP 程序
unload-xdp:
	@echo "📦 卸载 XDP 程序..."
	sudo ip link set dev eth0 xdp off

# 加载 TC 程序
load-tc: tc_phantom.o
	@echo "📦 加载 TC 程序..."
	sudo tc qdisc add dev eth0 clsact 2>/dev/null || true
	sudo tc filter add dev eth0 egress bpf da obj $< sec tc
	sudo tc filter add dev eth0 ingress bpf da obj $< sec tc

# 卸载 TC 程序
unload-tc:
	@echo "📦 卸载 TC 程序..."
	sudo tc filter del dev eth0 egress 2>/dev/null || true
	sudo tc filter del dev eth0 ingress 2>/dev/null || true

# 查看程序信息
info: $(TARGETS)
	@for f in $(TARGETS); do \
		echo "=== $$f ==="; \
		llvm-objdump -S $$f | head -50; \
		echo ""; \
	done

# 清理
clean:
	rm -f $(TARGETS) vmlinux.h
	@echo "✅ 清理完成"


