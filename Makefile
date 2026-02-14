

# =============================================================================
# 文件: Makefile (项目根目录)
# 描述: 完整构建脚本
# =============================================================================

BINARY := phantom-server
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "4.0.0")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%d %H:%M:%S')

LDFLAGS := -s -w \
	-X 'main.Version=$(VERSION)' \
	-X 'main.BuildTime=$(BUILD_TIME)' \
	-X 'main.GitCommit=$(COMMIT)'

GO_FILES := $(shell find . -name '*.go' -type f)

.PHONY: all build clean test lint run release ebpf install

all: build

# 构建主程序
build:
	@echo "🔨 构建 $(BINARY) v$(VERSION)..."
	@go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/phantom-server
	@echo "✅ 完成: $(BINARY)"

# 构建 eBPF 程序
ebpf:
	@echo "🔨 构建 eBPF 程序..."
	@$(MAKE) -C ebpf
	@echo "✅ eBPF 程序构建完成"

# 完整构建 (包含 eBPF)
build-all: build ebpf
	@echo "✅ 全部构建完成"

# 多平台构建
release:
	@echo "🚀 构建多平台版本..."
	@mkdir -p dist
	@for platform in "linux/amd64" "linux/arm64" "linux/arm" "darwin/amd64" "darwin/arm64" "windows/amd64" "freebsd/amd64"; do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} CGO_ENABLED=0 \
		go build -trimpath -ldflags "$(LDFLAGS)" \
		-o dist/$(BINARY)-$${platform%/*}-$${platform#*/}$$([ "$${platform%/*}" = "windows" ] && echo ".exe") \
		./cmd/phantom-server; \
		echo "  ✓ $${platform}"; \
	done
	@echo "✅ 完成"
	@ls -lh dist/

# 运行测试
test:
	@echo "🧪 运行测试..."
	@go test -v -race -coverprofile=coverage.out ./...
	@echo "✅ 测试完成"

# 代码检查
lint:
	@echo "🔍 代码检查..."
	@go vet ./...
	@if command -v golangci-lint &> /dev/null; then \
		golangci-lint run; \
	else \
		echo "⚠️  golangci-lint 未安装，跳过"; \
	fi
	@echo "✅ 检查完成"

# 运行
run: build
	@./$(BINARY) -c configs/config.example.yaml

# 生成 PSK
gen-psk:
	@./$(BINARY) -gen-psk 2>/dev/null || openssl rand -base64 32

# 安装到系统
install: build
	@echo "📦 安装到 /usr/local/bin..."
	@sudo cp $(BINARY) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/$(BINARY)
	@echo "✅ 安装完成"

# 安装 eBPF 程序
install-ebpf: ebpf
	@echo "📦 安装 eBPF 程序..."
	@sudo mkdir -p /opt/phantom/ebpf
	@sudo cp ebpf/*.o /opt/phantom/ebpf/
	@echo "✅ eBPF 程序安装完成"

# 清理
clean:
	@rm -f $(BINARY)
	@rm -rf dist/
	@rm -f coverage.out
	@$(MAKE) -C ebpf clean 2>/dev/null || true
	@echo "✅ 清理完成"

# 依赖更新
deps:
	@echo "📦 更新依赖..."
	@go mod tidy
	@go mod download
	@echo "✅ 依赖更新完成"

# Docker 构建
docker:
	@echo "🐳 构建 Docker 镜像..."
	@docker build -t phantom-server:$(VERSION) .
	@echo "✅ Docker 镜像构建完成"

# 帮助
help:
	@echo "Phantom Server v$(VERSION) - 构建命令"
	@echo ""
	@echo "用法: make [目标]"
	@echo ""
	@echo "目标:"
	@echo "  build       - 构建主程序"
	@echo "  ebpf        - 构建 eBPF 程序"
	@echo "  build-all   - 构建所有 (包含 eBPF)"
	@echo "  release     - 多平台构建"
	@echo "  test        - 运行测试"
	@echo "  lint        - 代码检查"
	@echo "  run         - 运行程序"
	@echo "  gen-psk     - 生成 PSK"
	@echo "  install     - 安装到系统"
	@echo "  install-ebpf- 安装 eBPF 程序"
	@echo "  clean       - 清理构建产物"
	@echo "  deps        - 更新依赖"
	@echo "  docker      - 构建 Docker 镜像"
	@echo "  help        - 显示帮助"



