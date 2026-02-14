


# =============================================================================
# 文件: Dockerfile
# 描述: Docker 构建文件
# =============================================================================

# 构建阶段
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /app

# 复制依赖文件
COPY go.mod go.sum ./
RUN go mod download

# 复制源码
COPY . .

# 构建
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o phantom-server ./cmd/phantom-server

# 运行阶段
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/phantom-server .
COPY --from=builder /app/configs/config.example.yaml /etc/phantom/config.yaml

# 创建非 root 用户 (注意: eBPF 功能需要 root)
RUN adduser -D -u 1000 phantom

# 默认使用 root 以支持 eBPF (可按需修改)
# USER phantom

EXPOSE 54321/udp 54321/tcp 54322/tcp 54323/tcp

ENTRYPOINT ["./phantom-server"]
CMD ["-c", "/etc/phantom/config.yaml"]

