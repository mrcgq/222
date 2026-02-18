// internal/transport/client_stub.go
//go:build !linux

package transport

import (
	"errors"
	"net"
)

// 因为非 Linux 平台没有这个结构体，我们需要定义一个占位符防止编译失败
type FakeTCPConfig struct {
	// 保持为空即可
}

// 提供一个默认配置函数
func DefaultFakeTCPConfig() *FakeTCPConfig {
	return &FakeTCPConfig{}
}

// NewFakeTCPClient 的桩函数
// 当在 Windows/Mac 上调用时，它会编译通过，但运行时会返回错误
func NewFakeTCPClient(serverAddr string, cfg *FakeTCPConfig) (net.Conn, error) {
	return nil, errors.New("FakeTCP is only supported on Linux")
}

// 如果还有其他报错的函数（如 NewWebSocketClient），也在这里补齐桩函数
func NewWebSocketClient(serverAddr string, fingerprint string) (net.Conn, error) {
	return nil, errors.New("WebSocket client not implemented for this platform")
}
