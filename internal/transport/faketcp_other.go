//go:build !linux

// =============================================================================
// 文件: internal/transport/faketcp_other.go
// 描述: FakeTCP 非 Linux 平台存根
// =============================================================================
package transport

import (
	"context"
	"fmt"
	"net"
)

// FakeTCPServer FakeTCP 服务器存根
type FakeTCPServer struct {
	config *FakeTCPConfig
}

// NewFakeTCPServer 创建 FakeTCP 服务器存根
func NewFakeTCPServer(addr, iface string, handler PacketHandler, logLevel string) *FakeTCPServer {
	return &FakeTCPServer{
		config: DefaultFakeTCPConfig(),
	}
}

// EnableEBPFTC 启用 eBPF TC 加速存根
func (s *FakeTCPServer) EnableEBPFTC(programPath string) error {
	return fmt.Errorf("FakeTCP 仅支持 Linux 系统")
}

// Start 启动服务器存根
func (s *FakeTCPServer) Start(ctx context.Context) error {
	return fmt.Errorf("FakeTCP 仅支持 Linux 系统")
}

// Stop 停止服务器存根
func (s *FakeTCPServer) Stop() {}

// SendTo 发送数据存根
func (s *FakeTCPServer) SendTo(data []byte, addr *net.UDPAddr) error {
	return fmt.Errorf("FakeTCP 仅支持 Linux 系统")
}

// IsRunning 是否运行中存根
func (s *FakeTCPServer) IsRunning() bool {
	return false
}

// GetStats 获取统计存根
func (s *FakeTCPServer) GetStats() FakeTCPStats {
	return FakeTCPStats{}
}
