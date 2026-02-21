//go:build !linux

// =============================================================================
// 文件: internal/switcher/wrappers_stub.go
// 描述: 非 Linux 平台的包装器存根
// =============================================================================

package switcher

import (
	"fmt"
	"net"
	"time"

	"github.com/mrcgq/211/internal/transport"
)

// =============================================================================
// UDP 传输包装器存根
// =============================================================================

// UDPTransportWrapper UDP 传输包装器存根
type UDPTransportWrapper struct {
	server *transport.UDPServer
}

// NewUDPTransportWrapper 创建 UDP 包装器
func NewUDPTransportWrapper(server *transport.UDPServer) *UDPTransportWrapper {
	return &UDPTransportWrapper{server: server}
}

// Send 发送数据
func (w *UDPTransportWrapper) Send(data []byte, addr *net.UDPAddr) error {
	if w.server == nil {
		return fmt.Errorf("UDP server is nil")
	}
	return w.server.SendTo(data, addr)
}

// IsRunning 是否运行中
func (w *UDPTransportWrapper) IsRunning() bool {
	return w.server != nil && w.server.IsRunning()
}

// GetStats 获取统计信息
func (w *UDPTransportWrapper) GetStats() TransportStats {
	return TransportStats{}
}

// Probe 探测连接质量
func (w *UDPTransportWrapper) Probe() (time.Duration, error) {
	return time.Millisecond, nil
}

// =============================================================================
// TCP 传输包装器存根
// =============================================================================

// TCPTransportWrapper TCP 传输包装器存根
type TCPTransportWrapper struct {
	server *transport.TCPServer
}

// NewTCPTransportWrapper 创建 TCP 包装器
func NewTCPTransportWrapper(server *transport.TCPServer) *TCPTransportWrapper {
	return &TCPTransportWrapper{server: server}
}

// Send 发送数据
func (w *TCPTransportWrapper) Send(data []byte, addr *net.UDPAddr) error {
	if w.server == nil {
		return fmt.Errorf("TCP server is nil")
	}
	return w.server.SendTo(data, addr)
}

// IsRunning 是否运行中
func (w *TCPTransportWrapper) IsRunning() bool {
	return w.server != nil && w.server.IsRunning()
}

// GetStats 获取统计信息
func (w *TCPTransportWrapper) GetStats() TransportStats {
	return TransportStats{}
}

// Probe 探测连接质量
func (w *TCPTransportWrapper) Probe() (time.Duration, error) {
	return time.Millisecond, nil
}

// =============================================================================
// FakeTCP 传输包装器存根
// =============================================================================

// FakeTCPTransportWrapper FakeTCP 传输包装器存根
type FakeTCPTransportWrapper struct {
	server *transport.FakeTCPServer
}

// NewFakeTCPTransportWrapper 创建 FakeTCP 包装器
func NewFakeTCPTransportWrapper(server *transport.FakeTCPServer) *FakeTCPTransportWrapper {
	return &FakeTCPTransportWrapper{server: server}
}

// Send 发送数据
func (w *FakeTCPTransportWrapper) Send(data []byte, addr *net.UDPAddr) error {
	if w.server == nil {
		return fmt.Errorf("FakeTCP server is nil")
	}
	return w.server.SendTo(data, addr)
}

// IsRunning 是否运行中
func (w *FakeTCPTransportWrapper) IsRunning() bool {
	return w.server != nil && w.server.IsRunning()
}

// GetStats 获取统计信息
func (w *FakeTCPTransportWrapper) GetStats() TransportStats {
	return TransportStats{}
}

// Probe 探测连接质量
func (w *FakeTCPTransportWrapper) Probe() (time.Duration, error) {
	return time.Millisecond * 2, nil
}

// =============================================================================
// WebSocket 传输包装器存根
// =============================================================================

// WSTransportWrapper WebSocket 传输包装器存根
type WSTransportWrapper struct {
	server *transport.WebSocketServer
}

// NewWSTransportWrapper 创建 WebSocket 包装器
func NewWSTransportWrapper(server *transport.WebSocketServer) *WSTransportWrapper {
	return &WSTransportWrapper{server: server}
}

// Send 发送数据
func (w *WSTransportWrapper) Send(data []byte, addr *net.UDPAddr) error {
	if w.server == nil {
		return fmt.Errorf("WebSocket server is nil")
	}
	return w.server.SendTo(data, addr)
}

// IsRunning 是否运行中
func (w *WSTransportWrapper) IsRunning() bool {
	return w.server != nil && w.server.IsRunning()
}

// GetStats 获取统计信息
func (w *WSTransportWrapper) GetStats() TransportStats {
	return TransportStats{}
}

// Probe 探测连接质量
func (w *WSTransportWrapper) Probe() (time.Duration, error) {
	return time.Millisecond * 5, nil
}

// =============================================================================
// eBPF 传输包装器存根
// =============================================================================

// EBPFTransportWrapper eBPF 传输包装器存根
type EBPFTransportWrapper struct {
	accel *transport.EBPFAccelerator
}

// NewEBPFTransportWrapper 创建 eBPF 包装器
func NewEBPFTransportWrapper(accel *transport.EBPFAccelerator) *EBPFTransportWrapper {
	return &EBPFTransportWrapper{accel: accel}
}

// Send 发送数据
func (w *EBPFTransportWrapper) Send(data []byte, addr *net.UDPAddr) error {
	return fmt.Errorf("eBPF not supported on this platform")
}

// IsRunning 是否运行中
func (w *EBPFTransportWrapper) IsRunning() bool {
	return false
}

// GetStats 获取统计信息
func (w *EBPFTransportWrapper) GetStats() TransportStats {
	return TransportStats{}
}

// Probe 探测连接质量
func (w *EBPFTransportWrapper) Probe() (time.Duration, error) {
	return 0, fmt.Errorf("eBPF not supported on this platform")
}

// =============================================================================
// 确保实现接口
// =============================================================================

var (
	_ TransportHandler = (*UDPTransportWrapper)(nil)
	_ TransportHandler = (*TCPTransportWrapper)(nil)
	_ TransportHandler = (*FakeTCPTransportWrapper)(nil)
	_ TransportHandler = (*WSTransportWrapper)(nil)
	_ TransportHandler = (*EBPFTransportWrapper)(nil)
)
