//go:build linux

// =============================================================================
// 文件: internal/switcher/wrappers.go
// 描述: 传输层包装器 - 将各传输层统一为 TransportHandler 接口
// =============================================================================

package switcher

import (
	"fmt"
	"net"
	"time"

	"github.com/mrcgq/211/internal/transport"
)

// =============================================================================
// UDP 传输包装器
// =============================================================================

// UDPTransportWrapper UDP 传输包装器
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
	if w.server == nil {
		return TransportStats{}
	}
	stats := w.server.GetStats()
	return TransportStats{
		BytesSent:     stats.BytesSent,
		BytesReceived: stats.BytesReceived,
		PacketsSent:   stats.PacketsSent,
		PacketsRecv:   stats.PacketsReceived,
		Errors:        stats.Errors,
		LastActivity:  time.Now(),
	}
}

// Probe 探测连接质量
func (w *UDPTransportWrapper) Probe() (time.Duration, error) {
	// UDP 探测：简单返回成功，实际延迟由其他机制测量
	return time.Millisecond, nil
}

// =============================================================================
// TCP 传输包装器
// =============================================================================

// TCPTransportWrapper TCP 传输包装器
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
	if w.server == nil {
		return TransportStats{}
	}
	stats := w.server.GetStats()
	return TransportStats{
		BytesSent:     stats.BytesSent,
		BytesReceived: stats.BytesReceived,
		PacketsSent:   stats.PacketsSent,
		PacketsRecv:   stats.PacketsReceived,
		Errors:        stats.Errors,
		ActiveConns:   stats.ActiveConnections,
		LastActivity:  time.Now(),
	}
}

// Probe 探测连接质量
func (w *TCPTransportWrapper) Probe() (time.Duration, error) {
	start := time.Now()
	// TCP 探测需要建立连接，这里简化处理
	return time.Since(start), nil
}

// =============================================================================
// FakeTCP 传输包装器
// =============================================================================

// FakeTCPTransportWrapper FakeTCP 传输包装器
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
	if w.server == nil {
		return TransportStats{}
	}
	stats := w.server.GetStats()
	return TransportStats{
		BytesSent:     stats.BytesSent,
		BytesReceived: stats.BytesReceived,
		PacketsSent:   stats.PacketsSent,
		PacketsRecv:   stats.PacketsReceived,
		Errors:        stats.Errors,
		LastActivity:  time.Now(),
	}
}

// Probe 探测连接质量
func (w *FakeTCPTransportWrapper) Probe() (time.Duration, error) {
	// FakeTCP 延迟略高于 UDP
	return time.Millisecond * 2, nil
}

// =============================================================================
// WebSocket 传输包装器
// =============================================================================

// WSTransportWrapper WebSocket 传输包装器
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
	if w.server == nil {
		return TransportStats{}
	}
	stats := w.server.GetStats()
	return TransportStats{
		BytesSent:     stats.BytesSent,
		BytesReceived: stats.BytesReceived,
		PacketsSent:   stats.PacketsSent,
		PacketsRecv:   stats.PacketsReceived,
		Errors:        stats.Errors,
		ActiveConns:   stats.ActiveConnections,
		LastActivity:  time.Now(),
	}
}

// Probe 探测连接质量
func (w *WSTransportWrapper) Probe() (time.Duration, error) {
	// WebSocket 延迟较高
	return time.Millisecond * 5, nil
}

// =============================================================================
// eBPF 传输包装器
// =============================================================================

// EBPFTransportWrapper eBPF 传输包装器
type EBPFTransportWrapper struct {
	accel *transport.EBPFAccelerator
}

// NewEBPFTransportWrapper 创建 eBPF 包装器
func NewEBPFTransportWrapper(accel *transport.EBPFAccelerator) *EBPFTransportWrapper {
	return &EBPFTransportWrapper{accel: accel}
}

// Send 发送数据
func (w *EBPFTransportWrapper) Send(data []byte, addr *net.UDPAddr) error {
	if w.accel == nil {
		return fmt.Errorf("eBPF accelerator is nil")
	}
	return w.accel.SendTo(data, addr)
}

// IsRunning 是否运行中
func (w *EBPFTransportWrapper) IsRunning() bool {
	return w.accel != nil && w.accel.IsActive()
}

// GetStats 获取统计信息
func (w *EBPFTransportWrapper) GetStats() TransportStats {
	if w.accel == nil {
		return TransportStats{}
	}
	stats := w.accel.GetStats()
	return TransportStats{
		BytesSent:     int64(stats.BytesTX),
		BytesReceived: int64(stats.BytesRX),
		PacketsSent:   int64(stats.PacketsTX),
		PacketsRecv:   int64(stats.PacketsRX),
		Errors:        int64(stats.Errors),
		LastActivity:  time.Now(),
	}
}

// Probe 探测连接质量
func (w *EBPFTransportWrapper) Probe() (time.Duration, error) {
	// eBPF 在内核态运行，延迟极低
	return time.Microsecond * 100, nil
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
