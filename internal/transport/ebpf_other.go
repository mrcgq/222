//go:build !linux

// =============================================================================
// 文件: internal/transport/ebpf_other.go
// 描述: 非 Linux 平台的 eBPF 存根 (Stub)
// =============================================================================
package transport

import (
	"context"
	"fmt"
	"net"
	"time"
)

// =============================================================================
// EBPFStats 存根
// =============================================================================

// EBPFStats eBPF 统计信息
type EBPFStats struct {
	PacketsRX       uint64
	PacketsTX       uint64
	BytesRX         uint64
	BytesTX         uint64
	PacketsDropped  uint64
	SessionsCreated uint64
	SessionsDeleted uint64
	Errors          uint64
}

// EBPFAcceleratorStats 加速器统计
type EBPFAcceleratorStats struct {
	Active          bool
	Uptime          time.Duration
	XDPMode         string
	Interface       string
	ProgramLoaded   bool
	ActiveSessions  int
	EventsProcessed uint64
	EBPFStats       EBPFStats
}

// =============================================================================
// EBPFAccelerator 存根
// =============================================================================

// EBPFAccelerator 空壳结构体
type EBPFAccelerator struct {
	active bool
}

// NewEBPFAccelerator 返回一个空的加速器
func NewEBPFAccelerator(
	iface, xdpMode, programPath string,
	mapSize int, enableStats bool,
	handler PacketHandler, logLevel string,
) *EBPFAccelerator {
	return &EBPFAccelerator{active: false}
}

// Start 总是返回错误，因为非 Linux 不支持 eBPF
func (e *EBPFAccelerator) Start(ctx context.Context, listenAddr string) error {
	return fmt.Errorf("eBPF 仅支持 Linux 系统")
}

// Stop 空操作
func (e *EBPFAccelerator) Stop() {}

// IsActive 总是返回 false
func (e *EBPFAccelerator) IsActive() bool {
	return false
}

// SendTo 总是返回错误
func (e *EBPFAccelerator) SendTo(data []byte, addr *net.UDPAddr) error {
	return fmt.Errorf("eBPF 不可用")
}

// GetStats 返回空统计
func (e *EBPFAccelerator) GetStats() EBPFStats {
	return EBPFStats{}
}

// GetAcceleratorStats 返回空统计
func (e *EBPFAccelerator) GetAcceleratorStats() *EBPFAcceleratorStats {
	return &EBPFAcceleratorStats{
		Active: false,
		Uptime: 0,
	}
}

// =============================================================================
// EBPFTCManager 存根
// =============================================================================

// EBPFTCManager TC 管理器存根
type EBPFTCManager struct{}

// NewEBPFTCManager 创建 TC 管理器存根
func NewEBPFTCManager(iface, programPath string) *EBPFTCManager {
	return &EBPFTCManager{}
}

// LoadFakeTCP 加载 FakeTCP 程序存根
func (m *EBPFTCManager) LoadFakeTCP(udpPort, tcpPort uint16) error {
	return fmt.Errorf("eBPF TC 仅支持 Linux 系统")
}

// Unload 卸载存根
func (m *EBPFTCManager) Unload() error {
	return nil
}

// IsLoaded 是否已加载存根
func (m *EBPFTCManager) IsLoaded() bool {
	return false
}
