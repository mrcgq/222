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
