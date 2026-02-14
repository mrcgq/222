//go:build !linux

// =============================================================================
// 文件: internal/transport/ebpf_other.go
// 描述: 非 Linux 平台的 eBPF 存根 (Stub) - 修复版
// =============================================================================
package transport

import (
	"context"
	"fmt"
	"net"
)

// =============================================================================
// EBPF 加速器存根
// =============================================================================

type EBPFAccelerator struct {
	active bool
}

func NewEBPFAccelerator(
	iface, xdpMode, programPath string,
	mapSize int, enableStats bool,
	handler PacketHandler, logLevel string,
) *EBPFAccelerator {
	return &EBPFAccelerator{active: false}
}

func (e *EBPFAccelerator) Start(ctx context.Context, listenAddr string) error {
	return fmt.Errorf("eBPF 仅支持 Linux 系统")
}

func (e *EBPFAccelerator) Stop() {}

func (e *EBPFAccelerator) IsActive() bool { return false }

func (e *EBPFAccelerator) SendTo(data []byte, addr *net.UDPAddr) error {
	return fmt.Errorf("eBPF 不可用")
}

func (e *EBPFAccelerator) GetStats() EBPFStats { return EBPFStats{} }

func (e *EBPFAccelerator) GetAcceleratorStats() *EBPFAcceleratorStats {
	return &EBPFAcceleratorStats{Active: false}
}

// =============================================================================
// TC 管理器存根 (解决 FakeTCP 在 Windows/Mac 下的编译错误)
// =============================================================================

type EBPFTCManager struct {}

func NewEBPFTCManager(iface, programPath string) *EBPFTCManager {
	return &EBPFTCManager{}
}

func (m *EBPFTCManager) LoadFakeTCP(udpPort, tcpPort uint16) error {
	return nil
}

func (m *EBPFTCManager) Unload() error {
	return nil
}

func (m *EBPFTCManager) IsLoaded() bool {
	return false
}
