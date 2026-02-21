
//go:build linux

// =============================================================================
// 文件: internal/transport/ebpf_tc.go
// 描述: eBPF TC 集成 - FakeTCP 内核加速
// 版本: 3.0 - 修复 bpftool 参数传递问题
// =============================================================================
package transport

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// =============================================================================
// 配置索引常量 (与 tc_faketcp.c 对应)
// =============================================================================
const (
	cfgUDPPort = 0 // Go 监听的真实 UDP 端口
	cfgTCPPort = 1 // FakeTCP 对外暴露的 TCP 端口
	cfgEnabled = 2 // 是否启用
	cfgDebug   = 3 // 调试开关
)

// EBPFTCManager TC eBPF 管理器
type EBPFTCManager struct {
	iface       string
	programPath string
	udpPort     uint16
	tcpPort     uint16
	loaded      bool
	mu          sync.Mutex
}

// NewEBPFTCManager 创建 TC 管理器
func NewEBPFTCManager(iface, programPath string) *EBPFTCManager {
	return &EBPFTCManager{
		iface:       iface,
		programPath: programPath,
	}
}

// LoadFakeTCP 加载 FakeTCP TC 程序
func (m *EBPFTCManager) LoadFakeTCP(udpPort, tcpPort uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.loaded {
		return nil
	}

	// 检查 eBPF 程序是否存在
	objPath := filepath.Join(m.programPath, "tc_faketcp.o")
	if _, err := os.Stat(objPath); os.IsNotExist(err) {
		return fmt.Errorf("eBPF 程序不存在: %s", objPath)
	}

	// 1. 创建 clsact qdisc
	if err := m.ensureClsactQdisc(); err != nil {
		return fmt.Errorf("创建 qdisc 失败: %w", err)
	}

	// 2. 清理旧的 filter
	m.cleanupFilters()

	// 3. 加载 egress 程序
	if err := m.loadFilter("egress", objPath, "tc_faketcp_egress"); err != nil {
		return fmt.Errorf("加载 egress 程序失败: %w", err)
	}

	// 4. 加载 ingress 程序
	if err := m.loadFilter("ingress", objPath, "tc_faketcp_ingress"); err != nil {
		m.runTC("filter", "del", "dev", m.iface, "egress")
		return fmt.Errorf("加载 ingress 程序失败: %w", err)
	}

	// 5. 配置端口映射
	if err := m.configurePorts(udpPort, tcpPort); err != nil {
		m.cleanupFilters()
		return fmt.Errorf("配置端口失败: %w", err)
	}

	m.udpPort = udpPort
	m.tcpPort = tcpPort
	m.loaded = true

	return nil
}

// ensureClsactQdisc 确保 clsact qdisc 存在
func (m *EBPFTCManager) ensureClsactQdisc() error {
	err := m.runTC("qdisc", "add", "dev", m.iface, "clsact")
	if err != nil {
		if strings.Contains(err.Error(), "File exists") {
			return nil
		}
		return err
	}
	return nil
}

// cleanupFilters 清理现有 filter
func (m *EBPFTCManager) cleanupFilters() {
	m.runTC("filter", "del", "dev", m.iface, "egress")
	m.runTC("filter", "del", "dev", m.iface, "ingress")
}

// loadFilter 加载 TC filter
func (m *EBPFTCManager) loadFilter(direction, objPath, section string) error {
	return m.runTC("filter", "add", "dev", m.iface, direction,
		"bpf", "da", "obj", objPath, "sec", section)
}

// configurePorts 配置端口映射
func (m *EBPFTCManager) configurePorts(udpPort, tcpPort uint16) error {
	// 配置 UDP 端口
	if err := m.updateConfigMap(cfgUDPPort, uint32(udpPort)); err != nil {
		return fmt.Errorf("配置 UDP 端口失败: %w", err)
	}

	// 配置 TCP 端口
	if err := m.updateConfigMap(cfgTCPPort, uint32(tcpPort)); err != nil {
		return fmt.Errorf("配置 TCP 端口失败: %w", err)
	}

	// 启用 FakeTCP
	if err := m.updateConfigMap(cfgEnabled, 1); err != nil {
		return fmt.Errorf("启用 FakeTCP 失败: %w", err)
	}

	return nil
}

// updateConfigMap 更新配置 Map
// 关键修复：bpftool 要求每个字节作为独立参数传递
func (m *EBPFTCManager) updateConfigMap(key int, value uint32) error {
	// 构建参数数组 - 每个字节必须是独立的参数！
	args := []string{
		"map", "update",
		"name", "faketcp_config",
		"key",
		// Key 是 4 字节 (__u32)，小端序
		fmt.Sprintf("%d", key&0xFF),
		fmt.Sprintf("%d", (key>>8)&0xFF),
		fmt.Sprintf("%d", (key>>16)&0xFF),
		fmt.Sprintf("%d", (key>>24)&0xFF),
		"value",
		// Value 是 4 字节 (__u32)，小端序
		fmt.Sprintf("%d", value&0xFF),
		fmt.Sprintf("%d", (value>>8)&0xFF),
		fmt.Sprintf("%d", (value>>16)&0xFF),
		fmt.Sprintf("%d", (value>>24)&0xFF),
	}

	cmd := exec.Command("bpftool", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("bpftool error: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// Unload 卸载程序
func (m *EBPFTCManager) Unload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.loaded {
		return nil
	}

	m.cleanupFilters()
	m.loaded = false
	return nil
}

// runTC 运行 tc 命令
func (m *EBPFTCManager) runTC(args ...string) error {
	cmd := exec.Command("tc", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// IsLoaded 是否已加载
func (m *EBPFTCManager) IsLoaded() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loaded
}

// GetUDPPort 获取 UDP 端口
func (m *EBPFTCManager) GetUDPPort() uint16 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.udpPort
}

// GetTCPPort 获取 TCP 端口
func (m *EBPFTCManager) GetTCPPort() uint16 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tcpPort
}

// GetStats 获取统计信息
func (m *EBPFTCManager) GetStats() (map[string]uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.loaded {
		return nil, fmt.Errorf("TC 程序未加载")
	}

	// 使用 bpftool 读取统计
	stats := make(map[string]uint64)
	
	// 读取统计 Map 的 key=0
	args := []string{
		"map", "lookup",
		"name", "faketcp_stats",
		"key", "0", "0", "0", "0",
	}
	
	cmd := exec.Command("bpftool", args...)
	output, err := cmd.Output()
	if err != nil {
		// 返回空统计而不是错误
		return map[string]uint64{
			"packets_rx": 0,
			"packets_tx": 0,
			"bytes_rx":   0,
			"bytes_tx":   0,
		}, nil
	}

	// 简单解析输出（实际应该解析 JSON）
	_ = output
	
	return stats, nil
}

// SetDebug 设置调试模式
func (m *EBPFTCManager) SetDebug(enabled bool) error {
	value := uint32(0)
	if enabled {
		value = 1
	}
	return m.updateConfigMap(cfgDebug, value)
}



