

//go:build linux
// =============================================================================
// 文件: internal/transport/ebpf_tc.go
// 描述: eBPF TC 集成 - FakeTCP 加速 (集成 tc_faketcp.c)
// =============================================================================
package transport

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// EBPFTCManager TC eBPF 管理器
type EBPFTCManager struct {
	iface       string
	programPath string
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

	// 1. 创建 clsact qdisc
	if err := m.runTC("qdisc", "add", "dev", m.iface, "clsact"); err != nil {
		if !strings.Contains(err.Error(), "File exists") {
			return fmt.Errorf("创建 qdisc 失败: %w", err)
		}
	}

	// 2. 加载 egress 程序
	objPath := m.programPath + "/tc_faketcp.o"
	if err := m.runTC("filter", "add", "dev", m.iface, "egress",
		"bpf", "da", "obj", objPath, "sec", "tc_faketcp_egress"); err != nil {
		return fmt.Errorf("加载 egress 程序失败: %w", err)
	}

	// 3. 加载 ingress 程序
	if err := m.runTC("filter", "add", "dev", m.iface, "ingress",
		"bpf", "da", "obj", objPath, "sec", "tc_faketcp_ingress"); err != nil {
		return fmt.Errorf("加载 ingress 程序失败: %w", err)
	}

	// 4. 配置端口
	if err := m.configurePort(0, udpPort); err != nil {
		return fmt.Errorf("配置 UDP 端口失败: %w", err)
	}
	if err := m.configurePort(1, tcpPort); err != nil {
		return fmt.Errorf("配置 TCP 端口失败: %w", err)
	}

	m.loaded = true
	return nil
}

// Unload 卸载程序
func (m *EBPFTCManager) Unload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.loaded {
		return nil
	}

	m.runTC("filter", "del", "dev", m.iface, "egress")
	m.runTC("filter", "del", "dev", m.iface, "ingress")

	m.loaded = false
	return nil
}

// configurePort 配置端口
func (m *EBPFTCManager) configurePort(key int, port uint16) error {
	cmd := exec.Command("bpftool", "map", "update",
		"name", "faketcp_config",
		"key", strconv.Itoa(key), "0", "0", "0",
		"value",
		strconv.Itoa(int(port&0xFF)),
		strconv.Itoa(int((port>>8)&0xFF)),
		"0", "0",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", string(output), err)
	}
	return nil
}

// runTC 运行 tc 命令
func (m *EBPFTCManager) runTC(args ...string) error {
	cmd := exec.Command("tc", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", string(output), err)
	}
	return nil
}

// IsLoaded 是否已加载
func (m *EBPFTCManager) IsLoaded() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loaded
}



