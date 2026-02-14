// =============================================================================
// 文件: internal/tunnel/privilege_other.go
// 描述: 非 Linux 系统的权限管理存根
// =============================================================================
//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package tunnel

import (
	"os/exec"
)

// =============================================================================
// 平台特定函数实现（被 privilege.go 调用）
// =============================================================================

// configureCommandPlatform 其他平台的命令权限配置
func configureCommandPlatform(pm *PrivilegeManager, cmd *exec.Cmd) error {
	// 不支持的平台，跳过权限配置
	return nil
}

// configureCapsPlatform 其他平台的 capabilities 配置
func configureCapsPlatform(pm *PrivilegeManager, cmd *exec.Cmd, caps []string) error {
	return nil
}

// applySandboxPlatform 其他平台的沙箱配置
func applySandboxPlatform(cmd *exec.Cmd, cfg *SandboxConfig) error {
	return nil
}

// =============================================================================
// 存根类型和函数
// =============================================================================

// Capability 存根
type Capability uint

const (
	CAP_NET_BIND_SERVICE Capability = 10
	CAP_NET_RAW          Capability = 13
	CAP_NET_ADMIN        Capability = 12
	CAP_SYS_ADMIN        Capability = 21
)

// DropCapabilities 存根
func DropCapabilities(keep []Capability) error {
	return nil
}

// SetAmbientCapabilities 存根
func SetAmbientCapabilities(caps []Capability) error {
	return nil
}

// ClearAmbientCapabilities 存根
func ClearAmbientCapabilities() error {
	return nil
}

// NamespaceConfig 存根
type NamespaceConfig struct{}

// ConfigureNamespaces 存根
func ConfigureNamespaces(cmd *exec.Cmd, cfg *NamespaceConfig) error {
	return nil
}

// SeccompConfig 存根
type SeccompConfig struct{}

// ApplySeccompFilter 存根
func ApplySeccompFilter(cfg *SeccompConfig) error {
	return nil
}

// ResourceLimits 存根
type ResourceLimits struct {
	MaxOpenFiles uint64
	MaxProcesses uint64
	MaxMemory    uint64
	MaxCPUTime   uint64
	MaxFileSize  uint64
}

// DefaultResourceLimits 存根
func DefaultResourceLimits() *ResourceLimits {
	return &ResourceLimits{}
}

// ApplyResourceLimits 存根
func ApplyResourceLimits(limits *ResourceLimits) error {
	return nil
}

// ApplyResourceLimitsToCommand 存根
func ApplyResourceLimitsToCommand(cmd *exec.Cmd, limits *ResourceLimits) error {
	return nil
}
