//go:build freebsd || openbsd || netbsd || dragonfly

package tunnel

import (
	"os/exec"
	"syscall"
)

// configureCommandPlatform BSD 平台的命令权限配置
func configureCommandPlatform(pm *PrivilegeManager, cmd *exec.Cmd) error {
	if !pm.enabled || !pm.initialized {
		return nil
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    pm.uid,
			Gid:    pm.gid,
			Groups: []uint32{pm.gid},
		},
		Setpgid: true,
	}

	return nil
}

// configureCapsPlatform BSD 平台的 capabilities 配置
func configureCapsPlatform(pm *PrivilegeManager, cmd *exec.Cmd, caps []string) error {
	return nil
}

// applySandboxPlatform BSD 平台的沙箱配置
func applySandboxPlatform(cmd *exec.Cmd, cfg *SandboxConfig) error {
	return nil
}

// =============================================================================
// 存根类型和函数
// =============================================================================

type Capability uint

const (
	CAP_NET_BIND_SERVICE Capability = 10
	CAP_NET_RAW          Capability = 13
	CAP_NET_ADMIN        Capability = 12
	CAP_SYS_ADMIN        Capability = 21
)

func DropCapabilities(keep []Capability) error                              { return nil }
func SetAmbientCapabilities(caps []Capability) error                        { return nil }
func ClearAmbientCapabilities() error                                       { return nil }

type NamespaceConfig struct{}

func ConfigureNamespaces(cmd *exec.Cmd, cfg *NamespaceConfig) error { return nil }

type SeccompConfig struct{}

func ApplySeccompFilter(cfg *SeccompConfig) error { return nil }

type ResourceLimits struct {
	MaxOpenFiles uint64
	MaxProcesses uint64
	MaxMemory    uint64
	MaxCPUTime   uint64
	MaxFileSize  uint64
}

func DefaultResourceLimits() *ResourceLimits                                { return &ResourceLimits{} }
func ApplyResourceLimits(limits *ResourceLimits) error                      { return nil }
func ApplyResourceLimitsToCommand(cmd *exec.Cmd, limits *ResourceLimits) error { return nil }
