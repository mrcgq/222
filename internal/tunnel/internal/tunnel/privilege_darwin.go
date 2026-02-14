//go:build darwin
// +build darwin

// =============================================================================
// 文件: internal/tunnel/privilege_darwin.go
// 描述: 进程权限管理 - macOS 特定实现
// =============================================================================
package tunnel

import (
	"os/exec"
	"syscall"
)

// configureCommandPlatform macOS 平台的命令权限配置
func configureCommandPlatform(pm *PrivilegeManager, cmd *exec.Cmd) error {
	if !pm.enabled || !pm.initialized {
		return nil
	}

	// macOS 支持基本的凭据设置
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

// configureCapsPlatform macOS 平台的 capabilities 配置
func configureCapsPlatform(pm *PrivilegeManager, cmd *exec.Cmd, caps []string) error {
	// macOS 不支持 Linux capabilities
	// 忽略 caps 参数
	return nil
}

// applySandboxPlatform macOS 平台的沙箱配置
func applySandboxPlatform(cmd *exec.Cmd, cfg *SandboxConfig) error {
	// macOS 使用 sandbox-exec，但配置复杂
	// 这里不实现，返回 nil
	return nil
}
