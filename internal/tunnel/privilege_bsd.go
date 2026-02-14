//go:build freebsd || openbsd || netbsd || dragonfly
// +build freebsd openbsd netbsd dragonfly

// =============================================================================
// 文件: internal/tunnel/privilege_bsd.go
// 描述: 进程权限管理 - BSD 特定实现
// =============================================================================
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

	// BSD 支持基本的凭据设置
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
	// BSD 不支持 Linux capabilities
	return nil
}

// applySandboxPlatform BSD 平台的沙箱配置
func applySandboxPlatform(cmd *exec.Cmd, cfg *SandboxConfig) error {
	// BSD 有 jail/capsicum，但配置复杂
	// 这里不实现
	return nil
}
