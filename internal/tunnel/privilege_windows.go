//go:build windows
// +build windows

// =============================================================================
// 文件: internal/tunnel/privilege_windows.go
// 描述: 进程权限管理 - Windows 特定实现
// =============================================================================
package tunnel

import (
	"os/exec"
)

// configureCommandPlatform Windows 平台的命令权限配置
func configureCommandPlatform(pm *PrivilegeManager, cmd *exec.Cmd) error {
	// Windows 不支持 Unix 风格的权限降级
	// 可以考虑使用 CreateProcessAsUser，但需要更复杂的实现
	return nil
}

// configureCapsPlatform Windows 平台的 capabilities 配置
func configureCapsPlatform(pm *PrivilegeManager, cmd *exec.Cmd, caps []string) error {
	// Windows 不支持 Linux capabilities
	return nil
}

// applySandboxPlatform Windows 平台的沙箱配置
func applySandboxPlatform(cmd *exec.Cmd, cfg *SandboxConfig) error {
	// Windows 有 AppContainer 等沙箱机制，但配置复杂
	// 这里不实现
	return nil
}
