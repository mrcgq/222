// =============================================================================
// 文件: internal/tunnel/privilege.go
// 描述: 进程权限管理 - 跨平台通用接口
// =============================================================================
package tunnel

import (
	"os"
	"os/exec"
	"os/user"
	"runtime"
)

// =============================================================================
// 权限管理器
// =============================================================================

// PrivilegeManager 权限管理器
type PrivilegeManager struct {
	// 目标用户信息
	targetUser  string
	targetGroup string
	uid         uint32
	gid         uint32

	// 是否已初始化
	initialized bool

	// 是否启用权限降级
	enabled bool
}

// PrivilegeConfig 权限配置
type PrivilegeConfig struct {
	// 是否启用权限降级
	Enabled bool `yaml:"enabled"`

	// 目标用户名（默认: nobody）
	User string `yaml:"user"`

	// 目标用户组（默认: nogroup）
	Group string `yaml:"group"`

	// 是否创建专用用户
	CreateUser bool `yaml:"create_user"`

	// 专用用户名
	DedicatedUser string `yaml:"dedicated_user"`
}

// DefaultPrivilegeConfig 默认权限配置
func DefaultPrivilegeConfig() *PrivilegeConfig {
	return &PrivilegeConfig{
		Enabled:       true,
		User:          "nobody",
		Group:         "nogroup",
		CreateUser:    false,
		DedicatedUser: "cloudflared",
	}
}

// NewPrivilegeManager 创建权限管理器
func NewPrivilegeManager(cfg *PrivilegeConfig) (*PrivilegeManager, error) {
	if cfg == nil {
		cfg = DefaultPrivilegeConfig()
	}

	pm := &PrivilegeManager{
		enabled: cfg.Enabled,
	}

	// 非 Unix 系统或未启用时跳过
	if !isUnixLike() || !cfg.Enabled {
		pm.enabled = false
		return pm, nil
	}

	// 非 root 运行时无需权限降级
	if os.Getuid() != 0 {
		pm.enabled = false
		return pm, nil
	}

	// 初始化目标用户
	if err := pm.initTargetUser(cfg); err != nil {
		// 初始化失败不阻止程序运行，只是禁用权限降级
		pm.enabled = false
		return pm, nil
	}

	pm.initialized = true
	return pm, nil
}

// initTargetUser 初始化目标用户
func (pm *PrivilegeManager) initTargetUser(cfg *PrivilegeConfig) error {
	// 尝试查找配置的用户
	targetUser := cfg.User

	// 用户查找优先级：配置用户 -> nobody -> _nobody (macOS)
	u, err := user.Lookup(targetUser)
	if err != nil {
		u, err = user.Lookup("nobody")
		if err != nil {
			u, err = user.Lookup("_nobody")
			if err != nil {
				return err
			}
		}
		targetUser = u.Username
	}

	uid, err := parseUint32(u.Uid)
	if err != nil {
		return err
	}

	gid, err := parseUint32(u.Gid)
	if err != nil {
		return err
	}

	pm.targetUser = targetUser
	pm.targetGroup = cfg.Group
	pm.uid = uid
	pm.gid = gid

	return nil
}

// GetTargetUser 获取目标用户信息
func (pm *PrivilegeManager) GetTargetUser() (string, uint32, uint32) {
	return pm.targetUser, pm.uid, pm.gid
}

// IsEnabled 是否启用权限降级
func (pm *PrivilegeManager) IsEnabled() bool {
	return pm.enabled && pm.initialized
}

// PrepareDirectory 准备目录权限
func (pm *PrivilegeManager) PrepareDirectory(dir string) error {
	if !pm.enabled || !pm.initialized {
		return nil
	}

	// 创建目录
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	// 在 Unix 系统上修改所有者
	return chownIfPossible(dir, int(pm.uid), int(pm.gid))
}

// PrepareFile 准备文件权限
func (pm *PrivilegeManager) PrepareFile(path string, mode os.FileMode) error {
	if !pm.enabled || !pm.initialized {
		return nil
	}

	if err := os.Chmod(path, mode); err != nil {
		return err
	}

	return chownIfPossible(path, int(pm.uid), int(pm.gid))
}

// =============================================================================
// 安全沙箱配置
// =============================================================================

// SandboxConfig 沙箱配置
type SandboxConfig struct {
	// 是否启用沙箱
	Enabled bool

	// 允许的路径
	AllowedPaths []string

	// 允许的网络
	AllowNetwork bool

	// 只读文件系统
	ReadOnlyRoot bool

	// 禁止的系统调用
	BlockedSyscalls []string
}

// DefaultSandboxConfig 默认沙箱配置
func DefaultSandboxConfig() *SandboxConfig {
	return &SandboxConfig{
		Enabled:      true,
		AllowNetwork: true,
		ReadOnlyRoot: false,
		AllowedPaths: []string{
			"/tmp",
			"/var/tmp",
		},
	}
}

// =============================================================================
// 工具函数
// =============================================================================

// IsRoot 检查是否以 root 身份运行
func IsRoot() bool {
	return os.Getuid() == 0
}

// GetCurrentPrivileges 获取当前权限信息
func GetCurrentPrivileges() map[string]interface{} {
	info := map[string]interface{}{
		"uid":      os.Getuid(),
		"euid":     os.Geteuid(),
		"gid":      os.Getgid(),
		"egid":     os.Getegid(),
		"is_root":  IsRoot(),
		"platform": runtime.GOOS,
	}

	// 获取用户名
	if u, err := user.Current(); err == nil {
		info["username"] = u.Username
		info["home"] = u.HomeDir
	}

	// 获取组信息
	if groups, err := os.Getgroups(); err == nil {
		info["groups"] = groups
	}

	return info
}

// GetEffectiveUser 获取当前生效的用户
func GetEffectiveUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "unknown"
}

// isUnixLike 检查是否为类 Unix 系统
func isUnixLike() bool {
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "openbsd", "netbsd", "dragonfly":
		return true
	default:
		return false
	}
}

// parseUint32 解析字符串为 uint32
func parseUint32(s string) (uint32, error) {
	var result uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, os.ErrInvalid
		}
		result = result*10 + uint32(c-'0')
	}
	return result, nil
}

// chownIfPossible 尝试修改所有者（仅 Unix）
func chownIfPossible(path string, uid, gid int) error {
	if !isUnixLike() {
		return nil
	}
	return os.Chown(path, uid, gid)
}

// =============================================================================
// 跨平台空实现（由平台特定文件覆盖）
// =============================================================================

// ConfigureCommand 配置命令的权限降级（默认空实现）
func (pm *PrivilegeManager) ConfigureCommand(cmd *exec.Cmd) error {
	// 平台特定实现在 privilege_linux.go 和 privilege_unix.go 中
	return configureCommandPlatform(pm, cmd)
}

// ConfigureCommandWithCaps 配置命令的权限降级（带 capabilities）
func (pm *PrivilegeManager) ConfigureCommandWithCaps(cmd *exec.Cmd, caps []string) error {
	// 先配置基本权限
	if err := pm.ConfigureCommand(cmd); err != nil {
		return err
	}
	// Capabilities 仅在 Linux 上支持
	return configureCapsPlatform(pm, cmd, caps)
}

// ApplySandbox 应用沙箱配置
func ApplySandbox(cmd *exec.Cmd, cfg *SandboxConfig) error {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	return applySandboxPlatform(cmd, cfg)
}

// DropPrivileges 便捷函数：直接降权到指定用户
func DropPrivileges(username string) error {
	cfg := &PrivilegeConfig{
		Enabled: true,
		User:    username,
	}

	pm, err := NewPrivilegeManager(cfg)
	if err != nil {
		return err
	}

	if !pm.IsEnabled() {
		return nil
	}

	// 创建一个测试命令来验证降权可行
	cmd := exec.Command("id")
	return pm.ConfigureCommand(cmd)
}
