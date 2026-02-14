

// =============================================================================
// 文件: internal/tunnel/privilege.go
// 描述: 进程权限管理 - 安全的权限降级实现
// =============================================================================
package tunnel

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
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
	
	// 非 Linux 系统或未启用时跳过
	if runtime.GOOS != "linux" || !cfg.Enabled {
		return pm, nil
	}
	
	// 非 root 运行时无需权限降级
	if os.Getuid() != 0 {
		pm.enabled = false
		return pm, nil
	}
	
	// 初始化目标用户
	if err := pm.initTargetUser(cfg); err != nil {
		return nil, fmt.Errorf("初始化目标用户失败: %w", err)
	}
	
	pm.initialized = true
	return pm, nil
}

// initTargetUser 初始化目标用户
func (pm *PrivilegeManager) initTargetUser(cfg *PrivilegeConfig) error {
	// 优先尝试使用专用用户
	if cfg.CreateUser {
		if err := pm.ensureDedicatedUser(cfg.DedicatedUser); err == nil {
			return nil
		}
		// 创建失败则回退到默认用户
	}
	
	// 尝试查找配置的用户
	targetUser := cfg.User
	targetGroup := cfg.Group
	
	// 用户查找优先级：配置用户 -> nobody -> 当前用户
	u, err := user.Lookup(targetUser)
	if err != nil {
		// 尝试 nobody
		u, err = user.Lookup("nobody")
		if err != nil {
			// 最后尝试 _nobody (macOS)
			u, err = user.Lookup("_nobody")
			if err != nil {
				return fmt.Errorf("找不到合适的非特权用户")
			}
		}
		targetUser = u.Username
	}
	
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("解析 UID 失败: %w", err)
	}
	
	// 查找用户组
	gid := uid // 默认使用用户的主组
	g, err := user.LookupGroup(targetGroup)
	if err != nil {
		// 尝试 nogroup
		g, err = user.LookupGroup("nogroup")
		if err != nil {
			// 尝试 nobody 组
			g, err = user.LookupGroup("nobody")
			if err == nil {
				targetGroup = "nobody"
			}
		} else {
			targetGroup = "nogroup"
		}
	}
	
	if g != nil {
		parsedGid, err := strconv.ParseUint(g.Gid, 10, 32)
		if err == nil {
			gid = parsedGid
		}
	}
	
	pm.targetUser = targetUser
	pm.targetGroup = targetGroup
	pm.uid = uint32(uid)
	pm.gid = uint32(gid)
	
	return nil
}

// ensureDedicatedUser 确保专用用户存在
func (pm *PrivilegeManager) ensureDedicatedUser(username string) error {
	// 检查用户是否存在
	u, err := user.Lookup(username)
	if err == nil {
		// 用户已存在
		uid, _ := strconv.ParseUint(u.Uid, 10, 32)
		gid, _ := strconv.ParseUint(u.Gid, 10, 32)
		pm.targetUser = username
		pm.targetGroup = u.Gid
		pm.uid = uint32(uid)
		pm.gid = uint32(gid)
		return nil
	}
	
	// 创建用户（仅 Linux）
	if runtime.GOOS != "linux" {
		return fmt.Errorf("不支持在 %s 上创建用户", runtime.GOOS)
	}
	
	// 使用 useradd 创建系统用户
	cmd := exec.Command("useradd",
		"--system",           // 系统用户
		"--no-create-home",   // 不创建主目录
		"--shell", "/usr/sbin/nologin", // 禁止登录
		"--comment", "Cloudflared Tunnel User",
		username,
	)
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("创建用户失败: %w", err)
	}
	
	// 重新查找用户
	u, err = user.Lookup(username)
	if err != nil {
		return fmt.Errorf("查找新创建的用户失败: %w", err)
	}
	
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	pm.targetUser = username
	pm.targetGroup = u.Gid
	pm.uid = uint32(uid)
	pm.gid = uint32(gid)
	
	return nil
}

// ConfigureCommand 配置命令的权限降级
func (pm *PrivilegeManager) ConfigureCommand(cmd *exec.Cmd) error {
	if !pm.enabled || !pm.initialized {
		return nil
	}
	
	if runtime.GOOS != "linux" {
		return nil
	}
	
	// 设置进程凭据
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    pm.uid,
			Gid:    pm.gid,
			Groups: []uint32{pm.gid},
		},
		// 创建新的进程组
		Setpgid: true,
		Pgid:    0,
		
		// 安全标志
		Pdeathsig: syscall.SIGTERM, // 父进程退出时发送信号
	}
	
	return nil
}

// ConfigureCommandWithCaps 配置命令的权限降级（带 capabilities）
func (pm *PrivilegeManager) ConfigureCommandWithCaps(cmd *exec.Cmd, caps []string) error {
	if err := pm.ConfigureCommand(cmd); err != nil {
		return err
	}
	
	// Linux 特有：设置 capabilities
	if runtime.GOOS == "linux" && len(caps) > 0 {
		// 通过 ambient capabilities 传递权限
		// 注意：这需要内核支持 (Linux >= 4.3)
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		
		// 设置 AmbientCaps 需要特殊处理
		// 这里我们使用一个包装脚本或 capsh
		pm.wrapWithCapsh(cmd, caps)
	}
	
	return nil
}

// wrapWithCapsh 使用 capsh 包装命令以设置 capabilities
func (pm *PrivilegeManager) wrapWithCapsh(cmd *exec.Cmd, caps []string) {
	// 检查 capsh 是否可用
	capshPath, err := exec.LookPath("capsh")
	if err != nil {
		return // capsh 不可用，跳过 capabilities 设置
	}
	
	// 构建 capabilities 字符串
	capStr := ""
	for i, cap := range caps {
		if i > 0 {
			capStr += ","
		}
		capStr += "cap_" + cap
	}
	
	// 重构命令
	originalArgs := cmd.Args
	originalPath := cmd.Path
	
	newArgs := []string{
		capshPath,
		"--user=" + pm.targetUser,
		"--caps=" + capStr + "+eip",
		"--",
		"-c",
		originalPath,
	}
	newArgs = append(newArgs, originalArgs[1:]...)
	
	cmd.Path = capshPath
	cmd.Args = newArgs
}

// PrepareDirectory 准备目录权限
func (pm *PrivilegeManager) PrepareDirectory(dir string) error {
	if !pm.enabled || !pm.initialized {
		return nil
	}
	
	// 创建目录
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}
	
	// 修改所有者
	if err := os.Chown(dir, int(pm.uid), int(pm.gid)); err != nil {
		return fmt.Errorf("修改目录所有者失败: %w", err)
	}
	
	return nil
}

// PrepareFile 准备文件权限
func (pm *PrivilegeManager) PrepareFile(path string, mode os.FileMode) error {
	if !pm.enabled || !pm.initialized {
		return nil
	}
	
	// 修改权限
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("修改文件权限失败: %w", err)
	}
	
	// 修改所有者
	if err := os.Chown(path, int(pm.uid), int(pm.gid)); err != nil {
		return fmt.Errorf("修改文件所有者失败: %w", err)
	}
	
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

// ApplySandbox 应用沙箱配置
func ApplySandbox(cmd *exec.Cmd, cfg *SandboxConfig) error {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	
	if runtime.GOOS != "linux" {
		return nil
	}
	
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	
	// 设置基本隔离
	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUTS  // UTS 命名空间
	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWIPC  // IPC 命名空间
	
	// 如果不需要网络，隔离网络命名空间
	if !cfg.AllowNetwork {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNET
	}
	
	return nil
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


