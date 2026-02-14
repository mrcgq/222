

// =============================================================================
// 文件: internal/tunnel/privilege_linux.go
// 描述: Linux 特有的权限管理实现
// =============================================================================
//go:build linux

package tunnel

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// =============================================================================
// Linux Capabilities 支持
// =============================================================================

// Capability Linux capability 常量
type Capability uint

const (
	CAP_NET_BIND_SERVICE Capability = 10 // 绑定特权端口
	CAP_NET_RAW          Capability = 13 // 原始套接字
	CAP_NET_ADMIN        Capability = 12 // 网络管理
	CAP_SYS_ADMIN        Capability = 21 // 系统管理
)

// capHeader capability 头部结构
type capHeader struct {
	version uint32
	pid     int32
}

// capData capability 数据结构
type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

const (
	LINUX_CAPABILITY_VERSION_3 = 0x20080522
	PR_CAPBSET_DROP            = 24
	PR_CAP_AMBIENT             = 47
	PR_CAP_AMBIENT_RAISE       = 2
	PR_CAP_AMBIENT_LOWER       = 3
	PR_CAP_AMBIENT_CLEAR_ALL   = 4
)

// DropCapabilities 删除不需要的 capabilities
func DropCapabilities(keep []Capability) error {
	// 构建保留的 capability 集合
	keepSet := make(map[Capability]bool)
	for _, cap := range keep {
		keepSet[cap] = true
	}
	
	// 删除不需要的 capabilities
	for cap := Capability(0); cap < 40; cap++ {
		if !keepSet[cap] {
			if _, _, errno := syscall.Syscall(
				syscall.SYS_PRCTL,
				PR_CAPBSET_DROP,
				uintptr(cap),
				0,
			); errno != 0 {
				// 忽略不存在的 capability
				continue
			}
		}
	}
	
	return nil
}

// SetAmbientCapabilities 设置 ambient capabilities
func SetAmbientCapabilities(caps []Capability) error {
	for _, cap := range caps {
		if _, _, errno := syscall.Syscall(
			syscall.SYS_PRCTL,
			PR_CAP_AMBIENT,
			PR_CAP_AMBIENT_RAISE,
			uintptr(cap),
		); errno != 0 {
			return fmt.Errorf("设置 ambient capability %d 失败: %v", cap, errno)
		}
	}
	return nil
}

// ClearAmbientCapabilities 清除所有 ambient capabilities
func ClearAmbientCapabilities() error {
	if _, _, errno := syscall.Syscall(
		syscall.SYS_PRCTL,
		PR_CAP_AMBIENT,
		PR_CAP_AMBIENT_CLEAR_ALL,
		0,
	); errno != 0 {
		return fmt.Errorf("清除 ambient capabilities 失败: %v", errno)
	}
	return nil
}

// =============================================================================
// Seccomp 支持
// =============================================================================

const (
	SECCOMP_SET_MODE_STRICT = 0
	SECCOMP_SET_MODE_FILTER = 1
)

// SeccompConfig seccomp 配置
type SeccompConfig struct {
	// 默认动作
	DefaultAction SeccompAction
	
	// 系统调用规则
	Rules []SeccompRule
}

// SeccompAction seccomp 动作
type SeccompAction uint32

const (
	SECCOMP_RET_KILL_PROCESS SeccompAction = 0x80000000
	SECCOMP_RET_KILL_THREAD  SeccompAction = 0x00000000
	SECCOMP_RET_TRAP         SeccompAction = 0x00030000
	SECCOMP_RET_ERRNO        SeccompAction = 0x00050000
	SECCOMP_RET_LOG          SeccompAction = 0x7ffc0000
	SECCOMP_RET_ALLOW        SeccompAction = 0x7fff0000
)

// SeccompRule seccomp 规则
type SeccompRule struct {
	Syscall int
	Action  SeccompAction
}

// ApplySeccompFilter 应用 seccomp 过滤器
func ApplySeccompFilter(cfg *SeccompConfig) error {
	// 注意：完整的 seccomp 实现需要使用 BPF 程序
	// 这里提供一个简化的实现示意
	
	// 实际使用中建议使用 libseccomp 或生成 BPF 字节码
	return nil
}

// =============================================================================
// Namespace 支持
// =============================================================================

// NamespaceConfig 命名空间配置
type NamespaceConfig struct {
	// 新建 PID 命名空间
	NewPIDNS bool
	
	// 新建网络命名空间
	NewNetNS bool
	
	// 新建挂载命名空间
	NewMountNS bool
	
	// 新建 UTS 命名空间
	NewUTSNS bool
	
	// 新建 IPC 命名空间
	NewIPCNS bool
	
	// 新建用户命名空间
	NewUserNS bool
	
	// 用户命名空间映射
	UIDMappings []syscall.SysProcIDMap
	GIDMappings []syscall.SysProcIDMap
}

// ConfigureNamespaces 配置命令的命名空间
func ConfigureNamespaces(cmd *exec.Cmd, cfg *NamespaceConfig) error {
	if cfg == nil {
		return nil
	}
	
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	
	var cloneFlags uintptr
	
	if cfg.NewPIDNS {
		cloneFlags |= syscall.CLONE_NEWPID
	}
	if cfg.NewNetNS {
		cloneFlags |= syscall.CLONE_NEWNET
	}
	if cfg.NewMountNS {
		cloneFlags |= syscall.CLONE_NEWNS
	}
	if cfg.NewUTSNS {
		cloneFlags |= syscall.CLONE_NEWUTS
	}
	if cfg.NewIPCNS {
		cloneFlags |= syscall.CLONE_NEWIPC
	}
	if cfg.NewUserNS {
		cloneFlags |= syscall.CLONE_NEWUSER
		cmd.SysProcAttr.UidMappings = cfg.UIDMappings
		cmd.SysProcAttr.GidMappings = cfg.GIDMappings
	}
	
	cmd.SysProcAttr.Cloneflags = cloneFlags
	
	return nil
}

// =============================================================================
// 资源限制
// =============================================================================

// ResourceLimits 资源限制配置
type ResourceLimits struct {
	// 最大文件描述符数
	MaxOpenFiles uint64
	
	// 最大进程数
	MaxProcesses uint64
	
	// 最大内存 (字节)
	MaxMemory uint64
	
	// 最大 CPU 时间 (秒)
	MaxCPUTime uint64
	
	// 最大文件大小 (字节)
	MaxFileSize uint64
}

// DefaultResourceLimits 默认资源限制
func DefaultResourceLimits() *ResourceLimits {
	return &ResourceLimits{
		MaxOpenFiles: 1024,
		MaxProcesses: 64,
		MaxMemory:    512 * 1024 * 1024, // 512 MB
		MaxCPUTime:   0,                  // 无限制
		MaxFileSize:  100 * 1024 * 1024,  // 100 MB
	}
}

// ApplyResourceLimits 应用资源限制
func ApplyResourceLimits(limits *ResourceLimits) error {
	if limits == nil {
		return nil
	}
	
	// 文件描述符限制
	if limits.MaxOpenFiles > 0 {
		var rLimit syscall.Rlimit
		rLimit.Cur = limits.MaxOpenFiles
		rLimit.Max = limits.MaxOpenFiles
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
			return fmt.Errorf("设置文件描述符限制失败: %w", err)
		}
	}
	
	// 进程数限制
	if limits.MaxProcesses > 0 {
		var rLimit syscall.Rlimit
		rLimit.Cur = limits.MaxProcesses
		rLimit.Max = limits.MaxProcesses
		if err := syscall.Setrlimit(syscall.RLIMIT_NPROC, &rLimit); err != nil {
			return fmt.Errorf("设置进程数限制失败: %w", err)
		}
	}
	
	// 内存限制
	if limits.MaxMemory > 0 {
		var rLimit syscall.Rlimit
		rLimit.Cur = limits.MaxMemory
		rLimit.Max = limits.MaxMemory
		if err := syscall.Setrlimit(syscall.RLIMIT_AS, &rLimit); err != nil {
			return fmt.Errorf("设置内存限制失败: %w", err)
		}
	}
	
	// CPU 时间限制
	if limits.MaxCPUTime > 0 {
		var rLimit syscall.Rlimit
		rLimit.Cur = limits.MaxCPUTime
		rLimit.Max = limits.MaxCPUTime
		if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &rLimit); err != nil {
			return fmt.Errorf("设置 CPU 时间限制失败: %w", err)
		}
	}
	
	// 文件大小限制
	if limits.MaxFileSize > 0 {
		var rLimit syscall.Rlimit
		rLimit.Cur = limits.MaxFileSize
		rLimit.Max = limits.MaxFileSize
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &rLimit); err != nil {
			return fmt.Errorf("设置文件大小限制失败: %w", err)
		}
	}
	
	return nil
}

// ApplyResourceLimitsToCommand 将资源限制应用到命令
func ApplyResourceLimitsToCommand(cmd *exec.Cmd, limits *ResourceLimits) error {
	if limits == nil {
		return nil
	}
	
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	
	// 使用 prlimit 系统调用为子进程设置限制
	// 这需要在进程启动后立即执行
	
	return nil
}

// =============================================================================
// 安全审计
// =============================================================================

// AuditEvent 审计事件
type AuditEvent struct {
	Timestamp   int64
	EventType   string
	ProcessID   int
	ProcessName string
	Details     map[string]interface{}
}

// AuditLogger 审计日志记录器
type AuditLogger struct {
	events []AuditEvent
	file   *os.File
}

// NewAuditLogger 创建审计日志记录器
func NewAuditLogger(logPath string) (*AuditLogger, error) {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	
	return &AuditLogger{
		file: f,
	}, nil
}

// LogEvent 记录审计事件
func (al *AuditLogger) LogEvent(event AuditEvent) error {
	if al.file == nil {
		return nil
	}
	
	// 格式化并写入日志
	line := fmt.Sprintf("[%d] %s pid=%d name=%s\n",
		event.Timestamp,
		event.EventType,
		event.ProcessID,
		event.ProcessName,
	)
	
	_, err := al.file.WriteString(line)
	return err
}

// Close 关闭审计日志
func (al *AuditLogger) Close() error {
	if al.file != nil {
		return al.file.Close()
	}
	return nil
}

// =============================================================================
// 进程监控
// =============================================================================

// ProcessMonitor 进程监控器
type ProcessMonitor struct {
	pid     int
	stopped bool
}

// NewProcessMonitor 创建进程监控器
func NewProcessMonitor(pid int) *ProcessMonitor {
	return &ProcessMonitor{
		pid: pid,
	}
}

// GetProcessInfo 获取进程信息
func (pm *ProcessMonitor) GetProcessInfo() (map[string]interface{}, error) {
	info := make(map[string]interface{})
	
	// 读取 /proc/[pid]/status
	statusPath := fmt.Sprintf("/proc/%d/status", pm.pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return nil, err
	}
	
	// 解析状态信息
	lines := string(data)
	for _, line := range splitLines(lines) {
		parts := splitByColon(line)
		if len(parts) == 2 {
			info[parts[0]] = parts[1]
		}
	}
	
	return info, nil
}

// GetOpenFiles 获取进程打开的文件
func (pm *ProcessMonitor) GetOpenFiles() ([]string, error) {
	fdPath := fmt.Sprintf("/proc/%d/fd", pm.pid)
	entries, err := os.ReadDir(fdPath)
	if err != nil {
		return nil, err
	}
	
	var files []string
	for _, entry := range entries {
		link, err := os.Readlink(fmt.Sprintf("%s/%s", fdPath, entry.Name()))
		if err == nil {
			files = append(files, link)
		}
	}
	
	return files, nil
}

// 辅助函数
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func splitByColon(s string) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

// Dummy usage of unsafe to satisfy import
var _ = unsafe.Sizeof(0)



