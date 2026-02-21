
// =============================================================================
// 文件: internal/ebpf/loader.go
// 描述: eBPF 程序加载器 - 负责加载和管理 eBPF 程序与 Map
// =============================================================================

package ebpf

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// LoaderConfig eBPF 加载器配置
type LoaderConfig struct {
	ProgramPath string // eBPF 程序路径 (.o 文件)
	Interface   string // 网络接口名称
	XDPMode     string // XDP 模式: "native", "generic", "offload"
	MapSize     int    // Map 大小
	EnableStats bool   // 是否启用统计
}

// Loader eBPF 程序加载器
type Loader struct {
	config *LoaderConfig

	// eBPF 对象
	collection *ebpf.Collection
	spec       *ebpf.CollectionSpec

	// XDP 链接
	xdpLink link.Link

	// Map 引用
	BlacklistV4 *ebpf.Map
	BlacklistV6 *ebpf.Map
	RatelimitV4 *ebpf.Map
	RatelimitV6 *ebpf.Map
	Sessions    *ebpf.Map
	Stats       *ebpf.Map
	Config      *ebpf.Map
	ListenPorts *ebpf.Map
	Events      *ebpf.Map

	// 黑名单管理器
	blacklistMgr *BlacklistManager

	// 状态
	loaded   bool
	attached bool
}

// NewLoader 创建 eBPF 加载器
func NewLoader(config *LoaderConfig) *Loader {
	return &Loader{
		config: config,
	}
}

// Load 加载 eBPF 程序
func (l *Loader) Load() error {
	if l.loaded {
		return fmt.Errorf("eBPF 程序已加载")
	}

	// 检查程序文件是否存在
	programPath := l.config.ProgramPath
	if programPath == "" {
		// 尝试默认路径
		defaultPaths := []string{
			"ebpf/xdp_phantom.o",
			"/usr/local/lib/phantom/xdp_phantom.o",
			"/var/lib/phantom/xdp_phantom.o",
		}
		for _, p := range defaultPaths {
			if _, err := os.Stat(p); err == nil {
				programPath = p
				break
			}
		}
	}

	if programPath == "" {
		return fmt.Errorf("找不到 eBPF 程序文件")
	}

	// 获取绝对路径
	absPath, err := filepath.Abs(programPath)
	if err != nil {
		return fmt.Errorf("获取绝对路径失败: %w", err)
	}

	// 加载 eBPF 程序规格
	spec, err := ebpf.LoadCollectionSpec(absPath)
	if err != nil {
		return fmt.Errorf("加载 eBPF 规格失败: %w", err)
	}
	l.spec = spec

	// 调整 Map 大小
	if l.config.MapSize > 0 {
		for name, mapSpec := range spec.Maps {
			switch name {
			case "blacklist_v4", "blacklist_v6", "ratelimit_v4", "ratelimit_v6", "sessions":
				mapSpec.MaxEntries = uint32(l.config.MapSize)
			}
		}
	}

	// 加载 eBPF 集合
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("加载 eBPF 集合失败: %w", err)
	}
	l.collection = collection

	// 提取 Map 引用
	if err := l.extractMaps(); err != nil {
		collection.Close()
		return fmt.Errorf("提取 Map 失败: %w", err)
	}

	// 创建黑名单管理器
	if l.BlacklistV4 != nil && l.BlacklistV6 != nil {
		l.blacklistMgr = NewBlacklistManager(l.BlacklistV4, l.BlacklistV6)
	}

	l.loaded = true
	return nil
}

// extractMaps 提取所有 Map 引用
func (l *Loader) extractMaps() error {
	maps := l.collection.Maps

	// 黑名单 Map
	if m, ok := maps["blacklist_v4"]; ok {
		l.BlacklistV4 = m
	}
	if m, ok := maps["blacklist_v6"]; ok {
		l.BlacklistV6 = m
	}

	// 速率限制 Map
	if m, ok := maps["ratelimit_v4"]; ok {
		l.RatelimitV4 = m
	}
	if m, ok := maps["ratelimit_v6"]; ok {
		l.RatelimitV6 = m
	}

	// 会话 Map
	if m, ok := maps["sessions"]; ok {
		l.Sessions = m
	}

	// 统计 Map
	if m, ok := maps["stats"]; ok {
		l.Stats = m
	}

	// 配置 Map
	if m, ok := maps["config"]; ok {
		l.Config = m
	}

	// 监听端口 Map
	if m, ok := maps["listen_ports"]; ok {
		l.ListenPorts = m
	}

	// 事件 Map
	if m, ok := maps["events"]; ok {
		l.Events = m
	}

	return nil
}

// Attach 附加 XDP 程序到网络接口
func (l *Loader) Attach(programName string) error {
	if !l.loaded {
		return fmt.Errorf("eBPF 程序未加载")
	}
	if l.attached {
		return fmt.Errorf("XDP 程序已附加")
	}

	// 获取程序
	prog := l.collection.Programs[programName]
	if prog == nil {
		// 尝试默认程序名
		defaultNames := []string{"xdp_phantom_main", "xdp_phantom_fast", "xdp_phantom_filter"}
		for _, name := range defaultNames {
			if p, ok := l.collection.Programs[name]; ok {
				prog = p
				break
			}
		}
	}

	if prog == nil {
		return fmt.Errorf("找不到 XDP 程序: %s", programName)
	}

	// 解析 XDP 模式
	var xdpFlags link.XDPAttachFlags
	switch l.config.XDPMode {
	case "native", "drv":
		xdpFlags = link.XDPDriverMode
	case "offload", "hw":
		xdpFlags = link.XDPOffloadMode
	default:
		xdpFlags = link.XDPGenericMode
	}

	// 获取接口索引
	iface, err := getInterfaceByName(l.config.Interface)
	if err != nil {
		return fmt.Errorf("获取接口失败: %w", err)
	}

	// 附加 XDP 程序
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface,
		Flags:     xdpFlags,
	})
	if err != nil {
		// 如果 native 模式失败，尝试 generic 模式
		if xdpFlags != link.XDPGenericMode {
			xdpLink, err = link.AttachXDP(link.XDPOptions{
				Program:   prog,
				Interface: iface,
				Flags:     link.XDPGenericMode,
			})
		}
		if err != nil {
			return fmt.Errorf("附加 XDP 程序失败: %w", err)
		}
	}

	l.xdpLink = xdpLink
	l.attached = true

	return nil
}

// Detach 分离 XDP 程序
func (l *Loader) Detach() error {
	if !l.attached {
		return nil
	}

	if l.xdpLink != nil {
		if err := l.xdpLink.Close(); err != nil {
			return fmt.Errorf("分离 XDP 程序失败: %w", err)
		}
		l.xdpLink = nil
	}

	l.attached = false
	return nil
}

// Close 关闭加载器
func (l *Loader) Close() error {
	// 先分离
	if err := l.Detach(); err != nil {
		return err
	}

	// 关闭黑名单管理器
	if l.blacklistMgr != nil {
		l.blacklistMgr.Close()
		l.blacklistMgr = nil
	}

	// 关闭集合
	if l.collection != nil {
		l.collection.Close()
		l.collection = nil
	}

	l.loaded = false
	return nil
}

// GetBlacklistManager 获取黑名单管理器
func (l *Loader) GetBlacklistManager() *BlacklistManager {
	return l.blacklistMgr
}

// IsLoaded 是否已加载
func (l *Loader) IsLoaded() bool {
	return l.loaded
}

// IsAttached 是否已附加
func (l *Loader) IsAttached() bool {
	return l.attached
}

// GetStats 获取统计信息
func (l *Loader) GetStats() (*StatsCounter, error) {
	if l.Stats == nil {
		return nil, fmt.Errorf("统计 Map 不可用")
	}

	var key uint32 = 0
	var stats StatsCounter

	if err := l.Stats.Lookup(&key, &stats); err != nil {
		return nil, fmt.Errorf("读取统计失败: %w", err)
	}

	return &stats, nil
}

// UpdateConfig 更新配置
func (l *Loader) UpdateConfig(cfg *GlobalConfig) error {
	if l.Config == nil {
		return fmt.Errorf("配置 Map 不可用")
	}

	var key uint32 = 0
	return l.Config.Update(&key, cfg, ebpf.UpdateAny)
}

// AddListenPort 添加监听端口
func (l *Loader) AddListenPort(port uint16) error {
	if l.ListenPorts == nil {
		return fmt.Errorf("监听端口 Map 不可用")
	}

	cfg := PortConfig{
		Port:    port,
		Enabled: 1,
		Flags:   0,
	}

	return l.ListenPorts.Update(&port, &cfg, ebpf.UpdateAny)
}

// RemoveListenPort 移除监听端口
func (l *Loader) RemoveListenPort(port uint16) error {
	if l.ListenPorts == nil {
		return fmt.Errorf("监听端口 Map 不可用")
	}

	return l.ListenPorts.Delete(&port)
}

// =============================================================================
// 辅助结构体 (与 eBPF 结构体对应)
// =============================================================================

// StatsCounter 统计计数器 (与 C 结构体对应)
type StatsCounter struct {
	PacketsRx           uint64
	PacketsTx           uint64
	BytesRx             uint64
	BytesTx             uint64
	PacketsDropped      uint64
	PacketsPassed       uint64
	PacketsRedirected   uint64
	SessionsCreated     uint64
	SessionsExpired     uint64
	Errors              uint64
	ChecksumErrors      uint64
	InvalidPackets      uint64
	IPv6PacketsRx       uint64
	IPv6PacketsTx       uint64
	IPv6SessionsCreated uint64
	BlacklistHits       uint64
	RatelimitHits       uint64
	AutoBlockedIPs      uint64
	ReplayAttacks       uint64
	AuthFailures        uint64
}

// GlobalConfig 全局配置 (与 C 结构体对应)
type GlobalConfig struct {
	Magic           uint32
	ListenPort      uint16
	Mode            uint8
	LogLevel        uint8
	SessionTimeout  uint32
	MaxSessions     uint32
	EnableStats     uint8
	EnableConntrack uint8
	EnableIPv6      uint8
	Reserved        uint8
	RatelimitPPS    uint32
	RatelimitBPS    uint32
}

// PortConfig 端口配置 (与 C 结构体对应)
type PortConfig struct {
	Port    uint16
	Enabled uint8
	Flags   uint8
}

// =============================================================================
// 辅助函数
// =============================================================================

// getInterfaceByName 通过名称获取接口索引
func getInterfaceByName(name string) (int, error) {
	if name == "" {
		return 0, fmt.Errorf("接口名称为空")
	}

	// 读取接口索引
	indexPath := fmt.Sprintf("/sys/class/net/%s/ifindex", name)
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return 0, fmt.Errorf("读取接口索引失败: %w", err)
	}

	var ifindex int
	if _, err := fmt.Sscanf(string(data), "%d", &ifindex); err != nil {
		return 0, fmt.Errorf("解析接口索引失败: %w", err)
	}

	return ifindex, nil
}





