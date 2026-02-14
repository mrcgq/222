


// =============================================================================
// 文件: internal/transport/ebpf_loader.go
// 描述: eBPF 加速 - 程序加载器 (支持 Map Pinning 和平滑重启)
// =============================================================================
package transport

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// =============================================================================
// 常量定义
// =============================================================================

const (
	// BPF 文件系统路径
	DefaultBPFFS = "/sys/fs/bpf"
	
	// Pin 路径前缀
	PinPathPrefix = "phantom"
	
	// Map 名称常量
	MapNameSessions    = "sessions"
	MapNameListenPorts = "listen_ports"
	MapNameConfig      = "config"
	MapNameStats       = "stats"
	MapNameEvents      = "events"
	
	// Link 名称
	LinkNameXDP = "xdp_link"
)

// PinMode Map Pinning 模式
type PinMode int

const (
	// PinModeNone 不进行 Pinning
	PinModeNone PinMode = iota
	// PinModeReuse 优先复用已有的 Pinned Maps
	PinModeReuse
	// PinModeReplace 替换已有的 Pinned Maps
	PinModeReplace
	// PinModeStrict 严格模式，已存在则报错
	PinModeStrict
)

// =============================================================================
// 配置结构
// =============================================================================

// EBPFLoaderConfig 加载器配置
type EBPFLoaderConfig struct {
	*EBPFConfig
	
	// Pinning 配置
	EnablePinning   bool    // 启用 Map Pinning
	PinMode         PinMode // Pinning 模式
	PinPath         string  // Pin 路径 (默认: /sys/fs/bpf/phantom)
	
	// 平滑重启配置
	GracefulRestart bool          // 支持平滑重启
	StateTimeout    time.Duration // 状态保留超时
	
	// 清理配置
	CleanupOnExit   bool // 退出时清理 pinned 资源
	CleanupOrphans  bool // 清理孤立的 pinned 资源
}

// DefaultEBPFLoaderConfig 默认配置
func DefaultEBPFLoaderConfig() *EBPFLoaderConfig {
	return &EBPFLoaderConfig{
		EBPFConfig:      DefaultEBPFConfig(),
		EnablePinning:   true,
		PinMode:         PinModeReuse,
		PinPath:         filepath.Join(DefaultBPFFS, PinPathPrefix),
		GracefulRestart: true,
		StateTimeout:    5 * time.Minute,
		CleanupOnExit:   false,
		CleanupOrphans:  true,
	}
}

// =============================================================================
// 加载器结构
// =============================================================================

// EBPFLoader eBPF 程序加载器
type EBPFLoader struct {
	config *EBPFLoaderConfig
	mu     sync.RWMutex

	// 加载的程序
	xdpProgram    *ebpf.Program
	tcEgressProg  *ebpf.Program
	tcIngressProg *ebpf.Program

	// XDP 链接
	xdpLink link.Link

	// Maps
	sessionsMap    *ebpf.Map
	listenPortsMap *ebpf.Map
	configMap      *ebpf.Map
	statsMap       *ebpf.Map
	eventsMap      *ebpf.Map

	// Collection (用于生命周期管理)
	collection *ebpf.Collection

	// 状态
	loaded      bool
	attached    bool
	ifIndex     int
	xdpMode     string
	pinned      bool
	reusingMaps bool // 是否复用了已有的 Maps

	// 统计
	loadTime   time.Time
	attachTime time.Time
}

// NewEBPFLoader 创建加载器
func NewEBPFLoader(config *EBPFLoaderConfig) *EBPFLoader {
	if config == nil {
		config = DefaultEBPFLoaderConfig()
	}

	return &EBPFLoader{
		config: config,
	}
}

// =============================================================================
// 核心加载方法
// =============================================================================

// Load 加载 eBPF 程序
func (l *EBPFLoader) Load() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.loaded {
		return fmt.Errorf("程序已加载")
	}

	// 确保 BPF 文件系统已挂载
	if l.config.EnablePinning {
		if err := l.ensureBPFFS(); err != nil {
			return fmt.Errorf("BPF 文件系统初始化失败: %w", err)
		}
	}

	// 尝试复用已有的 pinned maps
	if l.config.EnablePinning && l.config.PinMode == PinModeReuse {
		if err := l.tryReusePinnedMaps(); err == nil {
			l.reusingMaps = true
			// 只需要加载程序，不需要创建新的 maps
			if err := l.loadProgramsOnly(); err != nil {
				return err
			}
			l.loaded = true
			l.loadTime = time.Now()
			return nil
		}
		// 复用失败，继续正常加载
	}

	// 正常加载
	if err := l.loadFull(); err != nil {
		return err
	}

	// Pin maps
	if l.config.EnablePinning {
		if err := l.pinMaps(); err != nil {
			l.Close()
			return fmt.Errorf("pinning maps 失败: %w", err)
		}
		l.pinned = true
	}

	l.loaded = true
	l.loadTime = time.Now()
	return nil
}

// loadFull 完整加载程序和 maps
func (l *EBPFLoader) loadFull() error {
	// 检查程序文件
	xdpPath := filepath.Join(l.config.ProgramPath, "xdp_phantom.o")
	tcPath := filepath.Join(l.config.ProgramPath, "tc_phantom.o")

	if _, err := os.Stat(xdpPath); os.IsNotExist(err) {
		return fmt.Errorf("XDP 程序不存在: %s", xdpPath)
	}

	// 加载 XDP 程序
	xdpSpec, err := ebpf.LoadCollectionSpec(xdpPath)
	if err != nil {
		return fmt.Errorf("加载 XDP spec 失败: %w", err)
	}

	// 调整 Map 大小
	l.adjustMapSpecs(xdpSpec)

	// 创建 Collection
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// 使用大页 (如果可用)
			PinPath: "", // 不在这里 pin，稍后手动处理
		},
	}

	xdpColl, err := ebpf.NewCollectionWithOptions(xdpSpec, opts)
	if err != nil {
		return fmt.Errorf("创建 XDP collection 失败: %w", err)
	}

	l.collection = xdpColl

	// 获取程序
	l.xdpProgram = xdpColl.Programs["xdp_phantom_main"]
	if l.xdpProgram == nil {
		xdpColl.Close()
		return fmt.Errorf("找不到 xdp_phantom_main 程序")
	}

	// 获取 Maps
	l.sessionsMap = xdpColl.Maps[MapNameSessions]
	l.listenPortsMap = xdpColl.Maps[MapNameListenPorts]
	l.configMap = xdpColl.Maps[MapNameConfig]
	l.statsMap = xdpColl.Maps[MapNameStats]
	l.eventsMap = xdpColl.Maps[MapNameEvents]

	// 加载 TC 程序 (可选)
	l.loadTCPrograms(tcPath)

	return nil
}

// loadProgramsOnly 只加载程序 (复用已有 maps)
func (l *EBPFLoader) loadProgramsOnly() error {
	xdpPath := filepath.Join(l.config.ProgramPath, "xdp_phantom.o")

	if _, err := os.Stat(xdpPath); os.IsNotExist(err) {
		return fmt.Errorf("XDP 程序不存在: %s", xdpPath)
	}

	xdpSpec, err := ebpf.LoadCollectionSpec(xdpPath)
	if err != nil {
		return fmt.Errorf("加载 XDP spec 失败: %w", err)
	}

	// 配置复用已有的 maps
	opts := ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			MapNameSessions:    l.sessionsMap,
			MapNameListenPorts: l.listenPortsMap,
			MapNameConfig:      l.configMap,
			MapNameStats:       l.statsMap,
			MapNameEvents:      l.eventsMap,
		},
	}

	xdpColl, err := ebpf.NewCollectionWithOptions(xdpSpec, opts)
	if err != nil {
		return fmt.Errorf("创建 XDP collection 失败: %w", err)
	}

	l.collection = xdpColl

	// 获取程序
	l.xdpProgram = xdpColl.Programs["xdp_phantom_main"]
	if l.xdpProgram == nil {
		xdpColl.Close()
		return fmt.Errorf("找不到 xdp_phantom_main 程序")
	}

	return nil
}

// loadTCPrograms 加载 TC 程序
func (l *EBPFLoader) loadTCPrograms(tcPath string) {
	if _, err := os.Stat(tcPath); err != nil {
		return
	}

	tcSpec, err := ebpf.LoadCollectionSpec(tcPath)
	if err != nil {
		return
	}

	// 使用相同的 maps
	opts := ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			MapNameSessions:    l.sessionsMap,
			MapNameListenPorts: l.listenPortsMap,
			MapNameConfig:      l.configMap,
			MapNameStats:       l.statsMap,
			MapNameEvents:      l.eventsMap,
		},
	}

	tcColl, err := ebpf.NewCollectionWithOptions(tcSpec, opts)
	if err != nil {
		return
	}

	l.tcEgressProg = tcColl.Programs["tc_phantom_egress"]
	l.tcIngressProg = tcColl.Programs["tc_phantom_ingress"]
}

// adjustMapSpecs 调整 Map 规格
func (l *EBPFLoader) adjustMapSpecs(spec *ebpf.CollectionSpec) {
	if mapSpec, ok := spec.Maps[MapNameSessions]; ok {
		mapSpec.MaxEntries = uint32(l.config.MapSize)
	}
}

// =============================================================================
// Map Pinning 方法
// =============================================================================

// ensureBPFFS 确保 BPF 文件系统可用
func (l *EBPFLoader) ensureBPFFS() error {
	// 检查 BPF 文件系统是否已挂载
	if err := checkBPFFS(); err != nil {
		// 尝试挂载
		if err := mountBPFFS(); err != nil {
			return fmt.Errorf("挂载 BPFFS 失败: %w", err)
		}
	}

	// 确保 pin 目录存在
	if err := os.MkdirAll(l.config.PinPath, 0755); err != nil {
		return fmt.Errorf("创建 pin 目录失败: %w", err)
	}

	return nil
}

// pinMaps 将 maps pin 到文件系统
func (l *EBPFLoader) pinMaps() error {
	maps := map[string]*ebpf.Map{
		MapNameSessions:    l.sessionsMap,
		MapNameListenPorts: l.listenPortsMap,
		MapNameConfig:      l.configMap,
		MapNameStats:       l.statsMap,
		MapNameEvents:      l.eventsMap,
	}

	for name, m := range maps {
		if m == nil {
			continue
		}

		pinPath := l.getMapPinPath(name)

		// 检查是否已存在
		if _, err := os.Stat(pinPath); err == nil {
			switch l.config.PinMode {
			case PinModeReplace:
				// 删除旧的
				if err := os.Remove(pinPath); err != nil {
					return fmt.Errorf("删除旧的 pin %s 失败: %w", name, err)
				}
			case PinModeStrict:
				return fmt.Errorf("pin 已存在: %s", pinPath)
			default:
				// 跳过
				continue
			}
		}

		// Pin
		if err := m.Pin(pinPath); err != nil {
			return fmt.Errorf("pin %s 失败: %w", name, err)
		}
	}

	// 记录元数据
	if err := l.savePinMetadata(); err != nil {
		// 非致命错误
		fmt.Printf("警告: 保存 pin 元数据失败: %v\n", err)
	}

	return nil
}

// tryReusePinnedMaps 尝试复用已 pin 的 maps
func (l *EBPFLoader) tryReusePinnedMaps() error {
	// 检查元数据
	meta, err := l.loadPinMetadata()
	if err != nil {
		return fmt.Errorf("加载元数据失败: %w", err)
	}

	// 检查状态超时
	if l.config.StateTimeout > 0 {
		age := time.Since(meta.PinTime)
		if age > l.config.StateTimeout {
			return fmt.Errorf("pinned 状态已过期: %v", age)
		}
	}

	// 尝试加载每个 map
	sessionsPath := l.getMapPinPath(MapNameSessions)
	listenPortsPath := l.getMapPinPath(MapNameListenPorts)
	configPath := l.getMapPinPath(MapNameConfig)
	statsPath := l.getMapPinPath(MapNameStats)
	eventsPath := l.getMapPinPath(MapNameEvents)

	var loadErr error

	l.sessionsMap, loadErr = ebpf.LoadPinnedMap(sessionsPath, nil)
	if loadErr != nil {
		return fmt.Errorf("加载 sessions map 失败: %w", loadErr)
	}

	l.listenPortsMap, loadErr = ebpf.LoadPinnedMap(listenPortsPath, nil)
	if loadErr != nil {
		l.sessionsMap.Close()
		return fmt.Errorf("加载 listen_ports map 失败: %w", loadErr)
	}

	l.configMap, loadErr = ebpf.LoadPinnedMap(configPath, nil)
	if loadErr != nil {
		l.sessionsMap.Close()
		l.listenPortsMap.Close()
		return fmt.Errorf("加载 config map 失败: %w", loadErr)
	}

	l.statsMap, loadErr = ebpf.LoadPinnedMap(statsPath, nil)
	if loadErr != nil {
		l.sessionsMap.Close()
		l.listenPortsMap.Close()
		l.configMap.Close()
		return fmt.Errorf("加载 stats map 失败: %w", loadErr)
	}

	// events map 可选
	l.eventsMap, _ = ebpf.LoadPinnedMap(eventsPath, nil)

	return nil
}

// getMapPinPath 获取 map 的 pin 路径
func (l *EBPFLoader) getMapPinPath(name string) string {
	return filepath.Join(l.config.PinPath, fmt.Sprintf("map_%s", name))
}

// getLinkPinPath 获取 link 的 pin 路径
func (l *EBPFLoader) getLinkPinPath(name string) string {
	return filepath.Join(l.config.PinPath, fmt.Sprintf("link_%s", name))
}

// =============================================================================
// Pin 元数据管理
// =============================================================================

// PinMetadata pin 元数据
type PinMetadata struct {
	Version   string    `json:"version"`
	PinTime   time.Time `json:"pin_time"`
	Interface string    `json:"interface"`
	XDPMode   string    `json:"xdp_mode"`
	MapSize   int       `json:"map_size"`
	PID       int       `json:"pid"`
}

// savePinMetadata 保存元数据
func (l *EBPFLoader) savePinMetadata() error {
	meta := PinMetadata{
		Version:   "1.0",
		PinTime:   time.Now(),
		Interface: l.config.Interface,
		XDPMode:   l.xdpMode,
		MapSize:   l.config.MapSize,
		PID:       os.Getpid(),
	}

	metaPath := filepath.Join(l.config.PinPath, "metadata.json")
	
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	return os.WriteFile(metaPath, data, 0644)
}

// loadPinMetadata 加载元数据
func (l *EBPFLoader) loadPinMetadata() (*PinMetadata, error) {
	metaPath := filepath.Join(l.config.PinPath, "metadata.json")
	
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}

	var meta PinMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

// =============================================================================
// 附加和分离
// =============================================================================

// Attach 附加到网卡
func (l *EBPFLoader) Attach() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.loaded {
		return fmt.Errorf("程序未加载")
	}

	if l.attached {
		return fmt.Errorf("程序已附加")
	}

	// 尝试复用已有的 pinned link
	if l.config.EnablePinning && l.config.GracefulRestart {
		if err := l.tryReusePinnedLink(); err == nil {
			l.attached = true
			l.attachTime = time.Now()
			return nil
		}
	}

	// 获取网卡索引
	iface, err := getInterfaceByName(l.config.Interface)
	if err != nil {
		return fmt.Errorf("获取网卡失败: %w", err)
	}
	l.ifIndex = iface.Index

	// 确定 XDP 模式
	mode := l.determineXDPMode()

	// 附加 XDP 程序
	var flags link.XDPAttachFlags
	switch mode {
	case XDPModeNative:
		flags = link.XDPDriverMode
	case XDPModeOffload:
		flags = link.XDPOffloadMode
	default:
		flags = link.XDPGenericMode
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   l.xdpProgram,
		Interface: l.ifIndex,
		Flags:     flags,
	})
	if err != nil {
		// 如果 native 失败，回退到 generic
		if flags == link.XDPDriverMode {
			xdpLink, err = link.AttachXDP(link.XDPOptions{
				Program:   l.xdpProgram,
				Interface: l.ifIndex,
				Flags:     link.XDPGenericMode,
			})
			if err == nil {
				mode = XDPModeGeneric
			}
		}
		if err != nil {
			return fmt.Errorf("附加 XDP 失败: %w", err)
		}
	}

	l.xdpLink = xdpLink
	l.xdpMode = mode

	// Pin link (用于平滑重启)
	if l.config.EnablePinning && l.config.GracefulRestart {
		if err := l.pinLink(); err != nil {
			fmt.Printf("警告: pin link 失败: %v\n", err)
		}
	}

	l.attached = true
	l.attachTime = time.Now()

	// 更新元数据
	l.savePinMetadata()

	return nil
}

// tryReusePinnedLink 尝试复用已 pin 的 link
func (l *EBPFLoader) tryReusePinnedLink() error {
	linkPath := l.getLinkPinPath(LinkNameXDP)
	
	pinnedLink, err := link.LoadPinnedLink(linkPath, nil)
	if err != nil {
		return err
	}

	// 验证 link 仍然有效
	info, err := pinnedLink.Info()
	if err != nil {
		pinnedLink.Close()
		return fmt.Errorf("link 无效: %w", err)
	}

	_ = info // 可以用于额外验证

	l.xdpLink = pinnedLink
	return nil
}

// pinLink pin link 到文件系统
func (l *EBPFLoader) pinLink() error {
	if l.xdpLink == nil {
		return fmt.Errorf("link 不存在")
	}

	linkPath := l.getLinkPinPath(LinkNameXDP)

	// 删除旧的 (如果存在)
	os.Remove(linkPath)

	return l.xdpLink.Pin(linkPath)
}

// Detach 分离程序
func (l *EBPFLoader) Detach() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.attached {
		return nil
	}

	// 如果支持平滑重启，不关闭 link
	if l.config.GracefulRestart && l.config.EnablePinning {
		// 只是标记为未附加，但保持 link pin
		l.attached = false
		return nil
	}

	if l.xdpLink != nil {
		// Unpin
		if l.pinned {
			linkPath := l.getLinkPinPath(LinkNameXDP)
			os.Remove(linkPath)
		}

		if err := l.xdpLink.Close(); err != nil {
			return fmt.Errorf("分离 XDP 失败: %w", err)
		}
		l.xdpLink = nil
	}

	l.attached = false
	return nil
}

// =============================================================================
// 清理方法
// =============================================================================

// Close 关闭加载器
func (l *EBPFLoader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// 分离
	if l.attached && !l.config.GracefulRestart {
		l.Detach()
	}

	// 清理 pinned 资源
	if l.config.CleanupOnExit && l.pinned {
		l.unpinAll()
	}

	// 关闭程序
	if l.xdpProgram != nil {
		l.xdpProgram.Close()
		l.xdpProgram = nil
	}
	if l.tcEgressProg != nil {
		l.tcEgressProg.Close()
		l.tcEgressProg = nil
	}
	if l.tcIngressProg != nil {
		l.tcIngressProg.Close()
		l.tcIngressProg = nil
	}

	// 关闭 maps (如果不保留)
	if !l.config.GracefulRestart || l.config.CleanupOnExit {
		l.closeMaps()
	}

	// 关闭 collection
	if l.collection != nil {
		l.collection.Close()
		l.collection = nil
	}

	l.loaded = false
	return nil
}

// closeMaps 关闭所有 maps
func (l *EBPFLoader) closeMaps() {
	if l.sessionsMap != nil {
		l.sessionsMap.Close()
		l.sessionsMap = nil
	}
	if l.listenPortsMap != nil {
		l.listenPortsMap.Close()
		l.listenPortsMap = nil
	}
	if l.configMap != nil {
		l.configMap.Close()
		l.configMap = nil
	}
	if l.statsMap != nil {
		l.statsMap.Close()
		l.statsMap = nil
	}
	if l.eventsMap != nil {
		l.eventsMap.Close()
		l.eventsMap = nil
	}
}

// unpinAll 取消所有 pin
func (l *EBPFLoader) unpinAll() {
	mapNames := []string{
		MapNameSessions,
		MapNameListenPorts,
		MapNameConfig,
		MapNameStats,
		MapNameEvents,
	}

	for _, name := range mapNames {
		path := l.getMapPinPath(name)
		os.Remove(path)
	}

	// 删除 link pin
	linkPath := l.getLinkPinPath(LinkNameXDP)
	os.Remove(linkPath)

	// 删除元数据
	metaPath := filepath.Join(l.config.PinPath, "metadata.json")
	os.Remove(metaPath)

	// 尝试删除目录 (如果为空)
	os.Remove(l.config.PinPath)

	l.pinned = false
}

// CleanupOrphanedPins 清理孤立的 pinned 资源
func (l *EBPFLoader) CleanupOrphanedPins() error {
	if !l.config.EnablePinning {
		return nil
	}

	// 读取元数据
	meta, err := l.loadPinMetadata()
	if err != nil {
		// 没有元数据，直接清理
		return l.forceCleanup()
	}

	// 检查创建进程是否仍在运行
	if processExists(meta.PID) {
		return fmt.Errorf("拥有进程 %d 仍在运行", meta.PID)
	}

	// 检查是否过期
	if l.config.StateTimeout > 0 {
		age := time.Since(meta.PinTime)
		if age > l.config.StateTimeout {
			return l.forceCleanup()
		}
	}

	return nil
}

// forceCleanup 强制清理
func (l *EBPFLoader) forceCleanup() error {
	// 列出 pin 目录中的所有文件
	entries, err := os.ReadDir(l.config.PinPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		path := filepath.Join(l.config.PinPath, entry.Name())
		if err := os.Remove(path); err != nil {
			fmt.Printf("警告: 删除 %s 失败: %v\n", path, err)
		}
	}

	// 删除目录
	return os.Remove(l.config.PinPath)
}

// =============================================================================
// 平滑重启支持
// =============================================================================

// PrepareGracefulRestart 准备平滑重启
func (l *EBPFLoader) PrepareGracefulRestart() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.loaded || !l.pinned {
		return fmt.Errorf("无法准备重启: 程序未加载或未 pin")
	}

	// 更新元数据
	return l.savePinMetadata()
}

// RecoverFromRestart 从重启中恢复
func (l *EBPFLoader) RecoverFromRestart() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.loaded {
		return fmt.Errorf("程序已加载")
	}

	// 尝试加载 pinned maps
	if err := l.tryReusePinnedMaps(); err != nil {
		return fmt.Errorf("恢复 maps 失败: %w", err)
	}

	l.reusingMaps = true

	// 加载程序
	if err := l.loadProgramsOnly(); err != nil {
		return fmt.Errorf("加载程序失败: %w", err)
	}

	// 尝试恢复 link
	if err := l.tryReusePinnedLink(); err != nil {
		// link 恢复失败，需要重新附加
		l.loaded = true
		l.loadTime = time.Now()
		return l.Attach()
	}

	l.loaded = true
	l.attached = true
	l.pinned = true
	l.loadTime = time.Now()
	l.attachTime = time.Now()

	return nil
}

// =============================================================================
// 辅助方法
// =============================================================================

// determineXDPMode 确定最佳 XDP 模式
func (l *EBPFLoader) determineXDPMode() string {
	if l.config.XDPMode != XDPModeAuto {
		return l.config.XDPMode
	}
	return XDPModeGeneric
}

// IsReusingMaps 是否复用了已有的 maps
func (l *EBPFLoader) IsReusingMaps() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.reusingMaps
}

// IsPinned 是否已 pin
func (l *EBPFLoader) IsPinned() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.pinned
}

// GetLoadTime 获取加载时间
func (l *EBPFLoader) GetLoadTime() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.loadTime
}

// GetAttachTime 获取附加时间
func (l *EBPFLoader) GetAttachTime() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.attachTime
}

// GetPinPath 获取 pin 路径
func (l *EBPFLoader) GetPinPath() string {
	return l.config.PinPath
}

// =============================================================================
// 配置和状态方法 (保持原有接口)
// =============================================================================

// ConfigurePort 配置监听端口
func (l *EBPFLoader) ConfigurePort(port uint16, enabled bool) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.listenPortsMap == nil {
		return fmt.Errorf("listen_ports map 不可用")
	}

	config := struct {
		Port    uint16
		Enabled uint8
		Flags   uint8
	}{
		Port:    port,
		Enabled: 0,
		Flags:   0,
	}
	if enabled {
		config.Enabled = 1
	}

	key := Htons(port)
	return l.listenPortsMap.Put(&key, &config)
}

// ConfigureGlobal 配置全局参数
func (l *EBPFLoader) ConfigureGlobal(listenPort uint16) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.configMap == nil {
		return fmt.Errorf("config map 不可用")
	}

	config := EBPFGlobalConfig{
		Magic:           0x5048414E, // "PHAN"
		ListenPort:      listenPort,
		Mode:            1,
		LogLevel:        1,
		SessionTimeout:  uint32(l.config.CleanupInterval.Seconds()),
		MaxSessions:     uint32(l.config.MapSize),
		EnableStats:     1,
		EnableConntrack: 1,
	}

	key := uint32(0)
	return l.configMap.Put(&key, &config)
}

// GetStats 获取统计信息
func (l *EBPFLoader) GetStats() (*EBPFStats, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.statsMap == nil {
		return nil, fmt.Errorf("stats map 不可用")
	}

	key := uint32(0)
	var stats EBPFStats

	if err := l.statsMap.Lookup(&key, &stats); err != nil {
		return nil, fmt.Errorf("读取统计失败: %w", err)
	}

	return &stats, nil
}

// GetSession 获取会话
func (l *EBPFLoader) GetSession(key *EBPFSessionKey) (*EBPFSessionValue, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.sessionsMap == nil {
		return nil, fmt.Errorf("sessions map 不可用")
	}

	var value EBPFSessionValue
	if err := l.sessionsMap.Lookup(key, &value); err != nil {
		return nil, err
	}

	return &value, nil
}

// DeleteSession 删除会话
func (l *EBPFLoader) DeleteSession(key *EBPFSessionKey) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.sessionsMap == nil {
		return fmt.Errorf("sessions map 不可用")
	}

	return l.sessionsMap.Delete(key)
}

// IterateSessions 遍历会话
func (l *EBPFLoader) IterateSessions(callback func(*EBPFSessionKey, *EBPFSessionValue) bool) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.sessionsMap == nil {
		return fmt.Errorf("sessions map 不可用")
	}

	var key EBPFSessionKey
	var value EBPFSessionValue

	iter := l.sessionsMap.Iterate()
	for iter.Next(&key, &value) {
		if !callback(&key, &value) {
			break
		}
	}

	return iter.Err()
}

// IsLoaded 是否已加载
func (l *EBPFLoader) IsLoaded() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.loaded
}

// IsAttached 是否已附加
func (l *EBPFLoader) IsAttached() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.attached
}

// GetXDPMode 获取 XDP 模式
func (l *EBPFLoader) GetXDPMode() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.xdpMode
}

// GetInterface 获取网卡名
func (l *EBPFLoader) GetInterface() string {
	return l.config.Interface
}

// GetMaps 获取 Maps
func (l *EBPFLoader) GetMaps() map[string]*ebpf.Map {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return map[string]*ebpf.Map{
		MapNameSessions:    l.sessionsMap,
		MapNameListenPorts: l.listenPortsMap,
		MapNameConfig:      l.configMap,
		MapNameStats:       l.statsMap,
		MapNameEvents:      l.eventsMap,
	}
}

// =============================================================================
// BPF 文件系统辅助函数
// =============================================================================

// checkBPFFS 检查 BPF 文件系统是否已挂载
func checkBPFFS() error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(DefaultBPFFS, &stat); err != nil {
		return err
	}

	// BPF_FS_MAGIC = 0xcafe4a11
	if stat.Type != 0xcafe4a11 {
		return fmt.Errorf("不是 BPFFS: type=%x", stat.Type)
	}

	return nil
}

// mountBPFFS 挂载 BPF 文件系统
func mountBPFFS() error {
	// 确保目录存在
	if err := os.MkdirAll(DefaultBPFFS, 0755); err != nil {
		return err
	}

	// 挂载
	return syscall.Mount("bpf", DefaultBPFFS, "bpf", 0, "")
}

// processExists 检查进程是否存在
func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// 发送信号 0 来检查进程是否存在
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// netInterface 网卡信息
type netInterface struct {
	Name  string
	Index int
}

// getInterfaceByName 通过名称获取网卡
func getInterfaceByName(name string) (*netInterface, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("创建 socket 失败: %w", err)
	}
	defer syscall.Close(fd)

	// 准备 ifreq 结构
	var ifr [40]byte
	copy(ifr[:], name)

	// SIOCGIFINDEX ioctl 调用
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		syscall.SIOCGIFINDEX,
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return nil, fmt.Errorf("ioctl SIOCGIFINDEX 失败: %v", errno)
	}

	// 从 ifr 结构中提取索引 (偏移 16 字节)
	index := *(*int32)(unsafe.Pointer(&ifr[16]))

	return &netInterface{
		Name:  name,
		Index: int(index),
	}, nil
}




