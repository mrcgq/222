//go:build linux

// =============================================================================
// 文件: internal/transport/ebpf_loader.go
// 描述: eBPF 加速 - 程序加载器 (支持 Map Pinning 和平滑重启)
// =============================================================================
package transport

import (
	"encoding/json"
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
// eBPF 常量定义
// =============================================================================

const (
	DefaultBPFFS       = "/sys/fs/bpf"
	PinPathPrefix      = "phantom"
	MapNameSessions    = "sessions"
	MapNameListenPorts = "listen_ports"
	MapNameConfig      = "config"
	MapNameStats       = "stats"
	MapNameEvents      = "events"
	LinkNameXDP        = "xdp_link"
	BPFFSMagic  uint32 = 0xcafe4a11
)

type PinMode int

const (
	PinModeNone    PinMode = iota
	PinModeReuse
	PinModeReplace
	PinModeStrict
)

// =============================================================================
// eBPF 结构体定义
// =============================================================================

// EBPFStats eBPF 统计信息结构
// 修复：添加缺失的字段
type EBPFStats struct {
	PacketsRX         uint64
	PacketsTX         uint64
	BytesRX            uint64
	BytesTX            uint64
	PacketsDropped    uint64
	SessionsCreated   uint64
	SessionsDestroyed uint64 // 修复：缺失字段
	AuthFailures      uint64 // 修复：缺失字段
	ReplayBlocked     uint64 // 修复：缺失字段
}

// EBPFSessionKey eBPF 会话键结构
type EBPFSessionKey struct {
	ClientIP [4]byte
	Bytes    uint64
}

// EBPFSessionValue eBPF 会话值结构
type EBPFSessionValue struct {
	IsClosed uint8
}

// EBPFGlobalConfig eBPF 全局配置结构
type EBPFGlobalConfig struct {
	Magic           uint32
	ListenPort      uint16
	Mode            uint8
	LogLevel        uint8
	SessionTimeout  uint32
	MaxSessions     uint32
	EnableStats     uint8
	EnableConntrack uint8
}

// XDPMode eBPF XDP 模式
type XDPMode string

const (
	XDPModeAuto   XDPMode = "auto"
	XDPModeNative XDPMode = "native"
	XDPModeGeneric XDPMode = "generic"
	XDPModeOffload XDPMode = "offload"
)

// =============================================================================
// 配置结构
// =============================================================================

type EBPFLoaderConfig struct {
	*EBPFConfig

	EnablePinning   bool
	PinMode         PinMode
	PinPath         string
	GracefulRestart bool
	StateTimeout    time.Duration
	CleanupOnExit   bool
	CleanupOrphans  bool
}

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

type EBPFLoader struct {
	config *EBPFLoaderConfig
	mu     sync.RWMutex

	xdpProgram    *ebpf.Program
	tcEgressProg  *ebpf.Program
	tcIngressProg *ebpf.Program

	xdpLink link.Link

	sessionsMap    *ebpf.Map
	listenPortsMap *ebpf.Map
	configMap      *ebpf.Map
	statsMap       *ebpf.Map
	eventsMap      *ebpf.Map

	collection *ebpf.Collection

	loaded      bool
	attached    bool
	ifIndex     int
	xdpMode     string
	pinned      bool
	reusingMaps bool

	loadTime   time.Time
	attachTime time.Time
}

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

func (l *EBPFLoader) Load() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.loaded {
		return fmt.Errorf("程序已加载")
	}

	if l.config.EnablePinning {
		if err := l.ensureBPFFS(); err != nil {
			return fmt.Errorf("BPF 文件系统初始化失败: %w", err)
		}
	}

	if l.config.EnablePinning && l.config.PinMode == PinModeReuse {
		if err := l.tryReusePinnedMaps(); err == nil {
			l.reusingMaps = true
			if err := l.loadProgramsOnly(); err != nil {
				return err
			}
			l.loaded = true
			l.loadTime = time.Now()
			return nil
		}
	}

	if err := l.loadFull(); err != nil {
		return err
	}

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

func (l *EBPFLoader) loadFull() error {
	xdpPath := filepath.Join(l.config.ProgramPath, "xdp_phantom.o")
	tcPath := filepath.Join(l.config.ProgramPath, "tc_phantom.o")

	if _, err := os.Stat(xdpPath); os.IsNotExist(err) {
		return fmt.Errorf("XDP 程序不存在: %s", xdpPath)
	}

	xdpSpec, err := ebpf.LoadCollectionSpec(xdpPath)
	if err != nil {
		return fmt.Errorf("加载 XDP spec 失败: %w", err)
	}

	l.adjustMapSpecs(xdpSpec)

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "",
		},
	}

	xdpColl, err := ebpf.NewCollectionWithOptions(xdpSpec, opts)
	if err != nil {
		return fmt.Errorf("创建 XDP collection 失败: %w", err)
	}

	l.collection = xdpColl

	l.xdpProgram = xdpColl.Programs["xdp_phantom_main"]
	if l.xdpProgram == nil {
		xdpColl.Close()
		return fmt.Errorf("找不到 xdp_phantom_main 程序")
	}

	l.sessionsMap = xdpColl.Maps[MapNameSessions]
	l.listenPortsMap = xdpColl.Maps[MapNameListenPorts]
	l.configMap = xdpColl.Maps[MapNameConfig]
	l.statsMap = xdpColl.Maps[MapNameStats]
	l.eventsMap = xdpColl.Maps[MapNameEvents]

	l.loadTCPrograms(tcPath)

	return nil
}

func (l *EBPFLoader) loadProgramsOnly() error {
	xdpPath := filepath.Join(l.config.ProgramPath, "xdp_phantom.o")

	if _, err := os.Stat(xdpPath); os.IsNotExist(err) {
		return fmt.Errorf("XDP 程序不存在: %s", xdpPath)
	}

	xdpSpec, err := ebpf.LoadCollectionSpec(xdpPath)
	if err != nil {
		return fmt.Errorf("加载 XDP spec 失败: %w", err)
	}

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

	l.xdpProgram = xdpColl.Programs["xdp_phantom_main"]
	if l.xdpProgram == nil {
		xdpColl.Close()
		return fmt.Errorf("找不到 xdp_phantom_main 程序")
	}

	return nil
}

func (l *EBPFLoader) loadTCPrograms(tcPath string) {
	if _, err := os.Stat(tcPath); err != nil {
		return
	}

	tcSpec, err := ebpf.LoadCollectionSpec(tcPath)
	if err != nil {
		return
	}

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

func (l *EBPFLoader) adjustMapSpecs(spec *ebpf.CollectionSpec) {
	if mapSpec, ok := spec.Maps[MapNameSessions]; ok {
		mapSpec.MaxEntries = uint32(l.config.MapSize)
	}
}

// =============================================================================
// Map Pinning 方法
// =============================================================================

func (l *EBPFLoader) ensureBPFFS() error {
	if err := checkBPFFS(); err != nil {
		if err := mountBPFFS(); err != nil {
			return fmt.Errorf("挂载 BPFFS 失败: %w", err)
		}
	}

	if err := os.MkdirAll(l.config.PinPath, 0755); err != nil {
		return fmt.Errorf("创建 pin 目录失败: %w", err)
	}

	return nil
}

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

		if _, err := os.Stat(pinPath); err == nil {
			switch l.config.PinMode {
			case PinModeReplace:
				if err := os.Remove(pinPath); err != nil {
					return fmt.Errorf("删除旧的 pin %s 失败: %w", name, err)
				}
			case PinModeStrict:
				return fmt.Errorf("pin 已存在: %s", pinPath)
			default:
				continue
			}
		}

		if err := m.Pin(pinPath); err != nil {
			return fmt.Errorf("pin %s 失败: %w", name, err)
		}
	}

	if err := l.savePinMetadata(); err != nil {
		fmt.Printf("警告: 保存 pin 元数据失败: %v\n", err)
	}

	return nil
}

func (l *EBPFLoader) tryReusePinnedMaps() error {
	meta, err := l.loadPinMetadata()
	if err != nil {
		return fmt.Errorf("加载元数据失败: %w", err)
	}

	if l.config.StateTimeout > 0 {
		age := time.Since(meta.PinTime)
		if age > l.config.StateTimeout {
			return fmt.Errorf("pinned 状态已过期: %v", age)
		}
	}

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

	l.eventsMap, _ = ebpf.LoadPinnedMap(eventsPath, nil)

	return nil
}

func (l *EBPFLoader) getMapPinPath(name string) string {
	return filepath.Join(l.config.PinPath, fmt.Sprintf("map_%s", name))
}

func (l *EBPFLoader) getLinkPinPath(name string) string {
	return filepath.Join(l.config.PinPath, fmt.Sprintf("link_%s", name))
}

// =============================================================================
// Pin 元数据管理
// =============================================================================

type PinMetadata struct {
	Version   string    `json:"version"`
	PinTime   time.Time `json:"pin_time"`
	Interface string    `json:"interface"`
	XDPMode   string    `json:"xdp_mode"`
	MapSize   int       `json:"map_size"`
	PID       int       `json:"pid"`
}

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

func (l *EBPFLoader) Attach() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.loaded {
		return fmt.Errorf("程序未加载")
	}

	if l.attached {
		return fmt.Errorf("程序已附加")
	}

	if l.config.EnablePinning && l.config.GracefulRestart {
		if err := l.tryReusePinnedLink(); err == nil {
			l.attached = true
			l.attachTime = time.Now()
			return nil
		}
	}

	iface, err := getInterfaceByName(l.config.Interface)
	if err != nil {
		return fmt.Errorf("获取网卡失败: %w", err)
	}
	l.ifIndex = iface.Index

	mode := l.determineXDPMode()

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

	if l.config.EnablePinning && l.config.GracefulRestart {
		if err := l.pinLink(); err != nil {
			fmt.Printf("警告: pin link 失败: %v\n", err)
		}
	}

	l.attached = true
	l.attachTime = time.Now()

	l.savePinMetadata()

	return nil
}

func (l *EBPFLoader) tryReusePinnedLink() error {
	linkPath := l.getLinkPinPath(LinkNameXDP)

	pinnedLink, err := link.LoadPinnedLink(linkPath, nil)
	if err != nil {
		return err
	}

	info, err := pinnedLink.Info()
	if err != nil {
		pinnedLink.Close()
		return fmt.Errorf("link 无效: %w", err)
	}

	_ = info

	l.xdpLink = pinnedLink
	return nil
}

func (l *EBPFLoader) pinLink() error {
	if l.xdpLink == nil {
		return fmt.Errorf("link 不存在")
	}

	linkPath := l.getLinkPinPath(LinkNameXDP)
	os.Remove(linkPath)

	return l.xdpLink.Pin(linkPath)
}

func (l *EBPFLoader) Detach() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.attached {
		return nil
	}

	if l.config.GracefulRestart && l.config.EnablePinning {
		l.attached = false
		return nil
	}

	if l.xdpLink != nil {
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

func (l *EBPFLoader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.attached && !l.config.GracefulRestart {
		l.Detach()
	}

	if l.config.CleanupOnExit && l.pinned {
		l.unpinAll()
	}

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

	if !l.config.GracefulRestart || l.config.CleanupOnExit {
		l.closeMaps()
	}

	if l.collection != nil {
		l.collection.Close()
		l.collection = nil
	}

	l.loaded = false
	return nil
}

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

	linkPath := l.getLinkPinPath(LinkNameXDP)
	os.Remove(linkPath)

	metaPath := filepath.Join(l.config.PinPath, "metadata.json")
	os.Remove(metaPath)

	os.Remove(l.config.PinPath)

	l.pinned = false
}

func (l *EBPFLoader) CleanupOrphanedPins() error {
	if !l.config.EnablePinning {
		return nil
	}

	meta, err := l.loadPinMetadata()
	if err != nil {
		return l.forceCleanup()
	}

	if processExists(meta.PID) {
		return fmt.Errorf("拥有进程 %d 仍在运行", meta.PID)
	}

	if l.config.StateTimeout > 0 {
		age := time.Since(meta.PinTime)
		if age > l.config.StateTimeout {
			return l.forceCleanup()
		}
	}

	return nil
}

func (l *EBPFLoader) forceCleanup() error {
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

	return os.Remove(l.config.PinPath)
}

// =============================================================================
// 平滑重启支持
// =============================================================================

func (l *EBPFLoader) PrepareGracefulRestart() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.loaded || !l.pinned {
		return fmt.Errorf("无法准备重启: 程序未加载或未 pin")
	}

	return l.savePinMetadata()
}

func (l *EBPFLoader) RecoverFromRestart() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.loaded {
		return fmt.Errorf("程序已加载")
	}

	if err := l.tryReusePinnedMaps(); err != nil {
		return fmt.Errorf("恢复 maps 失败: %w", err)
	}

	l.reusingMaps = true

	if err := l.loadProgramsOnly(); err != nil {
		return fmt.Errorf("加载程序失败: %w", err)
	}

	if err := l.tryReusePinnedLink(); err != nil {
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

func (l *EBPFLoader) determineXDPMode() string {
	if l.config.XDPMode != XDPModeAuto {
		return l.config.XDPMode
	}
	return XDPModeGeneric
}

func (l *EBPFLoader) IsReusingMaps() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.reusingMaps
}

func (l *EBPFLoader) IsPinned() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.pinned
}

func (l *EBPFLoader) GetLoadTime() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.loadTime
}

func (l *EBPFLoader) GetAttachTime() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.attachTime
}

func (l *EBPFLoader) GetPinPath() string {
	return l.config.PinPath
}

// =============================================================================
// 配置和状态方法
// =============================================================================

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

func (l *EBPFLoader) ConfigureGlobal(listenPort uint16) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.configMap == nil {
		return fmt.Errorf("config map 不可用")
	}

	config := EBPFGlobalConfig{
		Magic:           0x5048414E,
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
// 修复：正确处理 Per-CPU Map，必须传入切片指针并汇总所有 CPU 核心数据
func (l *EBPFLoader) GetStats() (*EBPFStats, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.statsMap == nil {
		return nil, fmt.Errorf("stats map 不可用")
	}

	key := uint32(0)

	// 方式1：Per-CPU 读取 (BPF_MAP_TYPE_PERCPU_ARRAY)
	// cilium/ebpf 库要求传入 *[]T 才能自动按 CPU 数分配
	var statsPerCPU []EBPFStats
	err := l.statsMap.Lookup(&key, &statsPerCPU)
	if err == nil && len(statsPerCPU) > 0 {
		// 汇总所有 CPU 核心的统计数据
		final := &EBPFStats{}
		for _, s := range statsPerCPU {
			final.PacketsRX += s.PacketsRX
			final.PacketsTX += s.PacketsTX
			final.BytesRX += s.BytesRX
			final.BytesTX += s.BytesTX
			final.PacketsDropped += s.PacketsDropped
			final.SessionsCreated += s.SessionsCreated
			final.SessionsDestroyed += s.SessionsDestroyed // 修复：添加缺失字段
			final.AuthFailures += s.AuthFailures       // 修复：添加缺失字段
			final.ReplayBlocked += s.ReplayBlocked      // 修复：添加缺失字段
		}
		return final, nil
	}

	// 方式2：回退到普通读取 (BPF_MAP_TYPE_ARRAY)
	var stats EBPFStats
	if err2 := l.statsMap.Lookup(&key, &stats); err2 != nil {
		return nil, fmt.Errorf("读取统计失败 (percpu: %v, normal: %v)", err, err2)
	}

	return &stats, nil
}

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

func (l *EBPFLoader) DeleteSession(key *EBPFSessionKey) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.sessionsMap == nil {
		return fmt.Errorf("sessions map 不可用")
	}

	return l.sessionsMap.Delete(key)
}

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

func (l *EBPFLoader) IsLoaded() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.loaded
}

func (l *EBPFLoader) IsAttached() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.attached
}

func (l *EBPFLoader) GetXDPMode() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.xdpMode
}

func (l *EBPFLoader) GetInterface() string {
	return l.config.Interface
}

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

func checkBPFFS() error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(DefaultBPFFS, &stat); err != nil {
		return err
	}

	if uint32(stat.Type) != BPFFSMagic {
		return fmt.Errorf("不是 BPFFS: type=%x", stat.Type)
	}

	return nil
}

func mountBPFFS() error {
	if err := os.MkdirAll(DefaultBPFFS, 0755); err != nil {
		return err
	}

	return syscall.Mount("bpf", DefaultBPFFS, "bpf", 0, "")
}

func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	err = process.Signal(syscall.Signal(0))
	return err == nil
}

type netInterface struct {
	Name  string
	Index int
}

func getInterfaceByName(name string) (*netInterface, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("创建 socket 失败: %w", err)
	}
	defer syscall.Close(fd)

	var ifr [40]byte
	copy(ifr[:], name)

	_, _, errno := syscall.SysCall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		syscall.SIOCGIFINDEX,
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return nil, fmt.Errorf("ioctl SIOCGIFINDEX 失败: %v", errno)
	}

	index := *(*int32)(unsafe.Pointer(&ifr[16]))

	return &netInterface{
		Name:  name,
		Index: int(index),
	}, nil
}
