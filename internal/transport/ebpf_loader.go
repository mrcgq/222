
//go:build linux

// =============================================================================
// 文件: internal/transport/ebpf_loader.go
// 描述: eBPF 加速 - 程序加载器 (使用 bpf2go 自动生成的绑定)
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
// 常量定义
// =============================================================================

const (
	DefaultBPFFS  = "/sys/fs/bpf"
	PinPathPrefix = "phantom"
	BPFFSMagic    = 0xcafe4a11
)

type PinMode int

const (
	PinModeNone PinMode = iota
	PinModeReuse
	PinModeReplace
	PinModeStrict
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

	// 使用 bpf2go 生成的对象
	objs PhantomObjects

	// XDP 链接
	xdpLink link.Link

	// 状态
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

	// 确保 BPF 文件系统已挂载
	if l.config.EnablePinning {
		if err := l.ensureBPFFS(); err != nil {
			return fmt.Errorf("BPF 文件系统初始化失败: %w", err)
		}
	}

	// 尝试重用已 pin 的 maps
	if l.config.EnablePinning && l.config.PinMode == PinModeReuse {
		if err := l.tryReusePinnedMaps(); err == nil {
			l.reusingMaps = true
			l.loaded = true
			l.loadTime = time.Now()
			return nil
		}
	}

	// 全新加载
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

func (l *EBPFLoader) loadFull() error {
	// 使用 bpf2go 生成的加载函数
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "", // 稍后手动 pin
		},
	}

	// 调整 map 大小
	spec, err := LoadPhantom()
	if err != nil {
		return fmt.Errorf("加载 eBPF spec 失败: %w", err)
	}

	// 调整 sessions map 大小
	if sessionsSpec, ok := spec.Maps["sessions"]; ok {
		sessionsSpec.MaxEntries = uint32(l.config.MapSize)
	}

	// 创建 collection
	if err := spec.LoadAndAssign(&l.objs, opts); err != nil {
		return fmt.Errorf("加载 eBPF 对象失败: %w", err)
	}

	return nil
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
		"sessions":     l.objs.Sessions,
		"listen_ports": l.objs.ListenPorts,
		"config":       l.objs.Config,
		"stats":        l.objs.Stats,
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

	// 保存元数据
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

	// 检查状态是否过期
	if l.config.StateTimeout > 0 {
		age := time.Since(meta.PinTime)
		if age > l.config.StateTimeout {
			return fmt.Errorf("pinned 状态已过期: %v", age)
		}
	}

	// 加载 pinned maps
	sessionsPath := l.getMapPinPath("sessions")
	listenPortsPath := l.getMapPinPath("listen_ports")
	configPath := l.getMapPinPath("config")
	statsPath := l.getMapPinPath("stats")

	var loadErr error

	l.objs.Sessions, loadErr = ebpf.LoadPinnedMap(sessionsPath, nil)
	if loadErr != nil {
		return fmt.Errorf("加载 sessions map 失败: %w", loadErr)
	}

	l.objs.ListenPorts, loadErr = ebpf.LoadPinnedMap(listenPortsPath, nil)
	if loadErr != nil {
		l.objs.Sessions.Close()
		return fmt.Errorf("加载 listen_ports map 失败: %w", loadErr)
	}

	l.objs.Config, loadErr = ebpf.LoadPinnedMap(configPath, nil)
	if loadErr != nil {
		l.objs.Sessions.Close()
		l.objs.ListenPorts.Close()
		return fmt.Errorf("加载 config map 失败: %w", loadErr)
	}

	l.objs.Stats, loadErr = ebpf.LoadPinnedMap(statsPath, nil)
	if loadErr != nil {
		l.objs.Sessions.Close()
		l.objs.ListenPorts.Close()
		l.objs.Config.Close()
		return fmt.Errorf("加载 stats map 失败: %w", loadErr)
	}

	// 重新加载程序（使用现有 maps）
	spec, err := LoadPhantom()
	if err != nil {
		return fmt.Errorf("加载 eBPF spec 失败: %w", err)
	}

	opts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"sessions":     l.objs.Sessions,
			"listen_ports": l.objs.ListenPorts,
			"config":       l.objs.Config,
			"stats":        l.objs.Stats,
		},
	}

	// 只加载程序
	var newObjs PhantomObjects
	if err := spec.LoadAndAssign(&newObjs, opts); err != nil {
		return fmt.Errorf("加载程序失败: %w", err)
	}

	// 复制程序引用
	l.objs.XdpPhantomMain = newObjs.XdpPhantomMain

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
		Version:   "2.0",
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

	// 获取网卡接口
	iface, err := getInterfaceByName(l.config.Interface)
	if err != nil {
		return fmt.Errorf("获取网卡失败: %w", err)
	}
	l.ifIndex = iface.Index

	// 确定 XDP 模式
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

	// 附加 XDP 程序
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   l.objs.XdpPhantomMain,
		Interface: l.ifIndex,
		Flags:     flags,
	})
	if err != nil {
		// 回退到 generic 模式
		if flags == link.XDPDriverMode {
			xdpLink, err = link.AttachXDP(link.XDPOptions{
				Program:   l.objs.XdpPhantomMain,
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

	// Pin link
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

func (l *EBPFLoader) pinLink() error {
	if l.xdpLink == nil {
		return fmt.Errorf("link 不存在")
	}

	linkPath := l.getLinkPinPath("xdp")
	os.Remove(linkPath)

	return l.xdpLink.Pin(linkPath)
}

func (l *EBPFLoader) Detach() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.attached {
		return nil
	}

	// 平滑重启模式下不实际分离
	if l.config.GracefulRestart && l.config.EnablePinning {
		l.attached = false
		return nil
	}

	if l.xdpLink != nil {
		if l.pinned {
			linkPath := l.getLinkPinPath("xdp")
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

	// 关闭所有对象
	l.objs.Close()

	l.loaded = false
	return nil
}

func (l *EBPFLoader) unpinAll() {
	mapNames := []string{"sessions", "listen_ports", "config", "stats"}

	for _, name := range mapNames {
		path := l.getMapPinPath(name)
		os.Remove(path)
	}

	linkPath := l.getLinkPinPath("xdp")
	os.Remove(linkPath)

	metaPath := filepath.Join(l.config.PinPath, "metadata.json")
	os.Remove(metaPath)

	os.Remove(l.config.PinPath)

	l.pinned = false
}

// =============================================================================
// 配置和状态方法
// =============================================================================

func (l *EBPFLoader) ConfigurePort(port uint16, enabled bool) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.objs.ListenPorts == nil {
		return fmt.Errorf("listen_ports map 不可用")
	}

	config := PhantomPortConfig{
		Port:    port,
		Enabled: 0,
		Flags:   0,
	}
	if enabled {
		config.Enabled = 1
	}

	key := Htons(port)
	return l.objs.ListenPorts.Put(&key, &config)
}

func (l *EBPFLoader) ConfigureGlobal(listenPort uint16) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.objs.Config == nil {
		return fmt.Errorf("config map 不可用")
	}

	config := PhantomGlobalConfig{
		Magic:           0x5048414E,
		ListenPort:      listenPort,
		Mode:            1,
		LogLevel:        1,
		SessionTimeout:  uint32(l.config.CleanupInterval.Seconds()),
		MaxSessions:     uint32(l.config.MapSize),
		EnableStats:     1,
		EnableConntrack: 1,
		EnableIpv6:      1,
	}

	key := uint32(0)
	return l.objs.Config.Put(&key, &config)
}

func (l *EBPFLoader) GetStats() (*PhantomStatsCounter, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.objs.Stats == nil {
		return nil, fmt.Errorf("stats map 不可用")
	}

	key := uint32(0)
	var stats PhantomStatsCounter

	if err := l.objs.Stats.Lookup(&key, &stats); err != nil {
		return nil, fmt.Errorf("读取统计失败: %w", err)
	}

	return &stats, nil
}

func (l *EBPFLoader) GetSession(key *PhantomSessionKey) (*PhantomSessionValue, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.objs.Sessions == nil {
		return nil, fmt.Errorf("sessions map 不可用")
	}

	var value PhantomSessionValue
	if err := l.objs.Sessions.Lookup(key, &value); err != nil {
		return nil, err
	}

	return &value, nil
}

func (l *EBPFLoader) DeleteSession(key *PhantomSessionKey) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.objs.Sessions == nil {
		return fmt.Errorf("sessions map 不可用")
	}

	return l.objs.Sessions.Delete(key)
}

func (l *EBPFLoader) IterateSessions(callback func(*PhantomSessionKey, *PhantomSessionValue) bool) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.objs.Sessions == nil {
		return fmt.Errorf("sessions map 不可用")
	}

	var key PhantomSessionKey
	var value PhantomSessionValue

	iter := l.objs.Sessions.Iterate()
	for iter.Next(&key, &value) {
		if !callback(&key, &value) {
			break
		}
	}

	return iter.Err()
}

// 状态查询方法
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

func (l *EBPFLoader) determineXDPMode() string {
	if l.config.XDPMode != XDPModeAuto {
		return l.config.XDPMode
	}
	return XDPModeGeneric
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

	_, _, errno := syscall.Syscall(
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

