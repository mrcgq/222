//go:build linux

// =============================================================================
// 文件: internal/transport/ebpf.go
// 描述: eBPF 加速 - 旧版加速器
// 状态: 已废弃 - 请使用 internal/ebpf.Loader + switcher.EBPFLoaderTransportWrapper
// 保留原因: 向后兼容
// =============================================================================
package transport

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// EBPFAccelerator eBPF 加速器
// Deprecated: 请使用 internal/ebpf.Loader 配合 EBPFLoaderTransportWrapper
type EBPFAccelerator struct {
	config   *EBPFConfig
	handler  PacketHandler
	logLevel int

	// eBPF 加载器
	loader *EBPFLoader

	// 主 UDP 连接（由外部注入，共享端口）
	// 修复：不再使用随机端口的 sendConn
	mainConn *net.UDPConn
	connMu   sync.RWMutex

	// 统计
	stats            EBPFAcceleratorStats
	packetsProcessed uint64
	bytesProcessed   uint64
	eventsProcessed  uint64

	// 事件处理
	eventChan chan *EBPFPacketEvent

	// 控制
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex

	running   int32
	startTime time.Time
}

// NewEBPFAccelerator 创建 eBPF 加速器
func NewEBPFAccelerator(
	iface, xdpMode, programPath string,
	mapSize int, enableStats bool,
	handler PacketHandler, logLevel string,
) *EBPFAccelerator {
	level := 1
	switch logLevel {
	case "debug":
		level = 2
	case "error":
		level = 0
	}

	config := &EBPFConfig{
		Enabled:         true,
		Interface:       iface,
		XDPMode:         xdpMode,
		ProgramPath:     programPath,
		MapSize:         mapSize,
		EnableStats:     enableStats,
		BatchSize:       64,
		PollTimeout:     100 * time.Millisecond,
		CleanupInterval: 30 * time.Second,
		LogLevel:        logLevel,
	}

	// 创建 EBPFLoaderConfig
	loaderConfig := &EBPFLoaderConfig{
		EBPFConfig:      config,
		EnablePinning:   true,
		PinMode:         PinModeReuse,
		PinPath:         DefaultBPFFS + "/" + PinPathPrefix,
		GracefulRestart: true,
		StateTimeout:    5 * time.Minute,
		CleanupOnExit:   false,
		CleanupOrphans:  true,
	}

	return &EBPFAccelerator{
		config:    config,
		handler:   handler,
		logLevel:  level,
		loader:    NewEBPFLoader(loaderConfig),
		eventChan: make(chan *EBPFPacketEvent, 1024),
	}
}

// SetMainConnection 注入主 UDP 连接（关键修复）
// 必须在 Start 之后、SendTo 之前调用
func (e *EBPFAccelerator) SetMainConnection(conn *net.UDPConn) {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	e.mainConn = conn
	e.log(2, "主 UDP 连接已注入")
}

// GetMainConnection 获取主连接
func (e *EBPFAccelerator) GetMainConnection() *net.UDPConn {
	e.connMu.RLock()
	defer e.connMu.RUnlock()
	return e.mainConn
}

// Start 启动加速器
// eBPF 只负责内核挂载，不监听端口（端口由 UDP 模块持有）
func (e *EBPFAccelerator) Start(ctx context.Context, listenAddr string) error {
	// 检查 eBPF 支持
	if !e.checkEBPFSupport() {
		return fmt.Errorf("eBPF 内核环境不支持")
	}

	// 加载 eBPF 程序
	if err := e.loader.Load(); err != nil {
		return fmt.Errorf("加载 eBPF 程序失败: %w", err)
	}

	// 附加到网卡
	if err := e.loader.Attach(); err != nil {
		e.loader.Close()
		return fmt.Errorf("附加 eBPF 程序失败: %w", err)
	}

	// 配置端口信息给内核 Map
	if err := e.configureListenPort(listenAddr); err != nil {
		e.log(1, "配置端口失败: %v", err)
	}

	// 修复：不再创建随机端口的发送 socket
	// 连接由外部通过 SetMainConnection 注入

	e.ctx, e.cancel = context.WithCancel(ctx)
	atomic.StoreInt32(&e.running, 1)
	e.startTime = time.Now()

	// 启动事件处理
	e.wg.Add(1)
	go e.eventLoop()

	// 启动统计收集
	if e.config.EnableStats {
		e.wg.Add(1)
		go e.statsLoop()
	}

	// 启动会话清理
	e.wg.Add(1)
	go e.cleanupLoop()

	e.stats.Active = true
	e.stats.XDPMode = e.loader.GetXDPMode()
	e.stats.Interface = e.loader.GetInterface()
	e.stats.ProgramLoaded = true

	e.log(1, "eBPF 加速引擎已挂载: %s (mode: %s)", e.config.Interface, e.loader.GetXDPMode())
	return nil
}

// checkEBPFSupport 检查 eBPF 支持
func (e *EBPFAccelerator) checkEBPFSupport() bool {
	// 检查内核版本
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return false
	}

	release := utsReleaseToString(&uname)
	var major, minor int
	fmt.Sscanf(release, "%d.%d", &major, &minor)

	// 需要 5.4+ 内核
	if major < 5 || (major == 5 && minor < 4) {
		e.log(2, "内核版本不足: %s (需要 5.4+)", release)
		return false
	}

	// 检查 root 权限
	if os.Geteuid() != 0 {
		e.log(2, "需要 root 权限")
		return false
	}

	// 检查 BTF 支持
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		e.log(2, "BTF 不可用")
		return false
	}

	// 检查程序文件
	programFile := e.config.ProgramPath + "/xdp_phantom.o"
	if _, err := os.Stat(programFile); os.IsNotExist(err) {
		e.log(2, "eBPF 程序不存在: %s", programFile)
		return false
	}

	return true
}

// utsReleaseToString 将 utsname.Release 转换为字符串
func utsReleaseToString(uname *syscall.Utsname) string {
	ptr := unsafe.Pointer(&uname.Release[0])
	length := len(uname.Release)

	bytes := make([]byte, 0, length)
	for i := 0; i < length; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i)))
		if b == 0 {
			break
		}
		bytes = append(bytes, b)
	}
	return string(bytes)
}

// configureListenPort 配置监听端口到 eBPF Map
func (e *EBPFAccelerator) configureListenPort(listenAddr string) error {
	_, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return err
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// 配置 eBPF Map
	if err := e.loader.ConfigurePort(port, true); err != nil {
		return err
	}

	if err := e.loader.ConfigureGlobal(port); err != nil {
		return err
	}

	e.log(2, "eBPF 配置监视端口: %d", port)
	return nil
}

// eventLoop 事件处理循环
func (e *EBPFAccelerator) eventLoop() {
	defer e.wg.Done()

	maps := e.loader.GetMaps()
	if maps["events"] == nil {
		return
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case event := <-e.eventChan:
			e.processEvent(event)
		case <-ticker.C:
			// 批量处理事件
		}
	}
}

// processEvent 处理事件
func (e *EBPFAccelerator) processEvent(event *EBPFPacketEvent) {
	atomic.AddUint64(&e.eventsProcessed, 1)

	srcIP := Uint32ToIP(event.SrcIP)
	dstIP := Uint32ToIP(event.DstIP)

	e.log(2, "事件: %s:%d -> %s:%d, action=%d",
		srcIP, Ntohs(event.SrcPort),
		dstIP, Ntohs(event.DstPort),
		event.Action)
}

// statsLoop 统计收集循环
func (e *EBPFAccelerator) statsLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.collectStats()
		}
	}
}

// collectStats 收集统计信息
func (e *EBPFAccelerator) collectStats() {
	stats, err := e.loader.GetStats()
	if err != nil {
		e.log(2, "读取统计失败: %v", err)
		return
	}

	e.mu.Lock()
	e.stats.Stats = *stats
	e.stats.Uptime = time.Since(e.startTime)
	e.stats.EventsProcessed = atomic.LoadUint64(&e.eventsProcessed)
	e.mu.Unlock()

	e.log(2, "eBPF 统计: rx=%d, tx=%d, dropped=%d, sessions=%d",
		stats.PacketsRX, stats.PacketsTX, stats.PacketsDropped, stats.SessionsCreated)
}

// cleanupLoop 会话清理循环
func (e *EBPFAccelerator) cleanupLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(e.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.cleanupSessions()
		}
	}
}

// cleanupSessions 清理过期会话
func (e *EBPFAccelerator) cleanupSessions() {
	now := uint64(time.Now().UnixNano())
	timeout := uint64(e.config.CleanupInterval.Nanoseconds()) * 10

	var toDelete []EBPFSessionKey
	count := 0

	err := e.loader.IterateSessions(func(key *EBPFSessionKey, value *EBPFSessionValue) bool {
		count++
		if now-value.LastSeenNS > timeout {
			toDelete = append(toDelete, *key)
		}
		return true
	})

	if err != nil {
		e.log(2, "遍历会话失败: %v", err)
		return
	}

	for _, key := range toDelete {
		e.loader.DeleteSession(&key)
	}

	e.mu.Lock()
	e.stats.ActiveSessions = count - len(toDelete)
	e.mu.Unlock()

	if len(toDelete) > 0 {
		e.log(2, "清理 %d 个过期会话", len(toDelete))
	}
}

// SendTo 发送数据 - 使用注入的主 UDP 连接（关键修复）
func (e *EBPFAccelerator) SendTo(data []byte, addr *net.UDPAddr) error {
	e.connMu.RLock()
	conn := e.mainConn
	e.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("主 UDP 连接未注入，请先调用 SetMainConnection")
	}

	_, err := conn.WriteToUDP(data, addr)
	if err != nil {
		return fmt.Errorf("发送失败: %w", err)
	}

	atomic.AddUint64(&e.stats.Stats.PacketsTX, 1)
	atomic.AddUint64(&e.stats.Stats.BytesTX, uint64(len(data)))

	return nil
}

// GetStats 获取统计信息
func (e *EBPFAccelerator) GetStats() EBPFStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats.Stats
}

// GetAcceleratorStats 获取加速器统计
func (e *EBPFAccelerator) GetAcceleratorStats() *EBPFAcceleratorStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := e.stats
	stats.Uptime = time.Since(e.startTime)
	return &stats
}

// IsActive 是否活跃
func (e *EBPFAccelerator) IsActive() bool {
	return atomic.LoadInt32(&e.running) == 1 && e.loader != nil && e.loader.IsAttached()
}

// GetLoader 获取 eBPF 加载器
func (e *EBPFAccelerator) GetLoader() *EBPFLoader {
	return e.loader
}

// Stop 停止加速器
func (e *EBPFAccelerator) Stop() {
	atomic.StoreInt32(&e.running, 0)

	if e.cancel != nil {
		e.cancel()
	}

	if e.loader != nil {
		e.loader.Close()
	}

	// 注意: mainConn 由外部管理，不在这里关闭

	e.wg.Wait()
	e.log(1, "eBPF 加速器已停止")
}

func (e *EBPFAccelerator) log(level int, format string, args ...interface{}) {
	if level > e.logLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [eBPF] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}
