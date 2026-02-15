


//go:build linux

// =============================================================================
// 文件: internal/transport/ebpf.go
// 描述: eBPF 加速 - 主加速器 (修复 SendTo 实现)
//       修复：移除自动 fallback 用户态监听，避免端口冲突
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
type EBPFAccelerator struct {
	config   *EBPFConfig
	handler  PacketHandler
	logLevel int

	// eBPF 加载器
	loader *EBPFLoader

	// 用户态发送 socket (不监听，仅发送)
	sendConn *net.UDPConn

	// 接收连接 (仅在独占模式下使用)
	recvConn     *net.UDPConn
	disableListen bool // 是否禁用用户态监听

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

// Start 启动加速器
// disableFallback: 是否禁用用户态监听回退 (避免与 UDP 服务器端口冲突)
func (e *EBPFAccelerator) Start(ctx context.Context, listenAddr string, disableFallback bool) error {
	e.disableListen = disableFallback

	// 检查 eBPF 支持
	if !e.checkEBPFSupport() {
		e.log(1, "eBPF 不可用")
		if disableFallback {
			return fmt.Errorf("eBPF 不可用且禁止回退")
		}
		return fmt.Errorf("eBPF 不可用")
	}

	// 加载 eBPF 程序
	if err := e.loader.Load(); err != nil {
		e.log(1, "加载 eBPF 程序失败: %v", err)
		return fmt.Errorf("加载 eBPF 程序失败: %w", err)
	}

	// 附加到网卡
	if err := e.loader.Attach(); err != nil {
		e.log(1, "附加 eBPF 程序失败: %v", err)
		e.loader.Close()
		return fmt.Errorf("附加 eBPF 程序失败: %w", err)
	}

	// 配置端口
	if err := e.configureListenPort(listenAddr); err != nil {
		e.log(1, "配置端口失败: %v", err)
	}

	// 创建用户态发送 socket (使用任意端口，仅用于发送)
	if err := e.createSendSocket(); err != nil {
		e.log(1, "创建发送 socket 失败: %v", err)
	}

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

	// 仅在非禁用监听模式下启动用户态接收
	if !e.disableListen {
		e.wg.Add(1)
		go e.userSpaceLoop(listenAddr)
	}

	e.stats.Active = true
	e.stats.XDPMode = e.loader.GetXDPMode()
	e.stats.Interface = e.loader.GetInterface()
	e.stats.ProgramLoaded = true

	e.log(1, "eBPF 加速器已启动: %s (mode: %s, listen: %v)",
		e.config.Interface, e.loader.GetXDPMode(), !e.disableListen)
	return nil
}

// createSendSocket 创建用户态发送 socket (不绑定特定端口)
func (e *EBPFAccelerator) createSendSocket() error {
	// 使用任意端口创建 UDP socket，仅用于发送
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}

	e.sendConn = conn
	return nil
}

// checkEBPFSupport 检查 eBPF 支持
func (e *EBPFAccelerator) checkEBPFSupport() bool {
	// 检查内核版本
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return false
	}

	// 使用 unsafe 转换 Release 字段，兼容不同架构
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
// 使用 unsafe.Pointer 处理不同架构上 int8/uint8 的差异
func utsReleaseToString(uname *syscall.Utsname) string {
	// 获取 Release 字段的指针，转换为 byte 指针
	ptr := unsafe.Pointer(&uname.Release[0])
	length := len(uname.Release)

	// 创建 byte slice
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

// configureListenPort 配置监听端口
func (e *EBPFAccelerator) configureListenPort(listenAddr string) error {
	_, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return err
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// 配置 eBPF
	if err := e.loader.ConfigurePort(port, true); err != nil {
		return err
	}

	if err := e.loader.ConfigureGlobal(port); err != nil {
		return err
	}

	e.log(2, "eBPF 配置端口: %d", port)
	return nil
}

// eventLoop 事件处理循环
func (e *EBPFAccelerator) eventLoop() {
	defer e.wg.Done()

	// 如果没有 events map，直接返回
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
	e.stats.EBPFStats = *stats
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
	timeout := uint64(e.config.CleanupInterval.Nanoseconds()) * 10 // 10 倍清理间隔

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

// userSpaceLoop 用户态处理循环 (仅在非禁用监听模式下运行)
func (e *EBPFAccelerator) userSpaceLoop(listenAddr string) {
	defer e.wg.Done()

	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		e.log(0, "解析地址失败: %v", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		e.log(0, "监听失败: %v", err)
		return
	}
	defer conn.Close()

	// 保存连接用于接收
	e.mu.Lock()
	e.recvConn = conn
	e.mu.Unlock()

	// 设置缓冲区
	_ = conn.SetReadBuffer(8 * 1024 * 1024)
	_ = conn.SetWriteBuffer(8 * 1024 * 1024)

	buf := make([]byte, 65535)

	for atomic.LoadInt32(&e.running) == 1 {
		select {
		case <-e.ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		atomic.AddUint64(&e.packetsProcessed, 1)
		atomic.AddUint64(&e.bytesProcessed, uint64(n))

		// 处理数据包
		if e.handler != nil {
			response := e.handler.HandlePacket(buf[:n], remoteAddr)
			if response != nil {
				conn.WriteToUDP(response, remoteAddr)
			}
		}
	}
}

// SendTo 发送数据
func (e *EBPFAccelerator) SendTo(data []byte, addr *net.UDPAddr) error {
	e.mu.RLock()
	conn := e.sendConn
	e.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("发送 socket 未初始化")
	}

	_, err := conn.WriteToUDP(data, addr)
	if err != nil {
		return fmt.Errorf("发送失败: %w", err)
	}

	atomic.AddUint64(&e.stats.EBPFStats.PacketsTX, 1)
	atomic.AddUint64(&e.stats.EBPFStats.BytesTX, uint64(len(data)))

	return nil
}

// GetStats 获取统计信息
func (e *EBPFAccelerator) GetStats() EBPFStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats.EBPFStats
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
	return e.loader != nil && e.loader.IsAttached()
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

	if e.sendConn != nil {
		e.sendConn.Close()
	}

	if e.recvConn != nil {
		e.recvConn.Close()
	}

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






















