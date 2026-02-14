// =============================================================================
// 文件: internal/transport/ebpf.go
// 描述: eBPF 加速 - 主加速器 (修复 SendTo 实现)
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
)

// EBPFAccelerator eBPF 加速器
type EBPFAccelerator struct {
	config   *EBPFConfig
	handler  PacketHandler
	logLevel int

	// eBPF 加载器
	loader *EBPFLoader

	// 用户态 UDP 回退
	fallbackUDP *UDPServer
	useFallback bool

	// 用户态发送 socket
	sendConn *net.UDPConn

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
func (e *EBPFAccelerator) Start(ctx context.Context, listenAddr string) error {
	// 检查 eBPF 支持
	if !e.checkEBPFSupport() {
		e.log(1, "eBPF 不可用，回退到用户态 UDP")
		return e.startFallback(ctx, listenAddr)
	}

	// 加载 eBPF 程序
	if err := e.loader.Load(); err != nil {
		e.log(1, "加载 eBPF 程序失败: %v，回退到用户态 UDP", err)
		return e.startFallback(ctx, listenAddr)
	}

	// 附加到网卡
	if err := e.loader.Attach(); err != nil {
		e.log(1, "附加 eBPF 程序失败: %v，回退到用户态 UDP", err)
		e.loader.Close()
		return e.startFallback(ctx, listenAddr)
	}

	// 配置端口
	if err := e.configureListenPort(listenAddr); err != nil {
		e.log(1, "配置端口失败: %v", err)
	}

	// 创建用户态发送 socket
	if err := e.createSendSocket(listenAddr); err != nil {
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

	// 启动用户态 UDP 处理 (处理需要应用层逻辑的包)
	e.wg.Add(1)
	go e.userSpaceLoop(listenAddr)

	e.stats.Active = true
	e.stats.XDPMode = e.loader.GetXDPMode()
	e.stats.Interface = e.loader.GetInterface()
	e.stats.ProgramLoaded = true

	e.log(1, "eBPF 加速器已启动: %s (mode: %s)", e.config.Interface, e.loader.GetXDPMode())
	return nil
}

// createSendSocket 创建用户态发送 socket
func (e *EBPFAccelerator) createSendSocket(listenAddr string) error {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}

	// 创建一个绑定到本地地址的 UDP socket 用于发送
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		// 如果绑定失败，尝试使用任意端口
		conn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return err
		}
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

	release := int8ToString(uname.Release[:])
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

func int8ToString(arr []int8) string {
	var buf []byte
	for _, v := range arr {
		if v == 0 {
			break
		}
		buf = append(buf, byte(v))
	}
	return string(buf)
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

// startFallback 启动用户态回退
func (e *EBPFAccelerator) startFallback(ctx context.Context, listenAddr string) error {
	e.useFallback = true
	e.fallbackUDP = NewUDPServer(listenAddr, e.handler, e.logLevelString())
	return e.fallbackUDP.Start(ctx)
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
	if e.useFallback {
		return
	}

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

// userSpaceLoop 用户态处理循环
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

	// 保存连接用于发送
	e.mu.Lock()
	if e.sendConn == nil {
		e.sendConn = conn
	}
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

// SendTo 发送数据 (修复: 实现完整的发送逻辑)
func (e *EBPFAccelerator) SendTo(data []byte, addr *net.UDPAddr) error {
	// 如果使用回退模式
	if e.useFallback && e.fallbackUDP != nil {
		return e.fallbackUDP.SendTo(data, addr)
	}

	// 使用用户态 socket 发送
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
	if e.useFallback {
		return EBPFStats{
			PacketsRX: atomic.LoadUint64(&e.packetsProcessed),
			BytesRX:   atomic.LoadUint64(&e.bytesProcessed),
		}
	}

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
	return !e.useFallback && e.loader != nil && e.loader.IsAttached()
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

	if e.fallbackUDP != nil {
		e.fallbackUDP.Stop()
	}

	if e.sendConn != nil {
		e.sendConn.Close()
	}

	e.wg.Wait()
	e.log(1, "eBPF 加速器已停止")
}

func (e *EBPFAccelerator) logLevelString() string {
	switch e.logLevel {
	case 0:
		return "error"
	case 2:
		return "debug"
	default:
		return "info"
	}
}

func (e *EBPFAccelerator) log(level int, format string, args ...interface{}) {
	if level > e.logLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [eBPF] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}
