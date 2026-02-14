// =============================================================================
// 文件: internal/switcher/switcher.go
// 描述: 智能链路切换 - 核心切换器 (修复锁竞争、ARQ 逻辑、质量异步更新)
// =============================================================================
package switcher

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrcgq/211/internal/config"
	"github.com/mrcgq/211/internal/congestion"
	"github.com/mrcgq/211/internal/crypto"
	"github.com/mrcgq/211/internal/handler"
	"github.com/mrcgq/211/internal/metrics"
	"github.com/mrcgq/211/internal/transport"
)

// Switcher 智能链路切换器
type Switcher struct {
	cfg       *config.Config
	switchCfg *SwitcherConfig
	crypto    *crypto.Crypto
	handler   *handler.UnifiedHandler
	metrics   *metrics.PhantomMetrics // 指标收集器

	transports map[TransportMode]TransportHandler
	udpServer  *transport.UDPServer
	tcpServer  *transport.TCPServer
	fakeTCP    *transport.FakeTCPServer
	webSocket  *transport.WebSocketServer
	ebpf       *transport.EBPFAccelerator

	congestion *congestion.Hysteria2Controller

	decision *DecisionEngine
	prober   *Prober

	currentMode TransportMode
	modeStats   map[TransportMode]*ModeStats

	// 异步质量更新队列 (修复锁竞争)
	qualityUpdates chan *qualityUpdate

	totalSwitches   uint64
	successSwitches uint64
	failedSwitches  uint64
	startTime       time.Time
	modeStartTime   time.Time

	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.RWMutex
	logLevel int
}

// qualityUpdate 质量更新事件
type qualityUpdate struct {
	mode    TransportMode
	success bool
	bytes   int64
	rtt     time.Duration
}

// arqHandlerWrapper ARQ 事件包装器
type arqHandlerWrapper struct {
	handler *handler.UnifiedHandler
}

func (h *arqHandlerWrapper) OnData(data []byte, from *net.UDPAddr) {
	h.handler.HandlePacket(data, from)
}

func (h *arqHandlerWrapper) OnConnected(addr *net.UDPAddr) {}

func (h *arqHandlerWrapper) OnDisconnected(addr *net.UDPAddr, reason error) {}

// New 创建切换器
func New(cfg *config.Config, cry *crypto.Crypto, h *handler.UnifiedHandler) *Switcher {
	switchCfg := &SwitcherConfig{
		Enabled:             cfg.Switcher.Enabled,
		CheckInterval:       time.Duration(cfg.Switcher.CheckInterval) * time.Millisecond,
		RTTThreshold:        time.Duration(cfg.Switcher.RTTThreshold) * time.Millisecond,
		LossThreshold:       cfg.Switcher.LossThreshold,
		FailThreshold:       cfg.Switcher.FailThreshold,
		RecoverThreshold:    cfg.Switcher.RecoverThreshold,
		MinSwitchInterval:   5 * time.Second,
		MaxSwitchRate:       6,
		CooldownPeriod:      10 * time.Second,
		EnableFallback:      true,
		FallbackMode:        ModeWebSocket,
		EnableProbe:         true,
		ProbeInterval:       30 * time.Second,
		ProbePacketSize:     64,
		ProbeCount:          3,
		ProbeTimeout:        5 * time.Second,
		LogLevel:            cfg.LogLevel,
	}

	// 解析优先级 (过滤 ARQ)
	for _, modeStr := range cfg.Switcher.Priority {
		mode := TransportMode(modeStr)
		if mode != "arq" {
			switchCfg.Priority = append(switchCfg.Priority, mode)
		}
	}
	if len(switchCfg.Priority) == 0 {
		switchCfg.Priority = []TransportMode{ModeEBPF, ModeFakeTCP, ModeUDP, ModeWebSocket}
	}

	logLevel := 1
	switch cfg.LogLevel {
	case "debug":
		logLevel = 2
	case "error":
		logLevel = 0
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Switcher{
		cfg:            cfg,
		switchCfg:      switchCfg,
		crypto:         cry,
		handler:        h,
		transports:     make(map[TransportMode]TransportHandler),
		decision:       NewDecisionEngine(switchCfg),
		prober:         NewProber(switchCfg),
		modeStats:      make(map[TransportMode]*ModeStats),
		qualityUpdates: make(chan *qualityUpdate, 1000),
		startTime:      time.Now(),
		ctx:            ctx,
		cancel:         cancel,
		logLevel:       logLevel,
	}

	if cfg.Hysteria2.Enabled {
		s.congestion = congestion.NewHysteria2Controller(
			cfg.Hysteria2.UpMbps,
			cfg.Hysteria2.DownMbps,
		)
	}

	for _, mode := range AllModes {
		s.modeStats[mode] = &ModeStats{
			Mode:  mode,
			State: StateUnknown,
		}
	}

	return s
}

// SetMetrics 设置指标收集器
func (s *Switcher) SetMetrics(m *metrics.PhantomMetrics) {
	s.metrics = m
}

// Start 启动切换器
func (s *Switcher) Start(ctx context.Context) error {
	s.log(1, "启动智能链路切换器...")

	// 启动异步质量更新处理器
	s.wg.Add(1)
	go s.qualityUpdateLoop()

	if err := s.startTransports(ctx); err != nil {
		return err
	}

	s.handler.SetSender(s.SendTo)
	s.selectInitialMode()

	if s.switchCfg.Enabled {
		s.wg.Add(1)
		go s.monitorLoop()

		if s.switchCfg.EnableProbe {
			s.wg.Add(1)
			go s.probeLoop()
		}
	}

	s.log(1, "智能链路切换器已启动, 当前模式: %s", s.currentMode)
	return nil
}

// qualityUpdateLoop 异步质量更新循环 (修复锁竞争)
func (s *Switcher) qualityUpdateLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		case update, ok := <-s.qualityUpdates:
			if !ok {
				return
			}
			s.decision.UpdateQuality(update.mode, func(monitor *QualityMonitor) {
				if update.success {
					if update.rtt > 0 {
						monitor.RecordRTT(update.rtt)
					}
					monitor.RecordPacket(true)
					if update.bytes > 0 {
						monitor.RecordBytes(update.bytes)
					}
				} else {
					monitor.RecordPacket(false)
				}
			})
		}
	}
}

// startTransports 启动所有传输层
func (s *Switcher) startTransports(ctx context.Context) error {
	logLevel := s.cfg.LogLevel

	// 1. UDP (始终启动，集成 ARQ 增强层)
	s.udpServer = transport.NewUDPServer(s.cfg.Listen, s.handler, logLevel)
	if s.congestion != nil {
		s.udpServer.SetCongestionController(s.congestion)
	}

	// 启用 ARQ 增强层
	if s.cfg.ARQ.Enabled {
		arqConfig := &transport.ARQConnConfig{
			MaxWindowSize:   s.cfg.ARQ.WindowSize,
			RTOMin:          time.Duration(s.cfg.ARQ.RTOMinMs) * time.Millisecond,
			RTOMax:          time.Duration(s.cfg.ARQ.RTOMaxMs) * time.Millisecond,
			MaxRetries:      s.cfg.ARQ.MaxRetries,
			EnableSACK:      s.cfg.ARQ.EnableSACK,
			EnableTimestamp: s.cfg.ARQ.EnableTimestamp,
		}
		arqHandler := &arqHandlerWrapper{handler: s.handler}
		s.udpServer.EnableARQ(arqConfig, arqHandler)
		s.log(1, "ARQ 增强层已启用 (窗口: %d)", s.cfg.ARQ.WindowSize)
	}

	if err := s.udpServer.Start(ctx); err != nil {
		return fmt.Errorf("UDP 启动失败: %w", err)
	}
	s.registerTransport(ModeUDP, NewUDPTransportWrapper(s.udpServer))
	s.modeStats[ModeUDP].State = StateRunning

	// 2. TCP
	s.tcpServer = transport.NewTCPServer(s.cfg.Listen, s.handler, logLevel)
	if err := s.tcpServer.Start(ctx); err != nil {
		s.log(1, "TCP 启动失败: %v (继续运行)", err)
	} else {
		s.registerTransport(ModeTCP, NewTCPTransportWrapper(s.tcpServer))
		s.modeStats[ModeTCP].State = StateRunning
	}

	// 3. FakeTCP (集成 eBPF TC 加速)
	if s.cfg.FakeTCP.Enabled {
		s.fakeTCP = transport.NewFakeTCPServer(
			s.cfg.FakeTCP.Listen,
			s.cfg.FakeTCP.Interface,
			s.handler,
			logLevel,
		)

		// 如果配置了 eBPF TC 加速
		if s.cfg.FakeTCP.UseEBPF && s.cfg.EBPF.ProgramPath != "" {
			if err := s.fakeTCP.EnableEBPFTC(s.cfg.EBPF.ProgramPath); err != nil {
				s.log(1, "FakeTCP eBPF TC 加速失败: %v (回退到用户态)", err)
			}
		}

		if err := s.fakeTCP.Start(ctx); err != nil {
			s.log(1, "FakeTCP 启动失败: %v", err)
		} else {
			s.registerTransport(ModeFakeTCP, NewFakeTCPTransportWrapper(s.fakeTCP))
			s.modeStats[ModeFakeTCP].State = StateRunning
		}
	}

	// 4. WebSocket
	if s.cfg.WebSocket.Enabled {
		s.webSocket = transport.NewWebSocketServer(
			s.cfg.WebSocket.Listen,
			s.cfg.WebSocket.Path,
			s.cfg.WebSocket.Host,
			s.cfg.WebSocket.TLS,
			s.cfg.WebSocket.CertFile,
			s.cfg.WebSocket.KeyFile,
			s.handler,
			logLevel,
		)
		if err := s.webSocket.Start(ctx); err != nil {
			s.log(1, "WebSocket 启动失败: %v", err)
		} else {
			s.registerTransport(ModeWebSocket, NewWSTransportWrapper(s.webSocket))
			s.modeStats[ModeWebSocket].State = StateRunning
		}
	}

	// 5. eBPF
	if s.cfg.EBPF.Enabled {
		s.ebpf = transport.NewEBPFAccelerator(
			s.cfg.EBPF.Interface,
			s.cfg.EBPF.XDPMode,
			s.cfg.EBPF.ProgramPath,
			s.cfg.EBPF.MapSize,
			s.cfg.EBPF.EnableStats,
			s.handler,
			logLevel,
		)
		if err := s.ebpf.Start(ctx, s.cfg.Listen); err != nil {
			s.log(1, "eBPF 启动失败: %v", err)
		} else if s.ebpf.IsActive() {
			s.registerTransport(ModeEBPF, NewEBPFTransportWrapper(s.ebpf))
			s.modeStats[ModeEBPF].State = StateRunning
		}
	}

	return nil
}

// registerTransport 注册传输层
func (s *Switcher) registerTransport(mode TransportMode, handler TransportHandler) {
	s.transports[mode] = handler
	s.prober.RegisterTransport(mode, handler)
}

// selectInitialMode 选择初始模式
func (s *Switcher) selectInitialMode() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, mode := range s.switchCfg.Priority {
		if stats, ok := s.modeStats[mode]; ok && stats.State == StateRunning {
			s.currentMode = mode
			s.modeStartTime = time.Now()
			s.modeStats[mode].LastActive = time.Now()
			s.modeStats[mode].SwitchInCount++
			s.log(1, "初始模式: %s", mode)
			return
		}
	}

	s.currentMode = ModeUDP
	s.modeStartTime = time.Now()
}

// monitorLoop 监控循环
func (s *Switcher) monitorLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.switchCfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkAndSwitch()
		}
	}
}

// checkAndSwitch 检查并切换
func (s *Switcher) checkAndSwitch() {
	s.mu.RLock()
	currentMode := s.currentMode
	s.mu.RUnlock()

	decision := s.decision.Evaluate(currentMode)
	if !decision.ShouldSwitch {
		return
	}

	s.doSwitch(currentMode, decision.TargetMode, decision.Reason)
}

// doSwitch 执行切换
func (s *Switcher) doSwitch(fromMode, toMode TransportMode, reason SwitchReason) {
	s.mu.Lock()

	if s.currentMode != fromMode {
		s.mu.Unlock()
		return
	}

	toStats, ok := s.modeStats[toMode]
	if !ok || toStats.State != StateRunning {
		s.mu.Unlock()
		s.log(2, "目标模式 %s 不可用, 取消切换", toMode)
		return
	}

	switchStart := time.Now()
	oldMode := s.currentMode
	s.currentMode = toMode
	s.modeStartTime = time.Now()

	if fromStats, ok := s.modeStats[fromMode]; ok {
		fromStats.TotalTime += time.Since(fromStats.LastActive)
		fromStats.SwitchOutCount++
	}
	toStats.LastActive = time.Now()
	toStats.SwitchInCount++

	s.mu.Unlock()

	event := SwitchEvent{
		Timestamp: time.Now(),
		FromMode:  oldMode,
		ToMode:    toMode,
		Reason:    reason,
		Success:   true,
		Duration:  time.Since(switchStart),
	}

	s.decision.RecordSwitch(event)
	atomic.AddUint64(&s.totalSwitches, 1)
	atomic.AddUint64(&s.successSwitches, 1)

	// 更新指标
	if s.metrics != nil {
		s.metrics.RecordModeSwitch(string(oldMode), string(toMode))
	}

	s.log(1, "链路切换: %s -> %s (原因: %s, 耗时: %v)",
		oldMode, toMode, reason, event.Duration)
}

// probeLoop 探测循环
func (s *Switcher) probeLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.switchCfg.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.probeInactiveModes()
		}
	}
}

// probeInactiveModes 探测非活跃模式
func (s *Switcher) probeInactiveModes() {
	s.mu.RLock()
	currentMode := s.currentMode
	s.mu.RUnlock()

	ctx, cancel := context.WithTimeout(s.ctx, s.switchCfg.ProbeTimeout*3)
	defer cancel()

	for mode, t := range s.transports {
		if mode == currentMode {
			continue
		}

		if !t.IsRunning() {
			continue
		}

		result := s.prober.ProbeMode(ctx, mode)

		s.decision.RecordProbeResult(mode, result.RTT, result.Available)

		s.mu.Lock()
		if stats, ok := s.modeStats[mode]; ok {
			if result.Available {
				stats.State = StateRunning
			} else {
				stats.State = StateDegraded
			}
		}
		s.mu.Unlock()

		s.log(2, "探测 %s: RTT=%v, 可用=%v", mode, result.RTT, result.Available)
	}
}

// SendTo 发送数据 (异步质量更新避免锁竞争)
func (s *Switcher) SendTo(data []byte, addr *net.UDPAddr) error {
	s.mu.RLock()
	mode := s.currentMode
	t := s.transports[mode]
	s.mu.RUnlock()

	if t == nil {
		return fmt.Errorf("传输层不可用: %s", mode)
	}

	err := t.Send(data, addr)

	// 异步更新质量
	select {
	case s.qualityUpdates <- &qualityUpdate{
		mode:    mode,
		success: err == nil,
		bytes:   int64(len(data)),
	}:
	default:
		// 队列满，丢弃更新
	}

	// 更新指标
	if s.metrics != nil && err == nil {
		s.metrics.AddBytesSent(int64(len(data)))
	}

	return err
}

// CurrentMode 获取当前模式
func (s *Switcher) CurrentMode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return string(s.currentMode)
}

// HasEBPF 是否启用 eBPF
func (s *Switcher) HasEBPF() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats, ok := s.modeStats[ModeEBPF]
	return ok && stats.State == StateRunning
}

// HasFakeTCP 是否启用 FakeTCP
func (s *Switcher) HasFakeTCP() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats, ok := s.modeStats[ModeFakeTCP]
	return ok && stats.State == StateRunning
}

// HasHysteria2 是否启用 Hysteria2
func (s *Switcher) HasHysteria2() bool {
	return s.congestion != nil
}

// HasWebSocket 是否启用 WebSocket
func (s *Switcher) HasWebSocket() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats, ok := s.modeStats[ModeWebSocket]
	return ok && stats.State == StateRunning
}

// HasARQ 是否启用 ARQ (UDP 的属性)
func (s *Switcher) HasARQ() bool {
	return s.cfg.ARQ.Enabled && s.udpServer != nil && s.udpServer.GetARQManager() != nil
}

// SwitchMode 手动切换模式
func (s *Switcher) SwitchMode(mode TransportMode) error {
	s.mu.RLock()
	currentMode := s.currentMode
	stats, ok := s.modeStats[mode]
	s.mu.RUnlock()

	if !ok {
		return fmt.Errorf("未知模式: %s", mode)
	}

	if stats.State != StateRunning {
		return fmt.Errorf("模式不可用: %s", mode)
	}

	s.doSwitch(currentMode, mode, ReasonManual)
	return nil
}

// GetStats 获取统计信息
func (s *Switcher) GetStats() *SwitcherStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &SwitcherStats{
		CurrentMode:     s.currentMode,
		TotalSwitches:   atomic.LoadUint64(&s.totalSwitches),
		SuccessSwitches: atomic.LoadUint64(&s.successSwitches),
		FailedSwitches:  atomic.LoadUint64(&s.failedSwitches),
		Uptime:          time.Since(s.startTime),
		CurrentModeTime: time.Since(s.modeStartTime),
		ModeStats:       make(map[TransportMode]*ModeStats),
		ARQEnabled:      s.cfg.ARQ.Enabled,
	}

	if monitor := s.decision.GetQualityMonitor(s.currentMode); monitor != nil {
		stats.CurrentQuality = monitor.GetQuality()
		stats.CurrentState = stats.CurrentQuality.State
	} else {
		stats.CurrentState = StateRunning
	}

	for mode, modeStats := range s.modeStats {
		statsCopy := *modeStats
		if monitor := s.decision.GetQualityMonitor(mode); monitor != nil {
			statsCopy.Quality = monitor.GetQuality()
		}
		stats.ModeStats[mode] = &statsCopy
	}

	if s.udpServer != nil && s.udpServer.GetARQManager() != nil {
		stats.ARQActiveConns = s.udpServer.GetARQManager().GetActiveConns()
	}

	history := s.decision.GetSwitchHistory(1)
	if len(history) > 0 {
		stats.LastSwitch = history[0].Timestamp
		stats.LastSwitchReason = history[0].Reason
	}

	return stats
}

// Stop 停止切换器
func (s *Switcher) Stop() {
	s.log(1, "停止智能链路切换器...")
	s.cancel()

	s.prober.Stop()

	if s.udpServer != nil {
		s.udpServer.Stop()
	}
	if s.tcpServer != nil {
		s.tcpServer.Stop()
	}
	if s.fakeTCP != nil {
		s.fakeTCP.Stop()
	}
	if s.webSocket != nil {
		s.webSocket.Stop()
	}
	if s.ebpf != nil {
		s.ebpf.Stop()
	}

	// 关闭质量更新通道，等待处理完成
	close(s.qualityUpdates)
	s.wg.Wait()
	s.log(1, "智能链路切换器已停止")
}

func (s *Switcher) log(level int, format string, args ...interface{}) {
	if level > s.logLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [Switcher] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}
