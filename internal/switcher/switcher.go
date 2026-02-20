// =============================================================================
// 文件: internal/switcher/switcher.go
// 描述: 智能链路切换器实现
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
	"github.com/mrcgq/211/internal/crypto"
	"github.com/mrcgq/211/internal/handler"
	"github.com/mrcgq/211/internal/metrics"
)

// Switcher 智能链路切换器
type Switcher struct {
	cfg       *config.Config
	swCfg     *SwitcherConfig
	crypto    *crypto.Crypto
	handler   *handler.UnifiedHandler
	metrics   *metrics.PhantomMetrics

	// 当前状态
	currentMode  TransportMode
	currentState TransportState
	startTime    time.Time
	modeStart    time.Time
	lastSwitch   time.Time

	// 端口所有权
	portOwnership PortOwnership

	// 监听器
	udpConn   *net.UDPConn
	tcpLn     net.Listener
	wsLn      net.Listener
	fakeTCPLn net.Listener

	// 统计
	totalSwitches   uint64
	successSwitches uint64
	failedSwitches  uint64
	modeStats       map[TransportMode]*ModeStats
	switchHistory   []SwitchEvent

	// 功能标志
	hasEBPF      bool
	hasFakeTCP   bool
	hasHysteria2 bool
	hasARQ       bool
	hasWebSocket bool

	// ARQ 状态
	arqEnabled     bool
	arqActiveConns int64

	// 控制
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	stopOnce sync.Once
}

// NewSwitcher 创建新的切换器
func NewSwitcher(cfg *config.Config, cry *crypto.Crypto, h *handler.UnifiedHandler) *Switcher {
	mode := TransportMode(cfg.Mode)
	if mode == "" {
		mode = ModeAuto
	}

	sw := &Switcher{
		cfg:           cfg,
		swCfg:         DefaultSwitcherConfig(),
		crypto:        cry,
		handler:       h,
		currentMode:   mode,
		currentState:  StateStopped,
		portOwnership: PortOwnerNone,
		modeStats:     make(map[TransportMode]*ModeStats),
		switchHistory: make([]SwitchEvent, 0, 100),
	}

	// 初始化模式统计
	for _, m := range AllModes {
		sw.modeStats[m] = &ModeStats{
			Mode:  m,
			State: StateStopped,
		}
	}

	// 检测功能
	sw.detectFeatures()

	return sw
}

// detectFeatures 检测可用功能
func (s *Switcher) detectFeatures() {
	// UDP + ARQ
	s.hasARQ = s.cfg.ARQ.Enabled

	// FakeTCP
	s.hasFakeTCP = s.cfg.FakeTCP.Enabled

	// WebSocket
	s.hasWebSocket = s.cfg.WebSocket.Enabled

	// Hysteria2 拥塞控制
	s.hasHysteria2 = s.cfg.Hysteria2.Enabled

	// eBPF (仅 Linux，需要 root)
	s.hasEBPF = s.cfg.EBPF.Enabled && isEBPFAvailable()
}

// SetMetrics 设置指标收集器
func (s *Switcher) SetMetrics(m *metrics.PhantomMetrics) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.metrics = m
}

// Start 启动切换器
func (s *Switcher) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentState == StateRunning || s.currentState == StateStarting {
		return fmt.Errorf("switcher already running")
	}

	s.ctx, s.cancel = context.WithCancel(ctx)
	s.currentState = StateStarting
	s.startTime = time.Now()

	// 根据模式启动
	var err error
	switch s.currentMode {
	case ModeAuto:
		err = s.startAutoMode()
	case ModeUDP:
		err = s.startUDPMode()
	case ModeFakeTCP:
		err = s.startFakeTCPMode()
	case ModeWebSocket:
		err = s.startWebSocketMode()
	case ModeEBPF:
		err = s.startEBPFMode()
	case ModeTCP:
		err = s.startTCPMode()
	default:
		err = s.startUDPMode()
	}

	if err != nil {
		s.currentState = StateFailed
		return fmt.Errorf("start transport failed: %w", err)
	}

	s.currentState = StateRunning
	s.modeStart = time.Now()

	// 更新模式统计
	if stats, ok := s.modeStats[s.currentMode]; ok {
		stats.State = StateRunning
		stats.SwitchInCount++
		stats.LastActive = time.Now()
	}

	// 记录切换事件
	s.recordSwitchEvent(TransportMode(""), s.currentMode, ReasonInitial, true)

	// 启动监控协程
	s.wg.Add(1)
	go s.monitorLoop()

	return nil
}

// startAutoMode 自动模式启动 - 按优先级尝试
func (s *Switcher) startAutoMode() error {
	for _, mode := range s.swCfg.Priority {
		var err error
		switch mode {
		case ModeEBPF:
			if s.hasEBPF {
				err = s.startEBPFMode()
			} else {
				continue
			}
		case ModeFakeTCP:
			if s.hasFakeTCP {
				err = s.startFakeTCPMode()
			} else {
				continue
			}
		case ModeUDP:
			err = s.startUDPMode()
		case ModeWebSocket:
			if s.hasWebSocket {
				err = s.startWebSocketMode()
			} else {
				continue
			}
		case ModeTCP:
			err = s.startTCPMode()
		default:
			continue
		}

		if err == nil {
			s.currentMode = mode
			return nil
		}
	}

	return fmt.Errorf("no available transport mode")
}

// startUDPMode 启动 UDP 模式
func (s *Switcher) startUDPMode() error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("resolve udp addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}

	// 设置缓冲区
	conn.SetReadBuffer(4 * 1024 * 1024)
	conn.SetWriteBuffer(4 * 1024 * 1024)

	s.udpConn = conn
	s.portOwnership = PortOwnerUDP
	s.arqEnabled = s.cfg.ARQ.Enabled

	// 启动 UDP 处理协程
	s.wg.Add(1)
	go s.handleUDP()

	return nil
}

// startTCPMode 启动 TCP 模式
func (s *Switcher) startTCPMode() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen tcp: %w", err)
	}

	s.tcpLn = ln

	s.wg.Add(1)
	go s.handleTCP()

	return nil
}

// startFakeTCPMode 启动 FakeTCP 模式
func (s *Switcher) startFakeTCPMode() error {
	if !s.cfg.FakeTCP.Enabled {
		return fmt.Errorf("faketcp not enabled in config")
	}

	listenAddr := s.cfg.FakeTCP.Listen
	if listenAddr == "" {
		listenAddr = s.cfg.Listen
	}

	// FakeTCP 实际上需要 raw socket，这里简化实现
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen faketcp: %w", err)
	}

	s.fakeTCPLn = ln

	s.wg.Add(1)
	go s.handleFakeTCP()

	return nil
}

// startWebSocketMode 启动 WebSocket 模式
func (s *Switcher) startWebSocketMode() error {
	if !s.cfg.WebSocket.Enabled {
		return fmt.Errorf("websocket not enabled in config")
	}

	listenAddr := s.cfg.WebSocket.Listen
	if listenAddr == "" {
		return fmt.Errorf("websocket listen address not configured")
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen websocket: %w", err)
	}

	s.wsLn = ln

	s.wg.Add(1)
	go s.handleWebSocket()

	return nil
}

// startEBPFMode 启动 eBPF 模式
func (s *Switcher) startEBPFMode() error {
	if !s.hasEBPF {
		return fmt.Errorf("ebpf not available")
	}

	// eBPF 模式需要独占端口
	if s.portOwnership != PortOwnerNone && s.portOwnership != PortOwnerEBPF {
		return fmt.Errorf("port already owned by %s", s.portOwnership)
	}

	// 实际的 eBPF 实现会在这里加载 BPF 程序
	// 这里先回退到 UDP 模式
	if err := s.startUDPMode(); err != nil {
		return err
	}

	s.portOwnership = PortOwnerEBPF
	return nil
}

// handleUDP 处理 UDP 连接
func (s *Switcher) handleUDP() {
	defer s.wg.Done()

	buf := make([]byte, 65536)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		s.udpConn.SetReadDeadline(time.Now().Add(time.Second))
		n, remoteAddr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.ctx.Done():
				return
			default:
				continue
			}
		}

		// 复制数据避免竞争
		data := make([]byte, n)
		copy(data, buf[:n])

		// 处理数据包
		go s.handler.HandleUDPPacket(s.udpConn, remoteAddr, data)
	}
}

// handleTCP 处理 TCP 连接
func (s *Switcher) handleTCP() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.tcpLn.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				continue
			}
		}

		go s.handler.HandleTCPConn(conn)
	}
}

// handleFakeTCP 处理 FakeTCP 连接
func (s *Switcher) handleFakeTCP() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.fakeTCPLn.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				continue
			}
		}

		go s.handler.HandleTCPConn(conn)
	}
}

// handleWebSocket 处理 WebSocket 连接
func (s *Switcher) handleWebSocket() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.wsLn.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				continue
			}
		}

		go s.handler.HandleWebSocket(conn)
	}
}

// monitorLoop 监控循环
func (s *Switcher) monitorLoop() {
	defer s.wg.Done()

	checkTicker := time.NewTicker(s.swCfg.CheckInterval)
	defer checkTicker.Stop()

	probeTicker := time.NewTicker(s.swCfg.ProbeInterval)
	defer probeTicker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-checkTicker.C:
			s.checkQuality()
		case <-probeTicker.C:
			if s.swCfg.EnableProbe {
				s.probeAlternatives()
			}
		}
	}
}

// checkQuality 检查链路质量
func (s *Switcher) checkQuality() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 更新当前模式统计
	if stats, ok := s.modeStats[s.currentMode]; ok {
		stats.TotalTime += s.swCfg.CheckInterval
		stats.Quality = s.getCurrentQuality()
	}

	// 检查是否需要切换
	decision := s.evaluateSwitchDecision()
	if decision.ShouldSwitch {
		s.executeSwitch(decision)
	}
}

// getCurrentQuality 获取当前链路质量
func (s *Switcher) getCurrentQuality() *LinkQuality {
	// 从 handler 获取统计
	handlerStats := s.handler.GetStats()

	quality := &LinkQuality{
		Available:   true,
		State:       s.currentState,
		LastCheck:   time.Now(),
		LastSuccess: time.Now(),
	}

	if activeConns, ok := handlerStats["active_conns"].(uint64); ok {
		quality.ActiveConns = int(activeConns)
	}
	if totalConns, ok := handlerStats["total_conns"].(uint64); ok {
		quality.TotalConns = totalConns
	}

	return quality
}

// evaluateSwitchDecision 评估是否需要切换
func (s *Switcher) evaluateSwitchDecision() *SwitchDecision {
	decision := &SwitchDecision{
		ShouldSwitch: false,
		TargetMode:   s.currentMode,
		Confidence:   0,
	}

	// 获取当前质量
	quality := s.getCurrentQuality()
	if quality == nil {
		return decision
	}

	// 检查 RTT
	if quality.RTT > s.swCfg.RTTThreshold {
		decision.Reason = ReasonHighRTT
		decision.Confidence = 0.7
	}

	// 检查丢包率
	if quality.LossRate > s.swCfg.LossThreshold {
		decision.Reason = ReasonHighLoss
		decision.Confidence = 0.8
	}

	// 检查连续失败
	if quality.ConsecutiveFailures >= s.swCfg.FailThreshold {
		decision.Reason = ReasonConnectionFailed
		decision.Confidence = 0.9
		decision.ShouldSwitch = true
	}

	// 冷却检查
	if decision.ShouldSwitch && time.Since(s.lastSwitch) < s.swCfg.CooldownPeriod {
		decision.ShouldSwitch = false
	}

	// 选择目标模式
	if decision.ShouldSwitch {
		decision.TargetMode = s.selectBestAlternative()
	}

	return decision
}

// selectBestAlternative 选择最佳备选模式
func (s *Switcher) selectBestAlternative() TransportMode {
	for _, mode := range s.swCfg.Priority {
		if mode == s.currentMode {
			continue
		}
		if s.isModeAvailable(mode) {
			return mode
		}
	}

	if s.swCfg.EnableFallback {
		return s.swCfg.FallbackMode
	}

	return s.currentMode
}

// isModeAvailable 检查模式是否可用
func (s *Switcher) isModeAvailable(mode TransportMode) bool {
	switch mode {
	case ModeEBPF:
		return s.hasEBPF
	case ModeFakeTCP:
		return s.hasFakeTCP
	case ModeWebSocket:
		return s.hasWebSocket
	case ModeUDP, ModeTCP:
		return true
	default:
		return false
	}
}

// executeSwitch 执行切换
func (s *Switcher) executeSwitch(decision *SwitchDecision) {
	if decision.TargetMode == s.currentMode {
		return
	}

	oldMode := s.currentMode
	s.currentState = StateDegraded

	// 记录切换开始
	atomic.AddUint64(&s.totalSwitches, 1)

	// 更新旧模式统计
	if stats, ok := s.modeStats[oldMode]; ok {
		stats.SwitchOutCount++
	}

	// 切换到新模式 (简化版：仅更新状态)
	s.currentMode = decision.TargetMode
	s.lastSwitch = time.Now()
	s.modeStart = time.Now()

	// 更新新模式统计
	if stats, ok := s.modeStats[s.currentMode]; ok {
		stats.SwitchInCount++
		stats.State = StateRunning
		stats.LastActive = time.Now()
	}

	s.currentState = StateRunning
	atomic.AddUint64(&s.successSwitches, 1)

	// 记录切换事件
	s.recordSwitchEvent(oldMode, s.currentMode, decision.Reason, true)
}

// probeAlternatives 探测备选模式
func (s *Switcher) probeAlternatives() {
	// 简化实现：仅更新可用性
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, mode := range AllModes {
		if mode == s.currentMode {
			continue
		}
		if stats, ok := s.modeStats[mode]; ok {
			stats.Quality = &LinkQuality{
				Available: s.isModeAvailable(mode),
				LastCheck: time.Now(),
			}
		}
	}
}

// recordSwitchEvent 记录切换事件
func (s *Switcher) recordSwitchEvent(from, to TransportMode, reason SwitchReason, success bool) {
	event := SwitchEvent{
		Timestamp: time.Now(),
		FromMode:  from,
		ToMode:    to,
		Reason:    reason,
		Success:   success,
	}

	// 保留最近 100 个事件
	if len(s.switchHistory) >= 100 {
		s.switchHistory = s.switchHistory[1:]
	}
	s.switchHistory = append(s.switchHistory, event)
}

// Stop 停止切换器
func (s *Switcher) Stop() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.currentState = StateStopped
		s.mu.Unlock()

		if s.cancel != nil {
			s.cancel()
		}

		// 关闭监听器
		if s.udpConn != nil {
			s.udpConn.Close()
		}
		if s.tcpLn != nil {
			s.tcpLn.Close()
		}
		if s.wsLn != nil {
			s.wsLn.Close()
		}
		if s.fakeTCPLn != nil {
			s.fakeTCPLn.Close()
		}

		// 等待所有协程退出
		s.wg.Wait()

		s.mu.Lock()
		s.portOwnership = PortOwnerNone
		s.mu.Unlock()
	})
}

// CurrentMode 获取当前模式
func (s *Switcher) CurrentMode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return string(s.currentMode)
}

// GetStats 获取统计信息
func (s *Switcher) GetStats() SwitcherStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var uptime, modeTime time.Duration
	if !s.startTime.IsZero() {
		uptime = time.Since(s.startTime)
	}
	if !s.modeStart.IsZero() {
		modeTime = time.Since(s.modeStart)
	}

	stats := SwitcherStats{
		CurrentMode:     s.currentMode,
		CurrentState:    s.currentState,
		CurrentQuality:  s.getCurrentQuality(),
		TotalSwitches:   atomic.LoadUint64(&s.totalSwitches),
		SuccessSwitches: atomic.LoadUint64(&s.successSwitches),
		FailedSwitches:  atomic.LoadUint64(&s.failedSwitches),
		LastSwitch:      s.lastSwitch,
		ModeStats:       make(map[TransportMode]*ModeStats),
		Uptime:          uptime,
		CurrentModeTime: modeTime,
		ARQEnabled:      s.arqEnabled,
		ARQActiveConns:  atomic.LoadInt64(&s.arqActiveConns),
		PortOwnership:   s.portOwnership,
	}

	// 复制模式统计
	for mode, ms := range s.modeStats {
		stats.ModeStats[mode] = &ModeStats{
			Mode:           ms.Mode,
			State:          ms.State,
			Quality:        ms.Quality,
			TotalTime:      ms.TotalTime,
			SwitchInCount:  ms.SwitchInCount,
			SwitchOutCount: ms.SwitchOutCount,
			FailureCount:   ms.FailureCount,
			LastActive:     ms.LastActive,
		}
	}

	return stats
}

// HasEBPF 检查 eBPF 是否可用
func (s *Switcher) HasEBPF() bool {
	return s.hasEBPF
}

// HasFakeTCP 检查 FakeTCP 是否可用
func (s *Switcher) HasFakeTCP() bool {
	return s.hasFakeTCP
}

// HasHysteria2 检查 Hysteria2 是否可用
func (s *Switcher) HasHysteria2() bool {
	return s.hasHysteria2
}

// HasARQ 检查 ARQ 是否可用
func (s *Switcher) HasARQ() bool {
	return s.hasARQ
}

// HasWebSocket 检查 WebSocket 是否可用
func (s *Switcher) HasWebSocket() bool {
	return s.hasWebSocket
}

// GetSwitchHistory 获取切换历史
func (s *Switcher) GetSwitchHistory() []SwitchEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	history := make([]SwitchEvent, len(s.switchHistory))
	copy(history, s.switchHistory)
	return history
}

// isEBPFAvailable 检查 eBPF 是否可用
func isEBPFAvailable() bool {
	// 简化检查：实际应检查内核版本、CAP_BPF 等
	// Linux 4.15+ 且需要 root 或 CAP_BPF
	return false // 默认禁用，需要显式启用
}
