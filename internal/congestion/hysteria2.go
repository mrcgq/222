


// =============================================================================
// 文件: internal/congestion/hysteria2.go
// 描述: Hysteria2 风格拥塞控制算法 - 完整实现
// =============================================================================
package congestion

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// 初始参数
	defaultInitialWindow = 32    // 初始窗口 (包数)
	defaultMaxWindow     = 512   // 最大窗口 (包数)
	defaultMinWindow     = 4     // 最小窗口 (包数)
	defaultMSS           = 1200  // 最大分段大小

	// Brutal 模式参数
	brutalMinRTT         = 10 * time.Millisecond
	brutalMaxRTT         = 500 * time.Millisecond
	brutalLossThreshold  = 0.30  // 30% 丢包率退出 brutal
	brutalRTTMultiplier  = 3.0   // RTT 超过最小 RTT 的 3 倍退出

	// 拥塞恢复参数
	recoveryLossThreshold  = 0.10 // 10% 丢包进入恢复
	slowStartLossThreshold = 0.02 // 2% 丢包退出慢启动
	
	// 窗口调整参数
	windowGainFactor    = 1.25  // 窗口增长因子
	windowLossFactor    = 0.7   // 窗口减少因子
	probeRTTDuration    = 200 * time.Millisecond
	probeRTTInterval    = 10 * time.Second
)

// Hysteria2Controller Hysteria2 拥塞控制器
type Hysteria2Controller struct {
	// 配置
	maxBandwidth float64 // 配置的最大带宽 (bytes/s)
	mss          int     // 最大分段大小

	// 窗口控制
	cwnd        float64 // 拥塞窗口 (bytes)
	maxWindow   float64 // 最大窗口
	minWindow   float64 // 最小窗口
	ssthresh    float64 // 慢启动阈值
	
	// 在途数据
	inFlight    int64   // 在途字节数

	// RTT 估算器
	rttEstimator *RTTEstimator

	// 带宽估算器
	bwEstimator *BandwidthEstimator

	// Pacer
	pacer *Pacer

	// 丢包追踪
	lostPackets    uint64
	totalPackets   uint64
	lossRate       float64
	lastLossUpdate time.Time
	recentLosses   []lossEvent

	// Brutal 模式
	brutalMode bool
	brutalRate float64

	// 状态
	state           CongestionState
	inRecovery      bool
	recoveryStart   time.Time
	recoverySeq     uint64
	lastProbeRTT    time.Time
	
	// 数据包追踪
	nextPacketNum   uint64
	largestAcked    uint64
	largestSent     uint64
	packets         sync.Map // packetNum -> *PacketInfo

	// 交付追踪
	deliveredBytes  int64
	deliveredTime   time.Time

	// 时间追踪
	lastSendTime time.Time
	lastAckTime  time.Time
	cycleStart   time.Time

	mu sync.RWMutex
}

type lossEvent struct {
	timestamp time.Time
	lostBytes int
}

// NewHysteria2Controller 创建 Hysteria2 控制器
func NewHysteria2Controller(upMbps, downMbps int) *Hysteria2Controller {
	maxBw := float64(max(upMbps, downMbps)) * 1024 * 1024 / 8

	initialCwnd := float64(defaultInitialWindow) * defaultMSS
	
	c := &Hysteria2Controller{
		maxBandwidth:  maxBw,
		mss:           defaultMSS,
		cwnd:          initialCwnd,
		maxWindow:     float64(defaultMaxWindow) * defaultMSS,
		minWindow:     float64(defaultMinWindow) * defaultMSS,
		ssthresh:      float64(defaultMaxWindow) * defaultMSS,
		rttEstimator:  NewRTTEstimator(),
		bwEstimator:   NewBandwidthEstimator(max(upMbps, downMbps)),
		pacer:         NewPacer(maxBw, defaultMSS),
		brutalMode:    true,
		brutalRate:    maxBw * 0.9,
		state:         StateSlowStart,
		recentLosses:  make([]lossEvent, 0, 100),
		cycleStart:    time.Now(),
		lastProbeRTT:  time.Now(),
		nextPacketNum: 1,
	}

	// 设置 pacer 最大速率
	c.pacer.SetMaxRate(maxBw)
	c.pacer.SetPacingRate(maxBw * 0.9)

	return c
}

// GetCongestionWindow 获取拥塞窗口
func (c *Hysteria2Controller) GetCongestionWindow() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if c.brutalMode {
		// Brutal 模式下使用更大的窗口
		return int(c.maxWindow)
	}
	return int(c.cwnd)
}

// CanSend 检查是否可以发送
func (c *Hysteria2Controller) CanSend(packetSize int) bool {
	c.mu.RLock()
	inFlight := atomic.LoadInt64(&c.inFlight)
	brutal := c.brutalMode
	cwnd := c.cwnd
	maxWnd := c.maxWindow
	c.mu.RUnlock()

	// Brutal 模式下更宽松
	if brutal {
		return inFlight+int64(packetSize) <= int64(maxWnd*2)
	}

	// 正常模式检查窗口
	if inFlight+int64(packetSize) > int64(cwnd) {
		return false
	}

	// 检查 pacer
	return c.pacer.CanSend(packetSize)
}

// OnPacketSent 数据包发送回调
func (c *Hysteria2Controller) OnPacketSent(packetNumber uint64, packetSize int, isRetransmit bool) {
	atomic.AddInt64(&c.inFlight, int64(packetSize))
	atomic.AddUint64(&c.totalPackets, 1)

	c.mu.Lock()
	now := time.Now()
	c.lastSendTime = now
	
	if packetNumber > c.largestSent {
		c.largestSent = packetNumber
	}
	
	// 记录包信息
	info := &PacketInfo{
		PacketNumber:   packetNumber,
		Size:           packetSize,
		SentTime:       now,
		IsRetransmit:   isRetransmit,
		InFlight:       true,
		DeliveredBytes: c.deliveredBytes,
		DeliveredTime:  c.deliveredTime,
	}
	c.packets.Store(packetNumber, info)
	c.mu.Unlock()

	// 通知 pacer
	c.pacer.OnPacketSent(packetSize)
	
	// 更新带宽估算器
	if !isRetransmit {
		c.bwEstimator.AddDelivered(int64(packetSize))
	}
}

// OnPacketAcked ACK 回调
func (c *Hysteria2Controller) OnPacketAcked(packetNumber uint64, ackedBytes int, rtt time.Duration) {
	atomic.AddInt64(&c.inFlight, -int64(ackedBytes))

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	
	// 更新 RTT
	if rtt > 0 {
		c.rttEstimator.Update(rtt, 0)
	}

	// 更新交付信息
	c.deliveredBytes += int64(ackedBytes)
	c.deliveredTime = now

	// 获取包信息
	if infoI, ok := c.packets.Load(packetNumber); ok {
		info := infoI.(*PacketInfo)
		info.Acked = true
		info.InFlight = false
		
		// 更新带宽估算
		if !info.IsRetransmit && rtt > 0 {
			c.bwEstimator.OnPacketDelivered(
				c.deliveredBytes,
				now,
				info.SentTime,
				rtt,
				false,
			)
		}
		
		c.packets.Delete(packetNumber)
	}

	// 更新最大确认
	if packetNumber > c.largestAcked {
		c.largestAcked = packetNumber
	}

	// 检查是否退出恢复
	if c.inRecovery && packetNumber >= c.recoverySeq {
		c.inRecovery = false
	}

	c.lastAckTime = now

	// 调整窗口
	c.adjustWindow(ackedBytes, rtt)
}

// OnPacketLost 丢包回调
func (c *Hysteria2Controller) OnPacketLost(packetNumber uint64, lostBytes int) {
	atomic.AddInt64(&c.inFlight, -int64(lostBytes))
	atomic.AddUint64(&c.lostPackets, 1)

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// 记录丢包事件
	c.recentLosses = append(c.recentLosses, lossEvent{
		timestamp: now,
		lostBytes: lostBytes,
	})
	
	// 清理旧的丢包记录 (保留最近 10 秒)
	cutoff := now.Add(-10 * time.Second)
	newLosses := c.recentLosses[:0]
	for _, l := range c.recentLosses {
		if l.timestamp.After(cutoff) {
			newLosses = append(newLosses, l)
		}
	}
	c.recentLosses = newLosses

	// 更新丢包率
	c.updateLossRate()

	// 更新包状态
	if infoI, ok := c.packets.Load(packetNumber); ok {
		info := infoI.(*PacketInfo)
		info.Lost = true
		info.InFlight = false
		c.packets.Delete(packetNumber)
	}

	// 处理拥塞
	c.onCongestionEvent(now, lostBytes)
}

// OnCongestionEvent 拥塞事件回调
func (c *Hysteria2Controller) OnCongestionEvent(eventTime time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onCongestionEvent(eventTime, 0)
}

// onCongestionEvent 内部拥塞处理
func (c *Hysteria2Controller) onCongestionEvent(eventTime time.Time, lostBytes int) {
	// Brutal 模式特殊处理
	if c.brutalMode {
		// 只有在极端丢包时才退出 brutal 模式
		if c.lossRate > brutalLossThreshold {
			c.brutalMode = false
			c.state = StateRecovery
			c.cwnd = math.Max(c.cwnd*windowLossFactor, c.minWindow)
			c.ssthresh = c.cwnd
			c.inRecovery = true
			c.recoveryStart = eventTime
			c.recoverySeq = c.largestSent + 1
			return
		}

		// RTT 暴涨也退出
		minRTT := c.rttEstimator.GetMinRTT()
		latestRTT := c.rttEstimator.GetLatestRTT()
		if minRTT > 0 && latestRTT > time.Duration(float64(minRTT)*brutalRTTMultiplier) {
			c.brutalMode = false
			c.state = StateRecovery
		}
		return
	}

	// 普通模式的拥塞处理
	if !c.inRecovery {
		c.inRecovery = true
		c.recoveryStart = eventTime
		c.recoverySeq = c.largestSent + 1

		// 根据状态调整窗口
		switch c.state {
		case StateSlowStart:
			c.ssthresh = c.cwnd / 2
			c.cwnd = c.ssthresh
			c.state = StateRecovery

		case StateCongestionAvoidance, StateProbeBW:
			c.cwnd = math.Max(c.cwnd*windowLossFactor, c.minWindow)
			c.ssthresh = c.cwnd
			c.state = StateRecovery
		}
	}
}

// adjustWindow 调整窗口
func (c *Hysteria2Controller) adjustWindow(ackedBytes int, rtt time.Duration) {
	if c.brutalMode {
		c.brutalModeAdjust(rtt)
		return
	}

	// 检查是否可以恢复 brutal 模式
	if c.maybeEnterBrutalMode() {
		return
	}

	// 根据状态调整
	switch c.state {
	case StateSlowStart:
		c.slowStartAdjust(ackedBytes)

	case StateCongestionAvoidance:
		c.congestionAvoidanceAdjust(ackedBytes)

	case StateRecovery:
		c.recoveryAdjust(ackedBytes)

	case StateProbeBW:
		c.probeBWAdjust(ackedBytes)
	}

	// 检查是否需要 ProbeRTT
	c.maybeProbeRTT()
}

// brutalModeAdjust Brutal 模式调整
func (c *Hysteria2Controller) brutalModeAdjust(rtt time.Duration) {
	minRTT := c.rttEstimator.GetMinRTT()
	
	// 只要没有严重问题就继续激进发送
	if rtt < brutalMaxRTT && c.lossRate < 0.15 {
		// 激进增长窗口
		c.cwnd = math.Min(c.cwnd*1.05, c.maxWindow)
		
		// 增加 brutal 速率
		c.brutalRate = math.Min(c.brutalRate*1.02, c.maxBandwidth)
		
		// 更新 pacer
		c.pacer.SetPacingRate(c.brutalRate)
	} else if rtt > time.Duration(float64(minRTT)*2) {
		// RTT 增长过快，略微减速
		c.brutalRate = math.Max(c.brutalRate*0.95, c.maxBandwidth*0.5)
		c.pacer.SetPacingRate(c.brutalRate)
	}
}

// maybeEnterBrutalMode 检查是否可以进入 brutal 模式
func (c *Hysteria2Controller) maybeEnterBrutalMode() bool {
	// 条件：丢包率低、RTT 稳定
	if c.lossRate < 0.03 {
		minRTT := c.rttEstimator.GetMinRTT()
		latestRTT := c.rttEstimator.GetLatestRTT()
		
		if minRTT > 0 && latestRTT < time.Duration(float64(minRTT)*1.5) {
			c.brutalMode = true
			c.brutalRate = c.maxBandwidth * 0.8
			c.state = StateProbeBW
			c.pacer.SetPacingRate(c.brutalRate)
			return true
		}
	}
	return false
}

// slowStartAdjust 慢启动调整
func (c *Hysteria2Controller) slowStartAdjust(ackedBytes int) {
	// 指数增长
	c.cwnd += float64(ackedBytes)
	
	// 检查是否退出慢启动
	if c.cwnd >= c.ssthresh {
		c.state = StateCongestionAvoidance
	}
	
	// 丢包退出慢启动
	if c.lossRate > slowStartLossThreshold {
		c.ssthresh = c.cwnd / 2
		c.state = StateCongestionAvoidance
	}
	
	c.cwnd = math.Min(c.cwnd, c.maxWindow)
}

// congestionAvoidanceAdjust 拥塞避免调整
func (c *Hysteria2Controller) congestionAvoidanceAdjust(ackedBytes int) {
	// AIMD: 每个 RTT 增加约 1 MSS
	increment := float64(c.mss) * float64(ackedBytes) / c.cwnd
	c.cwnd += increment
	c.cwnd = math.Min(c.cwnd, c.maxWindow)
}

// recoveryAdjust 恢复阶段调整
func (c *Hysteria2Controller) recoveryAdjust(ackedBytes int) {
	// 快速恢复
	if !c.inRecovery {
		c.state = StateCongestionAvoidance
		return
	}
	
	// PRR: 适度增长
	c.cwnd += float64(ackedBytes) * 0.5
}

// probeBWAdjust 带宽探测调整
func (c *Hysteria2Controller) probeBWAdjust(ackedBytes int) {
	// 使用估算的带宽 * RTT 计算目标窗口
	bw := c.bwEstimator.GetBandwidth()
	minRTT := c.rttEstimator.GetMinRTT()
	
	if bw > 0 && minRTT > 0 {
		bdp := bw * minRTT.Seconds()
		targetCwnd := bdp * windowGainFactor
		
		// 渐进调整
		if targetCwnd > c.cwnd {
			c.cwnd += float64(c.mss)
		} else if targetCwnd < c.cwnd*0.9 {
			c.cwnd = math.Max(c.cwnd*0.99, targetCwnd)
		}
	}
	
	c.cwnd = math.Max(c.cwnd, c.minWindow)
	c.cwnd = math.Min(c.cwnd, c.maxWindow)
}

// maybeProbeRTT 检查是否需要探测 RTT
func (c *Hysteria2Controller) maybeProbeRTT() {
	if time.Since(c.lastProbeRTT) < probeRTTInterval {
		return
	}
	
	// 进入 ProbeRTT 阶段
	c.state = StateProbeRTT
	c.lastProbeRTT = time.Now()
	
	// 降低窗口到最小值来测量真实 RTT
	oldCwnd := c.cwnd
	c.cwnd = c.minWindow
	
	// 一段时间后恢复
	go func() {
		time.Sleep(probeRTTDuration)
		c.mu.Lock()
		if c.state == StateProbeRTT {
			c.cwnd = oldCwnd
			c.state = StateProbeBW
		}
		c.mu.Unlock()
	}()
}

// updateLossRate 更新丢包率
func (c *Hysteria2Controller) updateLossRate() {
	total := atomic.LoadUint64(&c.totalPackets)
	lost := atomic.LoadUint64(&c.lostPackets)

	if total > 0 {
		c.lossRate = float64(lost) / float64(total)
	}

	// 定期重置计数器（滑动窗口效果）
	now := time.Now()
	if now.Sub(c.lastLossUpdate) > 10*time.Second {
		// 保留最近的统计
		atomic.StoreUint64(&c.totalPackets, total/2)
		atomic.StoreUint64(&c.lostPackets, lost/2)
		c.lastLossUpdate = now
	}
}

// GetPacingRate 获取 pacing 速率
func (c *Hysteria2Controller) GetPacingRate() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if c.brutalMode {
		return c.brutalRate
	}
	return c.pacer.GetPacingRate()
}

// GetPacingInterval 获取发包间隔
func (c *Hysteria2Controller) GetPacingInterval(packetSize int) time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if c.brutalMode {
		if c.brutalRate <= 0 {
			return time.Millisecond
		}
		return time.Duration(float64(packetSize) / c.brutalRate * float64(time.Second))
	}
	
	return c.pacer.GetPacingInterval(packetSize)
}

// GetRTT 获取 RTT
func (c *Hysteria2Controller) GetRTT() time.Duration {
	return c.rttEstimator.GetSmoothedRTT()
}

// GetMinRTT 获取最小 RTT
func (c *Hysteria2Controller) GetMinRTT() time.Duration {
	return c.rttEstimator.GetMinRTT()
}

// GetLatestRTT 获取最新 RTT
func (c *Hysteria2Controller) GetLatestRTT() time.Duration {
	return c.rttEstimator.GetLatestRTT()
}

// GetLossRate 获取丢包率
func (c *Hysteria2Controller) GetLossRate() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lossRate
}

// GetBandwidth 获取估算带宽
func (c *Hysteria2Controller) GetBandwidth() float64 {
	return c.bwEstimator.GetBandwidth()
}

// SetBrutalMode 设置 Brutal 模式
func (c *Hysteria2Controller) SetBrutalMode(enabled bool, rateMbps int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.brutalMode = enabled
	if rateMbps > 0 {
		c.brutalRate = float64(rateMbps) * 1024 * 1024 / 8
	}
	
	if enabled {
		c.state = StateProbeBW
		c.pacer.SetPacingRate(c.brutalRate)
	}
}

// IsBrutalMode 是否 Brutal 模式
func (c *Hysteria2Controller) IsBrutalMode() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.brutalMode
}

// GetStats 获取统计
func (c *Hysteria2Controller) GetStats() *CongestionStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return &CongestionStats{
		CongestionWindow: int64(c.cwnd),
		BytesInFlight:    atomic.LoadInt64(&c.inFlight),
		MaxWindow:        int64(c.maxWindow),
		MinWindow:        int64(c.minWindow),
		
		SmoothedRTT: c.rttEstimator.GetSmoothedRTT(),
		MinRTT:      c.rttEstimator.GetMinRTT(),
		LatestRTT:   c.rttEstimator.GetLatestRTT(),
		RTTVariance: c.rttEstimator.GetRTTVariance(),
		
		Bandwidth:     c.bwEstimator.GetBandwidth(),
		PacingRate:    c.pacer.GetPacingRate(),
		DeliveryRate:  c.bwEstimator.GetBandwidth(),
		BandwidthMbps: c.bwEstimator.GetBandwidth() * 8 / 1024 / 1024,
		
		LossRate:       c.lossRate,
		TotalPackets:   atomic.LoadUint64(&c.totalPackets),
		LostPackets:    atomic.LoadUint64(&c.lostPackets),
		
		BrutalMode: c.brutalMode,
		BrutalRate: c.brutalRate,
		
		State:         c.state.String(),
		SlowStartExit: c.state != StateSlowStart,
		InRecovery:    c.inRecovery,
	}
}

// Reset 重置
func (c *Hysteria2Controller) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cwnd = float64(defaultInitialWindow) * float64(c.mss)
	c.ssthresh = c.maxWindow
	atomic.StoreInt64(&c.inFlight, 0)
	
	c.rttEstimator.Reset()
	c.bwEstimator.Reset()
	c.pacer.Reset()
	
	c.lossRate = 0
	c.recentLosses = c.recentLosses[:0]
	
	c.brutalMode = true
	c.brutalRate = c.maxBandwidth * 0.9
	
	c.state = StateSlowStart
	c.inRecovery = false
	
	c.nextPacketNum = 1
	c.largestAcked = 0
	c.largestSent = 0
	c.packets = sync.Map{}
	
	c.deliveredBytes = 0
	c.cycleStart = time.Now()
	c.lastProbeRTT = time.Now()

	atomic.StoreUint64(&c.totalPackets, 0)
	atomic.StoreUint64(&c.lostPackets, 0)
}

// NextPacketNumber 获取下一个包号
func (c *Hysteria2Controller) NextPacketNumber() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	num := c.nextPacketNum
	c.nextPacketNum++
	return num
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}



