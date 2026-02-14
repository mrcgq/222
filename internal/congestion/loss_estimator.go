


// =============================================================================
// 文件: internal/congestion/loss_estimator.go
// 描述: 高精度丢包率估算器 - 多维度平滑算法
// =============================================================================
package congestion

import (
	"math"
	"sync"
	"time"
)

const (
	// EWMA 参数
	ewmaAlpha         = 0.125  // 短期 EWMA 权重 (1/8)
	ewmaBeta          = 0.25   // 长期 EWMA 权重 (1/4)
	ewmaGamma         = 0.0625 // 超长期 EWMA 权重 (1/16)
	
	// 时间窗口
	shortWindowSize   = 50     // 短期窗口：最近 50 个包
	mediumWindowSize  = 200    // 中期窗口：最近 200 个包
	longWindowSize    = 1000   // 长期窗口：最近 1000 个包
	
	// 时间衰减
	decayInterval     = 100 * time.Millisecond
	halfLifeMs        = 500.0  // 半衰期 500ms
	
	// 突发检测
	burstThreshold    = 0.3    // 30% 丢包率视为突发
	burstDecayFactor  = 0.8    // 突发后快速衰减
	
	// 稳定性检测
	stabilityWindow   = 10     // 稳定性检测窗口
	stabilityThreshold = 0.02  // 2% 变化视为稳定
)

// LossEstimator 高精度丢包率估算器
type LossEstimator struct {
	// EWMA 估算值
	ewmaShort    float64 // 短期 EWMA (快速响应)
	ewmaMedium   float64 // 中期 EWMA (平衡)
	ewmaLong     float64 // 长期 EWMA (稳定基线)
	
	// 滑动窗口
	shortWindow  *SlidingWindow
	mediumWindow *SlidingWindow
	longWindow   *SlidingWindow
	
	// 时间加权
	recentEvents []lossEventRecord
	lastDecay    time.Time
	
	// 突发检测
	burstDetector *BurstDetector
	
	// 统计
	totalSent     uint64
	totalLost     uint64
	totalAcked    uint64
	
	// 最终估算
	smoothedLoss  float64  // 平滑后的丢包率
	instantLoss   float64  // 瞬时丢包率
	trendLoss     float64  // 趋势丢包率
	
	// 置信度
	confidence    float64  // 估算置信度 [0, 1]
	sampleCount   int      // 样本数量
	
	mu sync.RWMutex
}

// lossEventRecord 丢包事件记录
type lossEventRecord struct {
	timestamp time.Time
	isLoss    bool
	bytes     int
	rtt       time.Duration
}

// SlidingWindow 滑动窗口
type SlidingWindow struct {
	size      int
	events    []bool  // true = loss, false = ack
	lossCount int
	head      int
	count     int
}

// BurstDetector 突发检测器
type BurstDetector struct {
	windowSize     int
	recentLosses   []time.Time
	burstStart     time.Time
	inBurst        bool
	burstIntensity float64
}

// NewLossEstimator 创建丢包率估算器
func NewLossEstimator() *LossEstimator {
	return &LossEstimator{
		shortWindow:   NewSlidingWindow(shortWindowSize),
		mediumWindow:  NewSlidingWindow(mediumWindowSize),
		longWindow:    NewSlidingWindow(longWindowSize),
		recentEvents:  make([]lossEventRecord, 0, 1000),
		lastDecay:     time.Now(),
		burstDetector: NewBurstDetector(20),
		confidence:    0,
	}
}

// NewSlidingWindow 创建滑动窗口
func NewSlidingWindow(size int) *SlidingWindow {
	return &SlidingWindow{
		size:   size,
		events: make([]bool, size),
	}
}

// NewBurstDetector 创建突发检测器
func NewBurstDetector(windowSize int) *BurstDetector {
	return &BurstDetector{
		windowSize:   windowSize,
		recentLosses: make([]time.Time, 0, windowSize),
	}
}

// OnPacketAcked 包确认回调
func (e *LossEstimator) OnPacketAcked(packetSize int, rtt time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	now := time.Now()
	e.totalAcked++
	e.totalSent++
	
	// 记录事件
	e.recordEvent(now, false, packetSize, rtt)
	
	// 更新滑动窗口
	e.shortWindow.Add(false)
	e.mediumWindow.Add(false)
	e.longWindow.Add(false)
	
	// 更新 EWMA
	e.updateEWMA(false)
	
	// 时间衰减
	e.applyTimeDecay(now)
	
	// 计算最终估算
	e.computeSmoothedLoss()
}

// OnPacketLost 包丢失回调
func (e *LossEstimator) OnPacketLost(packetSize int, estimatedRTT time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	now := time.Now()
	e.totalLost++
	e.totalSent++
	
	// 记录事件
	e.recordEvent(now, true, packetSize, estimatedRTT)
	
	// 更新滑动窗口
	e.shortWindow.Add(true)
	e.mediumWindow.Add(true)
	e.longWindow.Add(true)
	
	// 更新 EWMA
	e.updateEWMA(true)
	
	// 突发检测
	e.burstDetector.OnLoss(now)
	
	// 时间衰减
	e.applyTimeDecay(now)
	
	// 计算最终估算
	e.computeSmoothedLoss()
}

// recordEvent 记录事件
func (e *LossEstimator) recordEvent(t time.Time, isLoss bool, bytes int, rtt time.Duration) {
	event := lossEventRecord{
		timestamp: t,
		isLoss:    isLoss,
		bytes:     bytes,
		rtt:       rtt,
	}
	
	e.recentEvents = append(e.recentEvents, event)
	
	// 限制事件数量
	if len(e.recentEvents) > 2000 {
		e.recentEvents = e.recentEvents[len(e.recentEvents)-1000:]
	}
	
	e.sampleCount++
}

// updateEWMA 更新 EWMA 估算
func (e *LossEstimator) updateEWMA(isLoss bool) {
	sample := 0.0
	if isLoss {
		sample = 1.0
	}
	
	// 三层 EWMA
	// 短期：快速响应，alpha = 0.125
	e.ewmaShort = ewmaAlpha*sample + (1-ewmaAlpha)*e.ewmaShort
	
	// 中期：平衡响应，beta = 0.25
	e.ewmaMedium = ewmaBeta*sample + (1-ewmaBeta)*e.ewmaMedium
	
	// 长期：稳定基线，gamma = 0.0625
	e.ewmaLong = ewmaGamma*sample + (1-ewmaGamma)*e.ewmaLong
}

// applyTimeDecay 应用时间衰减
func (e *LossEstimator) applyTimeDecay(now time.Time) {
	elapsed := now.Sub(e.lastDecay)
	if elapsed < decayInterval {
		return
	}
	
	// 指数衰减因子
	// decay = 0.5^(elapsed_ms / half_life_ms)
	elapsedMs := float64(elapsed.Milliseconds())
	decay := math.Pow(0.5, elapsedMs/halfLifeMs)
	
	// 衰减旧数据的影响
	e.ewmaShort *= decay
	e.ewmaMedium *= decay
	e.ewmaLong *= decay
	
	// 清理过期事件
	cutoff := now.Add(-5 * time.Second)
	newEvents := e.recentEvents[:0]
	for _, ev := range e.recentEvents {
		if ev.timestamp.After(cutoff) {
			newEvents = append(newEvents, ev)
		}
	}
	e.recentEvents = newEvents
	
	e.lastDecay = now
}

// computeSmoothedLoss 计算平滑丢包率
func (e *LossEstimator) computeSmoothedLoss() {
	// 1. 计算瞬时丢包率（短期窗口）
	e.instantLoss = e.shortWindow.GetLossRate()
	
	// 2. 计算趋势丢包率（中长期 EWMA 加权）
	e.trendLoss = 0.6*e.ewmaMedium + 0.4*e.ewmaLong
	
	// 3. 突发调整
	burstFactor := 1.0
	if e.burstDetector.inBurst {
		// 突发期间，更重视瞬时值但加衰减
		burstFactor = e.burstDetector.burstIntensity * burstDecayFactor
	}
	
	// 4. 综合计算
	// 正常情况：瞬时 30% + EWMA短期 30% + 趋势 40%
	// 突发情况：提高瞬时权重，但加突发衰减
	var smoothed float64
	if e.burstDetector.inBurst {
		// 突发：瞬时 50% + 短期EWMA 30% + 趋势 20%，然后衰减
		smoothed = (0.5*e.instantLoss + 0.3*e.ewmaShort + 0.2*e.trendLoss) * burstFactor
	} else {
		// 正常：平衡加权
		smoothed = 0.3*e.instantLoss + 0.3*e.ewmaShort + 0.4*e.trendLoss
	}
	
	// 5. 滑动窗口验证
	// 如果滑动窗口估算与 EWMA 差距过大，倾向于滑动窗口
	windowLoss := e.mediumWindow.GetLossRate()
	diff := math.Abs(smoothed - windowLoss)
	if diff > 0.1 && e.sampleCount > 100 {
		// 差距大时，混合两者
		smoothed = 0.6*smoothed + 0.4*windowLoss
	}
	
	// 6. 置信度加权
	e.updateConfidence()
	if e.confidence < 0.5 {
		// 低置信度时更保守
		smoothed = math.Max(smoothed, e.longWindow.GetLossRate())
	}
	
	// 7. 边界限制
	e.smoothedLoss = math.Max(0, math.Min(1, smoothed))
}

// updateConfidence 更新置信度
func (e *LossEstimator) updateConfidence() {
	// 基于样本数量的置信度
	sampleConfidence := math.Min(float64(e.sampleCount)/100.0, 1.0)
	
	// 基于稳定性的置信度
	stabilityConfidence := e.computeStability()
	
	// 综合置信度
	e.confidence = 0.6*sampleConfidence + 0.4*stabilityConfidence
}

// computeStability 计算稳定性
func (e *LossEstimator) computeStability() float64 {
	if len(e.recentEvents) < stabilityWindow {
		return 0.5
	}
	
	// 计算最近窗口内的丢包率变化
	recent := e.recentEvents[len(e.recentEvents)-stabilityWindow:]
	
	var lossCount int
	for _, ev := range recent {
		if ev.isLoss {
			lossCount++
		}
	}
	
	recentRate := float64(lossCount) / float64(len(recent))
	variance := math.Abs(recentRate - e.smoothedLoss)
	
	// 变化小 = 高稳定性
	stability := 1.0 - math.Min(variance/0.2, 1.0)
	return stability
}

// GetLossRate 获取平滑丢包率
func (e *LossEstimator) GetLossRate() float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.smoothedLoss
}

// GetInstantLossRate 获取瞬时丢包率
func (e *LossEstimator) GetInstantLossRate() float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.instantLoss
}

// GetTrendLossRate 获取趋势丢包率
func (e *LossEstimator) GetTrendLossRate() float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.trendLoss
}

// GetConfidence 获取置信度
func (e *LossEstimator) GetConfidence() float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.confidence
}

// IsInBurst 是否处于突发丢包
func (e *LossEstimator) IsInBurst() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.burstDetector.inBurst
}

// GetStats 获取统计信息
func (e *LossEstimator) GetStats() LossStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	return LossStats{
		SmoothedLoss:   e.smoothedLoss,
		InstantLoss:    e.instantLoss,
		TrendLoss:      e.trendLoss,
		EWMAShort:      e.ewmaShort,
		EWMAMedium:     e.ewmaMedium,
		EWMALong:       e.ewmaLong,
		ShortWindow:    e.shortWindow.GetLossRate(),
		MediumWindow:   e.mediumWindow.GetLossRate(),
		LongWindow:     e.longWindow.GetLossRate(),
		Confidence:     e.confidence,
		SampleCount:    e.sampleCount,
		TotalSent:      e.totalSent,
		TotalLost:      e.totalLost,
		InBurst:        e.burstDetector.inBurst,
		BurstIntensity: e.burstDetector.burstIntensity,
	}
}

// Reset 重置
func (e *LossEstimator) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	e.ewmaShort = 0
	e.ewmaMedium = 0
	e.ewmaLong = 0
	e.shortWindow = NewSlidingWindow(shortWindowSize)
	e.mediumWindow = NewSlidingWindow(mediumWindowSize)
	e.longWindow = NewSlidingWindow(longWindowSize)
	e.recentEvents = e.recentEvents[:0]
	e.lastDecay = time.Now()
	e.burstDetector = NewBurstDetector(20)
	e.totalSent = 0
	e.totalLost = 0
	e.totalAcked = 0
	e.smoothedLoss = 0
	e.instantLoss = 0
	e.trendLoss = 0
	e.confidence = 0
	e.sampleCount = 0
}

// LossStats 丢包统计
type LossStats struct {
	SmoothedLoss   float64
	InstantLoss    float64
	TrendLoss      float64
	EWMAShort      float64
	EWMAMedium     float64
	EWMALong       float64
	ShortWindow    float64
	MediumWindow   float64
	LongWindow     float64
	Confidence     float64
	SampleCount    int
	TotalSent      uint64
	TotalLost      uint64
	InBurst        bool
	BurstIntensity float64
}

// ================== SlidingWindow 方法 ==================

// Add 添加事件
func (w *SlidingWindow) Add(isLoss bool) {
	if w.count >= w.size {
		// 移除最旧的
		oldIdx := (w.head - w.size + w.size) % w.size
		if w.events[oldIdx] {
			w.lossCount--
		}
	}
	
	w.events[w.head] = isLoss
	if isLoss {
		w.lossCount++
	}
	
	w.head = (w.head + 1) % w.size
	if w.count < w.size {
		w.count++
	}
}

// GetLossRate 获取丢包率
func (w *SlidingWindow) GetLossRate() float64 {
	if w.count == 0 {
		return 0
	}
	return float64(w.lossCount) / float64(w.count)
}

// ================== BurstDetector 方法 ==================

// OnLoss 丢包事件
func (b *BurstDetector) OnLoss(t time.Time) {
	// 清理过期记录
	cutoff := t.Add(-500 * time.Millisecond)
	newLosses := b.recentLosses[:0]
	for _, lt := range b.recentLosses {
		if lt.After(cutoff) {
			newLosses = append(newLosses, lt)
		}
	}
	b.recentLosses = newLosses
	
	// 添加新丢包
	b.recentLosses = append(b.recentLosses, t)
	
	// 检测突发
	if len(b.recentLosses) >= b.windowSize/2 {
		if !b.inBurst {
			b.inBurst = true
			b.burstStart = t
		}
		// 突发强度：短时间内丢包数 / 阈值
		b.burstIntensity = float64(len(b.recentLosses)) / float64(b.windowSize)
	} else {
		// 突发结束
		if b.inBurst && t.Sub(b.burstStart) > time.Second {
			b.inBurst = false
			b.burstIntensity = 0
		}
	}
}



