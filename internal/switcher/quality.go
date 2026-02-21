// =============================================================================
// 文件: internal/switcher/quality.go
// 描述: 智能链路切换 - 链路质量检测
// =============================================================================
package switcher

import (
	"math"
	"sync"
	"time"
)

const (
	// 采样窗口
	rttSampleWindow  = 20
	lossSampleWindow = 100
	throughputWindow = 10 * time.Second

	// 评分权重
	rttWeight        = 0.35
	lossWeight       = 0.35
	throughputWeight = 0.20
	stabilityWeight  = 0.10

	// EWMA 因子
	ewmaAlpha = 0.3
)

// QualityMonitor 链路质量监控器
type QualityMonitor struct {
	mode TransportMode

	// RTT 采样
	rttSamples []time.Duration
	rttIndex   int
	rttCount   int
	rttSum     time.Duration
	minRTT     time.Duration
	maxRTT     time.Duration

	// 丢包采样 (滑动窗口)
	lossBitmap   []bool
	lossIndex    int
	lossCount    int
	recentLosses int

	// 吞吐量采样
	throughputSamples []throughputSample
	lastBytesRecv     int64
	lastBytesTime     time.Time

	// 连接统计
	activeConns int
	totalConns  uint64
	failedConns uint64

	// 连续成功/失败
	consecutiveSuccesses int
	consecutiveFailures  int

	// 最后事件时间
	lastSuccess time.Time
	lastFailure time.Time
	lastUpdate  time.Time

	// 评分
	currentScore float64
	scoreHistory []float64

	mu sync.RWMutex
}

type throughputSample struct {
	bytes     int64
	duration  time.Duration
	timestamp time.Time
}

// NewQualityMonitor 创建质量监控器
func NewQualityMonitor(mode TransportMode) *QualityMonitor {
	return &QualityMonitor{
		mode:              mode,
		rttSamples:        make([]time.Duration, rttSampleWindow),
		lossBitmap:        make([]bool, lossSampleWindow),
		throughputSamples: make([]throughputSample, 0, 100),
		scoreHistory:      make([]float64, 0, 100),
		lastUpdate:        time.Now(),
	}
}

// RecordRTT 记录 RTT 采样
func (m *QualityMonitor) RecordRTT(rtt time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if rtt <= 0 {
		return
	}

	// 更新采样数组
	m.rttSamples[m.rttIndex] = rtt
	m.rttIndex = (m.rttIndex + 1) % rttSampleWindow
	if m.rttCount < rttSampleWindow {
		m.rttCount++
	}

	// 更新统计
	m.rttSum += rtt
	if m.minRTT == 0 || rtt < m.minRTT {
		m.minRTT = rtt
	}
	if rtt > m.maxRTT {
		m.maxRTT = rtt
	}

	m.lastSuccess = time.Now()
	m.consecutiveSuccesses++
	m.consecutiveFailures = 0
	m.lastUpdate = time.Now()
}

// RecordPacket 记录数据包 (成功/丢失)
func (m *QualityMonitor) RecordPacket(success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 更新丢包位图
	oldValue := m.lossBitmap[m.lossIndex]
	m.lossBitmap[m.lossIndex] = !success
	m.lossIndex = (m.lossIndex + 1) % lossSampleWindow

	if m.lossCount < lossSampleWindow {
		m.lossCount++
	}

	// 更新最近丢包计数
	if !success && !oldValue {
		m.recentLosses++
	} else if success && oldValue {
		m.recentLosses--
	} else if !success {
		m.recentLosses++
	}

	// 更新连续计数
	if success {
		m.consecutiveSuccesses++
		m.consecutiveFailures = 0
		m.lastSuccess = time.Now()
	} else {
		m.consecutiveFailures++
		m.consecutiveSuccesses = 0
		m.lastFailure = time.Now()
	}

	m.lastUpdate = time.Now()
}

// RecordBytes 记录字节数 (用于吞吐量计算)
func (m *QualityMonitor) RecordBytes(bytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if !m.lastBytesTime.IsZero() {
		duration := now.Sub(m.lastBytesTime)
		if duration > 0 {
			sample := throughputSample{
				bytes:     bytes - m.lastBytesRecv,
				duration:  duration,
				timestamp: now,
			}
			m.throughputSamples = append(m.throughputSamples, sample)

			// 清理过期采样
			cutoff := now.Add(-throughputWindow)
			newSamples := m.throughputSamples[:0]
			for _, s := range m.throughputSamples {
				if s.timestamp.After(cutoff) {
					newSamples = append(newSamples, s)
				}
			}
			m.throughputSamples = newSamples
		}
	}

	m.lastBytesRecv = bytes
	m.lastBytesTime = now
	m.lastUpdate = now
}

// RecordConnection 记录连接事件
func (m *QualityMonitor) RecordConnection(success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.totalConns++
	if success {
		m.activeConns++
	} else {
		m.failedConns++
		m.consecutiveFailures++
		m.consecutiveSuccesses = 0
		m.lastFailure = time.Now()
	}
	m.lastUpdate = time.Now()
}

// RecordDisconnection 记录断开连接
func (m *QualityMonitor) RecordDisconnection() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.activeConns > 0 {
		m.activeConns--
	}
	m.lastUpdate = time.Now()
}

// GetQuality 获取链路质量（返回 *LinkQualityMetrics）
func (m *QualityMonitor) GetQuality() *LinkQualityMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 计算平均 RTT
	var avgRTT time.Duration
	var rttJitter time.Duration
	if m.rttCount > 0 {
		var sum time.Duration
		for i := 0; i < m.rttCount; i++ {
			sum += m.rttSamples[i]
		}
		avgRTT = sum / time.Duration(m.rttCount)

		// 计算 RTT 抖动 (标准差)
		var variance float64
		avgNs := float64(avgRTT.Nanoseconds())
		for i := 0; i < m.rttCount; i++ {
			diff := float64(m.rttSamples[i].Nanoseconds()) - avgNs
			variance += diff * diff
		}
		rttJitter = time.Duration(math.Sqrt(variance / float64(m.rttCount)))
	}

	// 计算丢包率
	var lossRate float64
	if m.lossCount > 0 {
		lossRate = float64(m.recentLosses) / float64(m.lossCount)
	}

	// 计算吞吐量
	var throughput float64
	var peakThroughput float64
	if len(m.throughputSamples) > 0 {
		var totalBytes int64
		var totalDuration time.Duration
		for _, s := range m.throughputSamples {
			totalBytes += s.bytes
			totalDuration += s.duration
		}
		if totalDuration > 0 {
			throughput = float64(totalBytes) / totalDuration.Seconds()
		}

		// 峰值吞吐量
		for _, s := range m.throughputSamples {
			if s.duration > 0 {
				tp := float64(s.bytes) / s.duration.Seconds()
				if tp > peakThroughput {
					peakThroughput = tp
				}
			}
		}
	}

	// 计算可用性
	available := m.consecutiveFailures < 5 &&
		(m.lastSuccess.IsZero() || time.Since(m.lastSuccess) < 30*time.Second)

	var state LinkState
	if available {
		state = StateRunning
	} else if m.consecutiveFailures > 0 {
		state = StateDegraded
	} else {
		state = StateUnknown
	}

	// 构建 LinkQualityMetrics（只使用已定义的字段）
	q := &LinkQualityMetrics{
		RTT:                  avgRTT,
		LossRate:             lossRate,
		Throughput:           throughput,
		Available:            available,
		State:                state,
		Score:                0, // 稍后计算
		LastSuccess:          m.lastSuccess,
		LastFailure:          m.lastFailure,
		ConsecutiveFailures:  m.consecutiveFailures,
		ConsecutiveSuccesses: m.consecutiveSuccesses,
		RecentLosses:         m.recentLosses,
		TotalLosses:          uint64(m.recentLosses),
		TotalPackets:         uint64(m.lossCount),
		AvgThroughput:        throughput,
		PeakThroughput:       peakThroughput,
	}

	// 计算评分
	q.Score = m.calculateScoreInternal(avgRTT, lossRate, throughput, rttJitter)

	return q
}

// calculateScoreInternal 内部计算评分方法 (0-100)
func (m *QualityMonitor) calculateScoreInternal(avgRTT time.Duration, lossRate, throughput float64, rttJitter time.Duration) float64 {
	var score float64 = 100

	// RTT 评分 (越低越好)
	if avgRTT > 0 {
		rttMs := float64(avgRTT.Milliseconds())
		rttScore := 100 - math.Min(rttMs/5, 100) // 500ms 以上得 0 分
		score = score*rttWeight + rttScore*(1-rttWeight)
	}

	// 丢包率评分 (越低越好)
	lossScore := 100 * (1 - math.Min(lossRate*10, 1)) // 10% 以上得 0 分
	score = score*(1-lossWeight) + lossScore*lossWeight

	// 吞吐量评分
	if throughput > 0 {
		// 假设 10 MB/s 为满分
		tpScore := math.Min(throughput/(10*1024*1024)*100, 100)
		score = score*(1-throughputWeight) + tpScore*throughputWeight
	}

	// 稳定性评分
	stabilityScore := 100.0
	if m.consecutiveFailures > 0 {
		stabilityScore -= float64(m.consecutiveFailures) * 20
	}
	if rttJitter > 50*time.Millisecond {
		stabilityScore -= float64(rttJitter.Milliseconds()) / 10
	}
	stabilityScore = math.Max(stabilityScore, 0)
	score = score*(1-stabilityWeight) + stabilityScore*stabilityWeight

	// 保存评分历史
	m.currentScore = score
	m.scoreHistory = append(m.scoreHistory, score)
	if len(m.scoreHistory) > 100 {
		m.scoreHistory = m.scoreHistory[1:]
	}

	return math.Max(0, math.Min(100, score))
}

// GetScore 获取当前评分
func (m *QualityMonitor) GetScore() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentScore
}

// GetScoreTrend 获取评分趋势 (-1: 下降, 0: 稳定, 1: 上升)
func (m *QualityMonitor) GetScoreTrend() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.scoreHistory) < 10 {
		return 0
	}

	// 比较最近 5 个和之前 5 个的平均值
	recent := m.scoreHistory[len(m.scoreHistory)-5:]
	older := m.scoreHistory[len(m.scoreHistory)-10 : len(m.scoreHistory)-5]

	var recentSum, olderSum float64
	for _, s := range recent {
		recentSum += s
	}
	for _, s := range older {
		olderSum += s
	}

	recentAvg := recentSum / 5
	olderAvg := olderSum / 5

	diff := recentAvg - olderAvg
	if diff > 5 {
		return 1
	} else if diff < -5 {
		return -1
	}
	return 0
}

// Reset 重置统计
func (m *QualityMonitor) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.rttSamples = make([]time.Duration, rttSampleWindow)
	m.rttIndex = 0
	m.rttCount = 0
	m.rttSum = 0
	m.minRTT = 0
	m.maxRTT = 0

	m.lossBitmap = make([]bool, lossSampleWindow)
	m.lossIndex = 0
	m.lossCount = 0
	m.recentLosses = 0

	m.throughputSamples = m.throughputSamples[:0]
	m.lastBytesRecv = 0
	m.lastBytesTime = time.Time{}

	m.activeConns = 0
	m.consecutiveSuccesses = 0
	m.consecutiveFailures = 0

	m.currentScore = 0
	m.scoreHistory = m.scoreHistory[:0]

	m.lastUpdate = time.Now()
}
