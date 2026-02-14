

// =============================================================================
// 文件: internal/congestion/rtt.go
// 描述: RTT 测量与估算 (RFC 6298)
// =============================================================================
package congestion

import (
	"sync"
	"time"
)

const (
	// RTT 常量
	rttAlpha       = 0.125 // SRTT 平滑因子 (1/8)
	rttBeta        = 0.25  // RTT 方差因子 (1/4)
	defaultInitRTT = 100 * time.Millisecond
	minRTTWindow   = 10 * time.Second // 最小 RTT 窗口
	rttSampleSize  = 50               // RTT 采样数量
)

// RTTEstimator RTT 估算器
type RTTEstimator struct {
	// 核心 RTT 值
	smoothedRTT time.Duration // 平滑 RTT (SRTT)
	rttVariance time.Duration // RTT 方差 (RTTVAR)
	minRTT      time.Duration // 最小 RTT
	latestRTT   time.Duration // 最新 RTT
	maxRTT      time.Duration // 最大 RTT

	// 最小 RTT 追踪
	minRTTTimestamp time.Time // 最小 RTT 记录时间
	minRTTWindow    time.Duration

	// 采样历史
	samples      []rttSample
	sampleIdx    int
	sampleCount  int

	// 统计
	totalSamples uint64
	sumRTT       time.Duration

	// 是否已初始化
	initialized bool

	mu sync.RWMutex
}

type rttSample struct {
	rtt       time.Duration
	timestamp time.Time
}

// NewRTTEstimator 创建 RTT 估算器
func NewRTTEstimator() *RTTEstimator {
	return &RTTEstimator{
		smoothedRTT:  defaultInitRTT,
		rttVariance:  defaultInitRTT / 2,
		minRTT:       0,
		minRTTWindow: minRTTWindow,
		samples:      make([]rttSample, rttSampleSize),
		initialized:  false,
	}
}

// Update 更新 RTT (RFC 6298 算法)
func (r *RTTEstimator) Update(rttSample time.Duration, ackDelay time.Duration) {
	if rttSample <= 0 {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// 调整 ACK 延迟
	adjustedRTT := rttSample
	if ackDelay > 0 && rttSample > ackDelay {
		adjustedRTT = rttSample - ackDelay
	}

	r.latestRTT = adjustedRTT
	r.totalSamples++
	r.sumRTT += adjustedRTT

	// 记录采样
	r.samples[r.sampleIdx] = rttSample{
		rtt:       adjustedRTT,
		timestamp: now,
	}
	r.sampleIdx = (r.sampleIdx + 1) % rttSampleSize
	if r.sampleCount < rttSampleSize {
		r.sampleCount++
	}

	// 更新最小 RTT
	if r.minRTT == 0 || adjustedRTT < r.minRTT {
		r.minRTT = adjustedRTT
		r.minRTTTimestamp = now
	} else if now.Sub(r.minRTTTimestamp) > r.minRTTWindow {
		// 定期重新探测最小 RTT
		r.minRTT = r.findMinRTTInWindow()
		r.minRTTTimestamp = now
	}

	// 更新最大 RTT
	if adjustedRTT > r.maxRTT {
		r.maxRTT = adjustedRTT
	}

	// RFC 6298 SRTT 和 RTTVAR 计算
	if !r.initialized {
		r.smoothedRTT = adjustedRTT
		r.rttVariance = adjustedRTT / 2
		r.initialized = true
	} else {
		// RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
		diff := r.smoothedRTT - adjustedRTT
		if diff < 0 {
			diff = -diff
		}
		r.rttVariance = time.Duration(
			float64(r.rttVariance)*(1-rttBeta) + float64(diff)*rttBeta,
		)

		// SRTT = (1 - alpha) * SRTT + alpha * R
		r.smoothedRTT = time.Duration(
			float64(r.smoothedRTT)*(1-rttAlpha) + float64(adjustedRTT)*rttAlpha,
		)
	}
}

// findMinRTTInWindow 在采样窗口中找最小 RTT
func (r *RTTEstimator) findMinRTTInWindow() time.Duration {
	if r.sampleCount == 0 {
		return r.smoothedRTT
	}

	now := time.Now()
	minVal := time.Duration(1<<63 - 1)

	for i := 0; i < r.sampleCount; i++ {
		s := r.samples[i]
		if now.Sub(s.timestamp) <= r.minRTTWindow && s.rtt < minVal {
			minVal = s.rtt
		}
	}

	if minVal == time.Duration(1<<63-1) {
		return r.smoothedRTT
	}
	return minVal
}

// GetSmoothedRTT 获取平滑 RTT
func (r *RTTEstimator) GetSmoothedRTT() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.smoothedRTT
}

// GetMinRTT 获取最小 RTT
func (r *RTTEstimator) GetMinRTT() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.minRTT == 0 {
		return r.smoothedRTT
	}
	return r.minRTT
}

// GetLatestRTT 获取最新 RTT
func (r *RTTEstimator) GetLatestRTT() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.latestRTT
}

// GetRTTVariance 获取 RTT 方差
func (r *RTTEstimator) GetRTTVariance() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.rttVariance
}

// GetMaxRTT 获取最大 RTT
func (r *RTTEstimator) GetMaxRTT() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.maxRTT
}

// GetAverageRTT 获取平均 RTT
func (r *RTTEstimator) GetAverageRTT() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.totalSamples == 0 {
		return r.smoothedRTT
	}
	return time.Duration(int64(r.sumRTT) / int64(r.totalSamples))
}

// GetRTO 计算重传超时 (RFC 6298)
func (r *RTTEstimator) GetRTO() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// RTO = SRTT + max(G, 4*RTTVAR)
	// G 是时钟粒度，这里假设为 1ms
	rto := r.smoothedRTT + 4*r.rttVariance
	if rto < r.smoothedRTT+time.Millisecond {
		rto = r.smoothedRTT + time.Millisecond
	}

	// 最小 RTO
	if rto < 100*time.Millisecond {
		rto = 100 * time.Millisecond
	}
	// 最大 RTO
	if rto > 60*time.Second {
		rto = 60 * time.Second
	}

	return rto
}

// IsInitialized 是否已初始化
func (r *RTTEstimator) IsInitialized() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.initialized
}

// Reset 重置
func (r *RTTEstimator) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.smoothedRTT = defaultInitRTT
	r.rttVariance = defaultInitRTT / 2
	r.minRTT = 0
	r.latestRTT = 0
	r.maxRTT = 0
	r.minRTTTimestamp = time.Time{}
	r.sampleIdx = 0
	r.sampleCount = 0
	r.totalSamples = 0
	r.sumRTT = 0
	r.initialized = false
}

// GetStats 获取统计信息
func (r *RTTEstimator) GetStats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return map[string]interface{}{
		"srtt_ms":        r.smoothedRTT.Milliseconds(),
		"min_rtt_ms":     r.minRTT.Milliseconds(),
		"latest_rtt_ms":  r.latestRTT.Milliseconds(),
		"max_rtt_ms":     r.maxRTT.Milliseconds(),
		"rtt_var_ms":     r.rttVariance.Milliseconds(),
		"rto_ms":         r.GetRTO().Milliseconds(),
		"total_samples":  r.totalSamples,
		"initialized":    r.initialized,
	}
}

