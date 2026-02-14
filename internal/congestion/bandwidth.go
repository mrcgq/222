

// =============================================================================
// 文件: internal/congestion/bandwidth.go
// 描述: 带宽估算 (类似 BBR 的 BtlBw 估算)
// =============================================================================
package congestion

import (
	"sync"
	"time"
)

const (
	bandwidthWindowSize    = 10           // 带宽窗口采样数
	bandwidthWindowTime    = 10 * time.Second // 带宽窗口时间
	minBandwidthSamples    = 3            // 最小采样数
	bandwidthFilterLength  = 10           // 滤波器长度
)

// BandwidthEstimator 带宽估算器
type BandwidthEstimator struct {
	// 带宽采样
	samples       []bandwidthSample
	maxBandwidth  float64 // 最大带宽 (bytes/s)
	currBandwidth float64 // 当前带宽
	avgBandwidth  float64 // 平均带宽

	// 交付速率追踪
	deliveredBytes   int64
	deliveredTime    time.Time
	lastDelivered    int64
	lastDeliveredAt  time.Time

	// 应用限制检测
	appLimited     bool
	appLimitedSeq  uint64

	// 配置
	maxConfigured float64 // 配置的最大带宽

	// 统计
	sampleCount uint64

	mu sync.RWMutex
}

type bandwidthSample struct {
	bandwidth   float64
	rtt         time.Duration
	appLimited  bool
	timestamp   time.Time
	delivered   int64
}

// NewBandwidthEstimator 创建带宽估算器
func NewBandwidthEstimator(maxMbps int) *BandwidthEstimator {
	maxBw := float64(maxMbps) * 1024 * 1024 / 8 // bytes/s

	return &BandwidthEstimator{
		samples:       make([]bandwidthSample, 0, bandwidthWindowSize),
		maxConfigured: maxBw,
		deliveredTime: time.Now(),
	}
}

// OnPacketDelivered 数据包被确认时调用
func (b *BandwidthEstimator) OnPacketDelivered(
	deliveredBytes int64,
	deliveredTime time.Time,
	sentTime time.Time,
	rtt time.Duration,
	appLimited bool,
) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()

	// 计算交付速率
	var bw float64
	if b.lastDeliveredAt.IsZero() {
		b.lastDeliveredAt = now
		b.lastDelivered = deliveredBytes
		return
	}

	timeDelta := now.Sub(b.lastDeliveredAt)
	if timeDelta <= 0 {
		return
	}

	bytesDelta := deliveredBytes - b.lastDelivered
	if bytesDelta <= 0 {
		return
	}

	// 计算带宽: bytes / time
	bw = float64(bytesDelta) / timeDelta.Seconds()

	// 如果不是应用限制，更新采样
	sample := bandwidthSample{
		bandwidth:  bw,
		rtt:        rtt,
		appLimited: appLimited,
		timestamp:  now,
		delivered:  deliveredBytes,
	}

	// 添加采样
	b.samples = append(b.samples, sample)
	if len(b.samples) > bandwidthWindowSize {
		b.samples = b.samples[1:]
	}

	// 更新统计
	b.lastDelivered = deliveredBytes
	b.lastDeliveredAt = now
	b.sampleCount++

	// 更新带宽估计
	b.updateEstimate()
}

// updateEstimate 更新带宽估计
func (b *BandwidthEstimator) updateEstimate() {
	if len(b.samples) == 0 {
		return
	}

	now := time.Now()
	var sum, maxBw float64
	validCount := 0

	// 只使用最近窗口内的非应用限制采样
	for _, s := range b.samples {
		if now.Sub(s.timestamp) > bandwidthWindowTime {
			continue
		}
		if s.appLimited {
			continue
		}

		sum += s.bandwidth
		validCount++

		if s.bandwidth > maxBw {
			maxBw = s.bandwidth
		}
	}

	if validCount > 0 {
		b.avgBandwidth = sum / float64(validCount)
	}

	// BBR 风格：取最大值作为瓶颈带宽估计
	if maxBw > 0 {
		b.maxBandwidth = maxBw
	}

	b.currBandwidth = b.maxBandwidth
}

// GetBandwidth 获取估算带宽 (bytes/s)
func (b *BandwidthEstimator) GetBandwidth() float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.maxBandwidth > 0 {
		return b.maxBandwidth
	}
	return b.maxConfigured
}

// GetAvgBandwidth 获取平均带宽
func (b *BandwidthEstimator) GetAvgBandwidth() float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.avgBandwidth
}

// GetMaxConfigured 获取配置的最大带宽
func (b *BandwidthEstimator) GetMaxConfigured() float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.maxConfigured
}

// SetMaxConfigured 设置最大带宽
func (b *BandwidthEstimator) SetMaxConfigured(maxMbps int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.maxConfigured = float64(maxMbps) * 1024 * 1024 / 8
}

// SetAppLimited 设置应用限制状态
func (b *BandwidthEstimator) SetAppLimited(limited bool, seq uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.appLimited = limited
	if limited {
		b.appLimitedSeq = seq
	}
}

// IsAppLimited 是否处于应用限制
func (b *BandwidthEstimator) IsAppLimited() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.appLimited
}

// GetDelivered 获取已交付字节数
func (b *BandwidthEstimator) GetDelivered() int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.deliveredBytes
}

// AddDelivered 增加交付字节数
func (b *BandwidthEstimator) AddDelivered(bytes int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deliveredBytes += bytes
	b.deliveredTime = time.Now()
}

// Reset 重置
func (b *BandwidthEstimator) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.samples = b.samples[:0]
	b.maxBandwidth = 0
	b.currBandwidth = 0
	b.avgBandwidth = 0
	b.deliveredBytes = 0
	b.deliveredTime = time.Now()
	b.lastDelivered = 0
	b.lastDeliveredAt = time.Time{}
	b.appLimited = false
	b.sampleCount = 0
}

// GetStats 获取统计
func (b *BandwidthEstimator) GetStats() map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return map[string]interface{}{
		"max_bandwidth_mbps": b.maxBandwidth * 8 / 1024 / 1024,
		"avg_bandwidth_mbps": b.avgBandwidth * 8 / 1024 / 1024,
		"max_configured_mbps": b.maxConfigured * 8 / 1024 / 1024,
		"sample_count":        b.sampleCount,
		"app_limited":         b.appLimited,
		"delivered_bytes":     b.deliveredBytes,
	}
}
