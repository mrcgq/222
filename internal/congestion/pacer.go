

// =============================================================================
// 文件: internal/congestion/pacer.go
// 描述: Pacing 发送速率控制 (防止突发)
// =============================================================================
package congestion

import (
	"sync"
	"time"
)

const (
	// Pacing 常量
	defaultMTU            = 1200
	pacingGainCycle       = 8   // BBR 风格的 pacing 周期
	initialPacingGain     = 2.0 // 初始 pacing 增益
	steadyPacingGain      = 1.0 // 稳态 pacing 增益
	minPacingRate         = 100 * 1024 // 100 KB/s
	maxBurstPackets       = 10  // 最大突发包数
)

// Pacer 发送速率控制器
type Pacer struct {
	// 速率控制
	pacingRate     float64 // 当前 pacing 速率 (bytes/s)
	pacingGain     float64 // pacing 增益
	
	// 令牌桶
	tokens         float64 // 当前令牌数
	maxTokens      float64 // 最大令牌数
	lastRefill     time.Time
	
	// 突发控制
	burstTokens    int     // 突发令牌
	burstSize      int     // 突发大小
	
	// 配置
	mtu            int
	maxRate        float64 // 最大速率

	// 统计
	packetsSent    uint64
	bytesThrottled uint64
	
	mu sync.Mutex
}

// NewPacer 创建 Pacer
func NewPacer(initialRate float64, mtu int) *Pacer {
	if mtu <= 0 {
		mtu = defaultMTU
	}
	
	return &Pacer{
		pacingRate:  initialRate,
		pacingGain:  initialPacingGain,
		tokens:      float64(mtu * maxBurstPackets),
		maxTokens:   float64(mtu * maxBurstPackets),
		lastRefill:  time.Now(),
		burstSize:   mtu * maxBurstPackets,
		mtu:         mtu,
		maxRate:     initialRate * 2,
	}
}

// SetPacingRate 设置 pacing 速率
func (p *Pacer) SetPacingRate(rate float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if rate < minPacingRate {
		rate = minPacingRate
	}
	if rate > p.maxRate {
		rate = p.maxRate
	}
	
	p.pacingRate = rate
}

// SetMaxRate 设置最大速率
func (p *Pacer) SetMaxRate(rate float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxRate = rate
}

// SetPacingGain 设置 pacing 增益
func (p *Pacer) SetPacingGain(gain float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pacingGain = gain
}

// GetPacingRate 获取当前 pacing 速率
func (p *Pacer) GetPacingRate() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pacingRate * p.pacingGain
}

// TimeUntilSend 计算距离可以发送的时间
func (p *Pacer) TimeUntilSend(packetSize int) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.refillTokens()
	
	// 如果有足够的令牌，立即发送
	if p.tokens >= float64(packetSize) {
		return 0
	}
	
	// 计算需要等待的时间
	needed := float64(packetSize) - p.tokens
	rate := p.pacingRate * p.pacingGain
	if rate <= 0 {
		rate = minPacingRate
	}
	
	waitTime := time.Duration(needed / rate * float64(time.Second))
	return waitTime
}

// OnPacketSent 数据包发送时调用
func (p *Pacer) OnPacketSent(packetSize int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.refillTokens()
	
	p.tokens -= float64(packetSize)
	if p.tokens < 0 {
		p.tokens = 0
	}
	
	p.packetsSent++
}

// refillTokens 补充令牌
func (p *Pacer) refillTokens() {
	now := time.Now()
	elapsed := now.Sub(p.lastRefill)
	p.lastRefill = now
	
	if elapsed <= 0 {
		return
	}
	
	// 根据速率补充令牌
	rate := p.pacingRate * p.pacingGain
	tokensToAdd := rate * elapsed.Seconds()
	
	p.tokens += tokensToAdd
	if p.tokens > p.maxTokens {
		p.tokens = p.maxTokens
	}
}

// GetPacingInterval 获取发包间隔
func (p *Pacer) GetPacingInterval(packetSize int) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	rate := p.pacingRate * p.pacingGain
	if rate <= 0 {
		return time.Millisecond
	}
	
	return time.Duration(float64(packetSize) / rate * float64(time.Second))
}

// CanSend 是否可以立即发送
func (p *Pacer) CanSend(packetSize int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.refillTokens()
	return p.tokens >= float64(packetSize)
}

// SetBurstAllowed 设置突发模式
func (p *Pacer) SetBurstAllowed(packets int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.burstTokens = packets
	p.burstSize = packets * p.mtu
	p.maxTokens = float64(p.burstSize)
	p.tokens = p.maxTokens
}

// Reset 重置
func (p *Pacer) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.tokens = p.maxTokens
	p.lastRefill = time.Now()
	p.packetsSent = 0
	p.bytesThrottled = 0
	p.pacingGain = initialPacingGain
}

// GetStats 获取统计
func (p *Pacer) GetStats() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	return map[string]interface{}{
		"pacing_rate_mbps":   p.pacingRate * 8 / 1024 / 1024,
		"pacing_gain":        p.pacingGain,
		"effective_rate_mbps": p.pacingRate * p.pacingGain * 8 / 1024 / 1024,
		"tokens":             p.tokens,
		"max_tokens":         p.maxTokens,
		"packets_sent":       p.packetsSent,
	}
}



