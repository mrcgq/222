// =============================================================================
// 文件: internal/switcher/prober.go
// 描述: 智能链路切换 - 链路探测器
// =============================================================================
package switcher

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Prober 链路探测器
type Prober struct {
	config *SwitcherConfig

	// 传输层
	transports map[TransportMode]TransportHandler

	// 探测结果
	results map[TransportMode]*ProbeResult

	// 探测地址
	probeAddrs []*net.UDPAddr

	// 控制
	probing bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.RWMutex
}

// ProbeResult 探测结果
type ProbeResult struct {
	Mode         TransportMode
	Available    bool
	RTT          time.Duration
	MinRTT       time.Duration
	MaxRTT       time.Duration
	AvgRTT       time.Duration
	LossRate     float64
	Jitter       time.Duration
	ProbeCount   int
	SuccessCount int
	LastProbe    time.Time
	Error        error
}

// NewProber 创建探测器
func NewProber(config *SwitcherConfig) *Prober {
	ctx, cancel := context.WithCancel(context.Background())

	return &Prober{
		config:     config,
		transports: make(map[TransportMode]TransportHandler),
		results:    make(map[TransportMode]*ProbeResult),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// RegisterTransport 注册传输层
func (p *Prober) RegisterTransport(mode TransportMode, handler TransportHandler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.transports[mode] = handler
}

// AddProbeAddr 添加探测地址
func (p *Prober) AddProbeAddr(addr *net.UDPAddr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probeAddrs = append(p.probeAddrs, addr)
}

// ProbeAll 探测所有模式
func (p *Prober) ProbeAll(ctx context.Context) map[TransportMode]*ProbeResult {
	p.mu.Lock()
	if p.probing {
		p.mu.Unlock()
		return p.results
	}
	p.probing = true
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		p.probing = false
		p.mu.Unlock()
	}()

	results := make(map[TransportMode]*ProbeResult)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for mode, transport := range p.transports {
		if !transport.IsRunning() {
			continue
		}

		wg.Add(1)
		go func(m TransportMode, t TransportHandler) {
			defer wg.Done()

			result := p.probeMode(ctx, m, t)

			mu.Lock()
			results[m] = result
			p.results[m] = result
			mu.Unlock()
		}(mode, transport)
	}

	wg.Wait()
	return results
}

// ProbeMode 探测单个模式
func (p *Prober) ProbeMode(ctx context.Context, mode TransportMode) *ProbeResult {
	p.mu.RLock()
	transport, ok := p.transports[mode]
	p.mu.RUnlock()

	if !ok || !transport.IsRunning() {
		return &ProbeResult{
			Mode:      mode,
			Available: false,
			Error:     fmt.Errorf("传输层未运行"),
			LastProbe: time.Now(),
		}
	}

	result := p.probeMode(ctx, mode, transport)

	p.mu.Lock()
	p.results[mode] = result
	p.mu.Unlock()

	return result
}

// probeMode 内部探测实现
func (p *Prober) probeMode(ctx context.Context, mode TransportMode, transport TransportHandler) *ProbeResult {
	result := &ProbeResult{
		Mode:      mode,
		Available: false,
		LastProbe: time.Now(),
	}

	// 对每个地址进行探测
	var rtts []time.Duration
	var successCount int

	for i := 0; i < p.config.ProbeCount; i++ {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			result.Error = ctx.Err()
			return result
		default:
		}

		// 使用带超时的探测
		probeDone := make(chan struct{})
		var rtt time.Duration
		var err error

		go func() {
			// 调用不带参数的 Probe 方法
			rtt, err = transport.Probe()
			close(probeDone)
		}()

		select {
		case <-probeDone:
			// 探测完成
		case <-time.After(p.config.ProbeTimeout):
			err = fmt.Errorf("probe timeout")
		case <-ctx.Done():
			result.Error = ctx.Err()
			return result
		}

		result.ProbeCount++

		if err != nil {
			continue
		}

		successCount++
		rtts = append(rtts, rtt)
	}

	result.SuccessCount = successCount

	if len(rtts) == 0 {
		result.Error = fmt.Errorf("所有探测失败")
		return result
	}

	// 计算统计值
	var sum time.Duration
	result.MinRTT = rtts[0]
	result.MaxRTT = rtts[0]

	for _, rtt := range rtts {
		sum += rtt
		if rtt < result.MinRTT {
			result.MinRTT = rtt
		}
		if rtt > result.MaxRTT {
			result.MaxRTT = rtt
		}
	}

	result.AvgRTT = sum / time.Duration(len(rtts))
	result.RTT = result.AvgRTT

	// 计算抖动
	if len(rtts) > 1 {
		var variance float64
		avgNs := float64(result.AvgRTT.Nanoseconds())
		for _, rtt := range rtts {
			diff := float64(rtt.Nanoseconds()) - avgNs
			variance += diff * diff
		}
		result.Jitter = time.Duration(variance / float64(len(rtts)))
	}

	// 计算丢包率
	result.LossRate = 1 - float64(successCount)/float64(result.ProbeCount)

	// 判断可用性
	result.Available = result.LossRate < 0.5 && result.AvgRTT < p.config.RTTThreshold*2

	return result
}

// GetResult 获取探测结果
func (p *Prober) GetResult(mode TransportMode) *ProbeResult {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.results[mode]
}

// GetAllResults 获取所有探测结果
func (p *Prober) GetAllResults() map[TransportMode]*ProbeResult {
	p.mu.RLock()
	defer p.mu.RUnlock()

	results := make(map[TransportMode]*ProbeResult)
	for mode, result := range p.results {
		results[mode] = result
	}
	return results
}

// IsProbing 是否正在探测
func (p *Prober) IsProbing() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.probing
}

// Stop 停止探测
func (p *Prober) Stop() {
	p.cancel()
	p.wg.Wait()
}
