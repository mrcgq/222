// =============================================================================
// 文件: internal/switcher/decision.go
// 描述: 智能链路切换 - 决策引擎
// =============================================================================
package switcher

import (
	"sort"
	"sync"
	"time"
)

// DecisionEngine 决策引擎
type DecisionEngine struct {
	config *SwitcherConfig

	// 模式质量
	qualities map[TransportMode]*QualityMonitor

	// 切换历史
	switchHistory []SwitchEvent
	lastSwitch    time.Time

	// 冷却计数
	cooldowns map[TransportMode]time.Time

	// 探测状态
	probing      bool
	probeMode    TransportMode
	probeResults map[TransportMode]*probeResult

	mu sync.RWMutex
}

type probeResult struct {
	mode      TransportMode
	rtt       time.Duration
	success   bool
	timestamp time.Time
}

// NewDecisionEngine 创建决策引擎
func NewDecisionEngine(config *SwitcherConfig) *DecisionEngine {
	if config == nil {
		config = DefaultSwitcherConfig()
	}

	d := &DecisionEngine{
		config:        config,
		qualities:     make(map[TransportMode]*QualityMonitor),
		switchHistory: make([]SwitchEvent, 0, 100),
		cooldowns:     make(map[TransportMode]time.Time),
		probeResults:  make(map[TransportMode]*probeResult),
	}

	// 初始化所有模式的质量监控器
	for _, mode := range AllModes {
		d.qualities[mode] = NewQualityMonitor(mode)
	}

	return d
}

// Evaluate 评估是否需要切换
func (d *DecisionEngine) Evaluate(currentMode TransportMode) *SwitchDecision {
	d.mu.RLock()
	defer d.mu.RUnlock()

	decision := &SwitchDecision{
		ShouldSwitch: false,
		TargetMode:   currentMode,
		Reason:       ReasonNone,
		Confidence:   0,
		Alternatives: make([]TransportMode, 0),
	}

	// 检查冷却期
	if !d.canSwitch() {
		return decision
	}

	// 获取当前模式质量
	currentQuality := d.getQuality(currentMode)
	if currentQuality == nil {
		return decision
	}

	// 检查是否需要切换
	reason := d.checkSwitchConditions(currentMode, currentQuality)
	if reason == ReasonNone {
		// 检查是否可以恢复到更优模式
		reason = d.checkRecoveryConditions(currentMode, currentQuality)
	}

	if reason == ReasonNone {
		return decision
	}

	// 选择目标模式
	targetMode, confidence, alternatives := d.selectTargetMode(currentMode, reason)
	if targetMode == currentMode {
		return decision
	}

	decision.ShouldSwitch = true
	decision.TargetMode = targetMode
	decision.Reason = reason
	decision.Confidence = confidence
	decision.Alternatives = alternatives

	return decision
}

// checkSwitchConditions 检查切换条件
func (d *DecisionEngine) checkSwitchConditions(currentMode TransportMode, quality *LinkQualityMetrics) SwitchReason {
	// 连续失败
	if quality.ConsecutiveFailures >= d.config.FailThreshold {
		return ReasonConnectionFailed
	}

	// 高 RTT
	if quality.RTT > d.config.RTTThreshold && quality.RTT > 0 {
		return ReasonHighRTT
	}

	// 高丢包率
	if quality.LossRate > d.config.LossThreshold {
		return ReasonHighLoss
	}

	// 低吞吐量 (仅当有数据时)
	if quality.Throughput > 0 && quality.Throughput < d.config.ThroughputThreshold {
		return ReasonLowThroughput
	}

	// 状态降级
	if quality.State == StateDegraded || quality.State == StateFailed {
		return ReasonDegraded
	}

	return ReasonNone
}

// checkRecoveryConditions 检查恢复条件
func (d *DecisionEngine) checkRecoveryConditions(currentMode TransportMode, quality *LinkQualityMetrics) SwitchReason {
	// 获取当前模式优先级
	currentPriority := d.getModePriority(currentMode)

	// 检查是否有更高优先级的模式可用
	for _, mode := range d.config.Priority {
		if d.getModePriority(mode) >= currentPriority {
			continue
		}

		// 检查该模式是否在冷却期
		if cooldown, ok := d.cooldowns[mode]; ok && time.Now().Before(cooldown) {
			continue
		}

		modeQuality := d.getQuality(mode)
		if modeQuality == nil {
			continue
		}

		// 检查该模式是否稳定可用
		if modeQuality.Available &&
			modeQuality.ConsecutiveSuccesses >= d.config.RecoverThreshold &&
			modeQuality.Score > quality.Score+10 {
			return ReasonRecovery
		}
	}

	return ReasonNone
}

// selectTargetMode 选择目标模式
func (d *DecisionEngine) selectTargetMode(currentMode TransportMode, reason SwitchReason) (TransportMode, float64, []TransportMode) {
	candidates := make([]modeCandidate, 0)

	for _, mode := range d.config.Priority {
		if mode == currentMode {
			continue
		}

		// 检查冷却期
		if cooldown, ok := d.cooldowns[mode]; ok && time.Now().Before(cooldown) {
			continue
		}

		quality := d.getQuality(mode)
		if quality == nil {
			continue
		}

		// 计算候选分数
		score := quality.Score
		priority := d.getModePriority(mode)

		// 优先级加成
		score += float64(len(d.config.Priority)-priority) * 5

		// 如果是恢复，优先选择更高优先级的模式
		if reason == ReasonRecovery {
			if priority < d.getModePriority(currentMode) {
				score += 20
			}
		}

		// 如果该模式最近成功过，加分
		if !quality.LastSuccess.IsZero() && time.Since(quality.LastSuccess) < time.Minute {
			score += 10
		}

		candidates = append(candidates, modeCandidate{
			mode:     mode,
			score:    score,
			quality:  quality,
			priority: priority,
		})
	}

	// 按分数排序
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})

	if len(candidates) == 0 {
		// 使用回退模式
		if d.config.EnableFallback {
			return d.config.FallbackMode, 0.5, nil
		}
		return currentMode, 0, nil
	}

	// 选择最佳候选
	best := candidates[0]

	// 计算置信度
	confidence := best.score / 100
	if confidence > 1 {
		confidence = 1
	}

	// 收集备选
	alternatives := make([]TransportMode, 0)
	for i := 1; i < len(candidates) && i < 3; i++ {
		alternatives = append(alternatives, candidates[i].mode)
	}

	return best.mode, confidence, alternatives
}

type modeCandidate struct {
	mode     TransportMode
	score    float64
	quality  *LinkQualityMetrics
	priority int
}

// getModePriority 获取模式优先级
func (d *DecisionEngine) getModePriority(mode TransportMode) int {
	for i, m := range d.config.Priority {
		if m == mode {
			return i
		}
	}
	return len(d.config.Priority)
}

// getQuality 获取模式质量
func (d *DecisionEngine) getQuality(mode TransportMode) *LinkQualityMetrics {
	if monitor, ok := d.qualities[mode]; ok {
		return monitor.GetQuality()
	}
	return nil
}

// canSwitch 是否可以切换
func (d *DecisionEngine) canSwitch() bool {
	if d.lastSwitch.IsZero() {
		return true
	}

	// 检查最小切换间隔
	if time.Since(d.lastSwitch) < d.config.MinSwitchInterval {
		return false
	}

	// 检查切换频率
	recentSwitches := 0
	cutoff := time.Now().Add(-time.Minute)
	for _, event := range d.switchHistory {
		if event.Timestamp.After(cutoff) {
			recentSwitches++
		}
	}
	if float64(recentSwitches) >= d.config.MaxSwitchRate {
		return false
	}

	return true
}

// RecordSwitch 记录切换事件
func (d *DecisionEngine) RecordSwitch(event SwitchEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.switchHistory = append(d.switchHistory, event)
	d.lastSwitch = event.Timestamp

	// 如果切换失败，设置冷却期
	if !event.Success {
		d.cooldowns[event.ToMode] = time.Now().Add(d.config.CooldownPeriod)
	}

	// 限制历史大小
	if len(d.switchHistory) > 100 {
		d.switchHistory = d.switchHistory[1:]
	}
}

// UpdateQuality 更新模式质量
func (d *DecisionEngine) UpdateQuality(mode TransportMode, update func(*QualityMonitor)) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if monitor, ok := d.qualities[mode]; ok {
		update(monitor)
	}
}

// GetQualityMonitor 获取质量监控器
func (d *DecisionEngine) GetQualityMonitor(mode TransportMode) *QualityMonitor {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.qualities[mode]
}

// GetAllQualities 获取所有模式质量
func (d *DecisionEngine) GetAllQualities() map[TransportMode]*LinkQualityMetrics {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make(map[TransportMode]*LinkQualityMetrics)
	for mode, monitor := range d.qualities {
		result[mode] = monitor.GetQuality()
	}
	return result
}

// GetSwitchHistory 获取切换历史
func (d *DecisionEngine) GetSwitchHistory(limit int) []SwitchEvent {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if limit <= 0 || limit > len(d.switchHistory) {
		limit = len(d.switchHistory)
	}

	result := make([]SwitchEvent, limit)
	copy(result, d.switchHistory[len(d.switchHistory)-limit:])
	return result
}

// RecordProbeResult 记录探测结果
func (d *DecisionEngine) RecordProbeResult(mode TransportMode, rtt time.Duration, success bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.probeResults[mode] = &probeResult{
		mode:      mode,
		rtt:       rtt,
		success:   success,
		timestamp: time.Now(),
	}

	// 更新质量监控
	if monitor, ok := d.qualities[mode]; ok {
		if success {
			monitor.RecordRTT(rtt)
			monitor.RecordPacket(true)
		} else {
			monitor.RecordPacket(false)
		}
	}
}

// ClearCooldown 清除冷却期
func (d *DecisionEngine) ClearCooldown(mode TransportMode) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.cooldowns, mode)
}

// Reset 重置
func (d *DecisionEngine) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, monitor := range d.qualities {
		monitor.Reset()
	}
	d.switchHistory = d.switchHistory[:0]
	d.lastSwitch = time.Time{}
	d.cooldowns = make(map[TransportMode]time.Time)
	d.probeResults = make(map[TransportMode]*probeResult)
}
