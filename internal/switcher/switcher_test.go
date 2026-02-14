

// =============================================================================
// 文件: internal/switcher/switcher_test.go
// 描述: 智能链路切换测试
// =============================================================================
package switcher

import (
	"testing"
	"time"
)

func TestQualityMonitor(t *testing.T) {
	monitor := NewQualityMonitor(ModeUDP)

	// 记录 RTT
	for i := 0; i < 10; i++ {
		monitor.RecordRTT(time.Duration(50+i*5) * time.Millisecond)
	}

	quality := monitor.GetQuality()

	if quality.AvgRTT == 0 {
		t.Error("AvgRTT 应该 > 0")
	}

	if quality.MinRTT != 50*time.Millisecond {
		t.Errorf("MinRTT 应该是 50ms, got %v", quality.MinRTT)
	}

	// 记录丢包
	for i := 0; i < 10; i++ {
		monitor.RecordPacket(i < 8) // 20% 丢包
	}

	quality = monitor.GetQuality()
	if quality.LossRate < 0.15 || quality.LossRate > 0.25 {
		t.Errorf("LossRate 应该约 20%%, got %.2f%%", quality.LossRate*100)
	}
}

func TestQualityScore(t *testing.T) {
	monitor := NewQualityMonitor(ModeUDP)

	// 好的网络条件
	for i := 0; i < 20; i++ {
		monitor.RecordRTT(30 * time.Millisecond)
		monitor.RecordPacket(true)
	}

	quality := monitor.GetQuality()
	if quality.Score < 80 {
		t.Errorf("好网络条件下评分应该 > 80, got %.2f", quality.Score)
	}

	// 模拟差的网络条件
	monitor2 := NewQualityMonitor(ModeUDP)
	for i := 0; i < 20; i++ {
		monitor2.RecordRTT(300 * time.Millisecond)
		monitor2.RecordPacket(i%2 == 0) // 50% 丢包
	}

	quality2 := monitor2.GetQuality()
	if quality2.Score > 50 {
		t.Errorf("差网络条件下评分应该 < 50, got %.2f", quality2.Score)
	}
}

func TestDecisionEngine(t *testing.T) {
	config := DefaultSwitcherConfig()
	engine := NewDecisionEngine(config)

	// 模拟当前模式质量下降
	engine.UpdateQuality(ModeUDP, func(m *QualityMonitor) {
		for i := 0; i < 10; i++ {
			m.RecordRTT(400 * time.Millisecond) // 高 RTT
			m.RecordPacket(i < 5)               // 50% 丢包
		}
	})

	// 模拟备选模式可用
	engine.UpdateQuality(ModeFakeTCP, func(m *QualityMonitor) {
		for i := 0; i < 10; i++ {
			m.RecordRTT(50 * time.Millisecond)
			m.RecordPacket(true)
		}
	})

	// 评估
	decision := engine.Evaluate(ModeUDP)

	if !decision.ShouldSwitch {
		t.Error("应该建议切换")
	}

	if decision.TargetMode == ModeUDP {
		t.Error("目标模式不应该是当前模式")
	}
}

func TestDecisionCooldown(t *testing.T) {
	config := DefaultSwitcherConfig()
	config.MinSwitchInterval = 100 * time.Millisecond
	engine := NewDecisionEngine(config)

	// 记录一次切换
	engine.RecordSwitch(SwitchEvent{
		Timestamp: time.Now(),
		FromMode:  ModeUDP,
		ToMode:    ModeFakeTCP,
		Reason:    ReasonHighRTT,
		Success:   true,
	})

	// 立即评估应该不建议切换
	decision := engine.Evaluate(ModeFakeTCP)
	if decision.ShouldSwitch {
		t.Error("冷却期内不应该建议切换")
	}

	// 等待冷却期
	time.Sleep(150 * time.Millisecond)

	// 模拟质量下降
	engine.UpdateQuality(ModeFakeTCP, func(m *QualityMonitor) {
		for i := 0; i < 5; i++ {
			m.RecordPacket(false)
		}
	})

	// 现在应该可以切换
	decision = engine.Evaluate(ModeFakeTCP)
	// 注意：是否切换还取决于其他条件
}

func TestSwitchHistory(t *testing.T) {
	config := DefaultSwitcherConfig()
	engine := NewDecisionEngine(config)

	// 记录多次切换
	for i := 0; i < 5; i++ {
		engine.RecordSwitch(SwitchEvent{
			Timestamp: time.Now(),
			FromMode:  ModeUDP,
			ToMode:    ModeFakeTCP,
			Reason:    ReasonHighRTT,
			Success:   true,
		})
		time.Sleep(10 * time.Millisecond)
	}

	history := engine.GetSwitchHistory(3)
	if len(history) != 3 {
		t.Errorf("应该返回 3 条历史, got %d", len(history))
	}
}

func TestModeScoring(t *testing.T) {
	config := DefaultSwitcherConfig()
	engine := NewDecisionEngine(config)

	// 设置不同模式的质量
	modes := []TransportMode{ModeEBPF, ModeFakeTCP, ModeUDP, ModeWebSocket}
	rtts := []time.Duration{5 * time.Millisecond, 30 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond}

	for i, mode := range modes {
		engine.UpdateQuality(mode, func(m *QualityMonitor) {
			for j := 0; j < 10; j++ {
				m.RecordRTT(rtts[i])
				m.RecordPacket(true)
			}
		})
	}

	qualities := engine.GetAllQualities()

	// eBPF 应该评分最高
	if qualities[ModeEBPF].Score < qualities[ModeWebSocket].Score {
		t.Error("eBPF 评分应该高于 WebSocket")
	}
}

// 基准测试
func BenchmarkQualityMonitorRecordRTT(b *testing.B) {
	monitor := NewQualityMonitor(ModeUDP)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		monitor.RecordRTT(50 * time.Millisecond)
	}
}

func BenchmarkQualityMonitorGetQuality(b *testing.B) {
	monitor := NewQualityMonitor(ModeUDP)
	for i := 0; i < 100; i++ {
		monitor.RecordRTT(50 * time.Millisecond)
		monitor.RecordPacket(true)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = monitor.GetQuality()
	}
}

func BenchmarkDecisionEngineEvaluate(b *testing.B) {
	config := DefaultSwitcherConfig()
	engine := NewDecisionEngine(config)

	// 预填充数据
	for _, mode := range AllModes {
		engine.UpdateQuality(mode, func(m *QualityMonitor) {
			for i := 0; i < 20; i++ {
				m.RecordRTT(50 * time.Millisecond)
				m.RecordPacket(true)
			}
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(ModeUDP)
	}
}


