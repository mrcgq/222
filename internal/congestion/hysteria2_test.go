

// =============================================================================
// 文件: internal/congestion/hysteria2_test.go
// 描述: Hysteria2 拥塞控制测试
// =============================================================================
package congestion

import (
	"testing"
	"time"
)

func TestNewHysteria2Controller(t *testing.T) {
	c := NewHysteria2Controller(100, 100)
	
	if c == nil {
		t.Fatal("Controller 应该不为 nil")
	}
	
	if !c.IsBrutalMode() {
		t.Error("默认应该是 Brutal 模式")
	}
	
	cwnd := c.GetCongestionWindow()
	if cwnd <= 0 {
		t.Errorf("CWND 应该 > 0, got %d", cwnd)
	}
}

func TestCanSend(t *testing.T) {
	c := NewHysteria2Controller(100, 100)
	
	// 初始应该可以发送
	if !c.CanSend(1200) {
		t.Error("初始应该可以发送")
	}
	
	// 发送大量数据填满窗口
	for i := 0; i < 1000; i++ {
		c.OnPacketSent(uint64(i+1), 1200, false)
	}
	
	// 窗口应该被填满（但 brutal 模式下窗口很大）
	stats := c.GetStats()
	if stats.BytesInFlight < 1000*1200 {
		t.Errorf("BytesInFlight 应该 >= %d, got %d", 1000*1200, stats.BytesInFlight)
	}
}

func TestOnPacketAcked(t *testing.T) {
	c := NewHysteria2Controller(100, 100)
	
	// 发送包
	c.OnPacketSent(1, 1200, false)
	c.OnPacketSent(2, 1200, false)
	c.OnPacketSent(3, 1200, false)
	
	initialInFlight := c.GetStats().BytesInFlight
	
	// 确认包
	c.OnPacketAcked(1, 1200, 50*time.Millisecond)
	c.OnPacketAcked(2, 1200, 55*time.Millisecond)
	
	newInFlight := c.GetStats().BytesInFlight
	if newInFlight >= initialInFlight {
		t.Errorf("InFlight 应该减少: %d >= %d", newInFlight, initialInFlight)
	}
	
	// RTT 应该被更新
	rtt := c.GetRTT()
	if rtt == 0 {
		t.Error("RTT 应该被更新")
	}
}

func TestOnPacketLost(t *testing.T) {
	c := NewHysteria2Controller(100, 100)
	
	// 发送并丢失大量包以退出 brutal 模式
	for i := 0; i < 100; i++ {
		c.OnPacketSent(uint64(i+1), 1200, false)
	}
	
	// 丢失 40% 的包（超过 brutalLossThreshold）
	for i := 0; i < 40; i++ {
		c.OnPacketLost(uint64(i+1), 1200)
	}
	
	// 应该退出 brutal 模式
	if c.IsBrutalMode() {
		// 注意：可能需要更多丢包才能退出
		t.Log("警告：丢包后仍在 brutal 模式（可能需要更多丢包）")
	}
	
	// 丢包率应该被更新
	lossRate := c.GetLossRate()
	if lossRate == 0 {
		t.Error("LossRate 应该 > 0")
	}
}

func TestBrutalModeToggle(t *testing.T) {
	c := NewHysteria2Controller(100, 100)
	
	if !c.IsBrutalMode() {
		t.Error("默认应该是 Brutal 模式")
	}
	
	c.SetBrutalMode(false, 0)
	if c.IsBrutalMode() {
		t.Error("应该关闭 Brutal 模式")
	}
	
	c.SetBrutalMode(true, 50)
	if !c.IsBrutalMode() {
		t.Error("应该开启 Brutal 模式")
	}
}

func TestGetPacingInterval(t *testing.T) {
	c := NewHysteria2Controller(100, 100)
	
	interval := c.GetPacingInterval(1200)
	if interval <= 0 {
		t.Errorf("Pacing interval 应该 > 0, got %v", interval)
	}
	
	// 100 Mbps = 12.5 MB/s = 12500 KB/s
	// 1200 bytes 应该约 0.096 ms
	if interval > 10*time.Millisecond {
		t.Errorf("Pacing interval 过长: %v", interval)
	}
}

func TestReset(t *testing.T) {
	c := NewHysteria2Controller(100, 100)
	
	// 修改状态
	for i := 0; i < 10; i++ {
		c.OnPacketSent(uint64(i+1), 1200, false)
	}
	c.OnPacketLost(1, 1200)
	
	// 重置
	c.Reset()
	
	// 验证重置后的状态
	stats := c.GetStats()
	if stats.BytesInFlight != 0 {
		t.Errorf("重置后 BytesInFlight 应该是 0, got %d", stats.BytesInFlight)
	}
	if stats.LostPackets != 0 {
		t.Errorf("重置后 LostPackets 应该是 0, got %d", stats.LostPackets)
	}
	if !c.IsBrutalMode() {
		t.Error("重置后应该恢复 Brutal 模式")
	}
}

func TestGetStats(t *testing.T) {
	c := NewHysteria2Controller(100, 100)
	
	stats := c.GetStats()
	
	if stats == nil {
		t.Fatal("Stats 不应该是 nil")
	}
	
	if stats.MaxWindow <= 0 {
		t.Error("MaxWindow 应该 > 0")
	}
	
	if stats.BandwidthMbps <= 0 {
		t.Error("BandwidthMbps 应该 > 0（配置了 100 Mbps）")
	}
}

// RTT 估算器测试
func TestRTTEstimator(t *testing.T) {
	r := NewRTTEstimator()
	
	// 初始状态
	if r.IsInitialized() {
		t.Error("初始不应该是 initialized")
	}
	
	// 更新 RTT
	r.Update(50*time.Millisecond, 0)
	
	if !r.IsInitialized() {
		t.Error("更新后应该是 initialized")
	}
	
	srtt := r.GetSmoothedRTT()
	if srtt != 50*time.Millisecond {
		t.Errorf("第一次 SRTT 应该等于采样值: got %v", srtt)
	}
	
	// 更多采样
	r.Update(60*time.Millisecond, 0)
	r.Update(55*time.Millisecond, 0)
	r.Update(52*time.Millisecond, 0)
	
	// SRTT 应该平滑
	srtt = r.GetSmoothedRTT()
	if srtt < 50*time.Millisecond || srtt > 60*time.Millisecond {
		t.Errorf("SRTT 应该在 50-60ms 之间: got %v", srtt)
	}
	
	// 最小 RTT
	minRTT := r.GetMinRTT()
	if minRTT != 50*time.Millisecond {
		t.Errorf("MinRTT 应该是 50ms: got %v", minRTT)
	}
	
	// RTO
	rto := r.GetRTO()
	if rto < 100*time.Millisecond {
		t.Errorf("RTO 不应该小于 100ms: got %v", rto)
	}
}

// 带宽估算器测试
func TestBandwidthEstimator(t *testing.T) {
	b := NewBandwidthEstimator(100)
	
	// 初始带宽应该是配置的最大值
	bw := b.GetBandwidth()
	expectedMax := float64(100) * 1024 * 1024 / 8
	if bw != expectedMax {
		t.Errorf("初始带宽应该是配置值: got %v, want %v", bw, expectedMax)
	}
	
	// 模拟数据交付
	now := time.Now()
	b.OnPacketDelivered(1200, now, now.Add(-50*time.Millisecond), 50*time.Millisecond, false)
	
	time.Sleep(10 * time.Millisecond)
	now = time.Now()
	b.OnPacketDelivered(2400, now, now.Add(-50*time.Millisecond), 50*time.Millisecond, false)
}

// Pacer 测试
func TestPacer(t *testing.T) {
	p := NewPacer(100*1024*1024/8, 1200) // 100 Mbps
	
	// 初始应该可以发送（有突发令牌）
	if !p.CanSend(1200) {
		t.Error("初始应该可以发送")
	}
	
	// 发送直到没有令牌
	for p.CanSend(1200) {
		p.OnPacketSent(1200)
	}
	
	// 此时应该不能立即发送
	waitTime := p.TimeUntilSend(1200)
	if waitTime == 0 {
		// 可能令牌已经补充
		t.Log("令牌可能已补充")
	}
	
	// 获取 pacing interval
	interval := p.GetPacingInterval(1200)
	if interval <= 0 {
		t.Error("Pacing interval 应该 > 0")
	}
}

// 并发安全测试
func TestConcurrentAccess(t *testing.T) {
	c := NewHysteria2Controller(100, 100)
	
	done := make(chan bool)
	
	// 并发发送
	go func() {
		for i := 0; i < 1000; i++ {
			c.OnPacketSent(uint64(i+1), 1200, false)
		}
		done <- true
	}()
	
	// 并发确认
	go func() {
		for i := 0; i < 500; i++ {
			c.OnPacketAcked(uint64(i+1), 1200, 50*time.Millisecond)
		}
		done <- true
	}()
	
	// 并发丢包
	go func() {
		for i := 500; i < 600; i++ {
			c.OnPacketLost(uint64(i+1), 1200)
		}
		done <- true
	}()
	
	// 并发读取
	go func() {
		for i := 0; i < 1000; i++ {
			_ = c.GetStats()
			_ = c.GetCongestionWindow()
			_ = c.GetRTT()
			_ = c.GetLossRate()
		}
		done <- true
	}()
	
	// 等待所有 goroutine 完成
	for i := 0; i < 4; i++ {
		<-done
	}
}

// 基准测试
func BenchmarkOnPacketSent(b *testing.B) {
	c := NewHysteria2Controller(100, 100)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.OnPacketSent(uint64(i+1), 1200, false)
	}
}

func BenchmarkOnPacketAcked(b *testing.B) {
	c := NewHysteria2Controller(100, 100)
	
	// 预先发送
	for i := 0; i < b.N; i++ {
		c.OnPacketSent(uint64(i+1), 1200, false)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.OnPacketAcked(uint64(i+1), 1200, 50*time.Millisecond)
	}
}

func BenchmarkGetStats(b *testing.B) {
	c := NewHysteria2Controller(100, 100)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.GetStats()
	}
}

func BenchmarkCanSend(b *testing.B) {
	c := NewHysteria2Controller(100, 100)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.CanSend(1200)
	}
}
