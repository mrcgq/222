// =============================================================================
// 文件: internal/metrics/metrics.go
// 描述: 指标收集器 - 提供系统运行状态的监控指标
// =============================================================================
package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// PhantomMetrics 指标收集器
type PhantomMetrics struct {
	// 连接统计
	activeConnections int64
	totalConnections  uint64
	
	// 流量统计
	bytesSent     uint64
	bytesReceived uint64
	
	// 模式切换统计
	modeSwitches uint64
	switchHistory []ModeSwitchRecord
	
	// 启动时间
	startTime time.Time
	
	mu sync.RWMutex
}

// ModeSwitchRecord 模式切换记录
type ModeSwitchRecord struct {
	Timestamp time.Time
	FromMode  string
	ToMode    string
}

// New 创建指标收集器
func New() *PhantomMetrics {
	return &PhantomMetrics{
		startTime:     time.Now(),
		switchHistory: make([]ModeSwitchRecord, 0, 100),
	}
}

// =============================================================================
// 连接统计方法
// =============================================================================

// IncConnections 增加活跃连接数
func (m *PhantomMetrics) IncConnections() {
	atomic.AddInt64(&m.activeConnections, 1)
	atomic.AddUint64(&m.totalConnections, 1)
}

// DecConnections 减少活跃连接数
func (m *PhantomMetrics) DecConnections() {
	atomic.AddInt64(&m.activeConnections, -1)
}

// GetActiveConnections 获取活跃连接数
func (m *PhantomMetrics) GetActiveConnections() int64 {
	return atomic.LoadInt64(&m.activeConnections)
}

// GetTotalConnections 获取总连接数
func (m *PhantomMetrics) GetTotalConnections() uint64 {
	return atomic.LoadUint64(&m.totalConnections)
}

// =============================================================================
// 流量统计方法
// =============================================================================

// AddBytesSent 增加发送字节数
func (m *PhantomMetrics) AddBytesSent(n int64) {
	if n > 0 {
		atomic.AddUint64(&m.bytesSent, uint64(n))
	}
}

// AddBytesReceived 增加接收字节数
func (m *PhantomMetrics) AddBytesReceived(n int64) {
	if n > 0 {
		atomic.AddUint64(&m.bytesReceived, uint64(n))
	}
}

// GetBytesSent 获取发送字节数
func (m *PhantomMetrics) GetBytesSent() uint64 {
	return atomic.LoadUint64(&m.bytesSent)
}

// GetBytesReceived 获取接收字节数
func (m *PhantomMetrics) GetBytesReceived() uint64 {
	return atomic.LoadUint64(&m.bytesReceived)
}

// GetTotalBytes 获取总传输字节数
func (m *PhantomMetrics) GetTotalBytes() uint64 {
	return m.GetBytesSent() + m.GetBytesReceived()
}

// =============================================================================
// 模式切换统计方法
// =============================================================================

// RecordModeSwitch 记录模式切换
func (m *PhantomMetrics) RecordModeSwitch(fromMode, toMode string) {
	atomic.AddUint64(&m.modeSwitches, 1)
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	record := ModeSwitchRecord{
		Timestamp: time.Now(),
		FromMode:  fromMode,
		ToMode:    toMode,
	}
	
	// 保留最近100条记录
	if len(m.switchHistory) >= 100 {
		m.switchHistory = m.switchHistory[1:]
	}
	m.switchHistory = append(m.switchHistory, record)
}

// GetModeSwitches 获取模式切换次数
func (m *PhantomMetrics) GetModeSwitches() uint64 {
	return atomic.LoadUint64(&m.modeSwitches)
}

// GetSwitchHistory 获取切换历史
func (m *PhantomMetrics) GetSwitchHistory(limit int) []ModeSwitchRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if limit <= 0 || limit > len(m.switchHistory) {
		limit = len(m.switchHistory)
	}
	
	// 返回最近的记录（倒序）
	result := make([]ModeSwitchRecord, limit)
	for i := 0; i < limit; i++ {
		result[i] = m.switchHistory[len(m.switchHistory)-1-i]
	}
	return result
}

// =============================================================================
// 综合统计方法
// =============================================================================

// GetUptime 获取运行时间
func (m *PhantomMetrics) GetUptime() time.Duration {
	return time.Since(m.startTime)
}

// GetStats 获取所有统计信息
func (m *PhantomMetrics) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"uptime":             m.GetUptime().String(),
		"active_connections": m.GetActiveConnections(),
		"total_connections":  m.GetTotalConnections(),
		"bytes_sent":         m.GetBytesSent(),
		"bytes_received":     m.GetBytesReceived(),
		"total_bytes":        m.GetTotalBytes(),
		"mode_switches":      m.GetModeSwitches(),
	}
}

// Reset 重置所有统计（用于测试）
func (m *PhantomMetrics) Reset() {
	atomic.StoreInt64(&m.activeConnections, 0)
	atomic.StoreUint64(&m.totalConnections, 0)
	atomic.StoreUint64(&m.bytesSent, 0)
	atomic.StoreUint64(&m.bytesReceived, 0)
	atomic.StoreUint64(&m.modeSwitches, 0)
	
	m.mu.Lock()
	m.switchHistory = make([]ModeSwitchRecord, 0, 100)
	m.startTime = time.Now()
	m.mu.Unlock()
}
