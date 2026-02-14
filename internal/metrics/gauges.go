



// =============================================================================
// 文件: internal/metrics/gauges.go
// 描述: 实时埋点指标（Counter/Gauge/Histogram）
// =============================================================================
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// PhantomMetrics 全局指标集合
type PhantomMetrics struct {
	// 连接相关
	ActiveConnections prometheus.Gauge
	ConnectionsTotal  *prometheus.CounterVec

	// 流量相关
	BytesReceived *prometheus.CounterVec
	BytesSent     *prometheus.CounterVec
	PacketsTotal  *prometheus.CounterVec

	// 延迟相关
	PacketLatency *prometheus.HistogramVec
	RTT           *prometheus.GaugeVec

	// 错误相关
	Errors *prometheus.CounterVec

	// 模式切换
	ModeSwitches *prometheus.CounterVec

	// ARQ 相关
	ARQRetransmits  prometheus.Counter
	ARQAckLatency   prometheus.Histogram
	ARQWindowSize   prometheus.Gauge
	ARQPacketLoss   prometheus.Gauge

	// 拥塞控制
	CongestionWindow prometheus.Gauge
	SendRate         prometheus.Gauge
}

// NewPhantomMetrics 创建指标集合
func NewPhantomMetrics(registry *prometheus.Registry) *PhantomMetrics {
	m := &PhantomMetrics{
		ActiveConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "phantom",
			Name:      "active_connections",
			Help:      "Number of currently active connections",
		}),

		ConnectionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "phantom",
			Name:      "connections_total",
			Help:      "Total number of connections",
		}, []string{"mode", "status"}),

		BytesReceived: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "phantom",
			Name:      "bytes_received_total",
			Help:      "Total bytes received",
		}, []string{"mode"}),

		BytesSent: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "phantom",
			Name:      "bytes_sent_total",
			Help:      "Total bytes sent",
		}, []string{"mode"}),

		PacketsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "phantom",
			Name:      "packets_total",
			Help:      "Total packets processed",
		}, []string{"mode", "direction"}),

		PacketLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "phantom",
			Name:      "packet_latency_seconds",
			Help:      "Packet processing latency",
			Buckets:   []float64{.0001, .0005, .001, .005, .01, .025, .05, .1, .25, .5, 1},
		}, []string{"mode"}),

		RTT: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "phantom",
			Name:      "rtt_seconds",
			Help:      "Current RTT to peer",
		}, []string{"mode"}),

		Errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "phantom",
			Name:      "errors_total",
			Help:      "Total errors by type",
		}, []string{"type"}),

		ModeSwitches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "phantom",
			Subsystem: "switcher",
			Name:      "mode_switches_total",
			Help:      "Total mode switches",
		}, []string{"from", "to", "reason"}),

		ARQRetransmits: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "phantom",
			Subsystem: "arq",
			Name:      "retransmits_total",
			Help:      "Total ARQ retransmissions",
		}),

		ARQAckLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "phantom",
			Subsystem: "arq",
			Name:      "ack_latency_seconds",
			Help:      "ARQ acknowledgement latency",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5},
		}),

		ARQWindowSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "phantom",
			Subsystem: "arq",
			Name:      "window_size",
			Help:      "Current ARQ window size",
		}),

		ARQPacketLoss: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "phantom",
			Subsystem: "arq",
			Name:      "packet_loss_rate",
			Help:      "Current packet loss rate",
		}),

		CongestionWindow: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "phantom",
			Subsystem: "congestion",
			Name:      "window_bytes",
			Help:      "Current congestion window size in bytes",
		}),

		SendRate: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "phantom",
			Subsystem: "congestion",
			Name:      "send_rate_bytes_per_second",
			Help:      "Current send rate",
		}),
	}

	// 注册所有指标
	registry.MustRegister(
		m.ActiveConnections,
		m.ConnectionsTotal,
		m.BytesReceived,
		m.BytesSent,
		m.PacketsTotal,
		m.PacketLatency,
		m.RTT,
		m.Errors,
		m.ModeSwitches,
		m.ARQRetransmits,
		m.ARQAckLatency,
		m.ARQWindowSize,
		m.ARQPacketLoss,
		m.CongestionWindow,
		m.SendRate,
	)

	return m
}

// RecordConnection 记录连接
func (m *PhantomMetrics) RecordConnection(mode, status string) {
	m.ConnectionsTotal.WithLabelValues(mode, status).Inc()
	if status == "opened" {
		m.ActiveConnections.Inc()
	} else if status == "closed" {
		m.ActiveConnections.Dec()
	}
}

// RecordBytes 记录流量
func (m *PhantomMetrics) RecordBytes(mode string, received, sent uint64) {
	m.BytesReceived.WithLabelValues(mode).Add(float64(received))
	m.BytesSent.WithLabelValues(mode).Add(float64(sent))
}

// RecordPacket 记录数据包
func (m *PhantomMetrics) RecordPacket(mode, direction string) {
	m.PacketsTotal.WithLabelValues(mode, direction).Inc()
}

// RecordLatency 记录延迟
func (m *PhantomMetrics) RecordLatency(mode string, latencySeconds float64) {
	m.PacketLatency.WithLabelValues(mode).Observe(latencySeconds)
}

// RecordRTT 记录 RTT
func (m *PhantomMetrics) RecordRTT(mode string, rttSeconds float64) {
	m.RTT.WithLabelValues(mode).Set(rttSeconds)
}

// RecordError 记录错误
func (m *PhantomMetrics) RecordError(errorType string) {
	m.Errors.WithLabelValues(errorType).Inc()
}

// RecordModeSwitch 记录模式切换
func (m *PhantomMetrics) RecordModeSwitch(from, to, reason string) {
	m.ModeSwitches.WithLabelValues(from, to, reason).Inc()
}

// RecordARQRetransmit 记录 ARQ 重传
func (m *PhantomMetrics) RecordARQRetransmit() {
	m.ARQRetransmits.Inc()
}

// RecordARQAck 记录 ARQ ACK 延迟
func (m *PhantomMetrics) RecordARQAck(latencySeconds float64) {
	m.ARQAckLatency.Observe(latencySeconds)
}

// UpdateARQStats 更新 ARQ 统计
func (m *PhantomMetrics) UpdateARQStats(windowSize int, lossRate float64) {
	m.ARQWindowSize.Set(float64(windowSize))
	m.ARQPacketLoss.Set(lossRate)
}

// UpdateCongestionStats 更新拥塞控制统计
func (m *PhantomMetrics) UpdateCongestionStats(cwnd uint64, sendRate float64) {
	m.CongestionWindow.Set(float64(cwnd))
	m.SendRate.Set(sendRate)
}






