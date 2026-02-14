

// =============================================================================
// 文件: internal/metrics/collectors.go
// 描述: Prometheus 指标收集器定义
// =============================================================================
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// =============================================================================
// Switcher 收集器
// =============================================================================

// SwitcherStats Switcher 统计数据接口
type SwitcherStats interface {
	GetCurrentMode() string
	GetCurrentState() string
	GetTotalSwitches() uint64
	GetSuccessSwitches() uint64
	GetFailedSwitches() uint64
	GetUptimeSeconds() float64
	GetCurrentModeTimeSeconds() float64
	IsARQEnabled() bool
	GetARQActiveConns() int
	GetModeStats() map[string]ModeStatData
}

// ModeStatData 模式统计数据
type ModeStatData struct {
	State          string
	SwitchInCount  uint64
	SwitchOutCount uint64
	FailureCount   uint64
	TotalTimeSec   float64
	RTTMs          float64
	LossRate       float64
	TotalPackets   uint64
}

// SwitcherCollector Switcher 指标收集器
type SwitcherCollector struct {
	statsProvider SwitcherStats

	// 描述符
	currentModeDesc     *prometheus.Desc
	currentStateDesc    *prometheus.Desc
	totalSwitchesDesc   *prometheus.Desc
	successSwitchesDesc *prometheus.Desc
	failedSwitchesDesc  *prometheus.Desc
	uptimeDesc          *prometheus.Desc
	modeTimeDesc        *prometheus.Desc
	arqEnabledDesc      *prometheus.Desc
	arqActiveConnsDesc  *prometheus.Desc

	// 模式相关
	modeSwitchInDesc   *prometheus.Desc
	modeSwitchOutDesc  *prometheus.Desc
	modeFailureDesc    *prometheus.Desc
	modeTotalTimeDesc  *prometheus.Desc
	modeRTTDesc        *prometheus.Desc
	modeLossRateDesc   *prometheus.Desc
	modeTotalPktsDesc  *prometheus.Desc
}

// NewSwitcherCollector 创建 Switcher 收集器
func NewSwitcherCollector(provider SwitcherStats) *SwitcherCollector {
	namespace := "phantom"
	subsystem := "switcher"

	return &SwitcherCollector{
		statsProvider: provider,

		currentModeDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "current_mode"),
			"Current transport mode (1 = active)",
			[]string{"mode"}, nil,
		),
		currentStateDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "current_state"),
			"Current switcher state (1 = active)",
			[]string{"state"}, nil,
		),
		totalSwitchesDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "switches_total"),
			"Total number of mode switches",
			nil, nil,
		),
		successSwitchesDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "switches_success_total"),
			"Total successful mode switches",
			nil, nil,
		),
		failedSwitchesDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "switches_failed_total"),
			"Total failed mode switches",
			nil, nil,
		),
		uptimeDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "uptime_seconds"),
			"Switcher uptime in seconds",
			nil, nil,
		),
		modeTimeDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "current_mode_duration_seconds"),
			"Time spent in current mode",
			nil, nil,
		),
		arqEnabledDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "arq_enabled"),
			"Whether ARQ is enabled (1 = yes)",
			nil, nil,
		),
		arqActiveConnsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "arq_active_connections"),
			"Number of active ARQ connections",
			nil, nil,
		),

		// 模式相关
		modeSwitchInDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "mode_switch_in_total"),
			"Number of switches into this mode",
			[]string{"mode"}, nil,
		),
		modeSwitchOutDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "mode_switch_out_total"),
			"Number of switches out of this mode",
			[]string{"mode"}, nil,
		),
		modeFailureDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "mode_failures_total"),
			"Number of failures in this mode",
			[]string{"mode"}, nil,
		),
		modeTotalTimeDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "mode_total_time_seconds"),
			"Total time spent in this mode",
			[]string{"mode"}, nil,
		),
		modeRTTDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "mode_rtt_milliseconds"),
			"Current RTT for this mode",
			[]string{"mode"}, nil,
		),
		modeLossRateDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "mode_loss_rate"),
			"Current packet loss rate for this mode",
			[]string{"mode"}, nil,
		),
		modeTotalPktsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "mode_packets_total"),
			"Total packets processed in this mode",
			[]string{"mode"}, nil,
		),
	}
}

// Describe 实现 prometheus.Collector 接口
func (c *SwitcherCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.currentModeDesc
	ch <- c.currentStateDesc
	ch <- c.totalSwitchesDesc
	ch <- c.successSwitchesDesc
	ch <- c.failedSwitchesDesc
	ch <- c.uptimeDesc
	ch <- c.modeTimeDesc
	ch <- c.arqEnabledDesc
	ch <- c.arqActiveConnsDesc
	ch <- c.modeSwitchInDesc
	ch <- c.modeSwitchOutDesc
	ch <- c.modeFailureDesc
	ch <- c.modeTotalTimeDesc
	ch <- c.modeRTTDesc
	ch <- c.modeLossRateDesc
	ch <- c.modeTotalPktsDesc
}

// Collect 实现 prometheus.Collector 接口
func (c *SwitcherCollector) Collect(ch chan<- prometheus.Metric) {
	// 当前模式
	currentMode := c.statsProvider.GetCurrentMode()
	for _, mode := range []string{"udp", "faketcp", "websocket", "ebpf"} {
		val := 0.0
		if mode == currentMode {
			val = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.currentModeDesc, prometheus.GaugeValue, val, mode)
	}

	// 当前状态
	currentState := c.statsProvider.GetCurrentState()
	for _, state := range []string{"idle", "running", "switching", "degraded", "failed"} {
		val := 0.0
		if state == currentState {
			val = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.currentStateDesc, prometheus.GaugeValue, val, state)
	}

	// 切换统计
	ch <- prometheus.MustNewConstMetric(c.totalSwitchesDesc, prometheus.CounterValue,
		float64(c.statsProvider.GetTotalSwitches()))
	ch <- prometheus.MustNewConstMetric(c.successSwitchesDesc, prometheus.CounterValue,
		float64(c.statsProvider.GetSuccessSwitches()))
	ch <- prometheus.MustNewConstMetric(c.failedSwitchesDesc, prometheus.CounterValue,
		float64(c.statsProvider.GetFailedSwitches()))

	// 时间统计
	ch <- prometheus.MustNewConstMetric(c.uptimeDesc, prometheus.GaugeValue,
		c.statsProvider.GetUptimeSeconds())
	ch <- prometheus.MustNewConstMetric(c.modeTimeDesc, prometheus.GaugeValue,
		c.statsProvider.GetCurrentModeTimeSeconds())

	// ARQ 状态
	arqEnabled := 0.0
	if c.statsProvider.IsARQEnabled() {
		arqEnabled = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.arqEnabledDesc, prometheus.GaugeValue, arqEnabled)
	ch <- prometheus.MustNewConstMetric(c.arqActiveConnsDesc, prometheus.GaugeValue,
		float64(c.statsProvider.GetARQActiveConns()))

	// 各模式统计
	for mode, stats := range c.statsProvider.GetModeStats() {
		ch <- prometheus.MustNewConstMetric(c.modeSwitchInDesc, prometheus.CounterValue,
			float64(stats.SwitchInCount), mode)
		ch <- prometheus.MustNewConstMetric(c.modeSwitchOutDesc, prometheus.CounterValue,
			float64(stats.SwitchOutCount), mode)
		ch <- prometheus.MustNewConstMetric(c.modeFailureDesc, prometheus.CounterValue,
			float64(stats.FailureCount), mode)
		ch <- prometheus.MustNewConstMetric(c.modeTotalTimeDesc, prometheus.CounterValue,
			stats.TotalTimeSec, mode)
		ch <- prometheus.MustNewConstMetric(c.modeRTTDesc, prometheus.GaugeValue,
			stats.RTTMs, mode)
		ch <- prometheus.MustNewConstMetric(c.modeLossRateDesc, prometheus.GaugeValue,
			stats.LossRate, mode)
		ch <- prometheus.MustNewConstMetric(c.modeTotalPktsDesc, prometheus.CounterValue,
			float64(stats.TotalPackets), mode)
	}
}

// =============================================================================
// Handler 收集器
// =============================================================================

// HandlerStats Handler 统计数据接口
type HandlerStats interface {
	GetActiveConnections() int64
	GetTotalConnections() uint64
	GetTotalPacketsIn() uint64
	GetTotalPacketsOut() uint64
	GetTotalBytesIn() uint64
	GetTotalBytesOut() uint64
	GetAuthSuccessCount() uint64
	GetAuthFailureCount() uint64
	GetDecryptErrors() uint64
	GetReplayAttacks() uint64
}

// HandlerCollector Handler 指标收集器
type HandlerCollector struct {
	statsProvider HandlerStats

	activeConnsDesc    *prometheus.Desc
	totalConnsDesc     *prometheus.Desc
	packetsInDesc      *prometheus.Desc
	packetsOutDesc     *prometheus.Desc
	bytesInDesc        *prometheus.Desc
	bytesOutDesc       *prometheus.Desc
	authSuccessDesc    *prometheus.Desc
	authFailureDesc    *prometheus.Desc
	decryptErrorsDesc  *prometheus.Desc
	replayAttacksDesc  *prometheus.Desc
}

// NewHandlerCollector 创建 Handler 收集器
func NewHandlerCollector(provider HandlerStats) *HandlerCollector {
	namespace := "phantom"
	subsystem := "handler"

	return &HandlerCollector{
		statsProvider: provider,

		activeConnsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "active_connections"),
			"Number of active connections",
			nil, nil,
		),
		totalConnsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "connections_total"),
			"Total connections handled",
			nil, nil,
		),
		packetsInDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "packets_received_total"),
			"Total packets received",
			nil, nil,
		),
		packetsOutDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "packets_sent_total"),
			"Total packets sent",
			nil, nil,
		),
		bytesInDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "bytes_received_total"),
			"Total bytes received",
			nil, nil,
		),
		bytesOutDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "bytes_sent_total"),
			"Total bytes sent",
			nil, nil,
		),
		authSuccessDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "auth_success_total"),
			"Total successful authentications",
			nil, nil,
		),
		authFailureDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "auth_failure_total"),
			"Total failed authentications",
			nil, nil,
		),
		decryptErrorsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "decrypt_errors_total"),
			"Total decryption errors",
			nil, nil,
		),
		replayAttacksDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "replay_attacks_total"),
			"Total replay attacks detected",
			nil, nil,
		),
	}
}

// Describe 实现 prometheus.Collector 接口
func (c *HandlerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.activeConnsDesc
	ch <- c.totalConnsDesc
	ch <- c.packetsInDesc
	ch <- c.packetsOutDesc
	ch <- c.bytesInDesc
	ch <- c.bytesOutDesc
	ch <- c.authSuccessDesc
	ch <- c.authFailureDesc
	ch <- c.decryptErrorsDesc
	ch <- c.replayAttacksDesc
}

// Collect 实现 prometheus.Collector 接口
func (c *HandlerCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.activeConnsDesc, prometheus.GaugeValue,
		float64(c.statsProvider.GetActiveConnections()))
	ch <- prometheus.MustNewConstMetric(c.totalConnsDesc, prometheus.CounterValue,
		float64(c.statsProvider.GetTotalConnections()))
	ch <- prometheus.MustNewConstMetric(c.packetsInDesc, prometheus.CounterValue,
		float64(c.statsProvider.GetTotalPacketsIn()))
	ch <- prometheus.MustNewConstMetric(c.packetsOutDesc, prometheus.CounterValue,
		float64(c.statsProvider.GetTotalPacketsOut()))
	ch <- prometheus.MustNewConstMetric(c.bytesInDesc, prometheus.CounterValue,
		float64(c.statsProvider.GetTotalBytesIn()))
	ch <- prometheus.MustNewConstMetric(c.bytesOutDesc, prometheus.CounterValue,
		float64(c.statsProvider.GetTotalBytesOut()))
	ch <- prometheus.MustNewConstMetric(c.authSuccessDesc, prometheus.CounterValue,
		float64(c.statsProvider.GetAuthSuccessCount()))
	ch <- prometheus.MustNewConstMetric(c.authFailureDesc, prometheus.CounterValue,
		float64(c.statsProvider.GetAuthFailureCount()))
	ch <- prometheus.MustNewConstMetric(c.decryptErrorsDesc, prometheus.CounterValue,
		float64(c.statsProvider.GetDecryptErrors()))
	ch <- prometheus.MustNewConstMetric(c.replayAttacksDesc, prometheus.CounterValue,
		float64(c.statsProvider.GetReplayAttacks()))
}



