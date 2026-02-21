// =============================================================================
// 文件: internal/switcher/types.go
// 描述: 智能链路切换 - 类型定义
// =============================================================================

package switcher

import (
	"net"
	"time"
)

// =============================================================================
// 传输模式
// =============================================================================

// TransportMode 传输模式
type TransportMode string

const (
	ModeUDP       TransportMode = "udp"
	ModeTCP       TransportMode = "tcp"
	ModeFakeTCP   TransportMode = "faketcp"
	ModeWebSocket TransportMode = "websocket"
	ModeEBPF      TransportMode = "ebpf"
)

// AllModes 所有模式列表
var AllModes = []TransportMode{ModeUDP, ModeTCP, ModeFakeTCP, ModeWebSocket, ModeEBPF}

// String 返回模式字符串
func (m TransportMode) String() string {
	return string(m)
}

// =============================================================================
// 传输状态
// =============================================================================

// TransportState 传输状态
type TransportState int

const (
	StateUnknown TransportState = iota
	StateRunning
	StateDegraded
	StateFailed
	StateStopped
)

// String 返回状态字符串
func (s TransportState) String() string {
	switch s {
	case StateRunning:
		return "running"
	case StateDegraded:
		return "degraded"
	case StateFailed:
		return "failed"
	case StateStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// =============================================================================
// 切换原因
// =============================================================================

// SwitchReason 切换原因
type SwitchReason string

const (
	ReasonManual      SwitchReason = "manual"
	ReasonHighLatency SwitchReason = "high_latency"
	ReasonHighLoss    SwitchReason = "high_loss"
	ReasonFailed      SwitchReason = "failed"
	ReasonRecovered   SwitchReason = "recovered"
	ReasonProbe       SwitchReason = "probe"
	ReasonCooldown    SwitchReason = "cooldown"
	ReasonBetter      SwitchReason = "better_option"
)

// String 返回原因字符串
func (r SwitchReason) String() string {
	return string(r)
}

// =============================================================================
// 传输处理器接口
// =============================================================================

// TransportHandler 传输处理器接口
type TransportHandler interface {
	// Send 发送数据到指定地址
	Send(data []byte, addr *net.UDPAddr) error

	// IsRunning 检查是否运行中
	IsRunning() bool

	// GetStats 获取统计信息
	GetStats() TransportStats

	// Probe 探测连接质量，返回 RTT
	Probe() (time.Duration, error)
}

// TransportStats 传输统计
type TransportStats struct {
	BytesSent     int64
	BytesReceived int64
	PacketsSent   int64
	PacketsRecv   int64
	Errors        int64
	ActiveConns   int
	LastActivity  time.Time
}

// =============================================================================
// 模式统计
// =============================================================================

// ModeStats 模式统计
type ModeStats struct {
	Mode           TransportMode
	State          TransportState
	Quality        QualityInfo
	TotalTime      time.Duration
	LastActive     time.Time
	SwitchInCount  int
	SwitchOutCount int
	FailCount      int
	SuccessCount   int
}

// QualityInfo 质量信息
type QualityInfo struct {
	RTT       time.Duration
	Loss      float64
	Jitter    time.Duration
	Bandwidth int64
	State     TransportState
	Score     float64
}

// =============================================================================
// 切换事件
// =============================================================================

// SwitchEvent 切换事件
type SwitchEvent struct {
	Timestamp time.Time
	FromMode  TransportMode
	ToMode    TransportMode
	Reason    SwitchReason
	Success   bool
	Duration  time.Duration
	Error     error
}

// =============================================================================
// 切换器统计
// =============================================================================

// SwitcherStats 切换器统计
type SwitcherStats struct {
	// 当前状态
	CurrentMode     TransportMode
	CurrentState    TransportState
	CurrentQuality  QualityInfo
	CurrentModeTime time.Duration

	// 切换统计
	TotalSwitches    uint64
	SuccessSwitches  uint64
	FailedSwitches   uint64
	LastSwitch       time.Time
	LastSwitchReason SwitchReason

	// 模式统计
	ModeStats map[TransportMode]*ModeStats

	// ARQ 统计
	ARQEnabled     bool
	ARQActiveConns int

	// eBPF 统计
	EBPFStats map[string]uint64

	// 运行时间
	Uptime time.Duration
}

// =============================================================================
// 配置
// =============================================================================

// SwitcherConfig 切换器配置
type SwitcherConfig struct {
	// 基础配置
	Enabled           bool
	CheckInterval     time.Duration
	RTTThreshold      time.Duration
	LossThreshold     float64
	FailThreshold     int
	RecoverThreshold  int
	MinSwitchInterval time.Duration
	MaxSwitchRate     int
	CooldownPeriod    time.Duration

	// 回退配置
	EnableFallback bool
	FallbackMode   TransportMode

	// 探测配置
	EnableProbe     bool
	ProbeInterval   time.Duration
	ProbePacketSize int
	ProbeCount      int
	ProbeTimeout    time.Duration

	// 优先级
	Priority []TransportMode

	// 日志
	LogLevel string
}

// =============================================================================
// 决策结果
// =============================================================================

// SwitchDecision 切换决策
type SwitchDecision struct {
	ShouldSwitch bool
	TargetMode   TransportMode
	Reason       SwitchReason
	Confidence   float64
}

// ProbeResult 探测结果
type ProbeResult struct {
	Mode      TransportMode
	RTT       time.Duration
	Loss      float64
	Available bool
	Error     error
	Timestamp time.Time
}
