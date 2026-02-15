

// =============================================================================
// 文件: internal/switcher/types.go
// 描述: 智能链路切换 - 类型定义 (ARQ 已从独立模式中移除)
//       新增：eBPF 端口独占状态标记
// =============================================================================
package switcher

import (
	"net"
	"time"
)

// TransportMode 传输模式 (不含 ARQ，ARQ 是 UDP 的增强层)
type TransportMode string

const (
	ModeAuto      TransportMode = "auto"
	ModeUDP       TransportMode = "udp"
	ModeTCP       TransportMode = "tcp"
	ModeFakeTCP   TransportMode = "faketcp"
	ModeWebSocket TransportMode = "websocket"
	ModeEBPF      TransportMode = "ebpf"
)

// AllModes 所有支持的模式 (不含 ARQ)
var AllModes = []TransportMode{
	ModeEBPF,
	ModeFakeTCP,
	ModeUDP,
	ModeTCP,
	ModeWebSocket,
}

// TransportState 传输层状态
type TransportState int

const (
	StateUnknown TransportState = iota
	StateStarting
	StateRunning
	StateDegraded
	StateFailed
	StateStopped
)

func (s TransportState) String() string {
	names := []string{"unknown", "starting", "running", "degraded", "failed", "stopped"}
	if int(s) < len(names) {
		return names[s]
	}
	return "unknown"
}

// PortOwnership 端口所有权状态
type PortOwnership int

const (
	PortOwnerNone    PortOwnership = iota // 无所有者
	PortOwnerUDP                          // UDP 独占
	PortOwnerEBPF                         // eBPF 独占
	PortOwnerShared                       // 共享 (理论上不应该发生)
)

func (p PortOwnership) String() string {
	names := []string{"none", "udp", "ebpf", "shared"}
	if int(p) < len(names) {
		return names[p]
	}
	return "unknown"
}

// LinkQuality 链路质量
type LinkQuality struct {
	Available            bool
	State                TransportState
	LastCheck            time.Time
	LastSuccess          time.Time
	LastFailure          time.Time
	RTT                  time.Duration
	MinRTT               time.Duration
	MaxRTT               time.Duration
	AvgRTT               time.Duration
	RTTJitter            time.Duration
	LossRate             float64
	RecentLosses         int
	TotalLosses          uint64
	TotalPackets         uint64
	Throughput           float64
	PeakThroughput       float64
	AvgThroughput        float64
	ActiveConns          int
	TotalConns           uint64
	FailedConns          uint64
	ConsecutiveFailures  int
	ConsecutiveSuccesses int
	ErrorCount           uint64
	Score                float64
}

// SwitchEvent 切换事件
type SwitchEvent struct {
	Timestamp time.Time
	FromMode  TransportMode
	ToMode    TransportMode
	Reason    SwitchReason
	Quality   *LinkQuality
	Success   bool
	Duration  time.Duration
}

// SwitchReason 切换原因
type SwitchReason int

const (
	ReasonNone SwitchReason = iota
	ReasonInitial
	ReasonHighRTT
	ReasonHighLoss
	ReasonLowThroughput
	ReasonConnectionFailed
	ReasonTimeout
	ReasonManual
	ReasonRecovery
	ReasonProbe
	ReasonDegraded
)

func (r SwitchReason) String() string {
	names := []string{
		"none", "initial", "high_rtt", "high_loss", "low_throughput",
		"connection_failed", "timeout", "manual", "recovery", "probe", "degraded",
	}
	if int(r) < len(names) {
		return names[r]
	}
	return "unknown"
}

// SwitchDecision 切换决策
type SwitchDecision struct {
	ShouldSwitch bool
	TargetMode   TransportMode
	Reason       SwitchReason
	Confidence   float64
	Alternatives []TransportMode
}

// SwitcherConfig 切换器内部配置
type SwitcherConfig struct {
	Enabled             bool
	CheckInterval       time.Duration
	ProbeInterval       time.Duration
	RecoveryInterval    time.Duration
	RTTThreshold        time.Duration
	LossThreshold       float64
	ThroughputThreshold float64
	FailThreshold       int
	RecoverThreshold    int
	MinSwitchInterval   time.Duration
	MaxSwitchRate       float64
	CooldownPeriod      time.Duration
	Priority            []TransportMode
	EnableFallback      bool
	FallbackMode        TransportMode
	FallbackTimeout     time.Duration
	EnableProbe         bool
	ProbePacketSize     int
	ProbeCount          int
	ProbeTimeout        time.Duration
	LogLevel            string
}

// DefaultSwitcherConfig 默认配置
func DefaultSwitcherConfig() *SwitcherConfig {
	return &SwitcherConfig{
		Enabled:             true,
		CheckInterval:       time.Second,
		ProbeInterval:       30 * time.Second,
		RecoveryInterval:    10 * time.Second,
		RTTThreshold:        300 * time.Millisecond,
		LossThreshold:       0.10,
		ThroughputThreshold: 100 * 1024,
		FailThreshold:       3,
		RecoverThreshold:    5,
		MinSwitchInterval:   5 * time.Second,
		MaxSwitchRate:       6,
		CooldownPeriod:      10 * time.Second,
		Priority: []TransportMode{
			ModeEBPF,
			ModeFakeTCP,
			ModeUDP,
			ModeWebSocket,
		},
		EnableFallback:  true,
		FallbackMode:    ModeWebSocket,
		FallbackTimeout: 30 * time.Second,
		EnableProbe:     true,
		ProbePacketSize: 64,
		ProbeCount:      3,
		ProbeTimeout:    5 * time.Second,
		LogLevel:        "info",
	}
}

// TransportHandler 传输层处理接口
type TransportHandler interface {
	Start() error
	Stop() error
	IsRunning() bool
	Send(data []byte, addr *net.UDPAddr) error
	GetState() TransportState
	GetQuality() *LinkQuality
	GetStats() map[string]interface{}
	Probe(addr *net.UDPAddr) (time.Duration, error)
}

// SwitcherStats 切换器统计
type SwitcherStats struct {
	CurrentMode      TransportMode
	CurrentState     TransportState
	CurrentQuality   *LinkQuality
	TotalSwitches    uint64
	SuccessSwitches  uint64
	FailedSwitches   uint64
	LastSwitch       time.Time
	LastSwitchReason SwitchReason
	ModeStats        map[TransportMode]*ModeStats
	Uptime           time.Duration
	CurrentModeTime  time.Duration
	ARQEnabled       bool
	ARQActiveConns   int64
	PortOwnership    PortOwnership // 新增：端口所有权状态
}

// ModeStats 模式统计
type ModeStats struct {
	Mode           TransportMode
	State          TransportState
	Quality        *LinkQuality
	TotalTime      time.Duration
	SwitchInCount  uint64
	SwitchOutCount uint64
	FailureCount   uint64
	LastActive     time.Time
}

