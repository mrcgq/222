

// =============================================================================
// 文件: internal/congestion/types.go
// 描述: 拥塞控制类型定义
// =============================================================================
package congestion

import (
	"time"
)

// CongestionController 拥塞控制器接口
type CongestionController interface {
	// 窗口控制
	GetCongestionWindow() int
	CanSend(packetSize int) bool

	// 事件回调
	OnPacketSent(packetNumber uint64, packetSize int, isRetransmit bool)
	OnPacketAcked(packetNumber uint64, ackedBytes int, rtt time.Duration)
	OnPacketLost(packetNumber uint64, lostBytes int)
	OnCongestionEvent(eventTime time.Time)

	// 发送控制
	GetPacingRate() float64
	GetPacingInterval(packetSize int) time.Duration

	// RTT
	GetRTT() time.Duration
	GetMinRTT() time.Duration
	GetLatestRTT() time.Duration

	// 统计
	GetStats() *CongestionStats
	GetBandwidth() float64
	GetLossRate() float64

	// 模式控制
	SetBrutalMode(enabled bool, rateMbps int)
	IsBrutalMode() bool

	// 重置
	Reset()
}

// CongestionStats 拥塞控制统计
type CongestionStats struct {
	// 窗口相关
	CongestionWindow int64   `json:"cwnd"`
	BytesInFlight    int64   `json:"bytes_in_flight"`
	MaxWindow        int64   `json:"max_window"`
	MinWindow        int64   `json:"min_window"`

	// RTT 相关
	SmoothedRTT time.Duration `json:"srtt"`
	MinRTT      time.Duration `json:"min_rtt"`
	LatestRTT   time.Duration `json:"latest_rtt"`
	RTTVariance time.Duration `json:"rtt_var"`

	// 带宽相关
	Bandwidth      float64 `json:"bandwidth_bps"`
	PacingRate     float64 `json:"pacing_rate_bps"`
	DeliveryRate   float64 `json:"delivery_rate_bps"`
	BandwidthMbps  float64 `json:"bandwidth_mbps"`

	// 丢包相关
	LossRate       float64 `json:"loss_rate"`
	TotalPackets   uint64  `json:"total_packets"`
	LostPackets    uint64  `json:"lost_packets"`
	RetransmitPkts uint64  `json:"retransmit_packets"`

	// 模式
	BrutalMode bool    `json:"brutal_mode"`
	BrutalRate float64 `json:"brutal_rate_bps"`

	// 状态
	State           string `json:"state"`
	SlowStartExit   bool   `json:"slow_start_exit"`
	InRecovery      bool   `json:"in_recovery"`
	RecoveryEndTime int64  `json:"recovery_end_time_ms"`
}

// PacketInfo 数据包信息（用于追踪）
type PacketInfo struct {
	PacketNumber  uint64
	Size          int
	SentTime      time.Time
	IsRetransmit  bool
	InFlight      bool
	Acked         bool
	Lost          bool
	DeliveredTime time.Time
	DeliveredBytes int64
}

// BandwidthSample 带宽采样
type BandwidthSample struct {
	Bandwidth    float64
	RTT          time.Duration
	IsAppLimited bool
	Timestamp    time.Time
}

// AckInfo ACK 信息
type AckInfo struct {
	PacketNumber   uint64
	AckedBytes     int
	RTT            time.Duration
	ReceiveTime    time.Time
	DeliveredBytes int64
	DeliveredTime  time.Time
}

// LossInfo 丢包信息
type LossInfo struct {
	PacketNumber uint64
	LostBytes    int
	Reason       LossReason
	DetectTime   time.Time
}

// LossReason 丢包原因
type LossReason int

const (
	LossReasonTimeout LossReason = iota
	LossReasonReorder
	LossReasonECN
)

// CongestionState 拥塞状态
type CongestionState int

const (
	StateSlowStart CongestionState = iota
	StateCongestionAvoidance
	StateRecovery
	StateDrain
	StateProbeBW
	StateProbeRTT
)

func (s CongestionState) String() string {
	switch s {
	case StateSlowStart:
		return "slow_start"
	case StateCongestionAvoidance:
		return "congestion_avoidance"
	case StateRecovery:
		return "recovery"
	case StateDrain:
		return "drain"
	case StateProbeBW:
		return "probe_bw"
	case StateProbeRTT:
		return "probe_rtt"
	default:
		return "unknown"
	}
}

