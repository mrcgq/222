

// =============================================================================
// 文件: internal/transport/arq_types.go
// 描述: ARQ 可靠传输 - 统一类型定义 (唯一定义位置)
// =============================================================================
package transport

import (
	"net"
	"time"
)

// ARQ 协议常量
const (
	// 包头大小: Seq(4) + Ack(4) + Flags(2) + Window(2) + Timestamp(4) + Len(2) = 18 bytes
	ARQHeaderSize     = 18
	ARQMaxPayloadSize = 1400 - ARQHeaderSize

	// 标志位 (2 bytes)
	ARQFlagACK  uint16 = 0x0001 // 确认包
	ARQFlagSYN  uint16 = 0x0002 // 同步包 (连接建立)
	ARQFlagFIN  uint16 = 0x0004 // 结束包 (连接关闭)
	ARQFlagDATA uint16 = 0x0008 // 数据包
	ARQFlagRST  uint16 = 0x0010 // 重置包
	ARQFlagPING uint16 = 0x0020 // 心跳包
	ARQFlagPONG uint16 = 0x0040 // 心跳响应
	ARQFlagSACK uint16 = 0x0080 // 选择性确认
	ARQFlagECN  uint16 = 0x0100 // ECN 拥塞通知
	ARQFlagURG  uint16 = 0x0200 // 紧急数据

	// 默认参数
	ARQDefaultWindowSize  = 256
	ARQDefaultMTU         = 1400
	ARQDefaultRTOMin      = 100 * time.Millisecond
	ARQDefaultRTOMax      = 10 * time.Second
	ARQDefaultRTOInit     = 200 * time.Millisecond
	ARQDefaultMaxRetries  = 10
	ARQDefaultKeepalive   = 15 * time.Second
	ARQDefaultIdleTimeout = 2 * time.Minute
	ARQDefaultAckDelay    = 25 * time.Millisecond
	ARQDefaultMaxAckDelay = 100 * time.Millisecond

	// SACK 参数
	ARQMaxSACKRanges = 4 // 最多 4 个 SACK 区间
	ARQSACKRangeSize = 8 // 每个区间 8 字节 (start + end)

	// 快速重传
	ARQFastRetransmitThreshold = 3 // 3 个重复 ACK 触发快速重传

	// 缓冲区大小
	ARQRecvBufferSize = 512
	ARQSendBufferSize = 512
	ARQRecvQueueSize  = 1024
)

// ARQState 连接状态
type ARQState uint8

const (
	ARQStateClosed ARQState = iota
	ARQStateListen
	ARQStateSynSent
	ARQStateSynReceived
	ARQStateEstablished
	ARQStateFinWait1
	ARQStateFinWait2
	ARQStateCloseWait
	ARQStateClosing
	ARQStateLastAck
	ARQStateTimeWait
)

func (s ARQState) String() string {
	names := []string{
		"CLOSED", "LISTEN", "SYN_SENT", "SYN_RECEIVED",
		"ESTABLISHED", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT",
		"CLOSING", "LAST_ACK", "TIME_WAIT",
	}
	if int(s) < len(names) {
		return names[s]
	}
	return "UNKNOWN"
}

// SACKRange 选择性确认区间
type SACKRange struct {
	Start uint32 // 起始序列号 (包含)
	End   uint32 // 结束序列号 (不包含)
}

// ARQPacketInfo 发送包信息 (用于重传追踪)
type ARQPacketInfo struct {
	Seq          uint32
	Data         []byte
	Size         int
	SentTime     time.Time
	RetransmitAt time.Time
	Retries      int
	Acked        bool
	Lost         bool
	InFlight     bool

	// 用于带宽估算
	DeliveredBytes int64
	DeliveredTime  time.Time
	FirstSent      bool
	IsRetransmit   bool
}

// ARQRecvPacketInfo 接收包信息
type ARQRecvPacketInfo struct {
	Seq        uint32
	Data       []byte
	ReceivedAt time.Time
	Delivered  bool
}

// ARQConnConfig ARQ 连接配置 (唯一定义)
type ARQConnConfig struct {
	MaxWindowSize   int
	MTU             int
	RTOMin          time.Duration
	RTOMax          time.Duration
	RTOInit         time.Duration
	MaxRetries      int
	Keepalive       time.Duration
	IdleTimeout     time.Duration
	AckDelay        time.Duration
	MaxAckDelay     time.Duration
	EnableSACK      bool
	EnableTimestamp bool
}

// DefaultARQConnConfig 默认配置 (唯一定义)
func DefaultARQConnConfig() *ARQConnConfig {
	return &ARQConnConfig{
		MaxWindowSize:   ARQDefaultWindowSize,
		MTU:             ARQDefaultMTU,
		RTOMin:          ARQDefaultRTOMin,
		RTOMax:          ARQDefaultRTOMax,
		RTOInit:         ARQDefaultRTOInit,
		MaxRetries:      ARQDefaultMaxRetries,
		Keepalive:       ARQDefaultKeepalive,
		IdleTimeout:     ARQDefaultIdleTimeout,
		AckDelay:        ARQDefaultAckDelay,
		MaxAckDelay:     ARQDefaultMaxAckDelay,
		EnableSACK:      true,
		EnableTimestamp: true,
	}
}

// ARQStats 连接统计
type ARQStats struct {
	// 基本统计
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64

	// 重传统计
	Retransmits        uint64
	FastRetransmits    uint64
	TimeoutRetransmits uint64
	PacketsLost        uint64

	// ACK 统计
	AcksSent     uint64
	AcksReceived uint64
	DupAcks      uint64

	// 窗口统计
	SendWindow    int
	RecvWindow    int
	BytesInFlight int64

	// RTT 统计
	SRTT   time.Duration
	RTTVar time.Duration
	RTO    time.Duration
	MinRTT time.Duration
	MaxRTT time.Duration

	// 连接状态
	State        string
	LastActivity time.Time
	Uptime       time.Duration
}

// ARQHandler 数据处理接口 (唯一定义)
type ARQHandler interface {
	// OnData 收到有序数据时调用
	OnData(data []byte, from *net.UDPAddr)

	// OnConnected 连接建立时调用
	OnConnected(addr *net.UDPAddr)

	// OnDisconnected 连接断开时调用
	OnDisconnected(addr *net.UDPAddr, reason error)
}


