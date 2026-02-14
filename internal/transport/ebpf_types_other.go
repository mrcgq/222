//go:build !linux

// =============================================================================
// 文件: internal/transport/ebpf_types_other.go
// 描述: eBPF 类型定义 - 非 Linux 平台存根
// =============================================================================
package transport

import (
	"net"
	"time"
)

// eBPF 常量 (存根)
const (
	EBPFMaxSessions    = 65536
	EBPFMaxPorts       = 16
	EBPFSessionTimeout = 5 * time.Minute

	// 状态
	EBPFStateNew         = 0
	EBPFStateHandshake   = 1
	EBPFStateEstablished = 2
	EBPFStateClosing     = 3
	EBPFStateClosed      = 4

	// XDP 动作
	XDPAborted  = 0
	XDPDrop     = 1
	XDPPass     = 2
	XDPTX       = 3
	XDPRedirect = 4

	// XDP 模式
	XDPModeNative  = "native"
	XDPModeGeneric = "generic"
	XDPModeOffload = "offload"
	XDPModeAuto    = "auto"
)

// EBPFSessionKey 会话键存根
type EBPFSessionKey struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
}

// EBPFSessionValue 会话值存根
type EBPFSessionValue struct {
	PeerIP     uint32
	PeerPort   uint16
	State      uint8
	Flags      uint8
	CreatedNS  uint64
	LastSeenNS uint64
	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint64
	PacketsOut uint64
	SeqLocal   uint32
	SeqRemote  uint32
}

// EBPFGlobalConfig 全局配置存根
type EBPFGlobalConfig struct {
	Magic           uint32
	ListenPort      uint16
	Mode            uint8
	LogLevel        uint8
	SessionTimeout  uint32
	MaxSessions     uint32
	EnableStats     uint8
	EnableConntrack uint8
	Reserved        [2]uint8
}

// EBPFStats 统计计数器存根
type EBPFStats struct {
	PacketsRX         uint64
	PacketsTX         uint64
	BytesRX           uint64
	BytesTX           uint64
	PacketsDropped    uint64
	PacketsPassed     uint64
	PacketsRedirected uint64
	SessionsCreated   uint64
	SessionsExpired   uint64
	SessionsDeleted   uint64
	Errors            uint64
	ChecksumErrors    uint64
	InvalidPackets    uint64
}

// EBPFPacketEvent 数据包事件存根
type EBPFPacketEvent struct {
	Timestamp uint64
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	Len       uint16
	Protocol  uint8
	Action    uint8
	State     uint8
	Flags     uint8
	Reserved  [2]uint8
}

// EBPFConfig eBPF 配置存根
type EBPFConfig struct {
	Enabled         bool
	Interface       string
	XDPMode         string
	ProgramPath     string
	MapSize         int
	EnableStats     bool
	ListenPorts     []uint16
	BatchSize       int
	PollTimeout     time.Duration
	CleanupInterval time.Duration
	LogLevel        string
}

// DefaultEBPFConfig 默认配置
func DefaultEBPFConfig() *EBPFConfig {
	return &EBPFConfig{
		Enabled:         false,
		Interface:       "eth0",
		XDPMode:         XDPModeAuto,
		ProgramPath:     "/opt/phantom/ebpf",
		MapSize:         65536,
		EnableStats:     true,
		ListenPorts:     []uint16{54321},
		BatchSize:       64,
		PollTimeout:     100 * time.Millisecond,
		CleanupInterval: 30 * time.Second,
		LogLevel:        "info",
	}
}

// EBPFSession Go 侧会话表示存根
type EBPFSession struct {
	Key        EBPFSessionKey
	Value      EBPFSessionValue
	LocalAddr  *net.UDPAddr
	RemoteAddr *net.UDPAddr
	State      int
	CreatedAt  time.Time
	LastSeen   time.Time
	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint64
	PacketsOut uint64
}

// EBPFAcceleratorStats 加速器统计存根
type EBPFAcceleratorStats struct {
	Active          bool
	XDPMode         string
	Interface       string
	ProgramLoaded   bool
	EBPFStats       EBPFStats
	ActiveSessions  int
	TotalSessions   uint64
	EventsProcessed uint64
	AvgLatencyNS    uint64
	Uptime          time.Duration
}

// IP 转换辅助函数
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func Uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// 网络字节序转换
func Htons(n uint16) uint16 {
	return (n<<8)&0xFF00 | (n>>8)&0x00FF
}

func Ntohs(n uint16) uint16 {
	return Htons(n)
}

func Htonl(n uint32) uint32 {
	return (n<<24)&0xFF000000 | (n<<8)&0x00FF0000 | (n>>8)&0x0000FF00 | (n>>24)&0x000000FF
}

func Ntohl(n uint32) uint32 {
	return Htonl(n)
}
