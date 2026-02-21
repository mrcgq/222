//go:build !linux

// =============================================================================
// 文件: internal/transport/ebpf_types_other.go
// 描述: eBPF 类型定义 - 非 Linux 平台存根
// 注意: bpf2go 生成的类型在 phantom_stub.go 中定义
//       本文件仅定义辅助类型和函数
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

	// 地址族
	AFInetBPF  = 2
	AFInet6BPF = 10

	// 结构体大小常量
	SizeOfIpAddr       = 16
	SizeOfSessionKey   = 40
	SizeOfSessionValue = 88
	SizeOfGlobalConfig = 24
	SizeOfPortConfig   = 4
	SizeOfPacketEvent  = 48
)

// =============================================================================
// 类型别名 - 映射到存根类型
// =============================================================================

// EBPFStats 统计别名
type EBPFStats = PhantomStatsCounter

// EBPFSessionKey 会话键别名
type EBPFSessionKey = PhantomSessionKey

// EBPFSessionValue 会话值别名
type EBPFSessionValue = PhantomSessionValue

// EBPFPacketEvent 包事件
type EBPFPacketEvent struct {
	Timestamp uint64
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Action    uint8
	Flags     uint8
	Pad       uint8
}

// =============================================================================
// 配置类型
// =============================================================================

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

// =============================================================================
// Go 侧辅助类型
// =============================================================================

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
	Stats           EBPFStats
	ActiveSessions  int
	TotalSessions   uint64
	EventsProcessed uint64
	AvgLatencyNS    uint64
	Uptime          time.Duration
}

// =============================================================================
// IP 转换辅助函数
// =============================================================================

// IPToUint32 将 net.IP 转换为 uint32 (网络字节序)
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// Uint32ToIP 将 uint32 (网络字节序) 转换为 net.IP
func Uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// =============================================================================
// 网络字节序转换
// =============================================================================

// Htons 主机序转网络序 (16位)
func Htons(n uint16) uint16 {
	return (n<<8)&0xFF00 | (n>>8)&0x00FF
}

// Ntohs 网络序转主机序 (16位)
func Ntohs(n uint16) uint16 {
	return Htons(n)
}

// Htonl 主机序转网络序 (32位)
func Htonl(n uint32) uint32 {
	return (n<<24)&0xFF000000 | (n<<8)&0x00FF0000 | (n>>8)&0x0000FF00 | (n>>24)&0x000000FF
}

// Ntohl 网络序转主机序 (32位)
func Ntohl(n uint32) uint32 {
	return Htonl(n)
}
