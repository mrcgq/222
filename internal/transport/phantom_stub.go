//go:build !linux

// =============================================================================
// 文件: internal/transport/phantom_stub.go
// 描述: 非 Linux 平台的 eBPF 存根 - 仅包含 bpf2go 相关类型
// =============================================================================

package transport

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// =============================================================================
// eBPF 对象存根
// =============================================================================

// PhantomObjects 存根
type PhantomObjects struct {
	PhantomPrograms
	PhantomMaps
}

// Close 关闭所有对象
func (o *PhantomObjects) Close() error {
	return nil
}

// PhantomMaps 存根
type PhantomMaps struct {
	Sessions    *ebpf.Map
	ListenPorts *ebpf.Map
	Config      *ebpf.Map
	Stats       *ebpf.Map
	Events      *ebpf.Map
	BlacklistV4 *ebpf.Map
	BlacklistV6 *ebpf.Map
	RatelimitV4 *ebpf.Map
	RatelimitV6 *ebpf.Map
	TxPorts     *ebpf.Map
}

// PhantomPrograms 存根
type PhantomPrograms struct {
	XdpPhantomMain   *ebpf.Program
	XdpPhantomFast   *ebpf.Program
	XdpPhantomFilter *ebpf.Program
}

// LoadPhantom 加载 eBPF 程序规格 (存根)
func LoadPhantom() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("eBPF not supported on this platform")
}

// LoadPhantomFromPath 从指定路径加载 (存根)
func LoadPhantomFromPath(path string) (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("eBPF not supported on this platform")
}

// =============================================================================
// 数据结构存根 (bpf2go 生成的类型)
// =============================================================================

// PhantomIpAddr IP 地址存根
type PhantomIpAddr struct {
	V4  uint32
	Pad [12]uint8
}

// PhantomSessionKey 会话键存根
type PhantomSessionKey struct {
	SrcIP    PhantomIpAddr
	DstIP    PhantomIpAddr
	SrcPort  uint16
	DstPort  uint16
	Family   uint8
	Protocol uint8
	Pad      [2]uint8
}

// PhantomSessionValue 会话值存根
type PhantomSessionValue struct {
	CreatedNS  uint64
	LastSeenNS uint64
	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint64
	PacketsOut uint64
	PeerIP     PhantomIpAddr
	PeerPort   uint16
	State      uint8
	Flags      uint8
	Family     uint8
	Pad        [19]uint8
}

// PhantomGlobalConfig 全局配置存根
type PhantomGlobalConfig struct {
	Magic           uint32
	ListenPort      uint16
	Mode            uint8
	LogLevel        uint8
	SessionTimeout  uint32
	MaxSessions     uint32
	EnableStats     uint8
	EnableConntrack uint8
	EnableIpv6      uint8
	Pad1            uint8
	RatelimitPps    uint32
}

// PhantomPortConfig 端口配置存根
type PhantomPortConfig struct {
	Port    uint16
	Enabled uint8
	Flags   uint8
}

// PhantomStatsCounter 统计计数器存根
type PhantomStatsCounter struct {
	PacketsRx           uint64
	PacketsTx           uint64
	BytesRx             uint64
	BytesTx             uint64
	PacketsDropped      uint64
	PacketsPassed       uint64
	PacketsRedirected   uint64
	SessionsCreated     uint64
	SessionsExpired     uint64
	Errors              uint64
	ChecksumErrors      uint64
	InvalidPackets      uint64
	Ipv6PacketsRx       uint64
	Ipv6PacketsTx       uint64
	Ipv6SessionsCreated uint64
	BlacklistHits       uint64
	RatelimitHits       uint64
}

// PhantomPacketEvent 包事件存根
type PhantomPacketEvent struct {
	Timestamp uint64
	SrcIP     PhantomIpAddr
	DstIP     PhantomIpAddr
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Action    uint8
	Flags     uint8
	Family    uint8
}

// PhantomBlacklistEntryV4 IPv4 黑名单条目存根
type PhantomBlacklistEntryV4 struct {
	BlockFlag      uint8
	Severity       uint8
	FailCount      uint16
	FirstSeen      uint32
	LastSeen       uint32
	Pad            [4]uint8
	BlockedPackets uint64
	BlockedBytes   uint64
}

// PhantomBlacklistEntryV6 IPv6 黑名单条目存根
type PhantomBlacklistEntryV6 struct {
	BlockFlag      uint8
	Severity       uint8
	FailCount      uint16
	FirstSeen      uint32
	LastSeen       uint32
	Pad            [4]uint8
	BlockedPackets uint64
	BlockedBytes   uint64
}

// PhantomRatelimitEntry 速率限制条目存根
type PhantomRatelimitEntry struct {
	WindowStartNS uint64
	PacketCount   uint32
	ByteCount     uint32
	Warned        uint8
	Pad           [3]uint8
}
