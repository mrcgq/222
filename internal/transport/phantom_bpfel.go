//go:build linux

// =============================================================================
// 文件: internal/transport/phantom_bpfel.go
// 描述: bpf2go 生成的 eBPF 类型存根 (小端系统)
// 注意: 正式构建时由 go generate 自动生成，此文件为手动存根
// =============================================================================

package transport

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// =============================================================================
// eBPF 对象定义
// =============================================================================

// PhantomObjects 包含所有 eBPF 对象
type PhantomObjects struct {
	PhantomPrograms
	PhantomMaps
}

// PhantomPrograms 包含所有 eBPF 程序
type PhantomPrograms struct {
	XdpPhantomMain   *ebpf.Program `ebpf:"xdp_phantom_main"`
	XdpPhantomFast   *ebpf.Program `ebpf:"xdp_phantom_fast"`
	XdpPhantomFilter *ebpf.Program `ebpf:"xdp_phantom_filter"`
}

// PhantomMaps 包含所有 eBPF Maps
type PhantomMaps struct {
	Sessions    *ebpf.Map `ebpf:"sessions"`
	ListenPorts *ebpf.Map `ebpf:"listen_ports"`
	Config      *ebpf.Map `ebpf:"config"`
	Stats       *ebpf.Map `ebpf:"stats"`
	Events      *ebpf.Map `ebpf:"events"`
	BlacklistV4 *ebpf.Map `ebpf:"blacklist_v4"`
	BlacklistV6 *ebpf.Map `ebpf:"blacklist_v6"`
	RatelimitV4 *ebpf.Map `ebpf:"ratelimit_v4"`
	RatelimitV6 *ebpf.Map `ebpf:"ratelimit_v6"`
	TxPorts     *ebpf.Map `ebpf:"tx_ports"`
}

// Close 关闭所有对象
func (o *PhantomObjects) Close() error {
	var errs []error

	// 关闭程序
	if o.XdpPhantomMain != nil {
		if err := o.XdpPhantomMain.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if o.XdpPhantomFast != nil {
		if err := o.XdpPhantomFast.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if o.XdpPhantomFilter != nil {
		if err := o.XdpPhantomFilter.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// 关闭 Maps
	if o.Sessions != nil {
		if err := o.Sessions.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if o.ListenPorts != nil {
		if err := o.ListenPorts.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if o.Config != nil {
		if err := o.Config.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if o.Stats != nil {
		if err := o.Stats.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if o.Events != nil {
		if err := o.Events.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if o.BlacklistV4 != nil {
		if err := o.BlacklistV4.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if o.BlacklistV6 != nil {
		if err := o.BlacklistV6.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if o.RatelimitV4 != nil {
		if err := o.RatelimitV4.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if o.RatelimitV6 != nil {
		if err := o.RatelimitV6.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if o.TxPorts != nil {
		if err := o.TxPorts.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("关闭 eBPF 对象时发生 %d 个错误", len(errs))
	}
	return nil
}

// LoadPhantom 加载 eBPF 程序规格
func LoadPhantom() (*ebpf.CollectionSpec, error) {
	return ebpf.LoadCollectionSpec("/opt/phantom/ebpf/xdp_phantom.o")
}

// LoadPhantomFromPath 从指定路径加载 eBPF 程序规格
func LoadPhantomFromPath(path string) (*ebpf.CollectionSpec, error) {
	return ebpf.LoadCollectionSpec(path)
}

// =============================================================================
// IP 地址结构 (16 字节，支持 IPv4/IPv6)
// =============================================================================

// PhantomIpAddr IP 地址 (与 C 端 struct ip_addr 对应)
type PhantomIpAddr struct {
	V4  uint32    // IPv4 地址 (offset 0, 4 bytes)
	Pad [12]uint8 // 填充到 16 字节 (offset 4-15)
}

// =============================================================================
// 会话相关结构
// =============================================================================

// PhantomSessionKey 会话键 (40 字节)
type PhantomSessionKey struct {
	SrcIP    PhantomIpAddr // 源 IP (offset 0, 16 bytes)
	DstIP    PhantomIpAddr // 目的 IP (offset 16, 16 bytes)
	SrcPort  uint16        // 源端口 (offset 32, 2 bytes)
	DstPort  uint16        // 目的端口 (offset 34, 2 bytes)
	Family   uint8         // 地址族 (offset 36, 1 byte)
	Protocol uint8         // 协议 (offset 37, 1 byte)
	Pad      [2]uint8      // 填充 (offset 38-39)
}

// PhantomSessionValue 会话值 (88 字节)
type PhantomSessionValue struct {
	CreatedNS  uint64        // 创建时间 (纳秒) (offset 0)
	LastSeenNS uint64        // 最后活跃时间 (纳秒) (offset 8)
	BytesIn    uint64        // 入向字节数 (offset 16)
	BytesOut   uint64        // 出向字节数 (offset 24)
	PacketsIn  uint64        // 入向包数 (offset 32)
	PacketsOut uint64        // 出向包数 (offset 40)
	PeerIP     PhantomIpAddr // 对端 IP (offset 48, 16 bytes)
	PeerPort   uint16        // 对端端口 (offset 64)
	State      uint8         // 会话状态 (offset 66)
	Flags      uint8         // 标志位 (offset 67)
	Family     uint8         // 地址族 (offset 68)
	Pad        [19]uint8     // 填充到 88 字节 (offset 69-87)
}

// =============================================================================
// 配置相关结构
// =============================================================================

// PhantomGlobalConfig 全局配置 (24 字节)
type PhantomGlobalConfig struct {
	Magic           uint32 // 魔数 (offset 0)
	ListenPort      uint16 // 监听端口 (offset 4)
	Mode            uint8  // 模式 (offset 6)
	LogLevel        uint8  // 日志级别 (offset 7)
	SessionTimeout  uint32 // 会话超时 (秒) (offset 8)
	MaxSessions     uint32 // 最大会话数 (offset 12)
	EnableStats     uint8  // 启用统计 (offset 16)
	EnableConntrack uint8  // 启用连接跟踪 (offset 17)
	EnableIpv6      uint8  // 启用 IPv6 (offset 18)
	Pad1            uint8  // 填充 (offset 19)
	RatelimitPps    uint32 // 速率限制 PPS (offset 20)
}

// PhantomPortConfig 端口配置 (4 字节)
type PhantomPortConfig struct {
	Port    uint16 // 端口号 (offset 0)
	Enabled uint8  // 是否启用 (offset 2)
	Flags   uint8  // 标志 (offset 3)
}

// =============================================================================
// 统计相关结构
// =============================================================================

// PhantomStatsCounter 统计计数器 (136 字节)
type PhantomStatsCounter struct {
	PacketsRX           uint64 // 接收包数 (offset 0)
	PacketsTX           uint64 // 发送包数 (offset 8)
	BytesRX             uint64 // 接收字节数 (offset 16)
	BytesTX             uint64 // 发送字节数 (offset 24)
	PacketsDropped      uint64 // 丢弃包数 (offset 32)
	PacketsPassed       uint64 // 放行包数 (offset 40)
	PacketsRedirected   uint64 // 重定向包数 (offset 48)
	SessionsCreated     uint64 // 创建会话数 (offset 56)
	SessionsExpired     uint64 // 过期会话数 (offset 64)
	Errors              uint64 // 错误数 (offset 72)
	ChecksumErrors      uint64 // 校验和错误 (offset 80)
	InvalidPackets      uint64 // 无效包数 (offset 88)
	Ipv6PacketsRX       uint64 // IPv6 接收包数 (offset 96)
	Ipv6PacketsTX       uint64 // IPv6 发送包数 (offset 104)
	Ipv6SessionsCreated uint64 // IPv6 会话创建数 (offset 112)
	BlacklistHits       uint64 // 黑名单命中数 (offset 120)
	RatelimitHits       uint64 // 速率限制命中数 (offset 128)
}

// =============================================================================
// 事件相关结构
// =============================================================================

// PhantomPacketEvent 包事件 (48 字节)
type PhantomPacketEvent struct {
	Timestamp uint64        // 时间戳 (offset 0)
	SrcIP     PhantomIpAddr // 源 IP (offset 8, 16 bytes)
	DstIP     PhantomIpAddr // 目的 IP (offset 24, 16 bytes)
	SrcPort   uint16        // 源端口 (offset 40)
	DstPort   uint16        // 目的端口 (offset 42)
	Protocol  uint8         // 协议 (offset 44)
	Action    uint8         // 动作 (offset 45)
	Flags     uint8         // 标志 (offset 46)
	Family    uint8         // 地址族 (offset 47)
}

// =============================================================================
// 黑名单相关结构
// =============================================================================

// PhantomBlacklistEntryV4 IPv4 黑名单条目 (24 字节)
type PhantomBlacklistEntryV4 struct {
	BlockFlag      uint8    // 封禁原因 (offset 0)
	Severity       uint8    // 严重程度 (offset 1)
	FailCount      uint16   // 失败计数 (offset 2)
	FirstSeen      uint32   // 首次发现时间 (offset 4)
	LastSeen       uint32   // 最后发现时间 (offset 8)
	Pad            [4]uint8 // 填充 (offset 12)
	BlockedPackets uint64   // 已拦截包数 (offset 16)
	BlockedBytes   uint64   // 已拦截字节数 (offset 24)
}

// PhantomBlacklistEntryV6 IPv6 黑名单条目 (24 字节)
type PhantomBlacklistEntryV6 struct {
	BlockFlag      uint8    // 封禁原因 (offset 0)
	Severity       uint8    // 严重程度 (offset 1)
	FailCount      uint16   // 失败计数 (offset 2)
	FirstSeen      uint32   // 首次发现时间 (offset 4)
	LastSeen       uint32   // 最后发现时间 (offset 8)
	Pad            [4]uint8 // 填充 (offset 12)
	BlockedPackets uint64   // 已拦截包数 (offset 16)
	BlockedBytes   uint64   // 已拦截字节数 (offset 24)
}

// PhantomRatelimitEntry 速率限制条目 (16 字节)
type PhantomRatelimitEntry struct {
	WindowStartNS uint64   // 窗口开始时间 (offset 0)
	PacketCount   uint32   // 包计数 (offset 8)
	ByteCount     uint32   // 字节计数 (offset 12)
	Warned        uint8    // 是否已警告 (offset 16)
	Pad           [3]uint8 // 填充 (offset 17-19)
}
