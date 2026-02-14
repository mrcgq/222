

// =============================================================================
// 文件: internal/transport/faketcp_types.go
// 描述: FakeTCP 伪装 - 类型定义 (支持 IPv4/IPv6 双栈)
// =============================================================================
package transport

import (
	"net"
	"sync"
	"time"
)

// FakeTCP 协议常量
const (
	// TCP 头部大小
	TCPHeaderMinSize = 20
	TCPHeaderMaxSize = 60

	// IP 头部大小
	IPHeaderMinSize   = 20
	IPHeaderMaxSize   = 60
	IPv6HeaderSize    = 40
	IPv6PseudoHdrSize = 40

	// 伪头部大小
	PseudoHeaderSize     = 12 // IPv4
	PseudoHeaderV6Size   = 40 // IPv6

	// TCP 标志位
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
	TCPFlagECE = 0x40
	TCPFlagCWR = 0x80

	// TCP 选项
	TCPOptEnd       = 0
	TCPOptNOP       = 1
	TCPOptMSS       = 2
	TCPOptWScale    = 3
	TCPOptSACKPerm  = 4
	TCPOptSACK      = 5
	TCPOptTimestamp = 8

	// 默认值
	DefaultTCPMSS     = 1460
	DefaultTCPMSSv6   = 1440 // IPv6 头部更大，MSS 稍小
	DefaultTCPWindow  = 65535
	DefaultTCPTTL     = 64
	DefaultMaxSegment = 1400

	// 超时
	TCPConnTimeout      = 30 * time.Second
	TCPIdleTimeout      = 5 * time.Minute
	TCPRetransmitMin    = 200 * time.Millisecond
	TCPRetransmitMax    = 60 * time.Second
	TCPTimeWaitDuration = 2 * time.Minute

	// 缓冲区
	TCPRecvBufferSize = 256 * 1024
	TCPSendBufferSize = 256 * 1024

	// IP 版本
	IPVersion4 = 4
	IPVersion6 = 6

	// 协议号
	ProtocolTCP  = 6
	ProtocolUDP  = 17
	ProtocolICMP = 1
)

// TCPState TCP 连接状态
type TCPState uint8

const (
	TCPStateClosed TCPState = iota
	TCPStateListen
	TCPStateSynSent
	TCPStateSynReceived
	TCPStateEstablished
	TCPStateFinWait1
	TCPStateFinWait2
	TCPStateCloseWait
	TCPStateClosing
	TCPStateLastAck
	TCPStateTimeWait
)

func (s TCPState) String() string {
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

// TCPHeader TCP 头部
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8 // 高 4 位是数据偏移
	Flags      uint8
	Window     uint16
	Checksum   uint16
	UrgentPtr  uint16
	Options    []TCPOption
}

// TCPOption TCP 选项
type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

// IPHeader IPv4 头部
type IPHeader struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	TotalLen   uint16
	ID         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
}

// IPv6Header IPv6 头部
type IPv6Header struct {
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	PayloadLen   uint16
	NextHeader   uint8
	HopLimit     uint8
	SrcIP        net.IP
	DstIP        net.IP
}

// UnifiedIPHeader 统一的 IP 头部接口
type UnifiedIPHeader interface {
	GetVersion() uint8
	GetSrcIP() net.IP
	GetDstIP() net.IP
	GetProtocol() uint8
	GetPayloadLength() int
}

// 实现 UnifiedIPHeader 接口
func (h *IPHeader) GetVersion() uint8        { return 4 }
func (h *IPHeader) GetSrcIP() net.IP         { return h.SrcIP }
func (h *IPHeader) GetDstIP() net.IP         { return h.DstIP }
func (h *IPHeader) GetProtocol() uint8       { return h.Protocol }
func (h *IPHeader) GetPayloadLength() int    { return int(h.TotalLen) - int(h.IHL)*4 }

func (h *IPv6Header) GetVersion() uint8      { return 6 }
func (h *IPv6Header) GetSrcIP() net.IP       { return h.SrcIP }
func (h *IPv6Header) GetDstIP() net.IP       { return h.DstIP }
func (h *IPv6Header) GetProtocol() uint8     { return h.NextHeader }
func (h *IPv6Header) GetPayloadLength() int  { return int(h.PayloadLen) }

// FakeTCPPacket 完整的 FakeTCP 数据包 (支持双栈)
type FakeTCPPacket struct {
	// IP 层 (二选一)
	IPHeader   *IPHeader   // IPv4
	IPv6Header *IPv6Header // IPv6
	
	// TCP 层
	TCPHeader *TCPHeader
	Payload   []byte
}

// IsIPv6 检查是否为 IPv6 包
func (p *FakeTCPPacket) IsIPv6() bool {
	return p.IPv6Header != nil
}

// GetIPHeader 获取统一的 IP 头部接口
func (p *FakeTCPPacket) GetIPHeader() UnifiedIPHeader {
	if p.IPv6Header != nil {
		return p.IPv6Header
	}
	return p.IPHeader
}

// GetSrcIP 获取源 IP
func (p *FakeTCPPacket) GetSrcIP() net.IP {
	if p.IPv6Header != nil {
		return p.IPv6Header.SrcIP
	}
	if p.IPHeader != nil {
		return p.IPHeader.SrcIP
	}
	return nil
}

// GetDstIP 获取目的 IP
func (p *FakeTCPPacket) GetDstIP() net.IP {
	if p.IPv6Header != nil {
		return p.IPv6Header.DstIP
	}
	if p.IPHeader != nil {
		return p.IPHeader.DstIP
	}
	return nil
}

// =============================================================================
// 会话键 - 支持 IPv4/IPv6 双栈
// =============================================================================

// SessionKey 会话键 (使用字符串，兼容 IPv4/IPv6)
// 格式: "localIP:localPort-remoteIP:remotePort"
type SessionKey string

// NewSessionKey 创建会话键 (兼容 IPv4/IPv6)
func NewSessionKey(local, remote *net.UDPAddr) SessionKey {
	return SessionKey(local.String() + "-" + remote.String())
}

// NewSessionKeyFromIP 从 IP 和端口创建会话键
func NewSessionKeyFromIP(localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) SessionKey {
	local := net.JoinHostPort(localIP.String(), itoa(int(localPort)))
	remote := net.JoinHostPort(remoteIP.String(), itoa(int(remotePort)))
	return SessionKey(local + "-" + remote)
}

// itoa 简单的整数转字符串
func itoa(i int) string {
	if i < 0 {
		return "-" + uitoa(uint(-i))
	}
	return uitoa(uint(i))
}

func uitoa(val uint) string {
	if val == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf) - 1
	for val > 0 {
		buf[i] = byte('0' + val%10)
		val /= 10
		i--
	}
	return string(buf[i+1:])
}

// BinarySessionKey 二进制会话键 (高性能版本，支持 IPv4/IPv6)
type BinarySessionKey struct {
	// 使用固定大小数组存储 IP 地址
	// IPv4 使用前 4 字节，IPv6 使用全部 16 字节
	LocalIP    [16]byte
	RemoteIP   [16]byte
	LocalPort  uint16
	RemotePort uint16
	IsIPv6     bool
}

// NewBinarySessionKey 创建二进制会话键
func NewBinarySessionKey(local, remote *net.UDPAddr) BinarySessionKey {
	key := BinarySessionKey{
		LocalPort:  uint16(local.Port),
		RemotePort: uint16(remote.Port),
	}
	
	// 检测 IP 版本
	localIP4 := local.IP.To4()
	remoteIP4 := remote.IP.To4()
	
	if localIP4 != nil && remoteIP4 != nil {
		// IPv4
		copy(key.LocalIP[:4], localIP4)
		copy(key.RemoteIP[:4], remoteIP4)
		key.IsIPv6 = false
	} else {
		// IPv6
		copy(key.LocalIP[:], local.IP.To16())
		copy(key.RemoteIP[:], remote.IP.To16())
		key.IsIPv6 = true
	}
	
	return key
}

// String 返回字符串表示
func (k BinarySessionKey) String() string {
	var localIP, remoteIP net.IP
	if k.IsIPv6 {
		localIP = net.IP(k.LocalIP[:])
		remoteIP = net.IP(k.RemoteIP[:])
	} else {
		localIP = net.IP(k.LocalIP[:4])
		remoteIP = net.IP(k.RemoteIP[:4])
	}
	return net.JoinHostPort(localIP.String(), itoa(int(k.LocalPort))) + "-" +
		net.JoinHostPort(remoteIP.String(), itoa(int(k.RemotePort)))
}

// =============================================================================
// FakeTCP 会话
// =============================================================================

// FakeTCPSession FakeTCP 会话
type FakeTCPSession struct {
	// 标识
	LocalAddr  *net.UDPAddr
	RemoteAddr *net.UDPAddr
	IsIPv6     bool // 标记是否为 IPv6 会话

	// TCP 状态
	State TCPState

	// 序列号
	LocalSeq  uint32 // 本地发送序列号
	LocalAck  uint32 // 本地确认号 (期望接收的序列号)
	RemoteSeq uint32 // 远程初始序列号
	RemoteAck uint32 // 远程确认号

	// 窗口
	LocalWindow  uint16
	RemoteWindow uint16

	// 选项
	MSS           uint16
	WindowScale   uint8
	SACKPermitted bool
	Timestamps    bool

	// 时间戳
	TSVal     uint32
	TSEcr     uint32
	LastTSVal uint32

	// 重传
	RetransmitQueue []*tcpSegment
	RetransmitTimer *time.Timer
	RTO             time.Duration
	SRTT            time.Duration
	RTTVar          time.Duration

	// 统计
	BytesSent     uint64
	BytesReceived uint64
	PacketsSent   uint64
	PacketsRecv   uint64
	Retransmits   uint64

	// 时间
	CreatedAt     time.Time
	LastActive    time.Time
	EstablishedAt time.Time

	// 缓冲区
	RecvBuffer []byte
	SendBuffer []byte

	mu sync.RWMutex
}

type tcpSegment struct {
	SeqNum  uint32
	Data    []byte
	SentAt  time.Time
	Retries int
	Acked   bool
}

// GetMSS 获取 MSS (根据 IP 版本返回合适的值)
func (s *FakeTCPSession) GetMSS() uint16 {
	if s.MSS > 0 {
		return s.MSS
	}
	if s.IsIPv6 {
		return DefaultTCPMSSv6
	}
	return DefaultTCPMSS
}

// =============================================================================
// FakeTCP 配置
// =============================================================================

// FakeTCPConfig FakeTCP 配置
type FakeTCPConfig struct {
	// 监听配置
	ListenAddr string
	Interface  string

	// TCP 参数
	MSS         uint16
	MSSv6       uint16 // IPv6 专用 MSS
	WindowSize  uint16
	WindowScale uint8

	// 超时
	ConnTimeout   time.Duration
	IdleTimeout   time.Duration
	RetransmitMin time.Duration
	RetransmitMax time.Duration

	// 选项
	EnableTimestamps  bool
	EnableSACK        bool
	EnableWindowScale bool

	// 伪装
	TTL          uint8
	HopLimit     uint8 // IPv6 的 Hop Limit
	TOS          uint8
	TrafficClass uint8 // IPv6 的 Traffic Class
	RandomizeISN bool

	// IPv6 特定
	EnableIPv6  bool
	PreferIPv6  bool
	FlowLabel   uint32

	// 日志
	LogLevel string
}

// DefaultFakeTCPConfig 默认配置
func DefaultFakeTCPConfig() *FakeTCPConfig {
	return &FakeTCPConfig{
		ListenAddr:        ":54322",
		MSS:               DefaultTCPMSS,
		MSSv6:             DefaultTCPMSSv6,
		WindowSize:        DefaultTCPWindow,
		WindowScale:       7,
		ConnTimeout:       TCPConnTimeout,
		IdleTimeout:       TCPIdleTimeout,
		RetransmitMin:     TCPRetransmitMin,
		RetransmitMax:     TCPRetransmitMax,
		EnableTimestamps:  true,
		EnableSACK:        true,
		EnableWindowScale: true,
		TTL:               DefaultTCPTTL,
		HopLimit:          DefaultTCPTTL,
		TOS:               0,
		TrafficClass:      0,
		RandomizeISN:      true,
		EnableIPv6:        true,
		PreferIPv6:        false,
		FlowLabel:         0,
		LogLevel:          "info",
	}
}

// GetMSSForVersion 根据 IP 版本获取 MSS
func (c *FakeTCPConfig) GetMSSForVersion(isIPv6 bool) uint16 {
	if isIPv6 {
		if c.MSSv6 > 0 {
			return c.MSSv6
		}
		return DefaultTCPMSSv6
	}
	if c.MSS > 0 {
		return c.MSS
	}
	return DefaultTCPMSS
}

// =============================================================================
// FakeTCP 统计
// =============================================================================

// FakeTCPStats FakeTCP 统计
type FakeTCPStats struct {
	// 连接统计
	ActiveSessions    uint64
	TotalSessions     uint64
	SuccessHandshakes uint64
	FailedHandshakes  uint64

	// IPv6 统计
	IPv6Sessions    uint64
	IPv4Sessions    uint64

	// 数据统计
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64

	// 重传统计
	Retransmits    uint64
	TimeoutRetrans uint64
	FastRetrans    uint64

	// 错误统计
	ChecksumErrors uint64
	InvalidPackets uint64
	DroppedPackets uint64
}

// =============================================================================
// 辅助函数
// =============================================================================

// IsIPv6Addr 检查地址是否为 IPv6
func IsIPv6Addr(addr *net.UDPAddr) bool {
	if addr == nil || addr.IP == nil {
		return false
	}
	return addr.IP.To4() == nil
}

// IsIPv6IP 检查 IP 是否为 IPv6
func IsIPv6IP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}

// NormalizeIP 规范化 IP 地址
func NormalizeIP(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip.To16()
}



