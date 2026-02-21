//go:build linux

// =============================================================================
// 文件: internal/transport/ebpf_types.go
// 描述: eBPF 加速 - 辅助类型和函数 (仅 Linux)
// 注意: 核心数据结构由 bpf2go 自动生成，本文件仅保留辅助函数和常量
// 重要: 类型别名定义在 ebpf_stats.go 中，本文件不再重复定义
// 关键: 所有多字节字段使用原生内存读写，保持与 eBPF 内核一致的字节序
// =============================================================================
package transport

import (
	"net"
	"time"
	"unsafe"
)

// =============================================================================
// 常量定义
// =============================================================================

const (
	// Map 和会话相关
	EBPFMaxSessions    = 65536
	EBPFMaxPorts       = 16
	EBPFSessionTimeout = 5 * time.Minute

	// 会话状态 (与 C 端 STATE_* 对应)
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

	// 地址族 (与 C 端 AF_*_BPF 对应)
	AFInetBPF  = 2
	AFInet6BPF = 10

	// 结构体大小常量 (与 C 端 _Static_assert 对应)
	// 注意: 这些值需要与 bpf2go 生成的实际结构体大小匹配
	SizeOfIpAddr       = 16
	SizeOfSessionKey   = 40
	SizeOfSessionValue = 88
	SizeOfGlobalConfig = 24
	SizeOfPortConfig   = 4
	SizeOfPacketEvent  = 48
)

// =============================================================================
// 配置类型
// =============================================================================

// EBPFConfig eBPF 配置
type EBPFConfig struct {
	// 基础配置
	Enabled     bool
	Interface   string
	XDPMode     string
	ProgramPath string

	// Map 配置
	MapSize     int
	EnableStats bool

	// 端口配置
	ListenPorts []uint16

	// 性能配置
	BatchSize       int
	PollTimeout     time.Duration
	CleanupInterval time.Duration

	// 日志
	LogLevel string
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
// 注意: 类型别名 EBPFStats, EBPFSessionKey, EBPFSessionValue, EBPFPacketEvent
// 已在 ebpf_stats.go 中定义，此处不再重复
// =============================================================================

// =============================================================================
// Go 侧会话包装类型
// =============================================================================

// EBPFSession Go 侧会话表示 (包装自动生成的类型)
type EBPFSession struct {
	Key        PhantomSessionKey   // bpf2go 生成的类型
	Value      PhantomSessionValue // bpf2go 生成的类型
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

// EBPFAcceleratorStats 加速器统计
type EBPFAcceleratorStats struct {
	// 状态
	Active        bool
	XDPMode       string
	Interface     string
	ProgramLoaded bool

	// eBPF 统计 (使用 bpf2go 生成的类型)
	Stats PhantomStatsCounter

	// 会话统计
	ActiveSessions int
	TotalSessions  uint64

	// 性能指标
	EventsProcessed uint64
	AvgLatencyNS    uint64

	// 时间
	Uptime time.Duration
}

// =============================================================================
// IP 地址转换 - 使用 unsafe 确保兼容任意 bpf2go 生成的结构
// =============================================================================

// IPToUint32 将 net.IP 转换为 uint32 (网络字节序/大端)
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	// 网络字节序 (大端): 直接按字节顺序组合
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// IPToUint32LE 将 net.IP 转换为 uint32 (小端，用于 x86 系统)
func IPToUint32LE(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	// 小端字节序: 反向组合
	return uint32(ip[3])<<24 | uint32(ip[2])<<16 | uint32(ip[1])<<8 | uint32(ip[0])
}

// Uint32ToIP 将 uint32 (网络字节序) 转换为 net.IP
func Uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// Uint32LEToIP 将 uint32 (小端) 转换为 net.IP
func Uint32LEToIP(n uint32) net.IP {
	return net.IPv4(byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
}

// IPToPhantomAddr 将 net.IP 转换为 PhantomIpAddr
// 使用 unsafe 直接操作内存，无视 bpf2go 生成的具体字段名
func IPToPhantomAddr(ip net.IP) PhantomIpAddr {
	var addr PhantomIpAddr

	// 将 PhantomIpAddr 的内存地址直接映射为 []byte
	addrBytes := (*[SizeOfIpAddr]byte)(unsafe.Pointer(&addr))[:]

	if ip4 := ip.To4(); ip4 != nil {
		// IPv4: 写入前 4 个字节 (网络字节序，ip4 本身就是)
		copy(addrBytes[:4], ip4)
		// 剩余 12 字节清零 (确保一致性)
		for i := 4; i < SizeOfIpAddr; i++ {
			addrBytes[i] = 0
		}
	} else if ip6 := ip.To16(); ip6 != nil {
		// IPv6: 写入全部 16 个字节
		copy(addrBytes, ip6)
	}

	return addr
}

// PhantomAddrToIP 将 PhantomIpAddr 转换为 net.IP
// 使用 unsafe 直接读取内存
func PhantomAddrToIP(addr *PhantomIpAddr, family uint8) net.IP {
	// 将 PhantomIpAddr 内存映射为 []byte
	addrBytes := (*[SizeOfIpAddr]byte)(unsafe.Pointer(addr))[:]

	if family == AFInetBPF {
		// IPv4: 取前 4 个字节
		ip := make(net.IP, 4)
		copy(ip, addrBytes[:4])
		return ip
	}

	// IPv6: 取全部 16 个字节
	ip := make(net.IP, 16)
	copy(ip, addrBytes)
	return ip
}

// PhantomAddrIsZero 检查地址是否为零
func PhantomAddrIsZero(addr *PhantomIpAddr) bool {
	addrBytes := (*[SizeOfIpAddr]byte)(unsafe.Pointer(addr))[:]
	for _, b := range addrBytes {
		if b != 0 {
			return false
		}
	}
	return true
}

// PhantomAddrEqual 比较两个地址是否相等
func PhantomAddrEqual(a, b *PhantomIpAddr) bool {
	aBytes := (*[SizeOfIpAddr]byte)(unsafe.Pointer(a))[:]
	bBytes := (*[SizeOfIpAddr]byte)(unsafe.Pointer(b))[:]
	for i := 0; i < SizeOfIpAddr; i++ {
		if aBytes[i] != bBytes[i] {
			return false
		}
	}
	return true
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

// =============================================================================
// 会话键构建辅助函数 - 使用 unsafe 原生内存操作
// 关键：端口使用原生内存赋值，保持与 eBPF 内核读取的字节序一致
// =============================================================================

// MakeSessionKeyV4 创建 IPv4 会话键
// 注意: srcPort 和 dstPort 应该已经是网络字节序 (调用者使用 Htons 转换)
func MakeSessionKeyV4(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8) PhantomSessionKey {
	var key PhantomSessionKey

	// 获取 key 的内存视图
	keyBytes := (*[SizeOfSessionKey]byte)(unsafe.Pointer(&key))[:]

	// 清零整个结构
	for i := range keyBytes {
		keyBytes[i] = 0
	}

	// 写入源 IP (offset 0, 16 bytes, 但 IPv4 只用前 4 字节)
	if ip4 := srcIP.To4(); ip4 != nil {
		copy(keyBytes[0:4], ip4)
	}

	// 写入目的 IP (offset 16, 16 bytes, 但 IPv4 只用前 4 字节)
	if ip4 := dstIP.To4(); ip4 != nil {
		copy(keyBytes[16:20], ip4)
	}

	// 写入端口 - 使用原生内存赋值，保持字节序与 eBPF 内核一致
	// src_port @ offset 32 (2 bytes)
	*(*uint16)(unsafe.Pointer(&keyBytes[32])) = srcPort

	// dst_port @ offset 34 (2 bytes)
	*(*uint16)(unsafe.Pointer(&keyBytes[34])) = dstPort

	// family @ offset 36 (1 byte)
	keyBytes[36] = AFInetBPF

	// protocol @ offset 37 (1 byte)
	keyBytes[37] = proto

	// _pad @ offset 38-39 (2 bytes) - 已经是 0

	return key
}

// MakeSessionKeyV6 创建 IPv6 会话键
// 注意: srcPort 和 dstPort 应该已经是网络字节序 (调用者使用 Htons 转换)
func MakeSessionKeyV6(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8) PhantomSessionKey {
	var key PhantomSessionKey

	// 获取 key 的内存视图
	keyBytes := (*[SizeOfSessionKey]byte)(unsafe.Pointer(&key))[:]

	// 清零整个结构
	for i := range keyBytes {
		keyBytes[i] = 0
	}

	// 写入源 IP (offset 0, 16 bytes)
	if ip6 := srcIP.To16(); ip6 != nil {
		copy(keyBytes[0:16], ip6)
	}

	// 写入目的 IP (offset 16, 16 bytes)
	if ip6 := dstIP.To16(); ip6 != nil {
		copy(keyBytes[16:32], ip6)
	}

	// 写入端口 - 使用原生内存赋值
	// src_port @ offset 32 (2 bytes)
	*(*uint16)(unsafe.Pointer(&keyBytes[32])) = srcPort

	// dst_port @ offset 34 (2 bytes)
	*(*uint16)(unsafe.Pointer(&keyBytes[34])) = dstPort

	// family @ offset 36 (1 byte)
	keyBytes[36] = AFInet6BPF

	// protocol @ offset 37 (1 byte)
	keyBytes[37] = proto

	// _pad @ offset 38-39 (2 bytes) - 已经是 0

	return key
}

// MakeReverseKey 创建反向会话键
func MakeReverseKey(key *PhantomSessionKey) PhantomSessionKey {
	var rev PhantomSessionKey

	srcBytes := (*[SizeOfSessionKey]byte)(unsafe.Pointer(key))[:]
	revBytes := (*[SizeOfSessionKey]byte)(unsafe.Pointer(&rev))[:]

	// 交换 src_ip 和 dst_ip
	copy(revBytes[0:16], srcBytes[16:32])  // rev.src = key.dst
	copy(revBytes[16:32], srcBytes[0:16])  // rev.dst = key.src

	// 交换端口 - 使用原生内存读写
	srcPort := *(*uint16)(unsafe.Pointer(&srcBytes[32]))
	dstPort := *(*uint16)(unsafe.Pointer(&srcBytes[34]))
	*(*uint16)(unsafe.Pointer(&revBytes[32])) = dstPort  // rev.src_port = key.dst_port
	*(*uint16)(unsafe.Pointer(&revBytes[34])) = srcPort  // rev.dst_port = key.src_port

	// 复制 family 和 protocol
	revBytes[36] = srcBytes[36]
	revBytes[37] = srcBytes[37]

	// _pad 置零
	revBytes[38] = 0
	revBytes[39] = 0

	return rev
}

// GetSessionKeyInfo 从会话键中提取信息
func GetSessionKeyInfo(key *PhantomSessionKey) (srcIP, dstIP net.IP, srcPort, dstPort uint16, family, proto uint8) {
	keyBytes := (*[SizeOfSessionKey]byte)(unsafe.Pointer(key))[:]

	family = keyBytes[36]
	proto = keyBytes[37]

	if family == AFInetBPF {
		srcIP = make(net.IP, 4)
		dstIP = make(net.IP, 4)
		copy(srcIP, keyBytes[0:4])
		copy(dstIP, keyBytes[16:20])
	} else {
		srcIP = make(net.IP, 16)
		dstIP = make(net.IP, 16)
		copy(srcIP, keyBytes[0:16])
		copy(dstIP, keyBytes[16:32])
	}

	// 使用原生内存读取端口
	srcPort = *(*uint16)(unsafe.Pointer(&keyBytes[32]))
	dstPort = *(*uint16)(unsafe.Pointer(&keyBytes[34]))

	return
}

// =============================================================================
// 会话值读取辅助函数 - 使用 unsafe 直接读取内存
// =============================================================================

// GetSessionValueStats 从会话值中提取统计信息
func GetSessionValueStats(val *PhantomSessionValue) (createdNS, lastSeenNS, bytesIn, bytesOut, packetsIn, packetsOut uint64) {
	valBytes := (*[SizeOfSessionValue]byte)(unsafe.Pointer(val))[:]

	// 读取 uint64 值 (原生字节序)
	createdNS = *(*uint64)(unsafe.Pointer(&valBytes[0]))
	lastSeenNS = *(*uint64)(unsafe.Pointer(&valBytes[8]))
	bytesIn = *(*uint64)(unsafe.Pointer(&valBytes[16]))
	bytesOut = *(*uint64)(unsafe.Pointer(&valBytes[24]))
	packetsIn = *(*uint64)(unsafe.Pointer(&valBytes[32]))
	packetsOut = *(*uint64)(unsafe.Pointer(&valBytes[40]))

	return
}

// GetSessionValuePeer 从会话值中提取对端信息
func GetSessionValuePeer(val *PhantomSessionValue) (peerIP net.IP, peerPort uint16, state, flags, family uint8) {
	valBytes := (*[SizeOfSessionValue]byte)(unsafe.Pointer(val))[:]

	family = valBytes[76]

	// peer_ip @ offset 48, 16 bytes
	if family == AFInetBPF {
		peerIP = make(net.IP, 4)
		copy(peerIP, valBytes[48:52])
	} else {
		peerIP = make(net.IP, 16)
		copy(peerIP, valBytes[48:64])
	}

	// peer_port @ offset 72, 2 bytes - 使用原生内存读取
	peerPort = *(*uint16)(unsafe.Pointer(&valBytes[72]))

	// state @ offset 74
	state = valBytes[74]

	// flags @ offset 75
	flags = valBytes[75]

	return
}

// =============================================================================
// 统计计数器读取 - 使用 unsafe 直接读取内存，兼容任意字段名
// =============================================================================

// GetStatsCounterValues 从统计计数器中提取所有值
// 使用 unsafe 直接读取内存，避免依赖 bpf2go 生成的具体字段名
func GetStatsCounterValues(stats *PhantomStatsCounter) map[string]uint64 {
	// 获取结构体的内存视图
	// PhantomStatsCounter 包含多个 uint64 字段，按顺序排列
	size := unsafe.Sizeof(*stats)
	numFields := int(size / 8) // 每个 uint64 占 8 字节

	statsPtr := unsafe.Pointer(stats)
	result := make(map[string]uint64)

	// 字段名列表 (按 C 结构体定义顺序)
	fieldNames := []string{
		"packets_rx",
		"packets_tx",
		"bytes_rx",
		"bytes_tx",
		"packets_dropped",
		"packets_passed",
		"packets_redirected",
		"sessions_created",
		"sessions_expired",
		"errors",
		"checksum_errors",
		"invalid_packets",
		"ipv6_packets_rx",
		"ipv6_packets_tx",
		"ipv6_sessions_created",
		"blacklist_hits",
		"ratelimit_hits",
	}

	for i := 0; i < numFields && i < len(fieldNames); i++ {
		offset := uintptr(i * 8)
		value := *(*uint64)(unsafe.Pointer(uintptr(statsPtr) + offset))
		result[fieldNames[i]] = value
	}

	return result
}

// =============================================================================
// 全局配置写入 - 使用 unsafe 直接操作内存
// =============================================================================

// SetGlobalConfig 设置全局配置
func SetGlobalConfig(cfg *PhantomGlobalConfig, magic uint32, listenPort uint16, mode, logLevel uint8,
	sessionTimeout, maxSessions uint32, enableStats, enableConntrack, enableIPv6 uint8) {

	cfgBytes := (*[SizeOfGlobalConfig]byte)(unsafe.Pointer(cfg))[:]

	// 清零
	for i := range cfgBytes {
		cfgBytes[i] = 0
	}

	// magic @ offset 0, 4 bytes (原生字节序)
	*(*uint32)(unsafe.Pointer(&cfgBytes[0])) = magic

	// listen_port @ offset 4, 2 bytes (原生字节序)
	*(*uint16)(unsafe.Pointer(&cfgBytes[4])) = listenPort

	// mode @ offset 6
	cfgBytes[6] = mode

	// log_level @ offset 7
	cfgBytes[7] = logLevel

	// session_timeout @ offset 8, 4 bytes (原生字节序)
	*(*uint32)(unsafe.Pointer(&cfgBytes[8])) = sessionTimeout

	// max_sessions @ offset 12, 4 bytes (原生字节序)
	*(*uint32)(unsafe.Pointer(&cfgBytes[12])) = maxSessions

	// enable_stats @ offset 16
	cfgBytes[16] = enableStats

	// enable_conntrack @ offset 17
	cfgBytes[17] = enableConntrack

	// enable_ipv6 @ offset 18
	cfgBytes[18] = enableIPv6

	// _pad @ offset 19-23 已经是 0
}

// =============================================================================
// 端口配置写入 - 使用 unsafe 直接操作内存
// =============================================================================

// SetPortConfig 设置端口配置
func SetPortConfig(cfg *PhantomPortConfig, port uint16, enabled, flags uint8) {
	cfgBytes := (*[SizeOfPortConfig]byte)(unsafe.Pointer(cfg))[:]

	// port @ offset 0, 2 bytes (原生字节序)
	*(*uint16)(unsafe.Pointer(&cfgBytes[0])) = port

	// enabled @ offset 2
	cfgBytes[2] = enabled

	// flags @ offset 3
	cfgBytes[3] = flags
}

// =============================================================================
// 辅助函数
// =============================================================================

// SessionStateString 将会话状态转换为字符串
func SessionStateString(state uint8) string {
	switch state {
	case EBPFStateNew:
		return "NEW"
	case EBPFStateHandshake:
		return "HANDSHAKE"
	case EBPFStateEstablished:
		return "ESTABLISHED"
	case EBPFStateClosing:
		return "CLOSING"
	case EBPFStateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// NanoToTime 将纳秒时间戳转换为 time.Time
func NanoToTime(ns uint64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, int64(ns))
}

// TimeToNano 将 time.Time 转换为纳秒时间戳
func TimeToNano(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.UnixNano())
}
