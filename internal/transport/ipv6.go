


// =============================================================================
// 文件: internal/transport/ipv6.go
// 描述: IPv6 支持工具函数和统一会话键
// =============================================================================
package transport

import (
	"encoding/binary"
	"net"
)

// IPVersion IP 版本
type IPVersion int

const (
	DualStack IPVersion = 0
	IPv4Only  IPVersion = 4
	IPv6Only  IPVersion = 6
)

// IsIPv6 检查地址是否是 IPv6
func IsIPv6(ip net.IP) bool {
	return ip != nil && ip.To4() == nil && ip.To16() != nil
}

// IsIPv4 检查地址是否是 IPv4
func IsIPv4(ip net.IP) bool {
	return ip != nil && ip.To4() != nil
}

// ParseIPVersion 从地址解析 IP 版本
func ParseIPVersion(addr *net.UDPAddr) IPVersion {
	if addr == nil || addr.IP == nil {
		return DualStack
	}
	if IsIPv4(addr.IP) {
		return IPv4Only
	}
	return IPv6Only
}

// IPToUint32 将 IPv4 转换为 uint32
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// Uint32ToIP 将 uint32 转换为 IPv4
func Uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// IPToUint128 将 IPv6 转换为两个 uint64
func IPToUint128(ip net.IP) (high, low uint64) {
	ip = ip.To16()
	if ip == nil {
		return 0, 0
	}
	high = binary.BigEndian.Uint64(ip[:8])
	low = binary.BigEndian.Uint64(ip[8:])
	return high, low
}

// Uint128ToIP 将两个 uint64 转换为 IPv6
func Uint128ToIP(high, low uint64) net.IP {
	ip := make(net.IP, 16)
	binary.BigEndian.PutUint64(ip[:8], high)
	binary.BigEndian.PutUint64(ip[8:], low)
	return ip
}

// Htons 主机字节序转网络字节序 (16位)
func Htons(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

// Ntohs 网络字节序转主机字节序 (16位)
func Ntohs(v uint16) uint16 {
	return Htons(v)
}

// UnifiedSessionKey 统一会话键 (支持 IPv4/IPv6)
type UnifiedSessionKey struct {
	SrcIPHigh uint64
	SrcIPLow  uint64
	DstIPHigh uint64
	DstIPLow  uint64
	SrcPort   uint16
	DstPort   uint16
	IPVer     uint8
	_         [3]byte
}

// NewUnifiedSessionKey 创建统一会话键
func NewUnifiedSessionKey(srcAddr, dstAddr *net.UDPAddr) *UnifiedSessionKey {
	key := &UnifiedSessionKey{
		SrcPort: Htons(uint16(srcAddr.Port)),
		DstPort: Htons(uint16(dstAddr.Port)),
	}

	if IsIPv4(srcAddr.IP) {
		key.IPVer = 4
		key.SrcIPLow = uint64(IPToUint32(srcAddr.IP))
		key.DstIPLow = uint64(IPToUint32(dstAddr.IP))
	} else {
		key.IPVer = 6
		key.SrcIPHigh, key.SrcIPLow = IPToUint128(srcAddr.IP)
		key.DstIPHigh, key.DstIPLow = IPToUint128(dstAddr.IP)
	}

	return key
}

// ToAddrs 转换回地址
func (k *UnifiedSessionKey) ToAddrs() (src, dst *net.UDPAddr) {
	var srcIP, dstIP net.IP

	if k.IPVer == 4 {
		srcIP = Uint32ToIP(uint32(k.SrcIPLow))
		dstIP = Uint32ToIP(uint32(k.DstIPLow))
	} else {
		srcIP = Uint128ToIP(k.SrcIPHigh, k.SrcIPLow)
		dstIP = Uint128ToIP(k.DstIPHigh, k.DstIPLow)
	}

	return &net.UDPAddr{IP: srcIP, Port: int(Ntohs(k.SrcPort))},
		&net.UDPAddr{IP: dstIP, Port: int(Ntohs(k.DstPort))}
}






