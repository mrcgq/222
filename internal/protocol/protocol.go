// =============================================================================
// 文件: internal/protocol/protocol.go
// 修复: 添加 UDP 分片协议支持
// =============================================================================

package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
)

// 消息类型
const (
	TypeConnect   = 0x01
	TypeData      = 0x02
	TypeClose     = 0x03
	TypeHeartbeat = 0x04
	TypeFragment  = 0x05 // 新增：分片数据包
)

// 地址类型
const (
	AddrIPv4   = 0x01
	AddrIPv6   = 0x04
	AddrDomain = 0x03
)

// 网络类型
const (
	NetworkTCP = 0x01
	NetworkUDP = 0x02
)

// =============================================================================
// 分片相关常量
// =============================================================================

const (
	// MaxUDPPayloadSize 单个 UDP 包最大安全负载
	// MTU(1500) - IP头(20) - UDP头(8) - 加密开销(34) - 协议头(10) ≈ 1428
	// 保守设置为 1280，确保通过各种网络（包括 IPv6 最小 MTU）
	MaxUDPPayloadSize = 1280

	// FragmentHeaderSize 分片头大小
	// Type(1) + ReqID(4) + FragID(2) + FragIndex(1) + FragTotal(1) = 9
	FragmentHeaderSize = 9

	// MaxFragmentDataSize 单片最大数据量
	MaxFragmentDataSize = MaxUDPPayloadSize - FragmentHeaderSize

	// MaxFragments 最大分片数（防止攻击）
	MaxFragments = 64
)

// =============================================================================
// 分片包结构
// =============================================================================

// FragmentPacket 分片数据包
type FragmentPacket struct {
	ReqID      uint32 // 请求 ID（用于关联会话）
	FragID     uint16 // 分片组 ID（区分不同的大包）
	FragIndex  uint8  // 当前分片索引（0-based）
	FragTotal  uint8  // 总分片数
	Data       []byte // 分片数据
}

// BuildFragmentPacket 构建分片包
// 格式: Type(1) + ReqID(4) + FragID(2) + FragIndex(1) + FragTotal(1) + Data(N)
func BuildFragmentPacket(reqID uint32, fragID uint16, fragIndex, fragTotal uint8, data []byte) []byte {
	packet := make([]byte, FragmentHeaderSize+len(data))
	packet[0] = TypeFragment
	binary.BigEndian.PutUint32(packet[1:5], reqID)
	binary.BigEndian.PutUint16(packet[5:7], fragID)
	packet[7] = fragIndex
	packet[8] = fragTotal
	copy(packet[FragmentHeaderSize:], data)
	return packet
}

// ParseFragmentPacket 解析分片包
func ParseFragmentPacket(data []byte) (*FragmentPacket, error) {
	if len(data) < FragmentHeaderSize {
		return nil, fmt.Errorf("分片包太短: %d < %d", len(data), FragmentHeaderSize)
	}

	if data[0] != TypeFragment {
		return nil, fmt.Errorf("不是分片包: type=0x%02X", data[0])
	}

	fragTotal := data[8]
	if fragTotal == 0 || fragTotal > MaxFragments {
		return nil, fmt.Errorf("无效的分片总数: %d", fragTotal)
	}

	fragIndex := data[7]
	if fragIndex >= fragTotal {
		return nil, fmt.Errorf("分片索引越界: %d >= %d", fragIndex, fragTotal)
	}

	return &FragmentPacket{
		ReqID:     binary.BigEndian.Uint32(data[1:5]),
		FragID:    binary.BigEndian.Uint16(data[5:7]),
		FragIndex: fragIndex,
		FragTotal: fragTotal,
		Data:      data[FragmentHeaderSize:],
	}, nil
}

// IsFragmentPacket 检查是否是分片包
func IsFragmentPacket(data []byte) bool {
	return len(data) >= 1 && data[0] == TypeFragment
}

// =============================================================================
// 分片工具函数
// =============================================================================

// NeedsFragmentation 检查数据是否需要分片
func NeedsFragmentation(dataLen int) bool {
	return dataLen > MaxUDPPayloadSize
}

// CalculateFragmentCount 计算需要的分片数
func CalculateFragmentCount(dataLen int) int {
	if dataLen <= MaxFragmentDataSize {
		return 1
	}
	return (dataLen + MaxFragmentDataSize - 1) / MaxFragmentDataSize
}

// =============================================================================
// 原有代码（保持不变）
// =============================================================================

// Request 解析后的请求
type Request struct {
	Type    byte
	ReqID   uint32
	Network byte
	Address string
	Port    uint16
	Data    []byte
}

// ParseRequest 解析请求
// 格式: Type(1) + ReqID(4) + [Network(1) + AddrType(1) + Addr + Port(2)] + [Data]
func ParseRequest(data []byte) (*Request, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("数据太短: %d", len(data))
	}

	req := &Request{
		Type:  data[0],
		ReqID: binary.BigEndian.Uint32(data[1:5]),
	}

	// 根据请求类型分发处理
	switch req.Type {
	case TypeConnect:
		return parseConnect(req, data[5:])
	case TypeData:
		if len(data) > 5 {
			req.Data = data[5:]
		}
		return req, nil
	case TypeClose:
		return req, nil
	case TypeHeartbeat:
		return req, nil
	case TypeFragment:
		// 分片包需要单独处理，不走这里
		return nil, fmt.Errorf("分片包请使用 ParseFragmentPacket")
	default:
		return nil, fmt.Errorf("未知类型: %d", req.Type)
	}
}

func parseConnect(req *Request, data []byte) (*Request, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("Connect 数据不足")
	}

	req.Network = data[0]
	addrType := data[1]
	offset := 2

	switch addrType {
	case AddrIPv4:
		if len(data) < offset+4+2 {
			return nil, fmt.Errorf("IPv4 数据不足")
		}
		req.Address = net.IP(data[offset : offset+4]).String()
		offset += 4

	case AddrIPv6:
		if len(data) < offset+16+2 {
			return nil, fmt.Errorf("IPv6 数据不足")
		}
		req.Address = net.IP(data[offset : offset+16]).String()
		offset += 16

	case AddrDomain:
		if len(data) < offset+1 {
			return nil, fmt.Errorf("域名长度缺失")
		}
		dlen := int(data[offset])
		offset++
		if len(data) < offset+dlen+2 {
			return nil, fmt.Errorf("域名数据不足")
		}
		req.Address = string(data[offset : offset+dlen])
		offset += dlen

	default:
		return nil, fmt.Errorf("未知地址类型: %d", addrType)
	}

	req.Port = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 剩余的是初始数据
	if len(data) > offset {
		req.Data = data[offset:]
	}

	return req, nil
}

// TargetAddr 返回目标地址
func (r *Request) TargetAddr() string {
	if r.Address == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", r.Address, r.Port)
}

// NetworkString 返回网络类型字符串
func (r *Request) NetworkString() string {
	switch r.Network {
	case NetworkTCP:
		return "tcp"
	case NetworkUDP:
		return "udp"
	default:
		return "unknown"
	}
}

// BuildResponse 构建响应
// 格式: Type(1) + ReqID(4) + Status(1) + [Data]
func BuildResponse(reqID uint32, status byte, data []byte) []byte {
	resp := make([]byte, 6+len(data))
	resp[0] = TypeData
	binary.BigEndian.PutUint32(resp[1:5], reqID)
	resp[5] = status
	if len(data) > 0 {
		copy(resp[6:], data)
	}
	return resp
}

// BuildHeartbeatResponse 构建心跳响应
func BuildHeartbeatResponse(reqID uint32) []byte {
	resp := make([]byte, 5)
	resp[0] = TypeHeartbeat
	binary.BigEndian.PutUint32(resp[1:5], reqID)
	return resp
}

// IsARQPacket 检查是否可能是 ARQ 包
func IsARQPacket(data []byte) bool {
	if len(data) < 18 {
		return false
	}
	firstByte := data[0]
	return firstByte != TypeConnect && firstByte != TypeData &&
		firstByte != TypeClose && firstByte != TypeHeartbeat &&
		firstByte != TypeFragment
}
