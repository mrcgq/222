


// =============================================================================
// 文件: internal/protocol/protocol.go
// =============================================================================


package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
)

// 消息类型
const (
	TypeConnect = 0x01
	TypeData    = 0x02
	TypeClose   = 0x03
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

	// Connect 和 Data 有不同的格式
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

// IsARQPacket 检查是否可能是 ARQ 包
// ARQ 包格式: Seq(4) + Ack(4) + Flags(1) + Len(2) + Payload
// 协议包格式: Type(1) + ReqID(4) + ...
// 通过检查第一个字节来区分：ARQ 的 Seq 高位通常不为 0x01-0x03
func IsARQPacket(data []byte) bool {
	if len(data) < 18 {
		return false
	}
	firstByte := data[0]
	return firstByte != TypeConnect && firstByte != TypeData && firstByte != TypeClose
}

