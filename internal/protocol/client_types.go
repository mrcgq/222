// internal/protocol/client_types.go
// 客户端专用协议构建与解析函数
// 严格匹配服务端 ParseRequest 和 BuildResponse 的字节布局

package protocol

import (
	"encoding/binary"
	"errors"
	"net"
)

// ============================================
// 扩展常量（protocol.go 中没有的）
// ============================================

const (
	// 响应状态码
	StatusSuccess byte = 0x00
	StatusError   byte = 0x01
	StatusTimeout byte = 0x02
	StatusRefused byte = 0x03
)

// ============================================
// 服务端响应结构
// ============================================

// ServerResponse 服务端响应结构
type ServerResponse struct {
	Type    byte   // 消息类型
	ReqID   uint32 // 请求ID
	Status  byte   // 状态码（0x00=成功）
	Payload []byte // 数据载荷
}

// IsConnectAck 判断是否为连接确认响应
// 服务端使用 TypeData + 空 Payload 回复连接结果
func (r *ServerResponse) IsConnectAck() bool {
	return r.Type == TypeData && len(r.Payload) == 0
}

// IsDataPacket 判断是否为数据包
func (r *ServerResponse) IsDataPacket() bool {
	return r.Type == TypeData && len(r.Payload) > 0
}

// IsClosePacket 判断是否为关闭包
func (r *ServerResponse) IsClosePacket() bool {
	return r.Type == TypeClose
}

// IsDisconnect 判断是否为断开连接包
// 修复：添加 IsDisconnect 方法供 client_handler.go 调用
func (r *ServerResponse) IsDisconnect() bool {
	return r.Type == TypeClose
}

// IsHeartbeatResponse 判断是否为心跳响应
func (r *ServerResponse) IsHeartbeatResponse() bool {
	return r.Type == TypeHeartbeat
}

// ============================================
// 客户端请求构建函数
// ============================================

// BuildClientConnectRequest 构建连接请求包
// 格式: Type(1) + ReqID(4) + Network(1) + AddrType(1) + Addr(变长) + Port(2) + [InitData]
func BuildClientConnectRequest(reqID uint32, network byte, host string, port uint16, initData []byte) ([]byte, error) {
	// 1. 解析并编码目标地址
	addrType, addrBytes, err := encodeAddress(host)
	if err != nil {
		return nil, err
	}

	// 2. 计算总长度
	headerLen := 1 + 4 + 1 + 1 + len(addrBytes) + 2
	totalLen := headerLen + len(initData)

	buf := make([]byte, totalLen)
	offset := 0

	// 3. 按照服务端 ParseRequest 期望的顺序填充
	buf[offset] = TypeConnect
	offset++

	binary.BigEndian.PutUint32(buf[offset:], reqID)
	offset += 4

	buf[offset] = network
	offset++

	buf[offset] = addrType
	offset++

	copy(buf[offset:], addrBytes)
	offset += len(addrBytes)

	binary.BigEndian.PutUint16(buf[offset:], port)
	offset += 2

	// 4. 附加 0-RTT 初始数据
	if len(initData) > 0 {
		copy(buf[offset:], initData)
	}

	return buf, nil
}

// BuildClientDataRequest 构建数据传输包
// 格式: Type(1) + ReqID(4) + Payload
func BuildClientDataRequest(reqID uint32, payload []byte) []byte {
	buf := make([]byte, 1+4+len(payload))

	buf[0] = TypeData
	binary.BigEndian.PutUint32(buf[1:5], reqID)
	copy(buf[5:], payload)

	return buf
}

// BuildClientCloseRequest 构建关闭请求包
// 格式: Type(1) + ReqID(4)
func BuildClientCloseRequest(reqID uint32) []byte {
	buf := make([]byte, 5)

	buf[0] = TypeClose
	binary.BigEndian.PutUint32(buf[1:5], reqID)

	return buf
}

// BuildClientHeartbeat 构建心跳包
// 格式: Type(1) + ReqID(4)
func BuildClientHeartbeat(reqID uint32) []byte {
	buf := make([]byte, 5)

	buf[0] = TypeHeartbeat
	binary.BigEndian.PutUint32(buf[1:5], reqID)

	return buf
}

// ============================================
// 服务端响应解析函数
// ============================================

// ParseServerResponse 解析服务端 BuildResponse 发回的包
// 服务端格式: Type(1) + ReqID(4) + Status(1) + [Payload]
func ParseServerResponse(data []byte) (*ServerResponse, error) {
	// 最小长度检查: Type(1) + ReqID(4) + Status(1) = 6
	if len(data) < 6 {
		return nil, errors.New("response too short: need at least 6 bytes")
	}

	resp := &ServerResponse{
		Type:   data[0],
		ReqID:  binary.BigEndian.Uint32(data[1:5]),
		Status: data[5],
	}

	// 提取载荷
	if len(data) > 6 {
		resp.Payload = make([]byte, len(data)-6)
		copy(resp.Payload, data[6:])
	}

	return resp, nil
}

// ============================================
// 辅助函数
// ============================================

// encodeAddress 编码目标地址为字节流
func encodeAddress(host string) (addrType byte, addrBytes []byte, err error) {
	// 尝试解析为 IP
	ip := net.ParseIP(host)

	if ip != nil {
		// IPv4
		if ip4 := ip.To4(); ip4 != nil {
			return AddrIPv4, ip4, nil
		}
		// IPv6
		return AddrIPv6, ip.To16(), nil
	}

	// 域名
	if len(host) == 0 {
		return 0, nil, errors.New("empty host")
	}
	if len(host) > 255 {
		return 0, nil, errors.New("domain name too long")
	}

	// 域名格式: Length(1) + Domain
	addrBytes = make([]byte, 1+len(host))
	addrBytes[0] = byte(len(host))
	copy(addrBytes[1:], host)

	return AddrDomain, addrBytes, nil
}

// DecodeAddress 解码地址字节流
func DecodeAddress(addrType byte, data []byte) (host string, bytesRead int, err error) {
	switch addrType {
	case AddrIPv4:
		if len(data) < 4 {
			return "", 0, errors.New("insufficient data for IPv4")
		}
		return net.IP(data[:4]).String(), 4, nil

	case AddrIPv6:
		if len(data) < 16 {
			return "", 0, errors.New("insufficient data for IPv6")
		}
		return net.IP(data[:16]).String(), 16, nil

	case AddrDomain:
		if len(data) < 1 {
			return "", 0, errors.New("insufficient data for domain length")
		}
		domainLen := int(data[0])
		if len(data) < 1+domainLen {
			return "", 0, errors.New("insufficient data for domain")
		}
		return string(data[1 : 1+domainLen]), 1 + domainLen, nil

	default:
		return "", 0, errors.New("unknown address type")
	}
}
