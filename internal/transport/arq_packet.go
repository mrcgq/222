


// =============================================================================
// 文件: internal/transport/arq_packet.go
// 描述: ARQ 可靠传输 - 包编解码 (统一版本)
// =============================================================================
package transport

import (
	"encoding/binary"
	"fmt"
	"time"
)

// ARQPacket ARQ 数据包
type ARQPacket struct {
	Seq        uint32      // 序列号
	Ack        uint32      // 确认号
	Flags      uint16      // 标志位
	Window     uint16      // 接收窗口大小
	Timestamp  uint32      // 发送时间戳 (ms)
	Data       []byte      // 有效载荷
	SACKRanges []SACKRange // SACK 区间 (可选)
}

// Encode 编码 ARQ 包
func (p *ARQPacket) Encode() []byte {
	dataLen := len(p.Data)
	sackLen := 0
	if p.Flags&ARQFlagSACK != 0 && len(p.SACKRanges) > 0 {
		sackLen = 1 + len(p.SACKRanges)*ARQSACKRangeSize // 1字节计数 + 区间数据
	}
	totalLen := ARQHeaderSize + sackLen + dataLen

	buf := make([]byte, totalLen)

	// 编码头部
	binary.BigEndian.PutUint32(buf[0:4], p.Seq)
	binary.BigEndian.PutUint32(buf[4:8], p.Ack)
	binary.BigEndian.PutUint16(buf[8:10], p.Flags)
	binary.BigEndian.PutUint16(buf[10:12], p.Window)
	binary.BigEndian.PutUint32(buf[12:16], p.Timestamp)

	// 数据长度 (包含 SACK)
	binary.BigEndian.PutUint16(buf[16:18], uint16(sackLen+dataLen))

	offset := ARQHeaderSize

	// 编码 SACK 区间
	if p.Flags&ARQFlagSACK != 0 && len(p.SACKRanges) > 0 {
		buf[offset] = byte(len(p.SACKRanges))
		offset++
		for _, r := range p.SACKRanges {
			binary.BigEndian.PutUint32(buf[offset:offset+4], r.Start)
			binary.BigEndian.PutUint32(buf[offset+4:offset+8], r.End)
			offset += ARQSACKRangeSize
		}
	}

	// 编码数据
	if dataLen > 0 {
		copy(buf[offset:], p.Data)
	}

	return buf
}

// DecodeARQPacket 解码 ARQ 包
func DecodeARQPacket(data []byte) (*ARQPacket, error) {
	if len(data) < ARQHeaderSize {
		return nil, fmt.Errorf("数据太短: %d < %d", len(data), ARQHeaderSize)
	}

	p := &ARQPacket{
		Seq:       binary.BigEndian.Uint32(data[0:4]),
		Ack:       binary.BigEndian.Uint32(data[4:8]),
		Flags:     binary.BigEndian.Uint16(data[8:10]),
		Window:    binary.BigEndian.Uint16(data[10:12]),
		Timestamp: binary.BigEndian.Uint32(data[12:16]),
	}

	payloadLen := binary.BigEndian.Uint16(data[16:18])
	if len(data) < ARQHeaderSize+int(payloadLen) {
		return nil, fmt.Errorf("数据不完整: %d < %d", len(data), ARQHeaderSize+int(payloadLen))
	}

	offset := ARQHeaderSize

	// 解码 SACK
	if p.Flags&ARQFlagSACK != 0 && payloadLen > 0 && offset < len(data) {
		sackCount := int(data[offset])
		offset++
		if sackCount > ARQMaxSACKRanges {
			sackCount = ARQMaxSACKRanges
		}
		for i := 0; i < sackCount && offset+ARQSACKRangeSize <= len(data); i++ {
			r := SACKRange{
				Start: binary.BigEndian.Uint32(data[offset : offset+4]),
				End:   binary.BigEndian.Uint32(data[offset+4 : offset+8]),
			}
			p.SACKRanges = append(p.SACKRanges, r)
			offset += ARQSACKRangeSize
		}
	}

	// 解码数据
	dataEnd := ARQHeaderSize + int(payloadLen)
	if dataEnd > len(data) {
		dataEnd = len(data)
	}
	if offset < dataEnd {
		p.Data = make([]byte, dataEnd-offset)
		copy(p.Data, data[offset:dataEnd])
	}

	return p, nil
}

// NewDataPacket 创建数据包
func NewDataPacket(seq, ack uint32, window uint16, data []byte) *ARQPacket {
	p := &ARQPacket{
		Seq:       seq,
		Ack:       ack,
		Flags:     ARQFlagDATA | ARQFlagACK,
		Window:    window,
		Timestamp: uint32(time.Now().UnixMilli() & 0xFFFFFFFF),
	}
	if len(data) > 0 {
		p.Data = make([]byte, len(data))
		copy(p.Data, data)
	}
	return p
}

// NewAckPacket 创建纯 ACK 包
func NewAckPacket(ack uint32, window uint16, sackRanges []SACKRange) *ARQPacket {
	p := &ARQPacket{
		Seq:       0,
		Ack:       ack,
		Flags:     ARQFlagACK,
		Window:    window,
		Timestamp: uint32(time.Now().UnixMilli() & 0xFFFFFFFF),
	}
	if len(sackRanges) > 0 {
		p.Flags |= ARQFlagSACK
		p.SACKRanges = sackRanges
	}
	return p
}

// NewSynPacket 创建 SYN 包
func NewSynPacket(seq uint32, window uint16) *ARQPacket {
	return &ARQPacket{
		Seq:       seq,
		Ack:       0,
		Flags:     ARQFlagSYN,
		Window:    window,
		Timestamp: uint32(time.Now().UnixMilli() & 0xFFFFFFFF),
	}
}

// NewSynAckPacket 创建 SYN-ACK 包
func NewSynAckPacket(seq, ack uint32, window uint16) *ARQPacket {
	return &ARQPacket{
		Seq:       seq,
		Ack:       ack,
		Flags:     ARQFlagSYN | ARQFlagACK,
		Window:    window,
		Timestamp: uint32(time.Now().UnixMilli() & 0xFFFFFFFF),
	}
}

// NewFinPacket 创建 FIN 包
func NewFinPacket(seq, ack uint32) *ARQPacket {
	return &ARQPacket{
		Seq:       seq,
		Ack:       ack,
		Flags:     ARQFlagFIN | ARQFlagACK,
		Window:    0,
		Timestamp: uint32(time.Now().UnixMilli() & 0xFFFFFFFF),
	}
}

// NewRstPacket 创建 RST 包
func NewRstPacket(seq uint32) *ARQPacket {
	return &ARQPacket{
		Seq:       seq,
		Ack:       0,
		Flags:     ARQFlagRST,
		Window:    0,
		Timestamp: uint32(time.Now().UnixMilli() & 0xFFFFFFFF),
	}
}

// NewPingPacket 创建 PING 包
func NewPingPacket(seq, ack uint32) *ARQPacket {
	return &ARQPacket{
		Seq:       seq,
		Ack:       ack,
		Flags:     ARQFlagPING | ARQFlagACK,
		Window:    0,
		Timestamp: uint32(time.Now().UnixMilli() & 0xFFFFFFFF),
	}
}

// NewPongPacket 创建 PONG 包
func NewPongPacket(ack uint32, echoTimestamp uint32) *ARQPacket {
	return &ARQPacket{
		Seq:       0,
		Ack:       ack,
		Flags:     ARQFlagPONG | ARQFlagACK,
		Window:    0,
		Timestamp: echoTimestamp, // 回显对方的时间戳
	}
}

// IsARQPacketData 检查是否是 ARQ 包
func IsARQPacketData(data []byte) bool {
	if len(data) < ARQHeaderSize {
		return false
	}
	// 检查标志位是否有效
	flags := binary.BigEndian.Uint16(data[8:10])
	validFlags := ARQFlagACK | ARQFlagSYN | ARQFlagFIN | ARQFlagDATA |
		ARQFlagRST | ARQFlagPING | ARQFlagPONG | ARQFlagSACK | ARQFlagECN | ARQFlagURG
	return flags != 0 && (flags & ^validFlags) == 0
}

// CalculateRTT 从时间戳计算 RTT
func CalculateRTT(sentTimestamp uint32) time.Duration {
	now := uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
	diff := now - sentTimestamp
	// 处理时间戳回绕
	if diff > 0x80000000 {
		diff = sentTimestamp - now
	}
	return time.Duration(diff) * time.Millisecond
}


