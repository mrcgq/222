

// =============================================================================
// 文件: internal/transport/faketcp_codec.go
// 描述: FakeTCP 伪装 - TCP 包编解码 (支持 IPv4/IPv6 双栈)
// =============================================================================
package transport

import (
	"encoding/binary"
	"fmt"
	"net"
)

// =============================================================================
// TCP 编解码 (IPv4/IPv6 通用)
// =============================================================================

// EncodeTCPHeader 编码 TCP 头部
func EncodeTCPHeader(h *TCPHeader) []byte {
	// 计算选项长度
	optionsLen := 0
	for _, opt := range h.Options {
		if opt.Kind == TCPOptEnd || opt.Kind == TCPOptNOP {
			optionsLen++
		} else {
			optionsLen += 2 + len(opt.Data)
		}
	}
	// 填充到 4 字节边界
	padding := (4 - (optionsLen % 4)) % 4

	headerLen := TCPHeaderMinSize + optionsLen + padding
	dataOffset := uint8(headerLen / 4)

	buf := make([]byte, headerLen)

	// 基本头部
	binary.BigEndian.PutUint16(buf[0:2], h.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], h.DstPort)
	binary.BigEndian.PutUint32(buf[4:8], h.SeqNum)
	binary.BigEndian.PutUint32(buf[8:12], h.AckNum)
	buf[12] = dataOffset << 4
	buf[13] = h.Flags
	binary.BigEndian.PutUint16(buf[14:16], h.Window)
	// Checksum 稍后计算
	binary.BigEndian.PutUint16(buf[18:20], h.UrgentPtr)

	// 选项
	offset := TCPHeaderMinSize
	for _, opt := range h.Options {
		if opt.Kind == TCPOptEnd {
			buf[offset] = TCPOptEnd
			offset++
		} else if opt.Kind == TCPOptNOP {
			buf[offset] = TCPOptNOP
			offset++
		} else {
			buf[offset] = opt.Kind
			buf[offset+1] = opt.Length
			copy(buf[offset+2:], opt.Data)
			offset += 2 + len(opt.Data)
		}
	}

	// 填充
	for i := 0; i < padding; i++ {
		buf[offset+i] = TCPOptNOP
	}

	return buf
}

// DecodeTCPHeader 解码 TCP 头部
func DecodeTCPHeader(data []byte) (*TCPHeader, int, error) {
	if len(data) < TCPHeaderMinSize {
		return nil, 0, fmt.Errorf("TCP header too short: %d", len(data))
	}

	h := &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: data[12] >> 4,
		Flags:      data[13],
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		UrgentPtr:  binary.BigEndian.Uint16(data[18:20]),
	}

	headerLen := int(h.DataOffset) * 4
	if headerLen < TCPHeaderMinSize {
		return nil, 0, fmt.Errorf("invalid data offset: %d", h.DataOffset)
	}
	if len(data) < headerLen {
		return nil, 0, fmt.Errorf("data too short for header: %d < %d", len(data), headerLen)
	}

	// 解析选项
	if headerLen > TCPHeaderMinSize {
		h.Options = parseTCPOptions(data[TCPHeaderMinSize:headerLen])
	}

	return h, headerLen, nil
}

// parseTCPOptions 解析 TCP 选项
func parseTCPOptions(data []byte) []TCPOption {
	var options []TCPOption
	offset := 0

	for offset < len(data) {
		kind := data[offset]

		if kind == TCPOptEnd {
			options = append(options, TCPOption{Kind: TCPOptEnd})
			break
		}

		if kind == TCPOptNOP {
			options = append(options, TCPOption{Kind: TCPOptNOP})
			offset++
			continue
		}

		if offset+1 >= len(data) {
			break
		}

		length := int(data[offset+1])
		if length < 2 || offset+length > len(data) {
			break
		}

		opt := TCPOption{
			Kind:   kind,
			Length: uint8(length),
		}
		if length > 2 {
			opt.Data = make([]byte, length-2)
			copy(opt.Data, data[offset+2:offset+length])
		}
		options = append(options, opt)
		offset += length
	}

	return options
}

// BuildTCPOptions 构建常用 TCP 选项
func BuildTCPOptions(mss uint16, wscale uint8, sackPerm, timestamps bool, tsVal, tsEcr uint32) []TCPOption {
	var options []TCPOption

	// MSS 选项
	if mss > 0 {
		options = append(options, TCPOption{
			Kind:   TCPOptMSS,
			Length: 4,
			Data:   []byte{byte(mss >> 8), byte(mss)},
		})
	}

	// SACK Permitted
	if sackPerm {
		options = append(options, TCPOption{
			Kind:   TCPOptSACKPerm,
			Length: 2,
		})
	}

	// Timestamps
	if timestamps {
		data := make([]byte, 8)
		binary.BigEndian.PutUint32(data[0:4], tsVal)
		binary.BigEndian.PutUint32(data[4:8], tsEcr)
		options = append(options, TCPOption{
			Kind:   TCPOptTimestamp,
			Length: 10,
			Data:   data,
		})
	}

	// NOP 填充
	options = append(options, TCPOption{Kind: TCPOptNOP})

	// Window Scale
	if wscale > 0 {
		options = append(options, TCPOption{
			Kind:   TCPOptWScale,
			Length: 3,
			Data:   []byte{wscale},
		})
	}

	return options
}

// =============================================================================
// IPv4 编解码
// =============================================================================

// EncodeIPHeader 编码 IPv4 头部
func EncodeIPHeader(h *IPHeader, tcpLen int) []byte {
	buf := make([]byte, IPHeaderMinSize)

	buf[0] = (4 << 4) | 5 // Version + IHL
	buf[1] = h.TOS
	binary.BigEndian.PutUint16(buf[2:4], uint16(IPHeaderMinSize+tcpLen))
	binary.BigEndian.PutUint16(buf[4:6], h.ID)
	binary.BigEndian.PutUint16(buf[6:8], uint16(h.Flags)<<13|h.FragOffset)
	buf[8] = h.TTL
	buf[9] = h.Protocol
	// Checksum 稍后计算
	copy(buf[12:16], h.SrcIP.To4())
	copy(buf[16:20], h.DstIP.To4())

	// 计算校验和
	binary.BigEndian.PutUint16(buf[10:12], ipChecksum(buf))

	return buf
}

// DecodeIPHeader 解码 IPv4 头部
func DecodeIPHeader(data []byte) (*IPHeader, int, error) {
	if len(data) < IPHeaderMinSize {
		return nil, 0, fmt.Errorf("IP header too short: %d", len(data))
	}

	version := data[0] >> 4
	if version != 4 {
		return nil, 0, fmt.Errorf("not IPv4: version=%d", version)
	}

	ihl := int(data[0]&0x0F) * 4
	if ihl < IPHeaderMinSize || len(data) < ihl {
		return nil, 0, fmt.Errorf("invalid IHL: %d", ihl)
	}

	h := &IPHeader{
		Version:    version,
		IHL:        uint8(ihl / 4),
		TOS:        data[1],
		TotalLen:   binary.BigEndian.Uint16(data[2:4]),
		ID:         binary.BigEndian.Uint16(data[4:6]),
		Flags:      uint8(data[6] >> 5),
		FragOffset: binary.BigEndian.Uint16(data[6:8]) & 0x1FFF,
		TTL:        data[8],
		Protocol:   data[9],
		Checksum:   binary.BigEndian.Uint16(data[10:12]),
		SrcIP:      net.IP(data[12:16]).To4(),
		DstIP:      net.IP(data[16:20]).To4(),
	}

	return h, ihl, nil
}

// =============================================================================
// IPv6 编解码
// =============================================================================

// EncodeIPv6Header 编码 IPv6 头部
func EncodeIPv6Header(h *IPv6Header, payloadLen int) []byte {
	buf := make([]byte, IPv6HeaderSize)

	// Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits)
	versionTC := uint32(6)<<28 | uint32(h.TrafficClass)<<20 | (h.FlowLabel & 0xFFFFF)
	binary.BigEndian.PutUint32(buf[0:4], versionTC)

	// Payload Length
	binary.BigEndian.PutUint16(buf[4:6], uint16(payloadLen))

	// Next Header
	buf[6] = h.NextHeader

	// Hop Limit
	buf[7] = h.HopLimit

	// Source Address (16 bytes)
	copy(buf[8:24], h.SrcIP.To16())

	// Destination Address (16 bytes)
	copy(buf[24:40], h.DstIP.To16())

	return buf
}

// DecodeIPv6Header 解码 IPv6 头部
func DecodeIPv6Header(data []byte) (*IPv6Header, int, error) {
	if len(data) < IPv6HeaderSize {
		return nil, 0, fmt.Errorf("IPv6 header too short: %d", len(data))
	}

	// 解析第一个 32 位字
	firstWord := binary.BigEndian.Uint32(data[0:4])
	version := uint8(firstWord >> 28)
	if version != 6 {
		return nil, 0, fmt.Errorf("not IPv6: version=%d", version)
	}

	h := &IPv6Header{
		Version:      version,
		TrafficClass: uint8((firstWord >> 20) & 0xFF),
		FlowLabel:    firstWord & 0xFFFFF,
		PayloadLen:   binary.BigEndian.Uint16(data[4:6]),
		NextHeader:   data[6],
		HopLimit:     data[7],
		SrcIP:        make(net.IP, 16),
		DstIP:        make(net.IP, 16),
	}

	copy(h.SrcIP, data[8:24])
	copy(h.DstIP, data[24:40])

	return h, IPv6HeaderSize, nil
}

// =============================================================================
// 自动检测 IP 版本
// =============================================================================

// DecodeIPPacket 自动检测并解码 IP 包
func DecodeIPPacket(data []byte) (UnifiedIPHeader, int, error) {
	if len(data) < 1 {
		return nil, 0, fmt.Errorf("data too short")
	}

	version := data[0] >> 4
	switch version {
	case 4:
		return DecodeIPHeader(data)
	case 6:
		return DecodeIPv6Header(data)
	default:
		return nil, 0, fmt.Errorf("unknown IP version: %d", version)
	}
}

// =============================================================================
// TCP 校验和 (支持 IPv4/IPv6)
// =============================================================================

// CalculateTCPChecksum 计算 TCP 校验和 (自动检测 IP 版本)
func CalculateTCPChecksum(srcIP, dstIP net.IP, tcpHeader []byte, payload []byte) uint16 {
	// 规范化 IP 地址
	srcIP = NormalizeIP(srcIP)
	dstIP = NormalizeIP(dstIP)

	if IsIPv6IP(srcIP) || IsIPv6IP(dstIP) {
		return calculateTCPChecksumV6(srcIP.To16(), dstIP.To16(), tcpHeader, payload)
	}
	return calculateTCPChecksumV4(srcIP.To4(), dstIP.To4(), tcpHeader, payload)
}

// calculateTCPChecksumV4 计算 IPv4 TCP 校验和
func calculateTCPChecksumV4(srcIP, dstIP net.IP, tcpHeader []byte, payload []byte) uint16 {
	// 构建伪头部 (12 字节)
	pseudoHeader := make([]byte, PseudoHeaderSize)
	copy(pseudoHeader[0:4], srcIP)
	copy(pseudoHeader[4:8], dstIP)
	pseudoHeader[8] = 0
	pseudoHeader[9] = ProtocolTCP
	tcpLen := len(tcpHeader) + len(payload)
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(tcpLen))

	return checksumCombine(pseudoHeader, tcpHeader, payload)
}

// calculateTCPChecksumV6 计算 IPv6 TCP 校验和
func calculateTCPChecksumV6(srcIP, dstIP net.IP, tcpHeader []byte, payload []byte) uint16 {
	// 构建 IPv6 伪头部 (40 字节)
	pseudoHeader := make([]byte, PseudoHeaderV6Size)
	
	// 源地址 (16 字节)
	copy(pseudoHeader[0:16], srcIP)
	
	// 目的地址 (16 字节)
	copy(pseudoHeader[16:32], dstIP)
	
	// 上层协议长度 (4 字节)
	tcpLen := len(tcpHeader) + len(payload)
	binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(tcpLen))
	
	// 零填充 (3 字节) + 下一个头部 (1 字节)
	pseudoHeader[36] = 0
	pseudoHeader[37] = 0
	pseudoHeader[38] = 0
	pseudoHeader[39] = ProtocolTCP

	return checksumCombine(pseudoHeader, tcpHeader, payload)
}

// CalculateTCPChecksumWithIPHeader 使用统一 IP 头部计算校验和
func CalculateTCPChecksumWithIPHeader(ipHeader UnifiedIPHeader, tcpHeader []byte, payload []byte) uint16 {
	return CalculateTCPChecksum(ipHeader.GetSrcIP(), ipHeader.GetDstIP(), tcpHeader, payload)
}

// checksumCombine 组合计算校验和
func checksumCombine(parts ...[]byte) uint16 {
	var sum uint32

	for _, data := range parts {
		for i := 0; i < len(data)-1; i += 2 {
			sum += uint32(data[i])<<8 | uint32(data[i+1])
		}
		if len(data)%2 == 1 {
			sum += uint32(data[len(data)-1]) << 8
		}
	}

	// 折叠到 16 位
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}

	return ^uint16(sum)
}

// ipChecksum 计算 IPv4 校验和
func ipChecksum(data []byte) uint16 {
	var sum uint32

	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}

	return ^uint16(sum)
}

// =============================================================================
// 校验和验证
// =============================================================================

// VerifyTCPChecksum 验证 TCP 校验和 (自动检测 IP 版本)
func VerifyTCPChecksum(srcIP, dstIP net.IP, tcpData []byte) bool {
	if len(tcpData) < TCPHeaderMinSize {
		return false
	}

	// 保存原始校验和
	originalChecksum := binary.BigEndian.Uint16(tcpData[16:18])

	// 清零校验和字段
	tcpDataCopy := make([]byte, len(tcpData))
	copy(tcpDataCopy, tcpData)
	tcpDataCopy[16] = 0
	tcpDataCopy[17] = 0

	// 计算校验和
	calculated := CalculateTCPChecksum(srcIP, dstIP, tcpDataCopy, nil)

	return calculated == originalChecksum
}

// VerifyTCPChecksumWithHeader 使用统一 IP 头部验证校验和
func VerifyTCPChecksumWithHeader(ipHeader UnifiedIPHeader, tcpData []byte) bool {
	return VerifyTCPChecksum(ipHeader.GetSrcIP(), ipHeader.GetDstIP(), tcpData)
}

// =============================================================================
// TCP 选项辅助函数
// =============================================================================

// GetTCPTimestamp 从选项中获取时间戳
func GetTCPTimestamp(options []TCPOption) (tsVal, tsEcr uint32, found bool) {
	for _, opt := range options {
		if opt.Kind == TCPOptTimestamp && len(opt.Data) >= 8 {
			tsVal = binary.BigEndian.Uint32(opt.Data[0:4])
			tsEcr = binary.BigEndian.Uint32(opt.Data[4:8])
			return tsVal, tsEcr, true
		}
	}
	return 0, 0, false
}

// GetTCPMSS 从选项中获取 MSS
func GetTCPMSS(options []TCPOption) (uint16, bool) {
	for _, opt := range options {
		if opt.Kind == TCPOptMSS && len(opt.Data) >= 2 {
			return binary.BigEndian.Uint16(opt.Data[0:2]), true
		}
	}
	return 0, false
}

// GetTCPWindowScale 从选项中获取窗口缩放因子
func GetTCPWindowScale(options []TCPOption) (uint8, bool) {
	for _, opt := range options {
		if opt.Kind == TCPOptWScale && len(opt.Data) >= 1 {
			return opt.Data[0], true
		}
	}
	return 0, false
}

// HasTCPOption 检查是否包含指定选项
func HasTCPOption(options []TCPOption, kind uint8) bool {
	for _, opt := range options {
		if opt.Kind == kind {
			return true
		}
	}
	return false
}

// =============================================================================
// 完整数据包编解码
// =============================================================================

// EncodeFakeTCPPacket 编码完整的 FakeTCP 数据包
func EncodeFakeTCPPacket(pkt *FakeTCPPacket) ([]byte, error) {
	// 编码 TCP 头部
	tcpHeaderBytes := EncodeTCPHeader(pkt.TCPHeader)
	tcpLen := len(tcpHeaderBytes) + len(pkt.Payload)

	var ipHeaderBytes []byte

	if pkt.IPv6Header != nil {
		// IPv6
		ipHeaderBytes = EncodeIPv6Header(pkt.IPv6Header, tcpLen)
		
		// 计算 TCP 校验和
		checksum := calculateTCPChecksumV6(
			pkt.IPv6Header.SrcIP,
			pkt.IPv6Header.DstIP,
			tcpHeaderBytes,
			pkt.Payload,
		)
		binary.BigEndian.PutUint16(tcpHeaderBytes[16:18], checksum)
	} else if pkt.IPHeader != nil {
		// IPv4
		ipHeaderBytes = EncodeIPHeader(pkt.IPHeader, tcpLen)
		
		// 计算 TCP 校验和
		checksum := calculateTCPChecksumV4(
			pkt.IPHeader.SrcIP,
			pkt.IPHeader.DstIP,
			tcpHeaderBytes,
			pkt.Payload,
		)
		binary.BigEndian.PutUint16(tcpHeaderBytes[16:18], checksum)
	} else {
		return nil, fmt.Errorf("no IP header specified")
	}

	// 组装完整数据包
	result := make([]byte, len(ipHeaderBytes)+len(tcpHeaderBytes)+len(pkt.Payload))
	copy(result, ipHeaderBytes)
	copy(result[len(ipHeaderBytes):], tcpHeaderBytes)
	copy(result[len(ipHeaderBytes)+len(tcpHeaderBytes):], pkt.Payload)

	return result, nil
}

// DecodeFakeTCPPacket 解码完整的 FakeTCP 数据包
func DecodeFakeTCPPacket(data []byte) (*FakeTCPPacket, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short")
	}

	pkt := &FakeTCPPacket{}
	offset := 0

	// 检测 IP 版本
	version := data[0] >> 4

	switch version {
	case 4:
		// 解码 IPv4 头部
		ipHeader, ipLen, err := DecodeIPHeader(data)
		if err != nil {
			return nil, fmt.Errorf("decode IPv4 header: %w", err)
		}
		if ipHeader.Protocol != ProtocolTCP {
			return nil, fmt.Errorf("not TCP: protocol=%d", ipHeader.Protocol)
		}
		pkt.IPHeader = ipHeader
		offset = ipLen

	case 6:
		// 解码 IPv6 头部
		ipv6Header, ipLen, err := DecodeIPv6Header(data)
		if err != nil {
			return nil, fmt.Errorf("decode IPv6 header: %w", err)
		}
		if ipv6Header.NextHeader != ProtocolTCP {
			return nil, fmt.Errorf("not TCP: next header=%d", ipv6Header.NextHeader)
		}
		pkt.IPv6Header = ipv6Header
		offset = ipLen

	default:
		return nil, fmt.Errorf("unknown IP version: %d", version)
	}

	// 解码 TCP 头部
	if len(data) < offset+TCPHeaderMinSize {
		return nil, fmt.Errorf("data too short for TCP header")
	}

	tcpHeader, tcpLen, err := DecodeTCPHeader(data[offset:])
	if err != nil {
		return nil, fmt.Errorf("decode TCP header: %w", err)
	}
	pkt.TCPHeader = tcpHeader
	offset += tcpLen

	// 提取 payload
	if offset < len(data) {
		pkt.Payload = data[offset:]
	}

	return pkt, nil
}


