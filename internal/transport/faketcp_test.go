


// =============================================================================
// 文件: internal/transport/faketcp_test.go
// 描述: FakeTCP 伪装测试
// =============================================================================
package transport

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestTCPHeaderEncodeDecode(t *testing.T) {
	original := &TCPHeader{
		SrcPort:   12345,
		DstPort:   80,
		SeqNum:    1000,
		AckNum:    2000,
		Flags:     TCPFlagSYN | TCPFlagACK,
		Window:    65535,
		UrgentPtr: 0,
		Options: []TCPOption{
			{Kind: TCPOptMSS, Length: 4, Data: []byte{0x05, 0xB4}}, // MSS 1460
			{Kind: TCPOptNOP},
			{Kind: TCPOptWScale, Length: 3, Data: []byte{7}},
		},
	}

	encoded := EncodeTCPHeader(original)

	decoded, headerLen, err := DecodeTCPHeader(encoded)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}

	if decoded.SrcPort != original.SrcPort {
		t.Errorf("SrcPort 不匹配: got %d, want %d", decoded.SrcPort, original.SrcPort)
	}
	if decoded.DstPort != original.DstPort {
		t.Errorf("DstPort 不匹配: got %d, want %d", decoded.DstPort, original.DstPort)
	}
	if decoded.SeqNum != original.SeqNum {
		t.Errorf("SeqNum 不匹配: got %d, want %d", decoded.SeqNum, original.SeqNum)
	}
	if decoded.AckNum != original.AckNum {
		t.Errorf("AckNum 不匹配: got %d, want %d", decoded.AckNum, original.AckNum)
	}
	if decoded.Flags != original.Flags {
		t.Errorf("Flags 不匹配: got 0x%02x, want 0x%02x", decoded.Flags, original.Flags)
	}
	if decoded.Window != original.Window {
		t.Errorf("Window 不匹配: got %d, want %d", decoded.Window, original.Window)
	}

	// 检查头部长度
	if headerLen < TCPHeaderMinSize {
		t.Errorf("头部长度太小: %d", headerLen)
	}
}

func TestTCPChecksum(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1").To4()
	dstIP := net.ParseIP("192.168.1.2").To4()

	tcpHeader := &TCPHeader{
		SrcPort: 12345,
		DstPort: 80,
		SeqNum:  1000,
		AckNum:  0,
		Flags:   TCPFlagSYN,
		Window:  65535,
	}

	headerBuf := EncodeTCPHeader(tcpHeader)
	payload := []byte("Hello, TCP!")

	// 清零校验和
	headerBuf[16] = 0
	headerBuf[17] = 0

	// 计算校验和
	checksum := CalculateTCPChecksum(srcIP, dstIP, headerBuf, payload)

	// 设置校验和
	binary.BigEndian.PutUint16(headerBuf[16:18], checksum)

	// 验证
	tcpData := append(headerBuf, payload...)
	if !VerifyTCPChecksum(srcIP, dstIP, tcpData) {
		t.Error("校验和验证失败")
	}
}

func TestTCPOptions(t *testing.T) {
	options := BuildTCPOptions(1460, 7, true, true, 12345, 67890)

	// 检查 MSS
	mss, found := GetTCPMSS(options)
	if !found || mss != 1460 {
		t.Errorf("MSS 不正确: got %d, want 1460", mss)
	}

	// 检查 Window Scale
	wscale, found := GetTCPWindowScale(options)
	if !found || wscale != 7 {
		t.Errorf("Window Scale 不正确: got %d, want 7", wscale)
	}

	// 检查 SACK Permitted
	if !HasTCPOption(options, TCPOptSACKPerm) {
		t.Error("应该有 SACK Permitted 选项")
	}

	// 检查 Timestamp
	tsVal, tsEcr, found := GetTCPTimestamp(options)
	if !found {
		t.Error("应该有 Timestamp 选项")
	}
	if tsVal != 12345 || tsEcr != 67890 {
		t.Errorf("Timestamp 不正确: got (%d, %d), want (12345, 67890)", tsVal, tsEcr)
	}
}

func TestSessionState(t *testing.T) {
	localAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54322}
	config := DefaultFakeTCPConfig()
	mgr := NewFakeTCPSessionManager(config, localAddr)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	// 创建会话
	session := mgr.GetOrCreateSession(remoteAddr)
	if session == nil {
		t.Fatal("会话创建失败")
	}

	if session.State != TCPStateClosed {
		t.Errorf("初始状态应该是 CLOSED, got %s", session.State)
	}

	// 模拟收到 SYN
	synHeader := &TCPHeader{
		SrcPort: 12345,
		DstPort: 54322,
		SeqNum:  1000,
		Flags:   TCPFlagSYN,
		Window:  65535,
		Options: BuildTCPOptions(1460, 7, true, false, 0, 0),
	}

	response, _, err := mgr.HandleIncoming(session, synHeader, nil)
	if err != nil {
		t.Fatalf("处理 SYN 失败: %v", err)
	}

	if response == nil {
		t.Fatal("应该返回 SYN-ACK")
	}

	if response.TCPHeader.Flags&(TCPFlagSYN|TCPFlagACK) != (TCPFlagSYN | TCPFlagACK) {
		t.Errorf("响应应该是 SYN-ACK, got flags 0x%02x", response.TCPHeader.Flags)
	}

	if session.State != TCPStateSynReceived {
		t.Errorf("状态应该是 SYN_RECEIVED, got %s", session.State)
	}

	// 模拟收到 ACK
	ackHeader := &TCPHeader{
		SrcPort: 12345,
		DstPort: 54322,
		SeqNum:  1001,
		AckNum:  session.LocalSeq,
		Flags:   TCPFlagACK,
		Window:  65535,
	}

	_, _, err = mgr.HandleIncoming(session, ackHeader, nil)
	if err != nil {
		t.Fatalf("处理 ACK 失败: %v", err)
	}

	if session.State != TCPStateEstablished {
		t.Errorf("状态应该是 ESTABLISHED, got %s", session.State)
	}
}

func TestSessionDataTransfer(t *testing.T) {
	localAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54322}
	config := DefaultFakeTCPConfig()
	mgr := NewFakeTCPSessionManager(config, localAddr)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	session := mgr.GetOrCreateSession(remoteAddr)

	// 设置已建立状态
	session.State = TCPStateEstablished
	session.LocalSeq = 1000
	session.LocalAck = 2000
	session.RemoteAck = 1000
	session.MSS = 1460

	// 发送数据
	testData := []byte("Hello, FakeTCP!")
	pkt := mgr.SendData(session, testData)

	if pkt == nil {
		t.Fatal("SendData 返回 nil")
	}

	if !bytes.Equal(pkt.Payload, testData) {
		t.Errorf("Payload 不匹配: got %v, want %v", pkt.Payload, testData)
	}

	if pkt.TCPHeader.Flags&TCPFlagPSH == 0 {
		t.Error("应该设置 PSH 标志")
	}

	// 接收数据
	incomingData := []byte("Response data")
	dataHeader := &TCPHeader{
		SrcPort: 12345,
		DstPort: 54322,
		SeqNum:  session.LocalAck,
		AckNum:  session.LocalSeq,
		Flags:   TCPFlagACK | TCPFlagPSH,
		Window:  65535,
	}

	response, receivedData, err := mgr.HandleIncoming(session, dataHeader, incomingData)
	if err != nil {
		t.Fatalf("处理数据失败: %v", err)
	}

	if response == nil {
		t.Error("应该返回 ACK")
	}

	if !bytes.Equal(receivedData, incomingData) {
		t.Errorf("接收数据不匹配: got %v, want %v", receivedData, incomingData)
	}
}

func TestSessionCleanup(t *testing.T) {
	localAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54322}
	config := DefaultFakeTCPConfig()
	config.IdleTimeout = 100 * time.Millisecond
	mgr := NewFakeTCPSessionManager(config, localAddr)

	// 创建会话
	for i := 0; i < 10; i++ {
		remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345 + i}
		mgr.GetOrCreateSession(remoteAddr)
	}

	stats := mgr.GetStats()
	if stats.ActiveSessions != 10 {
		t.Errorf("应该有 10 个活跃会话, got %d", stats.ActiveSessions)
	}

	// 等待超时
	time.Sleep(150 * time.Millisecond)

	// 清理
	mgr.Cleanup()

	stats = mgr.GetStats()
	if stats.ActiveSessions != 0 {
		t.Errorf("清理后应该有 0 个会话, got %d", stats.ActiveSessions)
	}
}

func TestIPHeaderEncodeDecode(t *testing.T) {
	original := &IPHeader{
		Version:  4,
		IHL:      5,
		TOS:      0,
		TotalLen: 60,
		ID:       12345,
		TTL:      64,
		Protocol: 6, // TCP
		SrcIP:    net.ParseIP("192.168.1.1").To4(),
		DstIP:    net.ParseIP("192.168.1.2").To4(),
	}

	encoded := EncodeIPHeader(original, 40)

	decoded, headerLen, err := DecodeIPHeader(encoded)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}

	if headerLen != IPHeaderMinSize {
		t.Errorf("头部长度不正确: got %d, want %d", headerLen, IPHeaderMinSize)
	}

	if decoded.Version != 4 {
		t.Errorf("Version 不正确: got %d, want 4", decoded.Version)
	}

	if decoded.Protocol != 6 {
		t.Errorf("Protocol 不正确: got %d, want 6", decoded.Protocol)
	}

	if !decoded.SrcIP.Equal(original.SrcIP) {
		t.Errorf("SrcIP 不匹配: got %v, want %v", decoded.SrcIP, original.SrcIP)
	}

	if !decoded.DstIP.Equal(original.DstIP) {
		t.Errorf("DstIP 不匹配: got %v, want %v", decoded.DstIP, original.DstIP)
	}
}

// 基准测试
func BenchmarkTCPHeaderEncode(b *testing.B) {
	header := &TCPHeader{
		SrcPort: 12345,
		DstPort: 80,
		SeqNum:  1000,
		AckNum:  2000,
		Flags:   TCPFlagACK | TCPFlagPSH,
		Window:  65535,
		Options: BuildTCPOptions(1460, 7, true, true, 12345, 67890),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeTCPHeader(header)
	}
}

func BenchmarkTCPHeaderDecode(b *testing.B) {
	header := &TCPHeader{
		SrcPort: 12345,
		DstPort: 80,
		SeqNum:  1000,
		AckNum:  2000,
		Flags:   TCPFlagACK | TCPFlagPSH,
		Window:  65535,
		Options: BuildTCPOptions(1460, 7, true, true, 12345, 67890),
	}
	encoded := EncodeTCPHeader(header)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = DecodeTCPHeader(encoded)
	}
}

func BenchmarkTCPChecksum(b *testing.B) {
	srcIP := net.ParseIP("192.168.1.1").To4()
	dstIP := net.ParseIP("192.168.1.2").To4()
	tcpData := make([]byte, 1400)
	payload := make([]byte, 1200)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CalculateTCPChecksum(srcIP, dstIP, tcpData, payload)
	}
}

func BenchmarkSessionHandling(b *testing.B) {
	localAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54322}
	config := DefaultFakeTCPConfig()
	mgr := NewFakeTCPSessionManager(config, localAddr)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	session := mgr.GetOrCreateSession(remoteAddr)
	session.State = TCPStateEstablished
	session.LocalSeq = 1000
	session.LocalAck = 2000

	header := &TCPHeader{
		SrcPort: 12345,
		DstPort: 54322,
		SeqNum:  2000,
		AckNum:  1000,
		Flags:   TCPFlagACK | TCPFlagPSH,
		Window:  65535,
	}
	payload := make([]byte, 1200)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session.LocalAck = 2000 // 重置
		_, _, _ = mgr.HandleIncoming(session, header, payload)
	}
}



