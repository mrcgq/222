

// =============================================================================
// 文件: internal/transport/arq_test.go
// 描述: ARQ 可靠传输测试
// =============================================================================
package transport

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestARQPacketEncodeDecode(t *testing.T) {
	original := &ARQPacket{
		Seq:       12345,
		Ack:       67890,
		Flags:     ARQFlagDATA | ARQFlagACK,
		Window:    256,
		Timestamp: uint32(time.Now().UnixMilli() & 0xFFFFFFFF),
		Data:      []byte("Hello, ARQ!"),
	}

	encoded := original.Encode()
	decoded, err := DecodeARQPacket(encoded)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}

	if decoded.Seq != original.Seq {
		t.Errorf("Seq 不匹配: got %d, want %d", decoded.Seq, original.Seq)
	}
	if decoded.Ack != original.Ack {
		t.Errorf("Ack 不匹配: got %d, want %d", decoded.Ack, original.Ack)
	}
	if decoded.Flags != original.Flags {
		t.Errorf("Flags 不匹配: got %d, want %d", decoded.Flags, original.Flags)
	}
	if decoded.Window != original.Window {
		t.Errorf("Window 不匹配: got %d, want %d", decoded.Window, original.Window)
	}
	if !bytes.Equal(decoded.Data, original.Data) {
		t.Errorf("Data 不匹配: got %v, want %v", decoded.Data, original.Data)
	}
}

func TestARQSendBuffer(t *testing.T) {
	buf := NewARQSendBuffer(10, 1)

	// 添加数据
	seq1, ok := buf.Add([]byte("packet1"))
	if !ok || seq1 != 1 {
		t.Errorf("Add 失败: seq=%d, ok=%v", seq1, ok)
	}

	seq2, ok := buf.Add([]byte("packet2"))
	if !ok || seq2 != 2 {
		t.Errorf("Add 失败: seq=%d, ok=%v", seq2, ok)
	}

	// 检查可用空间
	if buf.Available() != 8 {
		t.Errorf("Available 不正确: got %d, want 8", buf.Available())
	}

	// 标记发送
	buf.MarkSent(1, 100*time.Millisecond)
	buf.MarkSent(2, 100*time.Millisecond)

	// 确认
	ackedBytes, rtt, _ := buf.OnAck(2)
	if ackedBytes != 7 { // len("packet1")
		t.Errorf("Ack bytes 不正确: got %d, want 7", ackedBytes)
	}
	if rtt == 0 {
		t.Error("RTT 应该被计算")
	}

	// 确认后可用空间增加
	if buf.Available() != 9 {
		t.Errorf("Ack 后 Available 不正确: got %d, want 9", buf.Available())
	}
}

func TestARQRecvBuffer(t *testing.T) {
	buf := NewARQRecvBuffer(10, 1)

	// 乱序插入
	buf.Insert(2, []byte("second"))
	buf.Insert(1, []byte("first"))
	buf.Insert(3, []byte("third"))

	// 读取有序数据
	data := buf.ReadOrdered()
	if len(data) != 3 {
		t.Fatalf("ReadOrdered 返回数量不正确: got %d, want 3", len(data))
	}

	if string(data[0]) != "first" {
		t.Errorf("第一个包不正确: got %s, want first", string(data[0]))
	}
	if string(data[1]) != "second" {
		t.Errorf("第二个包不正确: got %s, want second", string(data[1]))
	}
	if string(data[2]) != "third" {
		t.Errorf("第三个包不正确: got %s, want third", string(data[2]))
	}

	// 期望序列号应该更新
	if buf.GetExpectedSeq() != 4 {
		t.Errorf("ExpectedSeq 不正确: got %d, want 4", buf.GetExpectedSeq())
	}
}

func TestARQRecvBufferSACK(t *testing.T) {
	buf := NewARQRecvBuffer(10, 1)

	// 插入有空洞的数据
	buf.Insert(1, []byte("first"))
	buf.Insert(3, []byte("third"))
	buf.Insert(5, []byte("fifth"))

	// 读取连续部分
	data := buf.ReadOrdered()
	if len(data) != 1 {
		t.Errorf("应该只能读取 1 个: got %d", len(data))
	}

	// 检查是否有空洞
	if !buf.HasGaps() {
		t.Error("应该有空洞")
	}

	// 获取 SACK
	sackRanges := buf.GetSACKRanges()
	if len(sackRanges) == 0 {
		t.Error("应该有 SACK 区间")
	}
}

func TestARQConnectivity(t *testing.T) {
	// 创建两个 UDP socket
	serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("创建服务器失败: %v", err)
	}
	defer serverConn.Close()

	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	clientConn, err := net.ListenUDP("udp", clientAddr)
	if err != nil {
		t.Fatalf("创建客户端失败: %v", err)
	}
	defer clientConn.Close()

	serverUDPAddr := serverConn.LocalAddr().(*net.UDPAddr)

	// 创建处理器
	var serverReceived []byte
	var mu sync.Mutex

	handler := &testARQHandler{
		onData: func(data []byte, from *net.UDPAddr) {
			mu.Lock()
			serverReceived = append(serverReceived, data...)
			mu.Unlock()
		},
	}

	// 创建服务端管理器
	serverManager := NewARQManager(nil, nil, handler)
	defer serverManager.Close()

	// 创建客户端连接
	clientARQ := NewARQConn(clientConn, serverUDPAddr, nil, nil, nil)
	clientARQ.Start()
	defer clientARQ.Close()

	// 启动服务端接收
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			serverManager.HandlePacket(buf[:n], from, serverConn)
		}
	}()

	// 启动客户端接收
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := clientConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt, _ := DecodeARQPacket(buf[:n])
			if pkt != nil {
				clientARQ.HandlePacket(pkt)
			}
		}
	}()

	// 连接
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := clientARQ.Connect(ctx); err != nil {
		t.Fatalf("连接失败: %v", err)
	}

	// 等待连接建立
	time.Sleep(100 * time.Millisecond)

	if !clientARQ.IsEstablished() {
		t.Error("客户端应该已建立连接")
	}

	// 发送数据
	testData := []byte("Hello, ARQ!")
	if err := clientARQ.Send(testData); err != nil {
		t.Fatalf("发送失败: %v", err)
	}

	// 等待数据到达
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	if !bytes.Equal(serverReceived, testData) {
		t.Errorf("服务端收到的数据不正确: got %v, want %v", serverReceived, testData)
	}
	mu.Unlock()
}

type testARQHandler struct {
	onData         func(data []byte, from *net.UDPAddr)
	onConnected    func(addr *net.UDPAddr)
	onDisconnected func(addr *net.UDPAddr, reason error)
}

func (h *testARQHandler) OnData(data []byte, from *net.UDPAddr) {
	if h.onData != nil {
		h.onData(data, from)
	}
}

func (h *testARQHandler) OnConnected(addr *net.UDPAddr) {
	if h.onConnected != nil {
		h.onConnected(addr)
	}
}

func (h *testARQHandler) OnDisconnected(addr *net.UDPAddr, reason error) {
	if h.onDisconnected != nil {
		h.onDisconnected(addr, reason)
	}
}

func TestARQRetransmit(t *testing.T) {
	buf := NewARQSendBuffer(10, 1)

	// 添加数据
	buf.Add([]byte("packet1"))
	buf.Add([]byte("packet2"))

	// 标记发送，使用很短的 RTO
	buf.MarkSent(1, 10*time.Millisecond)
	buf.MarkSent(2, 10*time.Millisecond)

	// 等待超时
	time.Sleep(20 * time.Millisecond)

	// 获取重传包
	retransmits := buf.GetRetransmitPackets(time.Now())
	if len(retransmits) != 2 {
		t.Errorf("应该有 2 个重传包: got %d", len(retransmits))
	}
}

func TestARQFastRetransmit(t *testing.T) {
	buf := NewARQSendBuffer(10, 1)

	// 添加数据
	buf.Add([]byte("packet1"))
	buf.Add([]byte("packet2"))
	buf.Add([]byte("packet3"))

	buf.MarkSent(1, time.Second)
	buf.MarkSent(2, time.Second)
	buf.MarkSent(3, time.Second)

	// 模拟 3 个重复 ACK (ack=1 表示期望序列号 1)
	buf.OnAck(1) // 重复 ACK 1
	buf.OnAck(1) // 重复 ACK 2
	buf.OnAck(1) // 重复 ACK 3

	// 获取快速重传包
	fastRetransmits := buf.GetFastRetransmitPackets()
	if len(fastRetransmits) != 1 {
		t.Errorf("应该有 1 个快速重传包: got %d", len(fastRetransmits))
	}
}

// 基准测试
func BenchmarkARQPacketEncode(b *testing.B) {
	pkt := &ARQPacket{
		Seq:       12345,
		Ack:       67890,
		Flags:     ARQFlagDATA | ARQFlagACK,
		Window:    256,
		Timestamp: uint32(time.Now().UnixMilli() & 0xFFFFFFFF),
		Data:      make([]byte, 1200),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pkt.Encode()
	}
}

func BenchmarkARQPacketDecode(b *testing.B) {
	pkt := &ARQPacket{
		Seq:       12345,
		Ack:       67890,
		Flags:     ARQFlagDATA | ARQFlagACK,
		Window:    256,
		Timestamp: uint32(time.Now().UnixMilli() & 0xFFFFFFFF),
		Data:      make([]byte, 1200),
	}
	encoded := pkt.Encode()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeARQPacket(encoded)
	}
}

func BenchmarkARQSendBufferAdd(b *testing.B) {
	buf := NewARQSendBuffer(1024, 1)
	data := make([]byte, 1200)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq, ok := buf.Add(data)
		if ok {
			buf.OnAck(seq + 1) // 立即确认以释放空间
		}
	}
}

func BenchmarkARQRecvBufferInsert(b *testing.B) {
	buf := NewARQRecvBuffer(1024, 1)
	data := make([]byte, 1200)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Insert(uint32(i+1), data)
		if i%100 == 0 {
			buf.ReadOrdered() // 定期读取以释放空间
		}
	}
}
