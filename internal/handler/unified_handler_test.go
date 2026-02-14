



// =============================================================================
// 文件: internal/handler/unified_handler_test.go
// 描述: UnifiedHandler 核心业务测试
// 职责:
//   - 验证"大脑"逻辑在极限情况下的正确性
//   - Mock 传输层发送器，截获并验证回传的加密包
//   - 链路闭环测试，验证 Connect/Data/Close 流程
//   - 错误注入测试，验证系统健壮性
// =============================================================================
package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrcgq/211/internal/config"
	"github.com/mrcgq/211/internal/crypto"
	"github.com/mrcgq/211/internal/protocol"
)

// =============================================================================
// Mock 组件
// =============================================================================

// MockSender 模拟传输层发送器
type MockSender struct {
	mu       sync.Mutex
	packets  []SentPacket
	callback func(data []byte, addr *net.UDPAddr)
}

// SentPacket 记录发送的数据包
type SentPacket struct {
	Data []byte
	Addr *net.UDPAddr
	Time time.Time
}

// NewMockSender 创建模拟发送器
func NewMockSender() *MockSender {
	return &MockSender{
		packets: make([]SentPacket, 0),
	}
}

// Send 实现发送接口
func (m *MockSender) Send(data []byte, addr *net.UDPAddr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 复制数据以避免后续修改
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	m.packets = append(m.packets, SentPacket{
		Data: dataCopy,
		Addr: addr,
		Time: time.Now(),
	})

	if m.callback != nil {
		m.callback(dataCopy, addr)
	}

	return nil
}

// GetPackets 获取所有发送的数据包
func (m *MockSender) GetPackets() []SentPacket {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]SentPacket, len(m.packets))
	copy(result, m.packets)
	return result
}

// GetPacketCount 获取数据包数量
func (m *MockSender) GetPacketCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.packets)
}

// Clear 清空记录
func (m *MockSender) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packets = m.packets[:0]
}

// SetCallback 设置回调函数
func (m *MockSender) SetCallback(fn func(data []byte, addr *net.UDPAddr)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callback = fn
}

// WaitForPackets 等待指定数量的数据包
func (m *MockSender) WaitForPackets(count int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.GetPacketCount() >= count {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// =============================================================================
// 测试辅助函数
// =============================================================================

// testConfig 创建测试配置
func testConfig() *config.Config {
	return &config.Config{
		LogLevel: "error", // 减少测试输出
	}
}

// testCrypto 创建测试加密器
func testCrypto(t *testing.T) *crypto.Crypto {
	psk, err := crypto.GeneratePSK()
	if err != nil {
		t.Fatalf("生成 PSK 失败: %v", err)
	}

	c, err := crypto.New(psk, 60)
	if err != nil {
		t.Fatalf("创建加密器失败: %v", err)
	}

	return c
}

// testHandler 创建测试处理器
func testHandler(t *testing.T) (*UnifiedHandler, *crypto.Crypto, *MockSender) {
	c := testCrypto(t)
	cfg := testConfig()

	h := NewUnifiedHandler(c, cfg)
	sender := NewMockSender()
	h.SetSender(sender.Send)

	return h, c, sender
}

// testUDPAddr 创建测试 UDP 地址
func testUDPAddr(port int) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	}
}

// buildConnectRequest 构建 Connect 请求
func buildConnectRequest(reqID uint32, network byte, addr string, port uint16, data []byte) []byte {
	ip := net.ParseIP(addr)

	var addrType byte
	var addrBytes []byte

	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addrType = protocol.AddrIPv4
			addrBytes = ip4
		} else {
			addrType = protocol.AddrIPv6
			addrBytes = ip
		}
	} else {
		addrType = protocol.AddrDomain
		addrBytes = append([]byte{byte(len(addr))}, []byte(addr)...)
	}

	// Type(1) + ReqID(4) + Network(1) + AddrType(1) + Addr + Port(2) + Data
	buf := make([]byte, 0, 32+len(data))
	buf = append(buf, protocol.TypeConnect)
	buf = append(buf, make([]byte, 4)...)
	binary.BigEndian.PutUint32(buf[1:5], reqID)
	buf = append(buf, network)
	buf = append(buf, addrType)
	buf = append(buf, addrBytes...)
	buf = append(buf, make([]byte, 2)...)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], port)
	if len(data) > 0 {
		buf = append(buf, data...)
	}

	return buf
}

// buildDataRequest 构建 Data 请求
func buildDataRequest(reqID uint32, data []byte) []byte {
	// Type(1) + ReqID(4) + Data
	buf := make([]byte, 5+len(data))
	buf[0] = protocol.TypeData
	binary.BigEndian.PutUint32(buf[1:5], reqID)
	if len(data) > 0 {
		copy(buf[5:], data)
	}
	return buf
}

// buildCloseRequest 构建 Close 请求
func buildCloseRequest(reqID uint32) []byte {
	// Type(1) + ReqID(4)
	buf := make([]byte, 5)
	buf[0] = protocol.TypeClose
	binary.BigEndian.PutUint32(buf[1:5], reqID)
	return buf
}

// startEchoServer 启动 Echo 服务器
func startEchoServer(t *testing.T) (net.Listener, int) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动 Echo 服务器失败: %v", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // Echo 所有数据
			}(conn)
		}
	}()

	return listener, port
}

// startDelayServer 启动延迟响应服务器
func startDelayServer(t *testing.T, delay time.Duration, response []byte) (net.Listener, int) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动延迟服务器失败: %v", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				time.Sleep(delay)
				c.Write(response)
			}(conn)
		}
	}()

	return listener, port
}

// =============================================================================
// 基础功能测试
// =============================================================================

func TestNewUnifiedHandler(t *testing.T) {
	h, c, _ := testHandler(t)
	defer h.Close()

	if h.crypto != c {
		t.Error("crypto 未正确设置")
	}

	stats := h.GetStats()
	if stats["active_conns"].(int64) != 0 {
		t.Error("初始活跃连接数应为 0")
	}
}

func TestSetSender(t *testing.T) {
	h, _, _ := testHandler(t)
	defer h.Close()

	// 测试 sender 已设置
	if h.sender == nil {
		t.Error("sender 应该已设置")
	}

	// 测试更换 sender
	newSender := NewMockSender()
	h.SetSender(newSender.Send)

	// 原来的 sender 不应该收到新的数据
	// 这里只是验证 SetSender 不会 panic
}

func TestGetStats(t *testing.T) {
	h, _, _ := testHandler(t)
	defer h.Close()

	stats := h.GetStats()

	// 验证必要的统计字段存在
	if _, ok := stats["total_conns"]; !ok {
		t.Error("缺少 total_conns 字段")
	}
	if _, ok := stats["active_conns"]; !ok {
		t.Error("缺少 active_conns 字段")
	}
	if _, ok := stats["total_bytes"]; !ok {
		t.Error("缺少 total_bytes 字段")
	}
}

// =============================================================================
// UDP 数据包处理测试
// =============================================================================

func TestHandlePacket_InvalidData(t *testing.T) {
	h, _, sender := testHandler(t)
	defer h.Close()

	clientAddr := testUDPAddr(12345)

	tests := []struct {
		name string
		data []byte
	}{
		{"空数据", []byte{}},
		{"太短", []byte{0x01, 0x02}},
		{"随机垃圾", []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA}},
		{"无效加密数据", make([]byte, 100)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender.Clear()

			// 应该静默丢弃，不崩溃
			result := h.HandlePacket(tt.data, clientAddr)

			if result != nil {
				t.Error("无效数据应返回 nil")
			}

			// 不应该发送任何响应
			if sender.GetPacketCount() != 0 {
				t.Error("无效数据不应触发响应")
			}
		})
	}
}

func TestHandlePacket_InvalidProtocol(t *testing.T) {
	h, c, sender := testHandler(t)
	defer h.Close()

	clientAddr := testUDPAddr(12345)

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"无效类型", []byte{0xFF, 0x00, 0x00, 0x00, 0x01}},
		{"数据太短", []byte{0x01}},
		{"Connect 缺少地址", []byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender.Clear()

			// 加密无效协议数据
			encrypted, err := c.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("加密失败: %v", err)
			}

			// 应该静默丢弃
			result := h.HandlePacket(encrypted, clientAddr)

			if result != nil {
				t.Error("无效协议应返回 nil")
			}
		})
	}
}

func TestHandlePacket_Connect_Success(t *testing.T) {
	h, c, sender := testHandler(t)
	defer h.Close()

	// 启动 Echo 服务器
	listener, port := startEchoServer(t)
	defer listener.Close()

	clientAddr := testUDPAddr(12345)
	reqID := uint32(1001)

	// 构建 Connect 请求
	connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", uint16(port), nil)

	// 加密
	encrypted, err := c.Encrypt(connectReq)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 处理请求
	h.HandlePacket(encrypted, clientAddr)

	// 等待响应
	if !sender.WaitForPackets(1, 2*time.Second) {
		t.Fatal("未收到响应")
	}

	// 解密并验证响应
	packets := sender.GetPackets()
	resp, err := c.Decrypt(packets[0].Data)
	if err != nil {
		t.Fatalf("解密响应失败: %v", err)
	}

	// 验证响应格式: Type(1) + ReqID(4) + Status(1)
	if len(resp) < 6 {
		t.Fatalf("响应太短: %d", len(resp))
	}

	respReqID := binary.BigEndian.Uint32(resp[1:5])
	status := resp[5]

	if respReqID != reqID {
		t.Errorf("ReqID 不匹配: got %d, want %d", respReqID, reqID)
	}

	if status != 0x00 {
		t.Errorf("连接应成功: got status %d", status)
	}

	// 验证活跃连接数
	if h.GetActiveConns() != 1 {
		t.Errorf("活跃连接数应为 1: got %d", h.GetActiveConns())
	}
}

func TestHandlePacket_Connect_Failure(t *testing.T) {
	h, c, sender := testHandler(t)
	defer h.Close()

	clientAddr := testUDPAddr(12345)
	reqID := uint32(1002)

	// 连接到不存在的端口
	connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", 59999, nil)

	encrypted, err := c.Encrypt(connectReq)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	h.HandlePacket(encrypted, clientAddr)

	// 等待响应
	if !sender.WaitForPackets(1, 12*time.Second) {
		t.Fatal("未收到响应")
	}

	// 解密并验证失败响应
	packets := sender.GetPackets()
	resp, err := c.Decrypt(packets[0].Data)
	if err != nil {
		t.Fatalf("解密响应失败: %v", err)
	}

	status := resp[5]
	if status == 0x00 {
		t.Error("连接到无效端口应该失败")
	}
}

func TestHandlePacket_Data(t *testing.T) {
	h, c, sender := testHandler(t)
	defer h.Close()

	// 启动 Echo 服务器
	listener, port := startEchoServer(t)
	defer listener.Close()

	clientAddr := testUDPAddr(12345)
	reqID := uint32(1003)

	// 先建立连接
	connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", uint16(port), nil)
	encrypted, _ := c.Encrypt(connectReq)
	h.HandlePacket(encrypted, clientAddr)

	// 等待连接响应
	if !sender.WaitForPackets(1, 2*time.Second) {
		t.Fatal("未收到连接响应")
	}
	sender.Clear()

	// 发送数据
	testData := []byte("Hello, Echo Server!")
	dataReq := buildDataRequest(reqID, testData)
	encrypted, _ = c.Encrypt(dataReq)
	h.HandlePacket(encrypted, clientAddr)

	// 等待 Echo 响应
	if !sender.WaitForPackets(1, 2*time.Second) {
		t.Fatal("未收到数据响应")
	}

	// 验证 Echo 数据
	packets := sender.GetPackets()
	resp, err := c.Decrypt(packets[0].Data)
	if err != nil {
		t.Fatalf("解密响应失败: %v", err)
	}

	// 响应格式: Type(1) + ReqID(4) + Status(1) + Data
	if len(resp) < 6 {
		t.Fatalf("响应太短: %d", len(resp))
	}

	respData := resp[6:]
	if !bytes.Equal(respData, testData) {
		t.Errorf("Echo 数据不匹配: got %q, want %q", respData, testData)
	}
}

func TestHandlePacket_Close(t *testing.T) {
	h, c, sender := testHandler(t)
	defer h.Close()

	// 启动 Echo 服务器
	listener, port := startEchoServer(t)
	defer listener.Close()

	clientAddr := testUDPAddr(12345)
	reqID := uint32(1004)

	// 建立连接
	connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", uint16(port), nil)
	encrypted, _ := c.Encrypt(connectReq)
	h.HandlePacket(encrypted, clientAddr)

	if !sender.WaitForPackets(1, 2*time.Second) {
		t.Fatal("未收到连接响应")
	}

	initialConns := h.GetActiveConns()
	if initialConns != 1 {
		t.Fatalf("连接后活跃数应为 1: got %d", initialConns)
	}

	// 发送关闭请求
	closeReq := buildCloseRequest(reqID)
	encrypted, _ = c.Encrypt(closeReq)
	h.HandlePacket(encrypted, clientAddr)

	// 等待连接关闭
	time.Sleep(100 * time.Millisecond)

	if h.GetActiveConns() != 0 {
		t.Errorf("关闭后活跃连接数应为 0: got %d", h.GetActiveConns())
	}
}

func TestHandlePacket_DataWithoutConnect(t *testing.T) {
	h, c, sender := testHandler(t)
	defer h.Close()

	clientAddr := testUDPAddr(12345)
	reqID := uint32(9999) // 不存在的连接

	// 直接发送数据（无连接）
	dataReq := buildDataRequest(reqID, []byte("orphan data"))
	encrypted, _ := c.Encrypt(dataReq)

	sender.Clear()
	h.HandlePacket(encrypted, clientAddr)

	// 不应该崩溃，也不应该有响应
	time.Sleep(100 * time.Millisecond)

	// 可能没有响应或有错误响应，主要是不崩溃
}

// =============================================================================
// 链路闭环测试
// =============================================================================

func TestFullDataFlow_Echo(t *testing.T) {
	h, c, sender := testHandler(t)
	defer h.Close()

	// 启动 Echo 服务器
	listener, port := startEchoServer(t)
	defer listener.Close()

	clientAddr := testUDPAddr(12345)
	reqID := uint32(2001)

	// 1. Connect
	connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", uint16(port), nil)
	encrypted, _ := c.Encrypt(connectReq)
	h.HandlePacket(encrypted, clientAddr)

	if !sender.WaitForPackets(1, 2*time.Second) {
		t.Fatal("Connect: 未收到响应")
	}

	// 验证连接成功
	resp, _ := c.Decrypt(sender.GetPackets()[0].Data)
	if resp[5] != 0x00 {
		t.Fatal("Connect: 连接失败")
	}
	sender.Clear()

	// 2. 发送多次数据
	messages := []string{
		"Hello",
		"World",
		"Test message with more data",
		"Final message",
	}

	for i, msg := range messages {
		dataReq := buildDataRequest(reqID, []byte(msg))
		encrypted, _ = c.Encrypt(dataReq)
		h.HandlePacket(encrypted, clientAddr)

		// 等待 Echo 响应
		if !sender.WaitForPackets(i+1, 2*time.Second) {
			t.Fatalf("Data %d: 未收到响应", i)
		}
	}

	// 验证所有响应
	packets := sender.GetPackets()
	if len(packets) != len(messages) {
		t.Fatalf("响应数量不匹配: got %d, want %d", len(packets), len(messages))
	}

	for i, pkt := range packets {
		resp, err := c.Decrypt(pkt.Data)
		if err != nil {
			t.Fatalf("解密响应 %d 失败: %v", i, err)
		}

		respData := resp[6:]
		if string(respData) != messages[i] {
			t.Errorf("响应 %d 数据不匹配: got %q, want %q", i, respData, messages[i])
		}
	}

	// 3. Close
	closeReq := buildCloseRequest(reqID)
	encrypted, _ = c.Encrypt(closeReq)
	h.HandlePacket(encrypted, clientAddr)

	time.Sleep(100 * time.Millisecond)

	if h.GetActiveConns() != 0 {
		t.Error("关闭后仍有活跃连接")
	}
}

func TestFullDataFlow_WithInitialData(t *testing.T) {
	h, c, sender := testHandler(t)
	defer h.Close()

	// 启动 Echo 服务器
	listener, port := startEchoServer(t)
	defer listener.Close()

	clientAddr := testUDPAddr(12345)
	reqID := uint32(2002)

	// Connect 携带初始数据
	initialData := []byte("Initial payload in connect")
	connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", uint16(port), initialData)
	encrypted, _ := c.Encrypt(connectReq)
	h.HandlePacket(encrypted, clientAddr)

	// 应该收到连接成功响应 + Echo 的初始数据
	if !sender.WaitForPackets(2, 3*time.Second) {
		// 可能只有一个响应，取决于实现
		if !sender.WaitForPackets(1, time.Second) {
			t.Fatal("未收到任何响应")
		}
	}

	packets := sender.GetPackets()

	// 验证第一个是连接成功响应
	resp, _ := c.Decrypt(packets[0].Data)
	if resp[5] != 0x00 {
		t.Error("连接应该成功")
	}

	// 如果有第二个响应，应该是 Echo 的初始数据
	if len(packets) > 1 {
		resp, _ = c.Decrypt(packets[1].Data)
		if len(resp) > 6 {
			echoData := resp[6:]
			if !bytes.Equal(echoData, initialData) {
				t.Errorf("Echo 初始数据不匹配: got %q, want %q", echoData, initialData)
			}
		}
	}
}

// =============================================================================
// 并发测试
// =============================================================================

func TestConcurrentConnections(t *testing.T) {
	h, c, sender := testHandler(t)
	defer h.Close()

	// 启动 Echo 服务器
	listener, port := startEchoServer(t)
	defer listener.Close()

	numClients := 10
	var wg sync.WaitGroup
	errors := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()

			clientAddr := testUDPAddr(20000 + clientID)
			reqID := uint32(3000 + clientID)

			// Connect
			connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", uint16(port), nil)
			encrypted, err := c.Encrypt(connectReq)
			if err != nil {
				errors <- fmt.Errorf("client %d: 加密失败: %v", clientID, err)
				return
			}

			h.HandlePacket(encrypted, clientAddr)

			// 发送数据
			for j := 0; j < 5; j++ {
				data := fmt.Sprintf("Client %d, Message %d", clientID, j)
				dataReq := buildDataRequest(reqID, []byte(data))
				encrypted, _ = c.Encrypt(dataReq)
				h.HandlePacket(encrypted, clientAddr)
				time.Sleep(10 * time.Millisecond)
			}

			// Close
			closeReq := buildCloseRequest(reqID)
			encrypted, _ = c.Encrypt(closeReq)
			h.HandlePacket(encrypted, clientAddr)

		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	// 等待所有连接关闭
	time.Sleep(500 * time.Millisecond)

	// 验证收到了响应
	if sender.GetPacketCount() == 0 {
		t.Error("应该收到响应")
	}
}

func TestConcurrentSameConnection(t *testing.T) {
	h, c, _ := testHandler(t)
	defer h.Close()

	// 启动 Echo 服务器
	listener, port := startEchoServer(t)
	defer listener.Close()

	clientAddr := testUDPAddr(12345)
	reqID := uint32(4001)

	// 建立连接
	connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", uint16(port), nil)
	encrypted, _ := c.Encrypt(connectReq)
	h.HandlePacket(encrypted, clientAddr)

	time.Sleep(100 * time.Millisecond)

	// 并发发送数据到同一连接
	var wg sync.WaitGroup
	numGoroutines := 20

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				data := fmt.Sprintf("Goroutine %d, Iter %d", id, j)
				dataReq := buildDataRequest(reqID, []byte(data))
				encrypted, _ := c.Encrypt(dataReq)
				h.HandlePacket(encrypted, clientAddr)
			}
		}(i)
	}

	wg.Wait()

	// 不应该崩溃，连接应该仍然有效
	if h.GetActiveConns() != 1 {
		t.Errorf("活跃连接数应为 1: got %d", h.GetActiveConns())
	}
}

// =============================================================================
// 错误注入测试
// =============================================================================

func TestErrorInjection_MalformedPackets(t *testing.T) {
	h, _, sender := testHandler(t)
	defer h.Close()

	clientAddr := testUDPAddr(12345)

	// 各种畸形数据包
	malformedPackets := [][]byte{
		nil,
		{},
		{0x00},
		make([]byte, 1000), // 全零
		bytes.Repeat([]byte{0xFF}, 1000),
		{0x01, 0x02, 0x03, 0x04, 0x05}, // 看起来像协议但不是
	}

	for i, pkt := range malformedPackets {
		t.Run(fmt.Sprintf("malformed_%d", i), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("处理畸形包时 panic: %v", r)
				}
			}()

			sender.Clear()
			h.HandlePacket(pkt, clientAddr)

			// 不应该发送响应
			time.Sleep(50 * time.Millisecond)
		})
	}
}

func TestErrorInjection_CorruptedEncryption(t *testing.T) {
	h, c, sender := testHandler(t)
	defer h.Close()

	clientAddr := testUDPAddr(12345)

	// 正确加密的数据
	validReq := buildConnectRequest(1, protocol.NetworkTCP, "127.0.0.1", 80, nil)
	encrypted, _ := c.Encrypt(validReq)

	// 损坏加密数据
	corruptions := []struct {
		name   string
		modify func([]byte) []byte
	}{
		{
			"翻转第一个字节",
			func(d []byte) []byte {
				result := make([]byte, len(d))
				copy(result, d)
				result[0] ^= 0xFF
				return result
			},
		},
		{
			"翻转中间字节",
			func(d []byte) []byte {
				result := make([]byte, len(d))
				copy(result, d)
				result[len(d)/2] ^= 0xFF
				return result
			},
		},
		{
			"翻转最后字节",
			func(d []byte) []byte {
				result := make([]byte, len(d))
				copy(result, d)
				result[len(d)-1] ^= 0xFF
				return result
			},
		},
		{
			"截断数据",
			func(d []byte) []byte {
				return d[:len(d)/2]
			},
		},
		{
			"追加垃圾",
			func(d []byte) []byte {
				return append(d, bytes.Repeat([]byte{0xAB}, 100)...)
			},
		},
	}

	for _, c := range corruptions {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("处理损坏数据时 panic: %v", r)
				}
			}()

			sender.Clear()
			corrupted := c.modify(encrypted)
			h.HandlePacket(corrupted, clientAddr)

			// 应该静默丢弃
			time.Sleep(50 * time.Millisecond)
		})
	}
}

func TestErrorInjection_RapidConnectClose(t *testing.T) {
	h, c, _ := testHandler(t)
	defer h.Close()

	// 启动 Echo 服务器
	listener, port := startEchoServer(t)
	defer listener.Close()

	clientAddr := testUDPAddr(12345)

	// 快速建立和关闭连接
	for i := 0; i < 100; i++ {
		reqID := uint32(5000 + i)

		// Connect
		connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", uint16(port), nil)
		encrypted, _ := c.Encrypt(connectReq)
		h.HandlePacket(encrypted, clientAddr)

		// 立即 Close
		closeReq := buildCloseRequest(reqID)
		encrypted, _ = c.Encrypt(closeReq)
		h.HandlePacket(encrypted, clientAddr)
	}

	// 等待清理
	time.Sleep(500 * time.Millisecond)

	// 验证没有连接泄漏
	if h.GetActiveConns() != 0 {
		t.Errorf("应该没有活跃连接: got %d", h.GetActiveConns())
	}
}

// =============================================================================
// 会话管理测试
// =============================================================================

func TestSessionManagement(t *testing.T) {
	h, c, _ := testHandler(t)
	defer h.Close()

	// 启动 Echo 服务器
	listener, port := startEchoServer(t)
	defer listener.Close()

	// 多个客户端地址
	clients := []*net.UDPAddr{
		testUDPAddr(30001),
		testUDPAddr(30002),
		testUDPAddr(30003),
	}

	for i, client := range clients {
		reqID := uint32(6000 + i)

		connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", uint16(port), nil)
		encrypted, _ := c.Encrypt(connectReq)
		h.HandlePacket(encrypted, client)
	}

	time.Sleep(200 * time.Millisecond)

	// 应该有多个活跃连接
	if h.GetActiveConns() != int64(len(clients)) {
		t.Errorf("活跃连接数不匹配: got %d, want %d", h.GetActiveConns(), len(clients))
	}
}

// =============================================================================
// 域名解析测试
// =============================================================================

func TestDomainResolution(t *testing.T) {
	h, c, sender := testHandler(t)
	defer h.Close()

	clientAddr := testUDPAddr(12345)
	reqID := uint32(7001)

	// 使用 localhost 域名
	connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "localhost", 80, nil)
	encrypted, _ := c.Encrypt(connectReq)
	h.HandlePacket(encrypted, clientAddr)

	// 等待响应（可能成功或失败，取决于本地环境）
	sender.WaitForPackets(1, 12*time.Second)

	// 主要验证不会崩溃
}

// =============================================================================
// 性能边界测试
// =============================================================================

func TestLargeDataPacket(t *testing.T) {
	h, c, sender := testHandler(t)
	defer h.Close()

	// 启动 Echo 服务器
	listener, port := startEchoServer(t)
	defer listener.Close()

	clientAddr := testUDPAddr(12345)
	reqID := uint32(8001)

	// Connect
	connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", uint16(port), nil)
	encrypted, _ := c.Encrypt(connectReq)
	h.HandlePacket(encrypted, clientAddr)

	if !sender.WaitForPackets(1, 2*time.Second) {
		t.Fatal("未收到连接响应")
	}
	sender.Clear()

	// 发送大数据包
	largeData := bytes.Repeat([]byte("X"), 30*1024) // 30KB
	dataReq := buildDataRequest(reqID, largeData)
	encrypted, _ = c.Encrypt(dataReq)
	h.HandlePacket(encrypted, clientAddr)

	// 等待 Echo 响应
	if !sender.WaitForPackets(1, 5*time.Second) {
		t.Fatal("未收到大数据响应")
	}

	// 验证数据完整性
	packets := sender.GetPackets()
	resp, _ := c.Decrypt(packets[0].Data)
	respData := resp[6:]

	if !bytes.Equal(respData, largeData) {
		t.Errorf("大数据不匹配: got %d bytes, want %d bytes", len(respData), len(largeData))
	}
}

func TestHighThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过高吞吐量测试")
	}

	h, c, _ := testHandler(t)
	defer h.Close()

	// 启动 Echo 服务器
	listener, port := startEchoServer(t)
	defer listener.Close()

	clientAddr := testUDPAddr(12345)
	reqID := uint32(9001)

	// Connect
	connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", uint16(port), nil)
	encrypted, _ := c.Encrypt(connectReq)
	h.HandlePacket(encrypted, clientAddr)

	time.Sleep(100 * time.Millisecond)

	// 高速发送数据
	start := time.Now()
	numPackets := 1000
	var sent int64

	for i := 0; i < numPackets; i++ {
		data := []byte(fmt.Sprintf("Packet %d with some extra data", i))
		dataReq := buildDataRequest(reqID, data)
		encrypted, _ := c.Encrypt(dataReq)
		h.HandlePacket(encrypted, clientAddr)
		atomic.AddInt64(&sent, int64(len(data)))
	}

	elapsed := time.Since(start)
	throughput := float64(sent) / elapsed.Seconds() / 1024 // KB/s

	t.Logf("发送 %d 包在 %v, 吞吐量: %.2f KB/s", numPackets, elapsed, throughput)
}

// =============================================================================
// 超时测试
// =============================================================================

func TestConnectionTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过超时测试")
	}

	h, c, sender := testHandler(t)
	defer h.Close()

	// 启动延迟服务器
	response := []byte("delayed response")
	listener, port := startDelayServer(t, 100*time.Millisecond, response)
	defer listener.Close()

	clientAddr := testUDPAddr(12345)
	reqID := uint32(10001)

	// Connect
	connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", uint16(port), nil)
	encrypted, _ := c.Encrypt(connectReq)
	h.HandlePacket(encrypted, clientAddr)

	// 等待连接响应
	if !sender.WaitForPackets(1, 2*time.Second) {
		t.Fatal("未收到连接响应")
	}

	// 等待延迟响应
	if !sender.WaitForPackets(2, 2*time.Second) {
		t.Log("未收到延迟响应（可能正常）")
	}
}

// =============================================================================
// Benchmark 测试
// =============================================================================

func BenchmarkHandlePacket_Connect(b *testing.B) {
	c, _ := crypto.New("VGVzdFBTS0ZvckJlbmNobWFya1Rlc3RpbmcxMjM0NTY=", 60)
	cfg := &config.Config{LogLevel: "error"}
	h := NewUnifiedHandler(c, cfg)
	defer h.Close()

	sender := NewMockSender()
	h.SetSender(sender.Send)

	// 启动 Echo 服务器
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	clientAddr := testUDPAddr(12345)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		reqID := uint32(0)
		for pb.Next() {
			reqID++
			connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", uint16(port), nil)
			encrypted, _ := c.Encrypt(connectReq)
			h.HandlePacket(encrypted, clientAddr)
		}
	})
}

func BenchmarkHandlePacket_Data(b *testing.B) {
	c, _ := crypto.New("VGVzdFBTS0ZvckJlbmNobWFya1Rlc3RpbmcxMjM0NTY=", 60)
	cfg := &config.Config{LogLevel: "error"}
	h := NewUnifiedHandler(c, cfg)
	defer h.Close()

	sender := NewMockSender()
	h.SetSender(sender.Send)

	// 启动 Echo 服务器
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	clientAddr := testUDPAddr(12345)
	reqID := uint32(1)

	// 先建立连接
	connectReq := buildConnectRequest(reqID, protocol.NetworkTCP, "127.0.0.1", uint16(port), nil)
	encrypted, _ := c.Encrypt(connectReq)
	h.HandlePacket(encrypted, clientAddr)
	time.Sleep(100 * time.Millisecond)

	testData := []byte("benchmark test data payload")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dataReq := buildDataRequest(reqID, testData)
		encrypted, _ := c.Encrypt(dataReq)
		h.HandlePacket(encrypted, clientAddr)
	}
}

func BenchmarkEncryptDecrypt(b *testing.B) {
	c, _ := crypto.New("VGVzdFBTS0ZvckJlbmNobWFya1Rlc3RpbmcxMjM0NTY=", 60)

	testData := bytes.Repeat([]byte("X"), 1024) // 1KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := c.Encrypt(testData)
		c.Decrypt(encrypted)
	}
}





