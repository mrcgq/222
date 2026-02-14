




// =============================================================================
// 文件: internal/transport/ebpf_test.go
// 描述: eBPF 加速测试
// =============================================================================
package transport

import (
	"net"
	"testing"
)

func TestIPConversion(t *testing.T) {
	// 测试 IP 转换
	ip := net.ParseIP("192.168.1.100").To4()
	n := IPToUint32(ip)

	converted := Uint32ToIP(n)
	if !converted.Equal(ip) {
		t.Errorf("IP 转换不正确: got %v, want %v", converted, ip)
	}
}

func TestByteOrderConversion(t *testing.T) {
	// 测试字节序转换
	port := uint16(54321)
	netOrder := Htons(port)
	hostOrder := Ntohs(netOrder)

	if hostOrder != port {
		t.Errorf("端口转换不正确: got %d, want %d", hostOrder, port)
	}

	addr := uint32(0x12345678)
	netAddr := Htonl(addr)
	hostAddr := Ntohl(netAddr)

	if hostAddr != addr {
		t.Errorf("地址转换不正确: got %08x, want %08x", hostAddr, addr)
	}
}

func TestEBPFSessionKey(t *testing.T) {
	key := EBPFSessionKey{
		SrcIP:   IPToUint32(net.ParseIP("192.168.1.1")),
		DstIP:   IPToUint32(net.ParseIP("192.168.1.2")),
		SrcPort: Htons(12345),
		DstPort: Htons(54321),
	}

	srcIP := Uint32ToIP(key.SrcIP)
	dstIP := Uint32ToIP(key.DstIP)
	srcPort := Ntohs(key.SrcPort)
	dstPort := Ntohs(key.DstPort)

	if !srcIP.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("SrcIP 不正确: %v", srcIP)
	}
	if !dstIP.Equal(net.ParseIP("192.168.1.2")) {
		t.Errorf("DstIP 不正确: %v", dstIP)
	}
	if srcPort != 12345 {
		t.Errorf("SrcPort 不正确: %d", srcPort)
	}
	if dstPort != 54321 {
		t.Errorf("DstPort 不正确: %d", dstPort)
	}
}

func TestDefaultEBPFConfig(t *testing.T) {
	config := DefaultEBPFConfig()

	if config.Interface != "eth0" {
		t.Errorf("默认网卡应该是 eth0, got %s", config.Interface)
	}

	if config.MapSize != 65536 {
		t.Errorf("默认 MapSize 应该是 65536, got %d", config.MapSize)
	}

	if !config.EnableStats {
		t.Error("默认应该启用统计")
	}
}

func TestEBPFLoader_NoProgram(t *testing.T) {
	config := &EBPFConfig{
		ProgramPath: "/nonexistent/path",
		Interface:   "lo",
	}

	loader := NewEBPFLoader(config)

	err := loader.Load()
	if err == nil {
		t.Error("加载不存在的程序应该失败")
		loader.Close()
	}
}

func TestEBPFStats_ZeroValue(t *testing.T) {
	var stats EBPFStats

	if stats.PacketsRX != 0 {
		t.Error("初始 PacketsRX 应该是 0")
	}
	if stats.PacketsTX != 0 {
		t.Error("初始 PacketsTX 应该是 0")
	}
	if stats.Errors != 0 {
		t.Error("初始 Errors 应该是 0")
	}
}

func TestEBPFGlobalConfig(t *testing.T) {
	config := EBPFGlobalConfig{
		Magic:          0x5048414E,
		ListenPort:     54321,
		Mode:           1,
		LogLevel:       1,
		SessionTimeout: 300,
		MaxSessions:    65536,
		EnableStats:    1,
		EnableConntrack: 1,
	}

	if config.Magic != 0x5048414E {
		t.Errorf("Magic 不正确: got %08x", config.Magic)
	}

	if config.ListenPort != 54321 {
		t.Errorf("ListenPort 不正确: got %d", config.ListenPort)
	}
}

// 集成测试 (需要 root 和 eBPF 支持)
func TestEBPFAccelerator_Fallback(t *testing.T) {
	// 这个测试在没有 root 权限时应该回退到 UDP
	handler := &testPacketHandler{}

	accel := NewEBPFAccelerator(
		"lo",
		XDPModeGeneric,
		"/nonexistent",
		1024,
		true,
		handler,
		"info",
	)

	// 由于没有权限和程序，应该使用回退模式
	if accel.IsActive() {
		t.Error("在没有程序的情况下不应该活跃")
	}
}

type testPacketHandler struct{}

func (h *testPacketHandler) HandlePacket(data []byte, from *net.UDPAddr) []byte {
	return data
}

// 基准测试
func BenchmarkIPToUint32(b *testing.B) {
	ip := net.ParseIP("192.168.1.100").To4()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IPToUint32(ip)
	}
}

func BenchmarkUint32ToIP(b *testing.B) {
	n := IPToUint32(net.ParseIP("192.168.1.100"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Uint32ToIP(n)
	}
}

func BenchmarkHtons(b *testing.B) {
	port := uint16(54321)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Htons(port)
	}
}

func BenchmarkSessionKeyCreation(b *testing.B) {
	srcIP := IPToUint32(net.ParseIP("192.168.1.1"))
	dstIP := IPToUint32(net.ParseIP("192.168.1.2"))
	srcPort := Htons(12345)
	dstPort := Htons(54321)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EBPFSessionKey{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
	}
}

