


// =============================================================================
// 文件: internal/protocol/protocol_test.go
// =============================================================================






package protocol

import (
	"bytes"
	"testing"
)

func TestParseConnectIPv4(t *testing.T) {
	// Type(1) + ReqID(4) + Network(1) + AddrType(1) + IPv4(4) + Port(2)
	data := []byte{
		TypeConnect,
		0x00, 0x00, 0x00, 0x01, // ReqID = 1
		NetworkTCP,
		AddrIPv4,
		192, 168, 1, 1, // IP
		0x00, 0x50, // Port = 80
	}

	req, err := ParseRequest(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if req.Type != TypeConnect {
		t.Errorf("Type = %d, want %d", req.Type, TypeConnect)
	}
	if req.ReqID != 1 {
		t.Errorf("ReqID = %d, want 1", req.ReqID)
	}
	if req.Network != NetworkTCP {
		t.Errorf("Network = %d, want %d", req.Network, NetworkTCP)
	}
	if req.Address != "192.168.1.1" {
		t.Errorf("Address = %s, want 192.168.1.1", req.Address)
	}
	if req.Port != 80 {
		t.Errorf("Port = %d, want 80", req.Port)
	}
}

func TestParseConnectDomain(t *testing.T) {
	domain := "example.com"
	// Type(1) + ReqID(4) + Network(1) + AddrType(1) + DomainLen(1) + Domain + Port(2)
	data := make([]byte, 5+1+1+1+len(domain)+2)
	data[0] = TypeConnect
	data[1], data[2], data[3], data[4] = 0, 0, 0, 2 // ReqID = 2
	data[5] = NetworkTCP
	data[6] = AddrDomain
	data[7] = byte(len(domain))
	copy(data[8:8+len(domain)], domain)
	data[8+len(domain)] = 0x01
	data[9+len(domain)] = 0xBB // Port = 443

	req, err := ParseRequest(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if req.Address != domain {
		t.Errorf("Address = %s, want %s", req.Address, domain)
	}
	if req.Port != 443 {
		t.Errorf("Port = %d, want 443", req.Port)
	}
}

func TestParseData(t *testing.T) {
	payload := []byte("hello world")
	data := make([]byte, 5+len(payload))
	data[0] = TypeData
	data[1], data[2], data[3], data[4] = 0, 0, 0, 3 // ReqID = 3
	copy(data[5:], payload)

	req, err := ParseRequest(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if req.Type != TypeData {
		t.Errorf("Type = %d, want %d", req.Type, TypeData)
	}
	if !bytes.Equal(req.Data, payload) {
		t.Errorf("Data = %v, want %v", req.Data, payload)
	}
}

func TestBuildResponse(t *testing.T) {
	resp := BuildResponse(123, 0x00, []byte("test"))
	
	if resp[0] != TypeData {
		t.Errorf("Type = %d, want %d", resp[0], TypeData)
	}
	if resp[5] != 0x00 {
		t.Errorf("Status = %d, want 0", resp[5])
	}
}

func TestTargetAddr(t *testing.T) {
	req := &Request{
		Address: "example.com",
		Port:    443,
	}
	
	addr := req.TargetAddr()
	if addr != "example.com:443" {
		t.Errorf("TargetAddr = %s, want example.com:443", addr)
	}
}

func BenchmarkParseRequest(b *testing.B) {
	data := []byte{
		TypeConnect,
		0x00, 0x00, 0x00, 0x01,
		NetworkTCP,
		AddrIPv4,
		192, 168, 1, 1,
		0x00, 0x50,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseRequest(data)
	}
}



