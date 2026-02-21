
//go:build !linux

package transport

import (
	"errors"
	"net"
	"time"
)

// FakeTCPClient 非 Linux 平台的桩实现
type FakeTCPClient struct{}

// NewFakeTCPClient 仅在非 Linux 平台作为桩函数
func NewFakeTCPClient(serverAddr string, cfg *FakeTCPConfig) (*FakeTCPClient, error) {
	return nil, errors.New("FakeTCP is only supported on Linux")
}

// 以下方法为编译通过而提供的桩实现

func (c *FakeTCPClient) Send(data []byte) error {
	return errors.New("FakeTCP is only supported on Linux")
}

func (c *FakeTCPClient) Recv(ctx interface{}) ([]byte, error) {
	return nil, errors.New("FakeTCP is only supported on Linux")
}

func (c *FakeTCPClient) Close() error {
	return nil
}

func (c *FakeTCPClient) IsConnected() bool {
	return false
}

func (c *FakeTCPClient) Read(b []byte) (int, error) {
	return 0, errors.New("FakeTCP is only supported on Linux")
}

func (c *FakeTCPClient) Write(b []byte) (int, error) {
	return 0, errors.New("FakeTCP is only supported on Linux")
}

func (c *FakeTCPClient) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *FakeTCPClient) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *FakeTCPClient) SetDeadline(t time.Time) error {
	return errors.New("FakeTCP is only supported on Linux")
}

func (c *FakeTCPClient) SetReadDeadline(t time.Time) error {
	return errors.New("FakeTCP is only supported on Linux")
}

func (c *FakeTCPClient) SetWriteDeadline(t time.Time) error {
	return errors.New("FakeTCP is only supported on Linux")
}



