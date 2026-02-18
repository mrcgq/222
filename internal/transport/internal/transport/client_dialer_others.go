//go:build !linux

package transport

import (
	"errors"
	"net"
)

// NewFakeTCPClient 仅在非 Linux 平台作为桩函数
func NewFakeTCPClient(serverAddr string, cfg *FakeTCPConfig) (net.Conn, error) {
	return nil, errors.New("FakeTCP is only supported on Linux")
}
