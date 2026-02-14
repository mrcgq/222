//go:build !linux

// =============================================================================
// 文件: internal/transport/faketcp_nat_other.go
// 描述: FakeTCP NAT 穿透 - 非 Linux 平台存根
// =============================================================================
package transport

import (
	"fmt"
	"net"
	"time"
)

// =============================================================================
// TCP 绑定模式实现 (非 Linux - 存根)
// =============================================================================

func (h *NATHelper) setupTCPBind(localPort int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 非 Linux 平台使用简化实现
	laddr := &net.TCPAddr{
		IP:   net.IPv4zero,
		Port: localPort,
	}

	listener, err := net.Listen("tcp4", laddr.String())
	if err != nil {
		// 如果端口被占用，尝试使用系统分配的端口
		listener, err = net.Listen("tcp4", ":0")
		if err != nil {
			return fmt.Errorf("TCP 绑定失败: %w", err)
		}
	}

	h.tcpListener = listener
	h.localAddr = &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: listener.Addr().(*net.TCPAddr).Port,
	}

	// 启动一个 goroutine 接受并丢弃连接
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	return nil
}

// SimulateSYN 发送一个真实的 TCP SYN (非 Linux 简化实现)
func (h *NATHelper) SimulateSYN(serverAddr *net.TCPAddr) error {
	if h.mode != NATModeTCPBind {
		return nil
	}

	// 非 Linux 平台使用简化实现
	dialer := net.Dialer{
		Timeout: 100 * time.Millisecond,
	}

	conn, err := dialer.Dial("tcp4", serverAddr.String())
	if conn != nil {
		conn.Close()
	}
	_ = err

	return nil
}
