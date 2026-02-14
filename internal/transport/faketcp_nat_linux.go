//go:build linux

// =============================================================================
// 文件: internal/transport/faketcp_nat_linux.go
// 描述: FakeTCP NAT 穿透 - Linux 平台特定实现
// =============================================================================
package transport

import (
	"context"
	"net"
	"syscall"
	"time"
)

// =============================================================================
// TCP 绑定模式实现 (Linux)
// =============================================================================

func (h *NATHelper) setupTCPBind(localPort int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 创建 TCP 监听器来占用端口并建立 conntrack
	laddr := &net.TCPAddr{
		IP:   net.IPv4zero,
		Port: localPort,
	}

	// 使用 SO_REUSEADDR 和 SO_REUSEPORT
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if err != nil {
					return
				}
				// Linux 特定: SO_REUSEPORT
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15 /* SO_REUSEPORT */, 1)
			})
			return err
		},
	}

	listener, err := lc.Listen(context.Background(), "tcp4", laddr.String())
	if err != nil {
		return err
	}

	h.tcpListener = listener
	h.localAddr = &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: listener.Addr().(*net.TCPAddr).Port,
	}

	// 启动一个 goroutine 接受并丢弃连接（防止 RST）
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

// SimulateSYN 发送一个真实的 TCP SYN (用于建立 conntrack 记录)
func (h *NATHelper) SimulateSYN(serverAddr *net.TCPAddr) error {
	if h.mode != NATModeTCPBind {
		return nil
	}

	// 使用相同本地端口发起 TCP 连接
	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP:   h.localAddr.IP,
			Port: h.localAddr.Port,
		},
		Timeout: 100 * time.Millisecond,
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if err != nil {
					return
				}
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15, 1)
			})
			return err
		},
	}

	// 这个连接会失败，但会在 conntrack 中留下 SYN_SENT 记录
	conn, err := dialer.Dial("tcp4", serverAddr.String())
	if conn != nil {
		conn.Close()
	}

	// 忽略连接失败错误 - 我们只需要 SYN 发出去建立 conntrack 记录
	_ = err

	return nil
}
