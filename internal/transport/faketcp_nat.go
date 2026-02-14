// =============================================================================
// 文件:internal/transport/faketcp_nat.go
// 描述: FakeTCP 伪装 - NAT 穿透辅助器
// =============================================================================
package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// =============================================================================
// NAT 穿透策略
// =============================================================================

// NATTraversalMode NAT 穿透模式类型
type NATTraversalMode int

const (
	// NATModeAuto 自动检测并选择最佳策略
	NATModeAuto NATTraversalMode = iota
	// NATModeUDPHole UDP 打洞模式 (推荐)
	NATModeUDPHole
	// NATModeTCPBind TCP 端口绑定模式
	NATModeTCPBind
	// NATModeConntrack 手动 Conntrack 模式 (需要特权)
	NATModeConntrack
	// NATModeNone 不使用 NAT 穿透 (仅适用于公网或端口映射环境)
	NATModeNone
)

// NATHelper NAT 穿透辅助器
type NATHelper struct {
	mode       NATTraversalMode
	localAddr  *net.UDPAddr
	serverAddr *net.UDPAddr

	// UDP 辅助套接字 (用于建立 NAT 映射)
	udpConn *net.UDPConn

	// TCP 占位套接字 (用于建立 conntrack)
	tcpListener net.Listener

	// 保活
	keepAliveInterval time.Duration
	keepAliveChan     chan struct{}

	mu sync.Mutex
}

// NewNATHelper 创建 NAT 辅助器
func NewNATHelper(mode NATTraversalMode, localPort int, serverAddr *net.UDPAddr) (*NATHelper, error) {
	helper := &NATHelper{
		mode:              mode,
		serverAddr:        serverAddr,
		keepAliveInterval: 25 * time.Second, // NAT 映射通常 30s 超时
		keepAliveChan:     make(chan struct{}),
	}

	// 自动检测模式
	if mode == NATModeAuto {
		helper.mode = helper.detectBestMode()
	}

	var err error
	switch helper.mode {
	case NATModeUDPHole:
		err = helper.setupUDPHole(localPort)
	case NATModeTCPBind:
		err = helper.setupTCPBind(localPort)
	case NATModeConntrack:
		err = helper.setupConntrack(localPort)
	case NATModeNone:
		// 不做任何设置
		helper.localAddr = &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: localPort,
		}
	}

	if err != nil {
		return nil, fmt.Errorf("NAT helper 初始化失败 (mode=%d): %w", helper.mode, err)
	}

	return helper, nil
}

// detectBestMode 检测最佳 NAT 穿透模式
func (h *NATHelper) detectBestMode() NATTraversalMode {
	// 检查是否在公网环境
	if h.isPublicIP() {
		return NATModeNone
	}

	// 检查是否有特权 (用于 conntrack 模式)
	if h.hasConntrackCapability() {
		return NATModeConntrack
	}

	// 默认使用 UDP 打洞模式
	return NATModeUDPHole
}

// isPublicIP 检查本机是否有公网 IP
func (h *NATHelper) isPublicIP() bool {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return false
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ip := localAddr.IP

	// 检查是否为私有地址
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10", // CGNAT
	}

	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(ip) {
			return false
		}
	}

	return true
}

// hasConntrackCapability 检查是否有 conntrack 操作能力
func (h *NATHelper) hasConntrackCapability() bool {
	// 尝试读取 conntrack 表
	// 实际实现需要 netlink 库
	return false // 保守策略：默认返回 false
}

// =============================================================================
// UDP 打洞模式实现
// =============================================================================

func (h *NATHelper) setupUDPHole(localPort int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 绑定 UDP 套接字到指定端口
	laddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: localPort,
	}

	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		// 如果端口被占用，尝试使用系统分配的端口
		laddr.Port = 0
		conn, err = net.ListenUDP("udp4", laddr)
		if err != nil {
			return fmt.Errorf("UDP 绑定失败: %w", err)
		}
	}

	h.udpConn = conn
	h.localAddr = conn.LocalAddr().(*net.UDPAddr)

	return nil
}

// PunchHole 执行 UDP 打洞
func (h *NATHelper) PunchHole(ctx context.Context) error {
	if h.mode != NATModeUDPHole || h.udpConn == nil {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// 发送多个探测包以确保 NAT 映射建立
	probeData := []byte("FAKETCP_PROBE")

	for i := 0; i < 3; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_, err := h.udpConn.WriteToUDP(probeData, h.serverAddr)
		if err != nil {
			return fmt.Errorf("UDP 打洞失败: %w", err)
		}

		time.Sleep(50 * time.Millisecond)
	}

	return nil
}

// StartKeepAlive 启动 NAT 保活
func (h *NATHelper) StartKeepAlive(ctx context.Context) {
	if h.mode != NATModeUDPHole || h.udpConn == nil {
		return
	}

	go func() {
		ticker := time.NewTicker(h.keepAliveInterval)
		defer ticker.Stop()

		keepAliveData := []byte("KA")

		for {
			select {
			case <-ctx.Done():
				return
			case <-h.keepAliveChan:
				return
			case <-ticker.C:
				h.udpConn.WriteToUDP(keepAliveData, h.serverAddr)
			}
		}
	}()
}

// =============================================================================
// TCP 绑定模式实现
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
				// Linux 特定
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15 /* SO_REUSEPORT */, 1)
			})
			return err
		},
	}

	listener, err := lc.Listen(context.Background(), "tcp4", laddr.String())
	if err != nil {
		return fmt.Errorf("TCP 绑定失败: %w", err)
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

// =============================================================================
// Conntrack 模式实现 (需要特权)
// =============================================================================

func (h *NATHelper) setupConntrack(localPort int) error {
	// 需要使用 netlink 库操作 conntrack 表
	// 这里提供伪代码框架

	h.localAddr = &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: localPort,
	}

	return fmt.Errorf("conntrack 模式尚未实现")
}

// =============================================================================
// 通用方法
// =============================================================================

// GetLocalAddr 获取本地地址
func (h *NATHelper) GetLocalAddr() *net.UDPAddr {
	return h.localAddr
}

// GetLocalPort 获取本地端口
func (h *NATHelper) GetLocalPort() int {
	if h.localAddr != nil {
		return h.localAddr.Port
	}
	return 0
}

// Close 关闭 NAT 辅助器
func (h *NATHelper) Close() error {
	close(h.keepAliveChan)

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.udpConn != nil {
		h.udpConn.Close()
	}

	if h.tcpListener != nil {
		h.tcpListener.Close()
	}

	return nil
}
