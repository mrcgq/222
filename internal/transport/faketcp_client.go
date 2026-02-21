
//go:build linux

// =============================================================================
// internal/transport/faketcp_client.go
// 描述: 增强版 FakeTCP 客户端 - 集成 TLS 指纹伪装
// =============================================================================

package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mrcgq/211/internal/config"
)

// FakeTCPClient FakeTCP 客户端 (NAT 穿透增强版)
type FakeTCPClient struct {
	config     *FakeTCPConfig
	serverAddr *net.UDPAddr
	localAddr  *net.UDPAddr
	logLevel   int

	// NAT 穿透模式
	natMode NATTraversalMode

	// NAT 穿透辅助器
	natHelper *NATHelper

	// 原始套接字
	rawConn *net.IPConn

	// 会话
	session    *FakeTCPSession
	sessionMgr *FakeTCPSessionManager

	// 接收通道
	recvChan chan []byte

	// TLS 配置
	tlsConfig  *config.TLSConfig
	utlsClient *UTLSClient
	tlsConn    net.Conn // TLS 连接（如果启用）

	// 统计
	stats FakeTCPStats

	// 控制
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.RWMutex
	connected int32
	running   int32

	// 重试配置
	maxRetries    int
	retryInterval time.Duration
	synRetries    int32
}

// NewFakeTCPClient 创建 FakeTCP 客户端
func NewFakeTCPClient(serverAddr string, cfg *FakeTCPConfig) (*FakeTCPClient, error) {
	if cfg == nil {
		cfg = DefaultFakeTCPConfig()
	}

	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("解析地址失败: %w", err)
	}

	level := 1
	switch cfg.LogLevel {
	case "debug":
		level = 2
	case "error":
		level = 0
	}

	return &FakeTCPClient{
		config:        cfg,
		serverAddr:    addr,
		logLevel:      level,
		natMode:       NATModeAuto,
		recvChan:      make(chan []byte, 256),
		maxRetries:    3,
		retryInterval: 500 * time.Millisecond,
	}, nil
}

// NewFakeTCPClientWithTLS 创建带 TLS 的 FakeTCP 客户端
func NewFakeTCPClientWithTLS(serverAddr string, cfg *FakeTCPConfig, tlsCfg *config.TLSConfig) (*FakeTCPClient, error) {
	client, err := NewFakeTCPClient(serverAddr, cfg)
	if err != nil {
		return nil, err
	}

	if tlsCfg != nil && tlsCfg.Enabled {
		client.tlsConfig = tlsCfg

		utlsConfig := &UTLSConfig{
			ServerName:         tlsCfg.GetEffectiveSNI(),
			Fingerprint:        Fingerprint(tlsCfg.Fingerprint),
			InsecureSkipVerify: !tlsCfg.VerifyCert,
			ALPN:               tlsCfg.ALPN,
			MinVersion:         ParseTLSVersion(tlsCfg.MinVersion),
			MaxVersion:         ParseTLSVersion(tlsCfg.MaxVersion),
			FragmentEnabled:    tlsCfg.FragmentEnabled,
			FragmentSize:       tlsCfg.FragmentSize,
			FragmentSleepMs:    tlsCfg.FragmentSleepMs,
			PaddingEnabled:     tlsCfg.PaddingEnabled,
			PaddingMinSize:     tlsCfg.PaddingMinSize,
			PaddingMaxSize:     tlsCfg.PaddingMaxSize,
			EnableECH:          tlsCfg.EnableECH,
			HandshakeTimeout:   10 * time.Second,
			LogLevel:           client.logLevel,
		}

		client.utlsClient = NewUTLSClient(utlsConfig)
	}

	return client, nil
}

// SetNATMode 设置 NAT 穿透模式
func (c *FakeTCPClient) SetNATMode(mode NATTraversalMode) {
	c.natMode = mode
}

// Connect 连接到服务器 (增强版)
func (c *FakeTCPClient) Connect(ctx context.Context) error {
	localPort := c.generateLocalPort()
	natHelper, err := NewNATHelper(c.natMode, localPort, c.serverAddr)
	if err != nil {
		return fmt.Errorf("NAT 辅助器初始化失败: %w", err)
	}
	c.natHelper = natHelper
	c.localAddr = natHelper.GetLocalAddr()

	c.log(1, "NAT 模式: %d, 本地端口: %d", natHelper.mode, c.localAddr.Port)

	if err := c.natHelper.PunchHole(ctx); err != nil {
		c.natHelper.Close()
		return fmt.Errorf("NAT 打洞失败: %w", err)
	}

	conn, err := c.createRawSocket()
	if err != nil {
		c.natHelper.Close()
		return err
	}
	c.rawConn = conn

	if c.natHelper.mode == NATModeTCPBind {
		c.natHelper.SimulateSYN(&net.TCPAddr{
			IP:   c.serverAddr.IP,
			Port: c.serverAddr.Port,
		})
		time.Sleep(50 * time.Millisecond)
	}

	c.sessionMgr = NewFakeTCPSessionManager(c.config, c.localAddr)
	c.session = c.sessionMgr.GetOrCreateSession(c.serverAddr)

	c.ctx, c.cancel = context.WithCancel(ctx)
	atomic.StoreInt32(&c.running, 1)

	c.wg.Add(1)
	go c.readLoop()

	c.natHelper.StartKeepAlive(c.ctx)

	if err := c.sendSYNWithRetry(ctx); err != nil {
		c.Close()
		return err
	}

	select {
	case <-ctx.Done():
		c.Close()
		return ctx.Err()
	case <-time.After(c.config.ConnTimeout):
		c.Close()
		return fmt.Errorf("连接超时 (SYN 重试 %d 次)", atomic.LoadInt32(&c.synRetries))
	case <-c.waitConnected():
		c.log(1, "FakeTCP 连接已建立: %s (重试 %d 次)",
			c.serverAddr, atomic.LoadInt32(&c.synRetries))
	}

	if c.tlsConfig != nil && c.tlsConfig.Enabled {
		if err := c.upgradeTLS(ctx); err != nil {
			c.Close()
			return fmt.Errorf("TLS 握手失败: %w", err)
		}
		c.log(1, "TLS 连接已建立: SNI=%s, Fingerprint=%s",
			c.tlsConfig.GetEffectiveSNI(), c.tlsConfig.Fingerprint)
	}

	return nil
}

// upgradeTLS 升级为 TLS 连接
func (c *FakeTCPClient) upgradeTLS(ctx context.Context) error {
	if c.utlsClient == nil {
		return fmt.Errorf("uTLS 客户端未初始化")
	}

	adapter := NewFakeConnAdapter(c)

	tlsConn, err := c.utlsClient.WrapConn(adapter, c.tlsConfig.GetEffectiveSNI())
	if err != nil {
		return err
	}

	c.tlsConn = tlsConn
	return nil
}

// createRawSocket 创建原始套接字
func (c *FakeTCPClient) createRawSocket() (*net.IPConn, error) {
	conn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, fmt.Errorf("创建原始套接字失败: %w", err)
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("获取 syscall conn 失败: %w", err)
	}

	var setErr error
	err = rawConn.Control(func(fd uintptr) {
		setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("Control 失败: %w", err)
	}
	if setErr != nil {
		conn.Close()
		return nil, fmt.Errorf("设置 IP_HDRINCL 失败: %w", setErr)
	}

	return conn, nil
}

// sendSYNWithRetry 发送 SYN 包 (带重试)
func (c *FakeTCPClient) sendSYNWithRetry(ctx context.Context) error {
	var lastErr error

	for i := 0; i < c.maxRetries; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		atomic.StoreInt32(&c.synRetries, int32(i+1))

		if i > 0 && c.natHelper.mode == NATModeUDPHole {
			c.natHelper.PunchHole(ctx)
			time.Sleep(20 * time.Millisecond)
		}

		synPkt := c.sessionMgr.InitiateConnection(c.session)
		if err := c.sendPacket(synPkt); err != nil {
			lastErr = fmt.Errorf("发送 SYN 失败: %w", err)
			c.log(2, "SYN 发送失败 (尝试 %d/%d): %v", i+1, c.maxRetries, err)
			time.Sleep(c.retryInterval)
			continue
		}

		c.log(2, "SYN 已发送 (尝试 %d/%d)", i+1, c.maxRetries)

		waitCtx, cancel := context.WithTimeout(ctx, c.retryInterval*2)
		select {
		case <-waitCtx.Done():
			cancel()
			if atomic.LoadInt32(&c.connected) == 1 {
				return nil
			}
			continue
		case <-c.waitConnected():
			cancel()
			return nil
		}
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("SYN 发送失败，已重试 %d 次", c.maxRetries)
}

// waitConnected 等待连接建立
func (c *FakeTCPClient) waitConnected() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				if atomic.LoadInt32(&c.connected) == 1 {
					close(ch)
					return
				}
			}
		}
	}()
	return ch
}

// readLoop 读取循环
func (c *FakeTCPClient) readLoop() {
	defer c.wg.Done()

	buf := make([]byte, 65535)

	for atomic.LoadInt32(&c.running) == 1 {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		c.rawConn.SetReadDeadline(time.Now().Add(time.Second))
		n, srcAddr, err := c.rawConn.ReadFromIP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-c.ctx.Done():
				return
			default:
				continue
			}
		}

		if !srcAddr.IP.Equal(c.serverAddr.IP) {
			continue
		}

		ipHeader, ipHeaderLen, err := DecodeIPHeader(buf[:n])
		if err != nil {
			continue
		}

		if ipHeader.Protocol != 6 {
			continue
		}

		tcpData := buf[ipHeaderLen:n]
		tcpHeader, tcpHeaderLen, err := DecodeTCPHeader(tcpData)
		if err != nil {
			continue
		}

		if tcpHeader.SrcPort != uint16(c.serverAddr.Port) ||
			tcpHeader.DstPort != uint16(c.localAddr.Port) {
			continue
		}

		if !VerifyTCPChecksum(ipHeader.SrcIP, ipHeader.DstIP, tcpData) {
			c.log(2, "TCP 校验和错误")
			continue
		}

		payload := tcpData[tcpHeaderLen:]

		c.handlePacket(tcpHeader, payload)
	}
}

// handlePacket 处理收到的包
func (c *FakeTCPClient) handlePacket(tcpHeader *TCPHeader, payload []byte) {
	c.log(2, "收到包: Flags=0x%02x, Seq=%d, Ack=%d, Len=%d",
		tcpHeader.Flags, tcpHeader.SeqNum, tcpHeader.AckNum, len(payload))

	response, data, err := c.sessionMgr.HandleIncoming(c.session, tcpHeader, payload)
	if err != nil {
		c.log(2, "处理错误: %v", err)
		return
	}

	c.session.mu.RLock()
	state := c.session.State
	c.session.mu.RUnlock()

	if state == TCPStateEstablished && atomic.LoadInt32(&c.connected) == 0 {
		atomic.StoreInt32(&c.connected, 1)
		c.log(1, "连接状态: ESTABLISHED")
	}

	if response != nil {
		if err := c.sendPacket(response); err != nil {
			c.log(2, "发送响应失败: %v", err)
		}
	}

	if len(data) > 0 {
		select {
		case c.recvChan <- data:
			c.log(2, "数据已入队: %d 字节", len(data))
		default:
			c.log(0, "接收缓冲区满，丢弃数据")
		}
	}
}

// sendPacket 发送数据包
func (c *FakeTCPClient) sendPacket(pkt *FakeTCPPacket) error {
	pkt.TCPHeader.SrcPort = uint16(c.localAddr.Port)
	pkt.TCPHeader.DstPort = uint16(c.serverAddr.Port)

	tcpHeaderBuf := EncodeTCPHeader(pkt.TCPHeader)

	tcpHeaderBuf[16] = 0
	tcpHeaderBuf[17] = 0
	checksum := CalculateTCPChecksum(
		c.localAddr.IP,
		c.serverAddr.IP,
		tcpHeaderBuf,
		pkt.Payload,
	)
	binary.BigEndian.PutUint16(tcpHeaderBuf[16:18], checksum)

	var packet []byte
	packet = append(packet, tcpHeaderBuf...)
	packet = append(packet, pkt.Payload...)

	_, err := c.rawConn.WriteToIP(packet, &net.IPAddr{IP: c.serverAddr.IP})
	return err
}

// Send 发送数据
func (c *FakeTCPClient) Send(data []byte) error {
	if c.tlsConn != nil {
		_, err := c.tlsConn.Write(data)
		return err
	}

	return c.sendRaw(data)
}

// sendRaw 原始发送（不经过 TLS）
func (c *FakeTCPClient) sendRaw(data []byte) error {
	if atomic.LoadInt32(&c.connected) == 0 {
		return fmt.Errorf("未连接")
	}

	c.session.mu.RLock()
	mss := int(c.session.MSS)
	c.session.mu.RUnlock()

	if mss == 0 {
		mss = int(c.config.MSS)
	}
	if mss == 0 {
		mss = DefaultMSS
	}

	for len(data) > 0 {
		chunkSize := len(data)
		if chunkSize > mss {
			chunkSize = mss
		}

		chunk := data[:chunkSize]
		data = data[chunkSize:]

		pkt := c.sessionMgr.SendData(c.session, chunk)
		if pkt == nil {
			return fmt.Errorf("发送失败")
		}

		if err := c.sendPacket(pkt); err != nil {
			return err
		}
	}

	return nil
}

// Recv 接收数据
func (c *FakeTCPClient) Recv(ctx context.Context) ([]byte, error) {
	if c.tlsConn != nil {
		buf := make([]byte, 32*1024)
		n, err := c.tlsConn.Read(buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, fmt.Errorf("连接已关闭")
	case data := <-c.recvChan:
		return data, nil
	}
}

// RecvNonblock 非阻塞接收
func (c *FakeTCPClient) RecvNonblock() ([]byte, bool) {
	select {
	case data := <-c.recvChan:
		return data, true
	default:
		return nil, false
	}
}

// Close 关闭连接
func (c *FakeTCPClient) Close() error {
	atomic.StoreInt32(&c.running, 0)
	atomic.StoreInt32(&c.connected, 0)

	if c.tlsConn != nil {
		c.tlsConn.Close()
		c.tlsConn = nil
	}

	if c.session != nil && c.session.State == TCPStateEstablished {
		finPkt := c.sessionMgr.CloseConnection(c.session)
		if finPkt != nil {
			c.sendPacket(finPkt)
		}
	}

	if c.cancel != nil {
		c.cancel()
	}

	if c.natHelper != nil {
		c.natHelper.Close()
	}

	if c.rawConn != nil {
		c.rawConn.Close()
	}

	c.wg.Wait()
	return nil
}

// IsConnected 是否已连接
func (c *FakeTCPClient) IsConnected() bool {
	return atomic.LoadInt32(&c.connected) == 1
}

// IsTLSEnabled 是否启用 TLS
func (c *FakeTCPClient) IsTLSEnabled() bool {
	return c.tlsConn != nil
}

// GetNATMode 获取当前 NAT 模式
func (c *FakeTCPClient) GetNATMode() NATTraversalMode {
	if c.natHelper != nil {
		return c.natHelper.mode
	}
	return NATModeNone
}

// GetLocalAddr 获取本地地址
func (c *FakeTCPClient) GetLocalAddr() *net.UDPAddr {
	return c.localAddr
}

// 修复：实现 net.Conn 接口所需的 LocalAddr 方法
func (c *FakeTCPClient) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

// 修复：实现 net.Conn 接口所需的 RemoteAddr 方法
func (c *FakeTCPClient) RemoteAddr() net.Addr {
	if c.serverAddr != nil {
		return c.serverAddr
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

// 修复：实现 net.Conn 接口所需的 SetDeadline 方法
func (c *FakeTCPClient) SetDeadline(t time.Time) error {
	return c.rawConn.SetDeadline(t)
}

// 修复：实现 net.Conn 接口所需的 SetReadDeadline 方法
func (c *FakeTCPClient) SetReadDeadline(t time.Time) error {
	return c.rawConn.SetReadDeadline(t)
}

// 修复：实现 net.Conn 接口所需的 SetWriteDeadline 方法
func (c *FakeTCPClient) SetWriteDeadline(t time.Time) error {
	return c.rawConn.SetWriteDeadline(t)
}

// 修复：实现 io.Reader 接口
func (c *FakeTCPClient) Read(b []byte) (int, error) {
	data, err := c.Recv(c.ctx)
	if err != nil {
		return 0, err
	}
	n := copy(b, data)
	return n, nil
}

// 修复：实现 io.Writer 接口
func (c *FakeTCPClient) Write(b []byte) (int, error) {
	err := c.Send(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// generateLocalPort 生成本地端口
func (c *FakeTCPClient) generateLocalPort() int {
	return 32768 + int(time.Now().UnixNano()%32768)
}

func (c *FakeTCPClient) log(level int, format string, args ...interface{}) {
	if level > c.logLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [FakeTCP-Client] %s\n",
		prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}


