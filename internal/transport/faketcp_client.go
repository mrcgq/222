
// =============================================================================
// internal/transport/faketcp_client.go         增强版 FakeTCP 客户端
// =============================================================================

// FakeTCPClient FakeTCP 客户端 (NAT 穿透增强版)
type FakeTCPClient struct {
	config     *FakeTCPConfig
	serverAddr *net.UDPAddr
	localAddr  *net.UDPAddr
	logLevel   int

	// NAT 穿透辅助器
	natHelper *NATHelper

	// 原始套接字
	rawConn *net.IPConn

	// 会话
	session    *FakeTCPSession
	sessionMgr *FakeTCPSessionManager

	// 接收通道
	recvChan chan []byte

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
	maxRetries     int
	retryInterval  time.Duration
	synRetries     int32
}

// FakeTCPConfig 配置结构
type FakeTCPConfig struct {
	// NAT 穿透模式
	NATMode NATTraversalMode

	// 连接超时
	ConnTimeout time.Duration

	// 日志级别
	LogLevel string

	// 其他配置...
	MSS            uint16
	WindowSize     uint16
	EnableSACK     bool
	EnableTimestamp bool
}

// DefaultFakeTCPConfig 默认配置
func DefaultFakeTCPConfig() *FakeTCPConfig {
	return &FakeTCPConfig{
		NATMode:         NATModeAuto,
		ConnTimeout:     10 * time.Second,
		LogLevel:        "info",
		MSS:             1460,
		WindowSize:      65535,
		EnableSACK:      true,
		EnableTimestamp: true,
	}
}

// NewFakeTCPClient 创建 FakeTCP 客户端
func NewFakeTCPClient(serverAddr string, config *FakeTCPConfig) (*FakeTCPClient, error) {
	if config == nil {
		config = DefaultFakeTCPConfig()
	}

	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("解析地址失败: %w", err)
	}

	level := 1
	switch config.LogLevel {
	case "debug":
		level = 2
	case "error":
		level = 0
	}

	return &FakeTCPClient{
		config:        config,
		serverAddr:    addr,
		logLevel:      level,
		recvChan:      make(chan []byte, 256),
		maxRetries:    3,
		retryInterval: 500 * time.Millisecond,
	}, nil
}

// Connect 连接到服务器 (增强版)
func (c *FakeTCPClient) Connect(ctx context.Context) error {
	// 步骤 1: 初始化 NAT 辅助器
	localPort := c.generateLocalPort()
	natHelper, err := NewNATHelper(c.config.NATMode, localPort, c.serverAddr)
	if err != nil {
		return fmt.Errorf("NAT 辅助器初始化失败: %w", err)
	}
	c.natHelper = natHelper
	c.localAddr = natHelper.GetLocalAddr()

	c.log(1, "NAT 模式: %d, 本地端口: %d", natHelper.mode, c.localAddr.Port)

	// 步骤 2: 执行 NAT 打洞 (如果需要)
	if err := c.natHelper.PunchHole(ctx); err != nil {
		c.natHelper.Close()
		return fmt.Errorf("NAT 打洞失败: %w", err)
	}

	// 步骤 3: 创建原始套接字
	conn, err := c.createRawSocket()
	if err != nil {
		c.natHelper.Close()
		return err
	}
	c.rawConn = conn

	// 步骤 4: 发送模拟 SYN (TCP 绑定模式)
	if c.natHelper.mode == NATModeTCPBind {
		c.natHelper.SimulateSYN(&net.TCPAddr{
			IP:   c.serverAddr.IP,
			Port: c.serverAddr.Port,
		})
		time.Sleep(50 * time.Millisecond) // 等待 conntrack 记录建立
	}

	// 步骤 5: 初始化会话
	c.sessionMgr = NewFakeTCPSessionManager(c.config, c.localAddr)
	c.session = c.sessionMgr.GetOrCreateSession(c.serverAddr)

	c.ctx, c.cancel = context.WithCancel(ctx)
	atomic.StoreInt32(&c.running, 1)

	// 步骤 6: 启动读取循环
	c.wg.Add(1)
	go c.readLoop()

	// 步骤 7: 启动 NAT 保活
	c.natHelper.StartKeepAlive(c.ctx)

	// 步骤 8: 发送 SYN (带重试)
	if err := c.sendSYNWithRetry(ctx); err != nil {
		c.Close()
		return err
	}

	// 步骤 9: 等待连接建立
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
		return nil
	}
}

// createRawSocket 创建原始套接字
func (c *FakeTCPClient) createRawSocket() (*net.IPConn, error) {
	conn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, fmt.Errorf("创建原始套接字失败: %w", err)
	}

	// 设置 IP_HDRINCL
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

		// 重新执行 NAT 打洞 (每次重试前)
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

		// 等待一段时间看是否收到 SYN-ACK
		waitCtx, cancel := context.WithTimeout(ctx, c.retryInterval*2)
		select {
		case <-waitCtx.Done():
			cancel()
			if atomic.LoadInt32(&c.connected) == 1 {
				return nil
			}
			// 超时，继续重试
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

		// 检查是否来自服务器
		if !srcAddr.IP.Equal(c.serverAddr.IP) {
			continue
		}

		// 解析 IP 头
		ipHeader, ipHeaderLen, err := DecodeIPHeader(buf[:n])
		if err != nil {
			continue
		}

		if ipHeader.Protocol != 6 {
			continue
		}

		// 解析 TCP 头
		tcpData := buf[ipHeaderLen:n]
		tcpHeader, tcpHeaderLen, err := DecodeTCPHeader(tcpData)
		if err != nil {
			continue
		}

		// 检查端口
		if tcpHeader.SrcPort != uint16(c.serverAddr.Port) ||
			tcpHeader.DstPort != uint16(c.localAddr.Port) {
			continue
		}

		// 验证校验和
		if !VerifyTCPChecksum(ipHeader.SrcIP, ipHeader.DstIP, tcpData) {
			c.log(2, "TCP 校验和错误")
			continue
		}

		payload := tcpData[tcpHeaderLen:]

		// 处理包
		c.handlePacket(tcpHeader, payload)
	}
}

// handlePacket 处理收到的包
func (c *FakeTCPClient) handlePacket(tcpHeader *TCPHeader, payload []byte) {
	// 收到任何包都说明 NAT 穿透成功
	c.log(2, "收到包: Flags=0x%02x, Seq=%d, Ack=%d, Len=%d",
		tcpHeader.Flags, tcpHeader.SeqNum, tcpHeader.AckNum, len(payload))

	response, data, err := c.sessionMgr.HandleIncoming(c.session, tcpHeader, payload)
	if err != nil {
		c.log(2, "处理错误: %v", err)
		return
	}

	// 检查是否已建立连接
	c.session.mu.RLock()
	state := c.session.State
	c.session.mu.RUnlock()

	if state == TCPStateEstablished && atomic.LoadInt32(&c.connected) == 0 {
		atomic.StoreInt32(&c.connected, 1)
		c.log(1, "连接状态: ESTABLISHED")
	}

	// 发送响应
	if response != nil {
		if err := c.sendPacket(response); err != nil {
			c.log(2, "发送响应失败: %v", err)
		}
	}

	// 传递数据
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
	// 更新本地地址 (确保使用 NAT helper 分配的端口)
	pkt.TCPHeader.SrcPort = uint16(c.localAddr.Port)
	pkt.TCPHeader.DstPort = uint16(c.serverAddr.Port)

	// 编码 TCP 头部
	tcpHeaderBuf := EncodeTCPHeader(pkt.TCPHeader)

	// 计算校验和
	tcpHeaderBuf[16] = 0
	tcpHeaderBuf[17] = 0
	checksum := CalculateTCPChecksum(
		c.localAddr.IP,
		c.serverAddr.IP,
		tcpHeaderBuf,
		pkt.Payload,
	)
	binary.BigEndian.PutUint16(tcpHeaderBuf[16:18], checksum)

	// 构建完整包
	var packet []byte
	packet = append(packet, tcpHeaderBuf...)
	packet = append(packet, pkt.Payload...)

	_, err := c.rawConn.WriteToIP(packet, &net.IPAddr{IP: c.serverAddr.IP})
	return err
}

// Send 发送数据
func (c *FakeTCPClient) Send(data []byte) error {
	if atomic.LoadInt32(&c.connected) == 0 {
		return fmt.Errorf("未连接")
	}

	// 分片发送
	c.session.mu.RLock()
	mss := int(c.session.MSS)
	c.session.mu.RUnlock()

	if mss == 0 {
		mss = int(c.config.MSS)
	}
	if mss == 0 {
		mss = 1460
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

	// 发送 FIN
	if c.session != nil && c.session.State == TCPStateEstablished {
		finPkt := c.sessionMgr.CloseConnection(c.session)
		if finPkt != nil {
			c.sendPacket(finPkt)
		}
	}

	if c.cancel != nil {
		c.cancel()
	}

	// 关闭 NAT 辅助器
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



