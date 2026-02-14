

// =============================================================================
// 文件: internal/transport/faketcp.go
// 描述: FakeTCP 伪装 - 服务器实现 (集成 eBPF TC 加速)
// 注意: 类型定义已移至 faketcp_types.go，此处只引用不重复定义
// =============================================================================
package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// FakeTCPServer FakeTCP 服务器
type FakeTCPServer struct {
	config   *FakeTCPConfig
	handler  PacketHandler
	logLevel int

	rawConn    *net.IPConn
	localAddr  *net.UDPAddr
	sessionMgr *FakeTCPSessionManager

	// eBPF TC 加速
	tcManager *EBPFTCManager
	useEBPF   bool

	stats FakeTCPStats

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex

	running int32
}

// NewFakeTCPServer 创建 FakeTCP 服务器
func NewFakeTCPServer(addr, iface string, handler PacketHandler, logLevel string) *FakeTCPServer {
	level := 1
	switch logLevel {
	case "debug":
		level = 2
	case "error":
		level = 0
	}

	config := DefaultFakeTCPConfig()
	config.ListenAddr = addr
	config.Interface = iface
	config.LogLevel = logLevel

	return &FakeTCPServer{
		config:   config,
		handler:  handler,
		logLevel: level,
	}
}

// EnableEBPFTC 启用 eBPF TC 加速
func (s *FakeTCPServer) EnableEBPFTC(programPath string) error {
	if s.config.Interface == "" {
		return fmt.Errorf("需要指定网卡接口")
	}

	s.tcManager = NewEBPFTCManager(s.config.Interface, programPath)

	_, portStr, _ := net.SplitHostPort(s.config.ListenAddr)
	var udpPort uint16
	fmt.Sscanf(portStr, "%d", &udpPort)
	tcpPort := udpPort + 1

	if err := s.tcManager.LoadFakeTCP(udpPort, tcpPort); err != nil {
		return fmt.Errorf("加载 TC 程序失败: %w", err)
	}

	s.useEBPF = true
	s.log(1, "eBPF TC FakeTCP 加速已启用")
	return nil
}

// Start 启动服务器
func (s *FakeTCPServer) Start(ctx context.Context) error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("解析地址失败: %w", err)
	}
	s.localAddr = udpAddr

	conn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		return fmt.Errorf("创建原始套接字失败: %w", err)
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		return fmt.Errorf("获取 syscall conn 失败: %w", err)
	}

	var setErr error
	err = rawConn.Control(func(fd uintptr) {
		setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	})
	if err != nil {
		conn.Close()
		return fmt.Errorf("Control 失败: %w", err)
	}
	if setErr != nil {
		conn.Close()
		return fmt.Errorf("设置 IP_HDRINCL 失败: %w", setErr)
	}

	s.rawConn = conn
	s.sessionMgr = NewFakeTCPSessionManager(s.config, s.localAddr)

	s.ctx, s.cancel = context.WithCancel(ctx)
	atomic.StoreInt32(&s.running, 1)

	s.wg.Add(1)
	go s.readLoop()

	s.wg.Add(1)
	go s.cleanupLoop()

	s.log(1, "FakeTCP 服务器已启动: %s (eBPF: %v)", s.config.ListenAddr, s.useEBPF)
	return nil
}

// readLoop 读取循环
func (s *FakeTCPServer) readLoop() {
	defer s.wg.Done()

	buf := make([]byte, 65535)

	for atomic.LoadInt32(&s.running) == 1 {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		s.rawConn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := s.rawConn.ReadFromIP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue
		}

		if n < 20 {
			continue
		}

		atomic.AddUint64(&s.stats.PacketsReceived, 1)
		atomic.AddUint64(&s.stats.BytesReceived, uint64(n))

		data := make([]byte, n)
		copy(data, buf[:n])

		go s.handlePacket(data, addr)
	}
}

// handlePacket 处理包
func (s *FakeTCPServer) handlePacket(data []byte, addr *net.IPAddr) {
	// 解析 IP + TCP 头，提取载荷
	if len(data) < 40 {
		return
	}

	// 简化处理：跳过 IP 头 (20 bytes) + TCP 头 (20 bytes)
	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || len(data) < ihl+20 {
		return
	}

	tcpData := data[ihl:]
	// TCP 数据偏移
	dataOffset := int(tcpData[12]>>4) * 4
	if len(tcpData) < dataOffset {
		return
	}

	payload := tcpData[dataOffset:]
	if len(payload) == 0 {
		return
	}

	// 提取源端口作为 UDPAddr 的端口
	srcPort := int(tcpData[0])<<8 | int(tcpData[1])

	udpAddr := &net.UDPAddr{
		IP:   addr.IP,
		Port: srcPort,
	}

	if resp := s.handler.HandlePacket(payload, udpAddr); resp != nil {
		s.sendPacket(resp, udpAddr)
	}
}

// sendPacket 发送包
func (s *FakeTCPServer) sendPacket(data []byte, addr *net.UDPAddr) {
	if s.rawConn == nil || addr == nil {
		return
	}

	// 获取或创建会话
	session := s.sessionMgr.GetOrCreateSession(addr)
	if session == nil {
		return
	}

	// 构建 TCP 数据包
	pkt := s.sessionMgr.SendData(session, data)
	if pkt == nil {
		return
	}

	// 编码 TCP 头
	tcpHeader := EncodeTCPHeader(pkt.TCPHeader)

	// 计算校验和
	checksum := CalculateTCPChecksum(s.localAddr.IP, addr.IP, tcpHeader, pkt.Payload)
	tcpHeader[16] = byte(checksum >> 8)
	tcpHeader[17] = byte(checksum)

	// 构建完整包
	packet := append(tcpHeader, pkt.Payload...)

	// 发送
	_, err := s.rawConn.WriteToIP(packet, &net.IPAddr{IP: addr.IP})
	if err != nil {
		s.log(2, "发送失败: %v", err)
		return
	}

	atomic.AddUint64(&s.stats.PacketsSent, 1)
	atomic.AddUint64(&s.stats.BytesSent, uint64(len(data)))
}

// SendTo 发送数据到指定地址
func (s *FakeTCPServer) SendTo(data []byte, addr *net.UDPAddr) error {
	s.sendPacket(data, addr)
	return nil
}

// cleanupLoop 清理循环
func (s *FakeTCPServer) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if s.sessionMgr != nil {
				s.sessionMgr.Cleanup()
			}
		}
	}
}

// IsRunning 是否运行中
func (s *FakeTCPServer) IsRunning() bool {
	return atomic.LoadInt32(&s.running) == 1 && s.rawConn != nil
}

// GetStats 获取统计
func (s *FakeTCPServer) GetStats() FakeTCPStats {
	stats := FakeTCPStats{
		PacketsSent:     atomic.LoadUint64(&s.stats.PacketsSent),
		PacketsReceived: atomic.LoadUint64(&s.stats.PacketsReceived),
		BytesSent:       atomic.LoadUint64(&s.stats.BytesSent),
		BytesReceived:   atomic.LoadUint64(&s.stats.BytesReceived),
		Retransmits:     atomic.LoadUint64(&s.stats.Retransmits),
		ChecksumErrors:  atomic.LoadUint64(&s.stats.ChecksumErrors),
	}

	if s.sessionMgr != nil {
		mgrStats := s.sessionMgr.GetStats()
		stats.ActiveSessions = mgrStats.ActiveSessions
		stats.TotalSessions = mgrStats.TotalSessions
	}

	return stats
}

// Stop 停止服务器
func (s *FakeTCPServer) Stop() {
	atomic.StoreInt32(&s.running, 0)
	s.cancel()

	if s.tcManager != nil {
		s.tcManager.Unload()
	}

	if s.rawConn != nil {
		s.rawConn.Close()
	}

	s.wg.Wait()
	s.log(1, "FakeTCP 服务器已停止")
}

func (s *FakeTCPServer) log(level int, format string, args ...interface{}) {
	if level > s.logLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [FakeTCP] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}





