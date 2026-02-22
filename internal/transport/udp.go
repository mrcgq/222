
// =============================================================================
// 文件: internal/transport/udp.go
// 描述: 增强版 UDP 服务器 - ARQ 作为增强层集成（修复版 v3）
//       新增：SendOnly 模式，仅创建发送通道，不监听端口
// =============================================================================
package transport

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrcgq/211/internal/congestion"
	"golang.org/x/sync/singleflight"
)

// =============================================================================
// 常量定义
// =============================================================================

const (
	// 缓冲区配置
	defaultReadBufferSize  = 8 * 1024 * 1024  // 8MB 默认
	defaultWriteBufferSize = 8 * 1024 * 1024  // 8MB 默认
	maxBufferSize          = 64 * 1024 * 1024 // 64MB 最大
	minBufferSize          = 2 * 1024 * 1024  // 2MB 最小

	// Worker 配置
	defaultWorkerQueueSize = 4096
	minWorkers             = 4
	maxWorkers             = 64
)

// =============================================================================
// 缓冲区配置
// =============================================================================

// BufferConfig 缓冲区配置
type BufferConfig struct {
	// 目标带宽 (bps)，用于自动计算缓冲区
	TargetBandwidth uint64

	// 预期 RTT (ms)，用于计算 BDP
	ExpectedRTTMs uint32

	// 手动指定缓冲区大小（优先级高于自动计算）
	ReadBufferSize  int
	WriteBufferSize int

	// 缓冲区倍数（相对于 BDP）
	BufferMultiplier float64
}

// DefaultBufferConfig 默认缓冲区配置
func DefaultBufferConfig() *BufferConfig {
	return &BufferConfig{
		TargetBandwidth:  100 * 1024 * 1024, // 100 Mbps
		ExpectedRTTMs:    100,               // 100ms
		BufferMultiplier: 2.0,               // BDP 的 2 倍
	}
}

// HighBandwidthBufferConfig 高带宽配置 (1Gbps+)
func HighBandwidthBufferConfig() *BufferConfig {
	return &BufferConfig{
		TargetBandwidth:  1024 * 1024 * 1024, // 1 Gbps
		ExpectedRTTMs:    200,                // 200ms (跨国)
		BufferMultiplier: 2.5,
	}
}

// calculateBufferSize 计算推荐缓冲区大小
func (c *BufferConfig) calculateBufferSize() (readSize, writeSize int) {
	// 如果手动指定，直接使用
	if c.ReadBufferSize > 0 && c.WriteBufferSize > 0 {
		return clampBufferSize(c.ReadBufferSize), clampBufferSize(c.WriteBufferSize)
	}

	// 计算 BDP (Bandwidth-Delay Product)
	// BDP = Bandwidth (bytes/s) × RTT (s)
	bandwidthBytesPerSec := c.TargetBandwidth / 8
	rttSeconds := float64(c.ExpectedRTTMs) / 1000.0
	bdp := float64(bandwidthBytesPerSec) * rttSeconds

	// 缓冲区 = BDP × 倍数
	multiplier := c.BufferMultiplier
	if multiplier <= 0 {
		multiplier = 2.0
	}

	bufferSize := int(bdp * multiplier)
	bufferSize = clampBufferSize(bufferSize)

	return bufferSize, bufferSize
}

// clampBufferSize 限制缓冲区大小在合理范围内
func clampBufferSize(size int) int {
	if size < minBufferSize {
		return minBufferSize
	}
	if size > maxBufferSize {
		return maxBufferSize
	}
	return size
}

// =============================================================================
// 数据结构
// =============================================================================

// packetTask 数据包任务
type packetTask struct {
	data []byte
	addr *net.UDPAddr
}

// UDPServer 增强版 UDP 服务器
type UDPServer struct {
	addr     string
	handler  PacketHandler
	logLevel int

	conn   *net.UDPConn
	stopCh chan struct{}
	wg     sync.WaitGroup

	// 缓冲区配置
	bufferConfig *BufferConfig

	// 拥塞控制
	congestion *congestion.Hysteria2Controller

	// ARQ 增强层
	arqEnabled bool
	arqManager *ARQManager

	// Worker 池
	workers   int
	workerChs []chan *packetTask
	workerWg  sync.WaitGroup

	// 包序号
	nextPacketNum uint64

	// 状态标志
	running  int32
	started  int32
	sendOnly bool // 新增：仅发送模式

	// 统计信息
	packetsRecv    uint64
	packetsSent    uint64
	bytesRecv      uint64
	bytesSent      uint64
	packetsDropped uint64

	// 连接建立的 singleflight 防止并发竞争
	connectGroup singleflight.Group

	// 连接状态缓存（避免频繁锁操作）
	connCache    sync.Map // map[string]*arqConnState
	connCacheMu  sync.RWMutex
	connCacheTTL time.Duration

	mu sync.RWMutex
}

// arqConnState ARQ 连接状态缓存
type arqConnState struct {
	conn        *ARQConn
	established bool
	lastCheck   time.Time
}

// =============================================================================
// 构造函数
// =============================================================================

// NewUDPServer 创建 UDP 服务器
func NewUDPServer(addr string, h PacketHandler, logLevel string) *UDPServer {
	level := 1
	switch logLevel {
	case "debug":
		level = 2
	case "error":
		level = 0
	}

	workers := runtime.NumCPU() * 2
	if workers < minWorkers {
		workers = minWorkers
	}
	if workers > maxWorkers {
		workers = maxWorkers
	}

	return &UDPServer{
		addr:          addr,
		handler:       h,
		logLevel:      level,
		workers:       workers,
		stopCh:        make(chan struct{}),
		nextPacketNum: 1,
		bufferConfig:  DefaultBufferConfig(),
		connCacheTTL:  time.Second * 5,
		sendOnly:      false,
	}
}

// NewUDPServerSendOnly 创建仅发送模式的 UDP 服务器
// 不监听端口，仅用于发送数据 (配合 eBPF 使用)
func NewUDPServerSendOnly(addr string, h PacketHandler, logLevel string) *UDPServer {
	server := NewUDPServer(addr, h, logLevel)
	server.sendOnly = true
	return server
}

// NewUDPServerWithConfig 使用配置创建 UDP 服务器
func NewUDPServerWithConfig(addr string, h PacketHandler, logLevel string, bufConfig *BufferConfig) *UDPServer {
	server := NewUDPServer(addr, h, logLevel)
	if bufConfig != nil {
		server.bufferConfig = bufConfig
	}
	return server
}

// =============================================================================
// 配置方法
// =============================================================================

// SetBufferConfig 设置缓冲区配置（启动前调用）
func (s *UDPServer) SetBufferConfig(config *BufferConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if config != nil {
		s.bufferConfig = config
	}
}

// SetCongestionController 设置拥塞控制器
func (s *UDPServer) SetCongestionController(cc *congestion.Hysteria2Controller) {
	s.congestion = cc
}

// EnableARQ 启用 ARQ 增强层
func (s *UDPServer) EnableARQ(config *ARQConnConfig, handler ARQHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if config == nil {
		config = DefaultARQConnConfig()
	}

	s.arqEnabled = true
	s.arqManager = NewARQManagerWithConfig(config, s.congestion, handler)
}

// =============================================================================
// 启动与运行
// =============================================================================

// Start 启动服务器
func (s *UDPServer) Start(ctx context.Context) error {
	// SendOnly 模式：仅创建发送连接
	if s.sendOnly {
		return s.startSendOnly(ctx)
	}

	// 正常模式：监听并接收
	return s.startNormal(ctx)
}

// startSendOnly 仅发送模式启动
func (s *UDPServer) startSendOnly(ctx context.Context) error {
	// 创建一个不绑定特定端口的 UDP socket，仅用于发送
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return fmt.Errorf("创建发送 socket 失败: %w", err)
	}

	s.conn = conn

	// 设置写缓冲区
	_, writeSize := s.bufferConfig.calculateBufferSize()
	if err := s.conn.SetWriteBuffer(writeSize); err != nil {
		s.log(1, "写缓冲区设置失败: %v", err)
	}

	atomic.StoreInt32(&s.running, 1)
	atomic.StoreInt32(&s.started, 1)

	s.log(1, "UDP 服务器已启动 (SendOnly 模式)")
	return nil
}

// startNormal 正常模式启动
func (s *UDPServer) startNormal(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("解析地址: %w", err)
	}

	s.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("监听失败: %w", err)
	}

	// 设置优化的缓冲区
	if err := s.setupBuffers(); err != nil {
		s.log(1, "缓冲区设置警告: %v", err)
	}

	// 初始化 worker 池
	s.workerChs = make([]chan *packetTask, s.workers)
	for i := 0; i < s.workers; i++ {
		s.workerChs[i] = make(chan *packetTask, defaultWorkerQueueSize)
		s.workerWg.Add(1)
		go s.orderedWorker(i)
	}

	atomic.StoreInt32(&s.running, 1)
	atomic.StoreInt32(&s.started, 1)

	s.wg.Add(1)
	go s.readLoop(ctx)

	if s.congestion != nil {
		s.wg.Add(1)
		go s.congestionLoop(ctx)
	}

	// 启动连接缓存清理
	s.wg.Add(1)
	go s.connCacheCleanupLoop(ctx)

	s.log(1, "UDP 服务器已启动: %s (workers: %d, ARQ: %v)", s.addr, s.workers, s.arqEnabled)
	return nil
}

// setupBuffers 设置系统缓冲区
func (s *UDPServer) setupBuffers() error {
	readSize, writeSize := s.bufferConfig.calculateBufferSize()

	// 尝试设置读缓冲区
	if err := s.conn.SetReadBuffer(readSize); err != nil {
		// 如果失败，尝试较小的值
		for size := readSize / 2; size >= minBufferSize; size /= 2 {
			if err := s.conn.SetReadBuffer(size); err == nil {
				s.log(1, "读缓冲区降级设置为: %d bytes", size)
				readSize = size
				break
			}
		}
	}

	// 尝试设置写缓冲区
	if err := s.conn.SetWriteBuffer(writeSize); err != nil {
		for size := writeSize / 2; size >= minBufferSize; size /= 2 {
			if err := s.conn.SetWriteBuffer(size); err == nil {
				s.log(1, "写缓冲区降级设置为: %d bytes", size)
				writeSize = size
				break
			}
		}
	}

	s.log(2, "缓冲区配置: read=%dMB, write=%dMB, BDP目标=%.2fMB",
		readSize/1024/1024,
		writeSize/1024/1024,
		float64(s.bufferConfig.TargetBandwidth/8)*float64(s.bufferConfig.ExpectedRTTMs)/1000/1024/1024)

	return nil
}

// readLoop 读取循环
func (s *UDPServer) readLoop(ctx context.Context) {
	defer s.wg.Done()

	buf := make([]byte, 65535)

	for atomic.LoadInt32(&s.running) == 1 {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		default:
		}

		_ = s.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-s.stopCh:
				return
			default:
				continue
			}
		}

		if n == 0 {
			continue
		}

		atomic.AddUint64(&s.packetsRecv, 1)
		atomic.AddUint64(&s.bytesRecv, uint64(n))

		data := make([]byte, n)
		copy(data, buf[:n])

		// 检查是否是 ARQ 包
		if s.arqEnabled && IsARQPacketData(data) {
			s.arqManager.HandlePacket(data, addr, s.conn)
			continue
		}

		// 普通 UDP 包
		workerIdx := s.hashAddr(addr) % s.workers

		select {
		case s.workerChs[workerIdx] <- &packetTask{data: data, addr: addr}:
		default:
			atomic.AddUint64(&s.packetsDropped, 1)
		}
	}
}

// orderedWorker 保序处理 worker
func (s *UDPServer) orderedWorker(idx int) {
	defer s.workerWg.Done()

	for task := range s.workerChs[idx] {
		if task == nil {
			continue
		}

		if resp := s.handler.HandlePacket(task.data, task.addr); resp != nil {
			s.sendWithCongestion(resp, task.addr)
		}
	}
}

// connCacheCleanupLoop 连接缓存清理循环
func (s *UDPServer) connCacheCleanupLoop(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			s.connCache.Range(func(key, value interface{}) bool {
				state := value.(*arqConnState)
				if now.Sub(state.lastCheck) > s.connCacheTTL*10 {
					s.connCache.Delete(key)
				}
				return true
			})
		}
	}
}

// =============================================================================
// 发送方法
// =============================================================================


// sendWithCongestion 带拥塞控制的发送
func (s *UDPServer) sendWithCongestion(data []byte, addr *net.UDPAddr) {
	packetSize := len(data)

	if s.congestion != nil {
		for !s.congestion.CanSend(packetSize) {
			time.Sleep(s.congestion.GetPacingInterval(packetSize))
		}

		pktNum := atomic.AddUint64(&s.nextPacketNum, 1) - 1
		s.congestion.OnPacketSent(pktNum, packetSize, false)
	}

	n, err := s.conn.WriteToUDP(data, addr)
	if err != nil {
		s.log(0, "❌ WriteToUDP 失败: %v, to=%s", err, addr.String())
		if s.congestion != nil {
			pktNum := atomic.LoadUint64(&s.nextPacketNum) - 1
			s.congestion.OnPacketLost(pktNum, packetSize)
		}
	} else {
		s.log(2, "✅ WriteToUDP 成功: %d字节 -> %s", n, addr.String())
		atomic.AddUint64(&s.packetsSent, 1)
		atomic.AddUint64(&s.bytesSent, uint64(packetSize))
	}
}

// SendTo 发送数据到指定地址
func (s *UDPServer) SendTo(data []byte, addr *net.UDPAddr) error {
	if s.conn == nil {
		return fmt.Errorf("连接未初始化")
	}

	// 如果 ARQ 已启用且连接已建立，通过 ARQ 发送
	if s.arqEnabled && s.arqManager != nil && !s.sendOnly {
		if s.isARQConnEstablished(addr) {
			if conn := s.arqManager.GetConn(addr); conn != nil {
				return conn.Send(data)
			}
		}
	}

	s.sendWithCongestion(data, addr)
	return nil
}

// SendViaARQ 通过 ARQ 发送（使用 singleflight 防止并发连接）
func (s *UDPServer) SendViaARQ(ctx context.Context, data []byte, addr *net.UDPAddr) error {
	if !s.arqEnabled || s.arqManager == nil {
		return fmt.Errorf("ARQ 未启用")
	}

	// 使用地址作为 key 进行 singleflight
	key := addr.String()

	// 使用 singleflight 确保同一地址只有一个连接建立过程
	connInterface, err, _ := s.connectGroup.Do(key, func() (interface{}, error) {
		return s.getOrCreateARQConn(ctx, addr)
	})

	if err != nil {
		return fmt.Errorf("获取 ARQ 连接失败: %w", err)
	}

	conn := connInterface.(*ARQConn)
	return conn.Send(data)
}

// getOrCreateARQConn 获取或创建 ARQ 连接
func (s *UDPServer) getOrCreateARQConn(ctx context.Context, addr *net.UDPAddr) (*ARQConn, error) {
	key := addr.String()

	// 检查缓存
	if cached, ok := s.connCache.Load(key); ok {
		state := cached.(*arqConnState)
		if state.established && state.conn != nil && state.conn.IsEstablished() {
			state.lastCheck = time.Now()
			return state.conn, nil
		}
	}

	// 检查 ARQManager 中是否已有连接
	if conn := s.arqManager.GetConn(addr); conn != nil {
		if conn.IsEstablished() {
			// 更新缓存
			s.connCache.Store(key, &arqConnState{
				conn:        conn,
				established: true,
				lastCheck:   time.Now(),
			})
			return conn, nil
		}
	}

	// 创建新连接
	conn, err := s.arqManager.CreateConn(s.conn, addr)
	if err != nil {
		return nil, fmt.Errorf("创建 ARQ 连接失败: %w", err)
	}

	// 启动并建立连接
	conn.Start()

	if err := conn.Connect(ctx); err != nil {
		return nil, fmt.Errorf("ARQ 连接失败: %w", err)
	}

	// 更新缓存
	s.connCache.Store(key, &arqConnState{
		conn:        conn,
		established: true,
		lastCheck:   time.Now(),
	})

	return conn, nil
}

// isARQConnEstablished 检查 ARQ 连接是否已建立（带缓存）
func (s *UDPServer) isARQConnEstablished(addr *net.UDPAddr) bool {
	key := addr.String()

	if cached, ok := s.connCache.Load(key); ok {
		state := cached.(*arqConnState)
		// 缓存有效期内直接返回
		if time.Since(state.lastCheck) < s.connCacheTTL {
			return state.established
		}

		// 缓存过期，重新检查
		if state.conn != nil {
			established := state.conn.IsEstablished()
			state.established = established
			state.lastCheck = time.Now()
			return established
		}
	}

	// 没有缓存，检查 ARQManager
	if conn := s.arqManager.GetConn(addr); conn != nil {
		established := conn.IsEstablished()
		s.connCache.Store(key, &arqConnState{
			conn:        conn,
			established: established,
			lastCheck:   time.Now(),
		})
		return established
	}

	return false
}

// =============================================================================
// 拥塞控制循环
// =============================================================================

// congestionLoop 拥塞控制日志循环
func (s *UDPServer) congestionLoop(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			if s.congestion != nil {
				stats := s.congestion.GetStats()
				s.log(2, "拥塞控制: cwnd=%d, brutal=%v, rate=%.2f Mbps",
					stats.CongestionWindow,
					stats.BrutalMode,
					stats.BrutalRate*8/1024/1024)
			}
		}
	}
}

// =============================================================================
// 辅助方法
// =============================================================================

// hashAddr 计算地址哈希
func (s *UDPServer) hashAddr(addr *net.UDPAddr) int {
	hash := 0
	for _, b := range addr.IP {
		hash = hash*31 + int(b)
	}
	hash = hash*31 + addr.Port
	if hash < 0 {
		hash = -hash
	}
	return hash
}

// GetARQManager 获取 ARQ 管理器
func (s *UDPServer) GetARQManager() *ARQManager {
	return s.arqManager
}

// IsRunning 是否运行中 (真实状态检查)
func (s *UDPServer) IsRunning() bool {
	if atomic.LoadInt32(&s.running) != 1 {
		return false
	}
	if atomic.LoadInt32(&s.started) != 1 {
		return false
	}
	if s.conn == nil {
		return false
	}
	return true
}

// IsSendOnly 是否为仅发送模式
func (s *UDPServer) IsSendOnly() bool {
	return s.sendOnly
}

// OnAck 处理 ACK（供外部调用，如非 ARQ 场景）
func (s *UDPServer) OnAck(packetNumber uint64, ackedBytes int, rtt time.Duration) {
	if s.congestion != nil {
		s.congestion.OnPacketAcked(packetNumber, ackedBytes, rtt)
	}
}

// OnPacketLost 处理丢包（供外部调用）
func (s *UDPServer) OnPacketLost(packetNumber uint64, lostBytes int) {
	if s.congestion != nil {
		s.congestion.OnPacketLost(packetNumber, lostBytes)
	}
}

// GetCongestionStats 获取拥塞控制统计
func (s *UDPServer) GetCongestionStats() *congestion.CongestionStats {
	if s.congestion != nil {
		return s.congestion.GetStats()
	}
	return nil
}

// GetStats 获取统计信息
func (s *UDPServer) GetStats() map[string]uint64 {
	stats := map[string]uint64{
		"packets_recv":    atomic.LoadUint64(&s.packetsRecv),
		"packets_sent":    atomic.LoadUint64(&s.packetsSent),
		"bytes_recv":      atomic.LoadUint64(&s.bytesRecv),
		"bytes_sent":      atomic.LoadUint64(&s.bytesSent),
		"packets_dropped": atomic.LoadUint64(&s.packetsDropped),
	}

	if s.arqEnabled && s.arqManager != nil {
		stats["arq_active_conns"] = uint64(s.arqManager.GetActiveConns())
		stats["arq_total_conns"] = s.arqManager.GetTotalConns()
	}

	// 标记是否为 SendOnly 模式
	if s.sendOnly {
		stats["send_only_mode"] = 1
	} else {
		stats["send_only_mode"] = 0
	}

	return stats
}

// GetConn 获取底层 UDP 连接
func (s *UDPServer) GetConn() *net.UDPConn {
	return s.conn
}

// GetBufferStats 获取缓冲区统计
func (s *UDPServer) GetBufferStats() map[string]interface{} {
	readSize, writeSize := s.bufferConfig.calculateBufferSize()
	bdp := float64(s.bufferConfig.TargetBandwidth/8) * float64(s.bufferConfig.ExpectedRTTMs) / 1000

	return map[string]interface{}{
		"target_bandwidth_mbps": float64(s.bufferConfig.TargetBandwidth) / 1024 / 1024,
		"expected_rtt_ms":       s.bufferConfig.ExpectedRTTMs,
		"bdp_bytes":             int64(bdp),
		"read_buffer_bytes":     readSize,
		"write_buffer_bytes":    writeSize,
		"buffer_multiplier":     s.bufferConfig.BufferMultiplier,
		"send_only_mode":        s.sendOnly,
	}
}

// =============================================================================
// 停止方法
// =============================================================================

// Stop 停止服务器
func (s *UDPServer) Stop() {
	if !atomic.CompareAndSwapInt32(&s.running, 1, 0) {
		return
	}

	close(s.stopCh)

	// 仅在非 SendOnly 模式下关闭 worker
	if !s.sendOnly {
		for _, ch := range s.workerChs {
			if ch != nil {
				close(ch)
			}
		}
		s.workerWg.Wait()
	}

	if s.arqManager != nil {
		s.arqManager.Close()
	}

	if s.conn != nil {
		s.conn.Close()
	}
	s.wg.Wait()

	// 清理连接缓存
	s.connCache = sync.Map{}

	if s.sendOnly {
		s.log(1, "UDP 服务器已停止 (SendOnly 模式)")
	} else {
		s.log(1, "UDP 服务器已停止")
	}
}

// =============================================================================
// 日志方法
// =============================================================================

func (s *UDPServer) log(level int, format string, args ...interface{}) {
	if level > s.logLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [UDP] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}
