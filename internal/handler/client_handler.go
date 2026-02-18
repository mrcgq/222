









// internal/handler/client_handler.go
// Phantom 协议客户端处理器 - 服务端完美适配版
// 严格对齐 96 文件系统的 crypto、protocol、congestion 模块

package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrcgq/211/internal/congestion"
	"github.com/mrcgq/211/internal/crypto"
	"github.com/mrcgq/211/internal/protocol"
	"github.com/mrcgq/211/internal/transport"
)

// ============================================
// 常量定义
// ============================================

const (
	// 连接状态
	StateInit       int32 = 0
	StateConnecting int32 = 1
	StateConnected  int32 = 2
	StateClosed     int32 = 3

	// 缓冲区配置
	DefaultMTU         = 1400
	MaxPayloadSize     = 1350 // MTU - TSKD头(18) - 协议头(~32)
	ReadBufferSize     = 65536
	WriteBufferSize    = 65536
	SessionBufferSize  = 512

	// 超时配置
	ConnectTimeout   = 10 * time.Second
	ReadTimeout      = 60 * time.Second
	WriteTimeout     = 30 * time.Second
	HeartbeatInterval = 15 * time.Second
	SessionTimeout   = 120 * time.Second
)

// ============================================
// 错误定义
// ============================================

var (
	ErrSessionClosed    = errors.New("session closed")
	ErrConnectTimeout   = errors.New("connect timeout")
	ErrConnectRefused   = errors.New("connection refused by server")
	ErrInvalidResponse  = errors.New("invalid server response")
	ErrTransportClosed  = errors.New("transport closed")
)

// ============================================
// 配置结构
// ============================================

// Config 客户端处理器配置
type Config struct {
	// 服务端信息
	ServerAddr string
	ServerPort uint16

	// 安全配置
	PSK        string
	TimeWindow time.Duration

	// 性能配置
	UploadMbps   int
	DownloadMbps int

	// 传输配置
	TransportMode  string // "udp", "faketcp", "wss"
	TLSFingerprint string // "chrome", "firefox", "safari"
}

// ============================================
// 会话结构
// ============================================

// Session 单个代理会话
type Session struct {
	// 标识
	reqID uint32

	// 连接
	localConn  net.Conn
	targetAddr string
	targetPort uint16

	// 状态
	state      int32
	createTime time.Time
	lastActive time.Time

	// 数据通道
	recvChan chan *protocol.ServerResponse

	// 控制
	ctx    context.Context
	cancel context.CancelFunc

	// 同步
	mu sync.Mutex
}

// ============================================
// 主处理器结构
// ============================================

// PhantomClientHandler 客户端协议处理器
type PhantomClientHandler struct {
	// 核心组件 - 直接引用 96 文件模块
	crypto     *crypto.Crypto
	controller *congestion.Hysteria2Controller
	transport  transport.Transport

	// 配置
	config *Config

	// 会话管理
	sessions   map[uint32]*Session
	sessionsMu sync.RWMutex
	nextReqID  uint32

	// 生命周期控制
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// 统计
	stats struct {
		bytesSent     uint64
		bytesReceived uint64
		packetsSent   uint64
		packetsRecv   uint64
		sessionsTotal uint64
		sessionsActive int64
	}
}

// ============================================
// 构造函数
// ============================================

// NewClientHandler 创建客户端处理器
func NewClientHandler(cfg *Config) (*PhantomClientHandler, error) {
	// 参数验证
	if cfg.ServerAddr == "" {
		return nil, errors.New("server address required")
	}
	if cfg.PSK == "" {
		return nil, errors.New("PSK required")
	}

	// 设置默认值
	if cfg.TimeWindow == 0 {
		cfg.TimeWindow = 30 * time.Second
	}
	if cfg.UploadMbps == 0 {
		cfg.UploadMbps = 100
	}
	if cfg.DownloadMbps == 0 {
		cfg.DownloadMbps = 100
	}

	// 1. 初始化加密核心（调用 96 文件的 crypto 模块）
	cry, err := crypto.New(cfg.PSK, cfg.TimeWindow)
	if err != nil {
		return nil, fmt.Errorf("crypto init failed: %w", err)
	}

	// 2. 初始化拥塞控制（调用 96 文件的 congestion 模块）
	controller := congestion.NewHysteria2Controller(cfg.UploadMbps, cfg.DownloadMbps)

	// 3. 初始化传输层（调用 96 文件的 transport 模块）
	var trans transport.Transport
	serverEndpoint := fmt.Sprintf("%s:%d", cfg.ServerAddr, cfg.ServerPort)

	switch cfg.TransportMode {
	case "faketcp":
		trans, err = transport.NewFakeTCPClient(serverEndpoint)
		if err != nil {
			return nil, fmt.Errorf("faketcp init failed: %w", err)
		}
	case "wss":
		trans, err = transport.NewWebSocketClient(serverEndpoint, cfg.TLSFingerprint)
		if err != nil {
			return nil, fmt.Errorf("websocket init failed: %w", err)
		}
	default: // "udp" 或空
		trans, err = transport.NewUDPClient(serverEndpoint)
		if err != nil {
			return nil, fmt.Errorf("udp init failed: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	h := &PhantomClientHandler{
		crypto:     cry,
		controller: controller,
		transport:  trans,
		config:     cfg,
		sessions:   make(map[uint32]*Session),
		ctx:        ctx,
		cancel:     cancel,
	}

	// 启动后台协程
	h.wg.Add(2)
	go h.receiveLoop()
	go h.maintenanceLoop()

	return h, nil
}

// ============================================
// SOCKS5 接口实现
// ============================================

// Handle 处理来自 SOCKS5 的连接请求
// 实现 socks5.ClientHandler 接口
func (h *PhantomClientHandler) Handle(conn net.Conn, targetAddr string, targetPort uint16, initData []byte) error {
	// 分配请求 ID
	reqID := atomic.AddUint32(&h.nextReqID, 1)

	// 创建会话上下文
	sessionCtx, sessionCancel := context.WithCancel(h.ctx)

	session := &Session{
		reqID:      reqID,
		localConn:  conn,
		targetAddr: targetAddr,
		targetPort: targetPort,
		state:      StateConnecting,
		createTime: time.Now(),
		lastActive: time.Now(),
		recvChan:   make(chan *protocol.ServerResponse, SessionBufferSize),
		ctx:        sessionCtx,
		cancel:     sessionCancel,
	}

	// 注册会话
	h.registerSession(session)
	defer h.unregisterSession(reqID)

	// 统计
	atomic.AddUint64(&h.stats.sessionsTotal, 1)
	atomic.AddInt64(&h.stats.sessionsActive, 1)
	defer atomic.AddInt64(&h.stats.sessionsActive, -1)

	// 1. 发送 Connect 请求（携带 0-RTT 数据）
	if err := h.sendConnectRequest(session, initData); err != nil {
		return fmt.Errorf("send connect failed: %w", err)
	}

	// 2. 等待服务端确认
	if err := h.waitForConnectAck(session); err != nil {
		return fmt.Errorf("connect ack failed: %w", err)
	}

	// 3. 标记已连接
	atomic.StoreInt32(&session.state, StateConnected)

	// 4. 启动双向数据转发
	return h.runDataRelay(session)
}

// ============================================
// 协议操作
// ============================================

// sendConnectRequest 发送连接请求
func (h *PhantomClientHandler) sendConnectRequest(session *Session, initData []byte) error {
	// 使用 client_types.go 中的构建函数
	payload, err := protocol.BuildClientConnectRequest(
		session.reqID,
		protocol.NetworkTCP,
		session.targetAddr,
		session.targetPort,
		initData,
	)
	if err != nil {
		return err
	}

	return h.sendEncryptedPacket(payload)
}

// sendDataPacket 发送数据包
func (h *PhantomClientHandler) sendDataPacket(session *Session, data []byte) error {
	payload := protocol.BuildClientDataRequest(session.reqID, data)
	return h.sendEncryptedPacket(payload)
}

// sendClosePacket 发送关闭包
func (h *PhantomClientHandler) sendClosePacket(session *Session) error {
	payload := protocol.BuildClientCloseRequest(session.reqID)
	return h.sendEncryptedPacket(payload)
}

// sendHeartbeat 发送心跳包
func (h *PhantomClientHandler) sendHeartbeat() error {
	payload := protocol.BuildClientHeartbeat(0)
	return h.sendEncryptedPacket(payload)
}

// sendEncryptedPacket 加密并发送数据包
// 这是与服务端 eBPF 对接的关键！
func (h *PhantomClientHandler) sendEncryptedPacket(payload []byte) error {
	// 1. 拥塞控制检查（调用 Hysteria2 算法）
	for !h.controller.CanSend(len(payload)) {
		select {
		case <-h.ctx.Done():
			return h.ctx.Err()
		default:
			// 使用 Pacer 计算等待时间
			interval := h.controller.GetPacingInterval(len(payload))
			time.Sleep(interval)
		}
	}

	// 2. TSKD 18 字节头加密
	// 调用 crypto.Encrypt 会自动添加:
	// - UserID (4 bytes) - eBPF 用于识别用户
	// - Timestamp (2 bytes) - 防重放
	// - Nonce (12 bytes) - AEAD 随机数
	encrypted, err := h.crypto.Encrypt(payload)
	if err != nil {
		return fmt.Errorf("encrypt failed: %w", err)
	}

	// 3. 通过传输层发送
	n, err := h.transport.Write(encrypted)
	if err != nil {
		return fmt.Errorf("transport write failed: %w", err)
	}

	// 4. 更新统计和拥塞控制
	atomic.AddUint64(&h.stats.bytesSent, uint64(n))
	atomic.AddUint64(&h.stats.packetsSent, 1)
	h.controller.OnSent(n)

	return nil
}

// waitForConnectAck 等待连接确认
func (h *PhantomClientHandler) waitForConnectAck(session *Session) error {
	timer := time.NewTimer(ConnectTimeout)
	defer timer.Stop()

	for {
		select {
		case <-session.ctx.Done():
			return ErrSessionClosed

		case <-timer.C:
			return ErrConnectTimeout

		case resp := <-session.recvChan:
			// 验证是否为本会话的响应
			if resp.ReqID != session.reqID {
				continue
			}

			// 判断是否为连接确认
			// 服务端使用 TypeData 回复，连接确认时 Payload 为空
			if resp.IsConnectAck() {
				if resp.Status == protocol.StatusSuccess {
					return nil
				}
				return fmt.Errorf("%w: status=%d", ErrConnectRefused, resp.Status)
			}

			// 如果收到的是数据包，说明连接已成功，先缓存数据
			if resp.IsDataPacket() {
				// 将数据重新放回通道供后续处理
				select {
				case session.recvChan <- resp:
				default:
				}
				return nil
			}
		}
	}
}

// ============================================
// 数据转发
// ============================================

// runDataRelay 运行双向数据转发
func (h *PhantomClientHandler) runDataRelay(session *Session) error {
	errChan := make(chan error, 2)

	// 上行：本地 -> 远程
	go func() {
		errChan <- h.relayLocalToRemote(session)
	}()

	// 下行：远程 -> 本地
	go func() {
		errChan <- h.relayRemoteToLocal(session)
	}()

	// 等待任一方向结束
	err := <-errChan

	// 发送关闭指令
	h.sendClosePacket(session)

	// 取消会话
	session.cancel()

	// 等待另一个协程结束
	<-errChan

	return err
}

// relayLocalToRemote 本地到远程数据转发
func (h *PhantomClientHandler) relayLocalToRemote(session *Session) error {
	buf := make([]byte, MaxPayloadSize)

	for {
		select {
		case <-session.ctx.Done():
			return nil
		default:
		}

		// 设置读取超时
		session.localConn.SetReadDeadline(time.Now().Add(ReadTimeout))

		// 从本地连接读取数据
		n, err := session.localConn.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil // 正常关闭
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // 超时重试
			}
			return err
		}

		if n == 0 {
			continue
		}

		// 更新活跃时间
		session.lastActive = time.Now()

		// 发送到远程
		if err := h.sendDataPacket(session, buf[:n]); err != nil {
			return err
		}
	}
}

// relayRemoteToLocal 远程到本地数据转发
func (h *PhantomClientHandler) relayRemoteToLocal(session *Session) error {
	for {
		select {
		case <-session.ctx.Done():
			return nil

		case resp := <-session.recvChan:
			// 验证 ReqID
			if resp.ReqID != session.reqID {
				continue
			}

			// 处理关闭包
			if resp.IsClosePacket() {
				return nil
			}

			// 处理数据包
			if resp.IsDataPacket() && len(resp.Payload) > 0 {
				// 更新活跃时间
				session.lastActive = time.Now()

				// 写入本地连接
				session.localConn.SetWriteDeadline(time.Now().Add(WriteTimeout))
				if _, err := session.localConn.Write(resp.Payload); err != nil {
					return err
				}
			}
		}
	}
}

// ============================================
// 接收循环
// ============================================

// receiveLoop 后台接收循环
func (h *PhantomClientHandler) receiveLoop() {
	defer h.wg.Done()

	buf := make([]byte, ReadBufferSize)

	for {
		select {
		case <-h.ctx.Done():
			return
		default:
		}

		// 从传输层读取
		n, err := h.transport.Read(buf)
		if err != nil {
			if h.ctx.Err() != nil {
				return // 正常退出
			}
			continue
		}

		// 最小长度检查（18字节 TSKD 头 + 6字节协议最小长度）
		if n < 24 {
			continue
		}

		// 解密（crypto.Decrypt 会验证 UserID、Timestamp 和 Nonce）
		decrypted, err := h.crypto.Decrypt(buf[:n])
		if err != nil {
			// 解密失败可能是：
			// - 重放攻击
			// - 非法包
			// - 时间窗口外的包
			continue
		}

		// 更新统计
		atomic.AddUint64(&h.stats.bytesReceived, uint64(n))
		atomic.AddUint64(&h.stats.packetsRecv, 1)

		// 解析服务端响应
		resp, err := protocol.ParseServerResponse(decrypted)
		if err != nil {
			continue
		}

		// 更新拥塞控制
		h.controller.OnAck(time.Millisecond * 10) // 简化处理，实际应计算 RTT

		// 分发到对应会话
		h.dispatchResponse(resp)
	}
}

// dispatchResponse 分发响应到会话
func (h *PhantomClientHandler) dispatchResponse(resp *protocol.ServerResponse) {
	h.sessionsMu.RLock()
	session, ok := h.sessions[resp.ReqID]
	h.sessionsMu.RUnlock()

	if !ok {
		return // 会话不存在，可能已关闭
	}

	// 非阻塞发送到会话通道
	select {
	case session.recvChan <- resp:
	default:
		// 通道满，丢弃（极端情况）
	}
}

// ============================================
// 维护循环
// ============================================

// maintenanceLoop 后台维护循环
func (h *PhantomClientHandler) maintenanceLoop() {
	defer h.wg.Done()

	heartbeatTicker := time.NewTicker(HeartbeatInterval)
	cleanupTicker := time.NewTicker(30 * time.Second)

	defer heartbeatTicker.Stop()
	defer cleanupTicker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return

		case <-heartbeatTicker.C:
			h.sendHeartbeat()

		case <-cleanupTicker.C:
			h.cleanupStaleSessions()
		}
	}
}

// cleanupStaleSessions 清理过期会话
func (h *PhantomClientHandler) cleanupStaleSessions() {
	now := time.Now()
	var stale []uint32

	h.sessionsMu.RLock()
	for reqID, session := range h.sessions {
		if now.Sub(session.lastActive) > SessionTimeout {
			stale = append(stale, reqID)
		}
	}
	h.sessionsMu.RUnlock()

	for _, reqID := range stale {
		h.unregisterSession(reqID)
	}
}

// ============================================
// 会话管理
// ============================================

// registerSession 注册会话
func (h *PhantomClientHandler) registerSession(session *Session) {
	h.sessionsMu.Lock()
	h.sessions[session.reqID] = session
	h.sessionsMu.Unlock()
}

// unregisterSession 注销会话
func (h *PhantomClientHandler) unregisterSession(reqID uint32) {
	h.sessionsMu.Lock()
	session, ok := h.sessions[reqID]
	if ok {
		delete(h.sessions, reqID)
	}
	h.sessionsMu.Unlock()

	if ok && session != nil {
		atomic.StoreInt32(&session.state, StateClosed)
		session.cancel()
		session.localConn.Close()
		close(session.recvChan)
	}
}

// ============================================
// 生命周期管理
// ============================================

// Close 关闭处理器
func (h *PhantomClientHandler) Close() error {
	// 取消上下文
	h.cancel()

	// 关闭所有会话
	h.sessionsMu.Lock()
	for reqID, session := range h.sessions {
		h.sendClosePacket(session)
		session.cancel()
		session.localConn.Close()
		delete(h.sessions, reqID)
	}
	h.sessionsMu.Unlock()

	// 关闭传输层
	if h.transport != nil {
		h.transport.Close()
	}

	// 等待后台协程
	h.wg.Wait()

	return nil
}

// ============================================
// 统计接口
// ============================================

// Stats 统计信息
type Stats struct {
	BytesSent      uint64 `json:"bytes_sent"`
	BytesReceived  uint64 `json:"bytes_received"`
	PacketsSent    uint64 `json:"packets_sent"`
	PacketsRecv    uint64 `json:"packets_recv"`
	SessionsTotal  uint64 `json:"sessions_total"`
	SessionsActive int64  `json:"sessions_active"`
}

// GetStats 获取统计信息
func (h *PhantomClientHandler) GetStats() Stats {
	return Stats{
		BytesSent:      atomic.LoadUint64(&h.stats.bytesSent),
		BytesReceived:  atomic.LoadUint64(&h.stats.bytesReceived),
		PacketsSent:    atomic.LoadUint64(&h.stats.packetsSent),
		PacketsRecv:    atomic.LoadUint64(&h.stats.packetsRecv),
		SessionsTotal:  atomic.LoadUint64(&h.stats.sessionsTotal),
		SessionsActive: atomic.LoadInt64(&h.stats.sessionsActive),
	}
}



