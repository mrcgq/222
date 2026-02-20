// =============================================================================
// 文件: internal/handler/unified_handler.go
// 描述: 统一处理器 - 用户态核心处理中心
// =============================================================================
package handler

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrcgq/211/internal/config"
	"github.com/mrcgq/211/internal/crypto"
	"github.com/mrcgq/211/internal/metrics"
	"github.com/mrcgq/211/internal/protocol"
	"github.com/mrcgq/211/internal/transport"
)

// =============================================================================
// 常量定义
// =============================================================================

const (
	LogLevelError = iota
	LogLevelInfo
	LogLevelDebug
)

const (
	StatusOK    byte = 0x00
	StatusError byte = 0x01
)

const (
	connectTimeout     = 10 * time.Second
	writeTimeout       = 30 * time.Second
	readTimeout        = 5 * time.Minute
	connCleanupPeriod  = 30 * time.Second
	connIdleTimeout    = 5 * time.Minute
	sessionIdleTimeout = 10 * time.Minute
	readBufferSize     = 32 * 1024
)

// =============================================================================
// 类型定义
// =============================================================================

// Sender 标准发送函数类型（用于 UDP）
type Sender func(data []byte, addr *net.UDPAddr) error

// ResponseWriter 响应写入器接口（用于同步回传）
type ResponseWriter interface {
	Write(data []byte) error
}

// ResponseWriterFunc 函数适配器
type ResponseWriterFunc func(data []byte) error

func (f ResponseWriterFunc) Write(data []byte) error {
	return f(data)
}

// PacketContext 数据包处理上下文
type PacketContext struct {
	From           *net.UDPAddr
	ResponseWriter ResponseWriter // 如果非 nil，使用同步回传
	Responses      [][]byte       // 收集需要回传的响应
	mu             sync.Mutex
}

// AddResponse 添加响应数据
func (pc *PacketContext) AddResponse(data []byte) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.Responses = append(pc.Responses, data)
}

// UnifiedHandler 统一处理器
type UnifiedHandler struct {
	crypto  *crypto.Crypto
	cfg     *config.Config
	metrics *metrics.PhantomMetrics

	logLevel int

	connections sync.Map
	sessions    sync.Map

	sender Sender // UDP 异步发送器

	stats handlerStats

	ctx    context.Context
	cancel context.CancelFunc
}

// ProxyConnection 代理连接
type ProxyConnection struct {
	ID         uint32
	Target     net.Conn
	ClientAddr *net.UDPAddr
	Network    string
	TargetAddr string
	CreatedAt  time.Time
	LastActive time.Time
	BytesSent  uint64
	BytesRecv  uint64
	closed     int32
	mu         sync.Mutex

	// 用于 WebSocket 的同步响应通道
	responseChan   chan []byte
	responseWriter ResponseWriter
}

// ClientSession 客户端会话
type ClientSession struct {
	Addr       *net.UDPAddr
	LastActive time.Time
	ConnIDs    []uint32
	mu         sync.Mutex
}

// handlerStats 处理器统计
type handlerStats struct {
	totalConns     uint64
	activeConns    int64
	totalBytes     uint64
	authFailures   uint64
	replayBlocked  uint64
	decryptErrors  uint64
	heartbeatsRecv uint64
}

// =============================================================================
// 构造函数
// =============================================================================

// NewUnifiedHandler 创建统一处理器
func NewUnifiedHandler(c *crypto.Crypto, cfg *config.Config) *UnifiedHandler {
	ctx, cancel := context.WithCancel(context.Background())

	h := &UnifiedHandler{
		crypto:   c,
		cfg:      cfg,
		logLevel: parseLogLevel(cfg.LogLevel),
		ctx:      ctx,
		cancel:   cancel,
	}

	go h.cleanupLoop()

	return h
}

func parseLogLevel(level string) int {
	switch level {
	case "debug":
		return LogLevelDebug
	case "error":
		return LogLevelError
	default:
		return LogLevelInfo
	}
}

// =============================================================================
// 公共接口
// =============================================================================

// SetMetrics 设置指标收集器
func (h *UnifiedHandler) SetMetrics(m *metrics.PhantomMetrics) {
	h.metrics = m
}

// SetSender 设置 UDP 发送器
func (h *UnifiedHandler) SetSender(fn Sender) {
	h.sender = fn
}

// Close 关闭处理器
func (h *UnifiedHandler) Close() error {
	h.cancel()

	h.connections.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*ProxyConnection); ok {
			h.closeConnection(conn.ID)
		}
		return true
	})

	return nil
}

// GetStats 获取统计信息
func (h *UnifiedHandler) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total_conns":     atomic.LoadUint64(&h.stats.totalConns),
		"active_conns":    atomic.LoadInt64(&h.stats.activeConns),
		"total_bytes":     atomic.LoadUint64(&h.stats.totalBytes),
		"auth_failures":   atomic.LoadUint64(&h.stats.authFailures),
		"replay_blocked":  atomic.LoadUint64(&h.stats.replayBlocked),
		"decrypt_errors":  atomic.LoadUint64(&h.stats.decryptErrors),
		"heartbeats_recv": atomic.LoadUint64(&h.stats.heartbeatsRecv),
	}
}

// GetActiveConns 获取活跃连接数
func (h *UnifiedHandler) GetActiveConns() int64 {
	return atomic.LoadInt64(&h.stats.activeConns)
}

// GetAuthFailures 获取认证失败次数
func (h *UnifiedHandler) GetAuthFailures() uint64 {
	return atomic.LoadUint64(&h.stats.authFailures)
}

// GetReplayBlocked 获取重放攻击拦截次数
func (h *UnifiedHandler) GetReplayBlocked() uint64 {
	return atomic.LoadUint64(&h.stats.replayBlocked)
}

// =============================================================================
// UDP 数据包处理（异步模式）
// =============================================================================

// HandlePacket 处理 UDP 数据包（异步模式，使用全局 sender）
func (h *UnifiedHandler) HandlePacket(data []byte, from *net.UDPAddr) []byte {
	pctx := &PacketContext{
		From:           from,
		ResponseWriter: nil, // 异步模式
	}
	h.handlePacketWithContext(data, pctx)
	return nil // UDP 模式下响应通过 sender 异步发送
}

// HandlePacketSync 处理数据包（同步模式，用于 WebSocket）
// 返回需要回传的响应数据
func (h *UnifiedHandler) HandlePacketSync(data []byte, from *net.UDPAddr, writer ResponseWriter) [][]byte {
	pctx := &PacketContext{
		From:           from,
		ResponseWriter: writer,
		Responses:      make([][]byte, 0, 2),
	}
	h.handlePacketWithContext(data, pctx)
	return pctx.Responses
}

// handlePacketWithContext 带上下文的数据包处理
func (h *UnifiedHandler) handlePacketWithContext(data []byte, pctx *PacketContext) {
	// 1. 解密数据
	plaintext, err := h.crypto.Decrypt(data)
	if err != nil {
		atomic.AddUint64(&h.stats.decryptErrors, 1)

		errStr := err.Error()
		if contains(errStr, "UserID") {
			atomic.AddUint64(&h.stats.authFailures, 1)
		} else if contains(errStr, "重放") || contains(errStr, "replay") {
			atomic.AddUint64(&h.stats.replayBlocked, 1)
		}

		h.log(LogLevelDebug, "解密失败: %v", err)
		return
	}

	// 2. 解析协议请求
	req, err := protocol.ParseRequest(plaintext)
	if err != nil {
		h.log(LogLevelDebug, "解析请求失败: %v", err)
		return
	}

	// 3. 更新会话信息
	h.updateSession(pctx.From, req.ReqID)

	// 4. 根据请求类型分发处理
	switch req.Type {
	case protocol.TypeConnect:
		h.handleConnect(req, pctx)

	case protocol.TypeData:
		h.handleData(req, pctx)

	case protocol.TypeClose:
		h.handleClose(req)

	case protocol.TypeHeartbeat:
		atomic.AddUint64(&h.stats.heartbeatsRecv, 1)
		h.handleHeartbeat(req, pctx)

	default:
		h.log(LogLevelDebug, "未知请求类型: 0x%02X", req.Type)
	}
}

// handleConnect 处理连接请求
func (h *UnifiedHandler) handleConnect(req *protocol.Request, pctx *PacketContext) {
	network := req.NetworkString()
	target := req.TargetAddr()

	h.log(LogLevelInfo, "Connect: %s %s (ID:%d) from %s",
		network, target, req.ReqID, pctx.From.String())

	// 连接目标
	targetConn, err := net.DialTimeout(network, target, connectTimeout)
	if err != nil {
		h.log(LogLevelDebug, "连接目标失败: %s - %v", target, err)
		h.sendResponse(req.ReqID, StatusError, nil, pctx)
		return
	}

	h.configureTCPConnection(targetConn)

	// 创建代理连接
	conn := &ProxyConnection{
		ID:             req.ReqID,
		Target:         targetConn,
		ClientAddr:     pctx.From,
		Network:        network,
		TargetAddr:     target,
		CreatedAt:      time.Now(),
		LastActive:     time.Now(),
		responseWriter: pctx.ResponseWriter,
	}

	// 如果是同步模式（WebSocket），创建响应通道
	if pctx.ResponseWriter != nil {
		conn.responseChan = make(chan []byte, 64)
	}

	h.connections.Store(req.ReqID, conn)
	atomic.AddUint64(&h.stats.totalConns, 1)
	atomic.AddInt64(&h.stats.activeConns, 1)

	if h.metrics != nil {
		h.metrics.IncConnections()
	}

	// 发送初始数据（如果有）
	if len(req.Data) > 0 {
		if err := h.writeToTarget(conn, req.Data); err != nil {
			h.log(LogLevelDebug, "发送初始数据失败: %v", err)
		}
	}

	// 发送连接成功响应
	h.sendResponse(req.ReqID, StatusOK, nil, pctx)

	// 启动读取循环
	go h.readLoop(conn, pctx.ResponseWriter)
}

// handleData 处理数据请求
func (h *UnifiedHandler) handleData(req *protocol.Request, pctx *PacketContext) {
	conn := h.getConnection(req.ReqID)
	if conn == nil {
		h.log(LogLevelDebug, "连接不存在: ID:%d", req.ReqID)
		return
	}

	conn.mu.Lock()
	conn.LastActive = time.Now()
	conn.ClientAddr = pctx.From
	// 更新响应写入器（WebSocket 连接可能重连）
	if pctx.ResponseWriter != nil {
		conn.responseWriter = pctx.ResponseWriter
	}
	conn.mu.Unlock()

	if len(req.Data) > 0 {
		if err := h.writeToTarget(conn, req.Data); err != nil {
			h.log(LogLevelDebug, "写入目标失败: ID:%d - %v", req.ReqID, err)
			h.closeConnection(req.ReqID)
		}
	}
}

// handleClose 处理关闭请求
func (h *UnifiedHandler) handleClose(req *protocol.Request) {
	h.log(LogLevelInfo, "Close: ID:%d", req.ReqID)
	h.closeConnection(req.ReqID)
}

// handleHeartbeat 处理心跳请求
func (h *UnifiedHandler) handleHeartbeat(req *protocol.Request, pctx *PacketContext) {
	h.log(LogLevelDebug, "收到心跳: ID:%d from %s", req.ReqID, pctx.From.String())
	resp := protocol.BuildHeartbeatResponse(req.ReqID)
	h.sendEncryptedResponse(resp, pctx)
}

// readLoop 从目标服务器读取数据并回传给客户端
func (h *UnifiedHandler) readLoop(conn *ProxyConnection, syncWriter ResponseWriter) {
	defer h.closeConnection(conn.ID)

	buf := make([]byte, readBufferSize)

	for {
		if atomic.LoadInt32(&conn.closed) != 0 {
			return
		}

		_ = conn.Target.SetReadDeadline(time.Now().Add(readTimeout))

		n, err := conn.Target.Read(buf)
		if err != nil {
			if err != io.EOF {
				h.log(LogLevelDebug, "读取目标结束: ID:%d - %v", conn.ID, err)
			}
			return
		}

		conn.mu.Lock()
		conn.LastActive = time.Now()
		clientAddr := conn.ClientAddr
		currentWriter := conn.responseWriter
		conn.mu.Unlock()

		atomic.AddUint64(&conn.BytesRecv, uint64(n))
		atomic.AddUint64(&h.stats.totalBytes, uint64(n))

		if h.metrics != nil {
			h.metrics.AddBytesReceived(int64(n))
		}

		// 构建响应
		resp := protocol.BuildResponse(conn.ID, protocol.TypeData, buf[:n])
		encrypted, err := h.crypto.Encrypt(resp)
		if err != nil {
			h.log(LogLevelError, "加密响应失败: %v", err)
			continue
		}

		// 根据模式发送响应
		if currentWriter != nil {
			// 同步模式（WebSocket）
			if err := currentWriter.Write(encrypted); err != nil {
				h.log(LogLevelDebug, "同步发送失败: ID:%d - %v", conn.ID, err)
				return
			}
		} else if h.sender != nil {
			// 异步模式（UDP）
			if err := h.sender(encrypted, clientAddr); err != nil {
				h.log(LogLevelDebug, "异步发送失败: ID:%d - %v", conn.ID, err)
			}
		}

		if h.metrics != nil {
			h.metrics.AddBytesSent(int64(len(encrypted)))
		}
	}
}

// sendResponse 发送响应
func (h *UnifiedHandler) sendResponse(reqID uint32, status byte, data []byte, pctx *PacketContext) {
	resp := protocol.BuildResponse(reqID, status, data)
	h.sendEncryptedResponse(resp, pctx)
}

// sendEncryptedResponse 加密并发送响应
func (h *UnifiedHandler) sendEncryptedResponse(resp []byte, pctx *PacketContext) {
	encrypted, err := h.crypto.Encrypt(resp)
	if err != nil {
		h.log(LogLevelError, "加密响应失败: %v", err)
		return
	}

	// 同步模式：收集响应
	if pctx.ResponseWriter != nil {
		pctx.AddResponse(encrypted)
		return
	}

	// 异步模式：通过 sender 发送
	if h.sender != nil {
		if err := h.sender(encrypted, pctx.From); err != nil {
			h.log(LogLevelDebug, "发送响应失败: %v", err)
		} else if h.metrics != nil {
			h.metrics.AddBytesSent(int64(len(encrypted)))
		}
	} else {
		h.log(LogLevelError, "Sender 未设置，无法发送响应")
	}
}

// =============================================================================
// TCP 连接处理
// =============================================================================

// HandleConnection 处理 TCP 连接
func (h *UnifiedHandler) HandleConnection(ctx context.Context, clientConn net.Conn) {
	atomic.AddInt64(&h.stats.activeConns, 1)
	defer atomic.AddInt64(&h.stats.activeConns, -1)

	if h.metrics != nil {
		h.metrics.IncConnections()
		defer h.metrics.DecConnections()
	}

	clientAddr := clientConn.RemoteAddr().String()
	h.log(LogLevelDebug, "TCP 新连接: %s", clientAddr)
	defer h.log(LogLevelDebug, "TCP 连接关闭: %s", clientAddr)

	reader := transport.NewFrameReader(clientConn, transport.ReadTimeout)
	writer := transport.NewFrameWriter(clientConn, transport.WriteTimeout)

	h.tcpMainLoop(ctx, clientConn, reader, writer, clientAddr)
}

func (h *UnifiedHandler) tcpMainLoop(
	ctx context.Context,
	clientConn net.Conn,
	reader *transport.FrameReader,
	writer *transport.FrameWriter,
	clientAddr string,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.ctx.Done():
			return
		default:
		}

		encryptedFrame, err := reader.ReadFrame()
		if err != nil {
			if err != io.EOF {
				h.log(LogLevelDebug, "读取帧失败: %s - %v", clientAddr, err)
			}
			return
		}

		plaintext, err := h.crypto.Decrypt(encryptedFrame)
		if err != nil {
			atomic.AddUint64(&h.stats.decryptErrors, 1)
			h.log(LogLevelDebug, "解密失败: %s - %v", clientAddr, err)
			return
		}

		req, err := protocol.ParseRequest(plaintext)
		if err != nil {
			h.log(LogLevelDebug, "解析请求失败: %s - %v", clientAddr, err)
			continue
		}

		switch req.Type {
		case protocol.TypeConnect:
			h.handleTCPConnect(ctx, req, clientConn, reader, writer)
			return

		case protocol.TypeData:
			h.log(LogLevelDebug, "收到孤立的 Data 请求: %s", clientAddr)
			continue

		case protocol.TypeClose:
			h.log(LogLevelDebug, "收到 Close 请求: %s", clientAddr)
			return

		case protocol.TypeHeartbeat:
			atomic.AddUint64(&h.stats.heartbeatsRecv, 1)
			h.sendTCPResponse(writer, req.ReqID, protocol.TypeHeartbeat, nil)

		default:
			h.log(LogLevelDebug, "未知请求类型: 0x%02X", req.Type)
		}
	}
}

func (h *UnifiedHandler) handleTCPConnect(
	ctx context.Context,
	req *protocol.Request,
	clientConn net.Conn,
	reader *transport.FrameReader,
	writer *transport.FrameWriter,
) {
	network := req.NetworkString()
	target := req.TargetAddr()

	h.log(LogLevelInfo, "TCP Connect: %s %s (ID:%d)", network, target, req.ReqID)

	targetConn, err := net.DialTimeout(network, target, connectTimeout)
	if err != nil {
		h.log(LogLevelDebug, "连接目标失败: %s - %v", target, err)
		_ = h.sendTCPResponse(writer, req.ReqID, StatusError, nil)
		return
	}
	defer targetConn.Close()

	h.configureTCPConnection(targetConn)

	if len(req.Data) > 0 {
		_ = targetConn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := targetConn.Write(req.Data); err != nil {
			h.log(LogLevelDebug, "发送初始数据失败: %v", err)
			_ = h.sendTCPResponse(writer, req.ReqID, StatusError, nil)
			return
		}
	}

	if err := h.sendTCPResponse(writer, req.ReqID, StatusOK, nil); err != nil {
		h.log(LogLevelDebug, "发送响应失败: %v", err)
		return
	}

	h.log(LogLevelInfo, "TCP 代理建立: %s %s", network, target)

	h.tcpBidirectionalProxy(ctx, req.ReqID, clientConn, targetConn, reader, writer)
}

func (h *UnifiedHandler) tcpBidirectionalProxy(
	ctx context.Context,
	reqID uint32,
	clientConn net.Conn,
	targetConn net.Conn,
	reader *transport.FrameReader,
	writer *transport.FrameWriter,
) {
	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		h.tcpClientToTarget(proxyCtx, reqID, targetConn, reader)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		h.tcpTargetToClient(proxyCtx, reqID, targetConn, writer)
	}()

	wg.Wait()
	h.log(LogLevelInfo, "TCP 代理结束: ID:%d", reqID)
}

func (h *UnifiedHandler) tcpClientToTarget(
	ctx context.Context,
	reqID uint32,
	targetConn net.Conn,
	reader *transport.FrameReader,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		encryptedFrame, err := reader.ReadFrame()
		if err != nil {
			if err != io.EOF {
				h.log(LogLevelDebug, "读取客户端失败: ID:%d - %v", reqID, err)
			}
			return
		}

		plaintext, err := h.crypto.Decrypt(encryptedFrame)
		if err != nil {
			atomic.AddUint64(&h.stats.decryptErrors, 1)
			h.log(LogLevelDebug, "解密失败: ID:%d - %v", reqID, err)
			return
		}

		req, err := protocol.ParseRequest(plaintext)
		if err != nil {
			h.log(LogLevelDebug, "解析失败: ID:%d - %v", reqID, err)
			continue
		}

		switch req.Type {
		case protocol.TypeData:
			if len(req.Data) > 0 {
				_ = targetConn.SetWriteDeadline(time.Now().Add(writeTimeout))
				if n, err := targetConn.Write(req.Data); err != nil {
					h.log(LogLevelDebug, "写入目标失败: ID:%d - %v", reqID, err)
					return
				} else if h.metrics != nil {
					h.metrics.AddBytesSent(int64(n))
				}
			}

		case protocol.TypeClose:
			h.log(LogLevelDebug, "客户端主动关闭: ID:%d", reqID)
			return
		}
	}
}

func (h *UnifiedHandler) tcpTargetToClient(
	ctx context.Context,
	reqID uint32,
	targetConn net.Conn,
	writer *transport.FrameWriter,
) {
	buf := make([]byte, readBufferSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = targetConn.SetReadDeadline(time.Now().Add(transport.ReadTimeout))

		n, err := targetConn.Read(buf)
		if err != nil {
			if err != io.EOF {
				h.log(LogLevelDebug, "读取目标失败: ID:%d - %v", reqID, err)
			}
			_ = h.sendTCPResponse(writer, reqID, protocol.TypeClose, nil)
			return
		}

		if h.metrics != nil {
			h.metrics.AddBytesReceived(int64(n))
		}

		if err := h.sendTCPResponse(writer, reqID, protocol.TypeData, buf[:n]); err != nil {
			h.log(LogLevelDebug, "发送到客户端失败: ID:%d - %v", reqID, err)
			return
		}
	}
}

func (h *UnifiedHandler) sendTCPResponse(writer *transport.FrameWriter, reqID uint32, status byte, data []byte) error {
	resp := protocol.BuildResponse(reqID, status, data)

	encrypted, err := h.crypto.Encrypt(resp)
	if err != nil {
		return fmt.Errorf("加密失败: %w", err)
	}

	if err := writer.WriteFrame(encrypted); err != nil {
		return err
	}

	if h.metrics != nil {
		h.metrics.AddBytesSent(int64(len(encrypted)))
	}

	return nil
}

// =============================================================================
// 连接管理
// =============================================================================

func (h *UnifiedHandler) getConnection(reqID uint32) *ProxyConnection {
	if v, ok := h.connections.Load(reqID); ok {
		return v.(*ProxyConnection)
	}
	return nil
}

func (h *UnifiedHandler) closeConnection(reqID uint32) {
	v, ok := h.connections.LoadAndDelete(reqID)
	if !ok {
		return
	}

	conn := v.(*ProxyConnection)

	if !atomic.CompareAndSwapInt32(&conn.closed, 0, 1) {
		return
	}

	if conn.Target != nil {
		_ = conn.Target.Close()
	}

	// 关闭响应通道
	if conn.responseChan != nil {
		close(conn.responseChan)
	}

	atomic.AddInt64(&h.stats.activeConns, -1)

	if h.metrics != nil {
		h.metrics.DecConnections()
	}

	h.log(LogLevelInfo, "连接关闭: ID:%d %s (sent:%d recv:%d duration:%s)",
		reqID, conn.TargetAddr, conn.BytesSent, conn.BytesRecv,
		time.Since(conn.CreatedAt).Round(time.Second))
}

func (h *UnifiedHandler) writeToTarget(conn *ProxyConnection, data []byte) error {
	_ = conn.Target.SetWriteDeadline(time.Now().Add(writeTimeout))

	n, err := conn.Target.Write(data)
	if err != nil {
		return err
	}

	atomic.AddUint64(&conn.BytesSent, uint64(n))
	atomic.AddUint64(&h.stats.totalBytes, uint64(n))

	if h.metrics != nil {
		h.metrics.AddBytesSent(int64(n))
	}

	return nil
}

func (h *UnifiedHandler) configureTCPConnection(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
}

// =============================================================================
// 会话管理
// =============================================================================

func (h *UnifiedHandler) updateSession(addr *net.UDPAddr, connID uint32) {
	key := addr.String()

	v, _ := h.sessions.LoadOrStore(key, &ClientSession{
		Addr:       addr,
		LastActive: time.Now(),
		ConnIDs:    make([]uint32, 0, 4),
	})

	session := v.(*ClientSession)
	session.mu.Lock()
	defer session.mu.Unlock()

	session.LastActive = time.Now()

	for _, id := range session.ConnIDs {
		if id == connID {
			return
		}
	}
	session.ConnIDs = append(session.ConnIDs, connID)
}

// =============================================================================
// 后台清理
// =============================================================================

func (h *UnifiedHandler) cleanupLoop() {
	ticker := time.NewTicker(connCleanupPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.cleanup()
		}
	}
}

func (h *UnifiedHandler) cleanup() {
	now := time.Now()
	cleanedConns := 0
	cleanedSessions := 0

	h.connections.Range(func(key, value interface{}) bool {
		conn := value.(*ProxyConnection)
		conn.mu.Lock()
		idle := now.Sub(conn.LastActive)
		conn.mu.Unlock()

		if idle > connIdleTimeout {
			h.closeConnection(key.(uint32))
			cleanedConns++
		}
		return true
	})

	h.sessions.Range(func(key, value interface{}) bool {
		session := value.(*ClientSession)
		session.mu.Lock()
		idle := now.Sub(session.LastActive)
		session.mu.Unlock()

		if idle > sessionIdleTimeout {
			h.sessions.Delete(key)
			cleanedSessions++
		}
		return true
	})

	if cleanedConns > 0 || cleanedSessions > 0 {
		h.log(LogLevelDebug, "清理完成: 连接=%d 会话=%d", cleanedConns, cleanedSessions)
	}
}

// =============================================================================
// 辅助函数
// =============================================================================

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// 日志
// =============================================================================

func (h *UnifiedHandler) log(level int, format string, args ...interface{}) {
	if level > h.logLevel {
		return
	}

	prefix := ""
	switch level {
	case LogLevelError:
		prefix = "[ERROR]"
	case LogLevelInfo:
		prefix = "[INFO]"
	case LogLevelDebug:
		prefix = "[DEBUG]"
	}

	fmt.Printf("%s %s [Handler] %s\n",
		prefix,
		time.Now().Format("15:04:05"),
		fmt.Sprintf(format, args...))
}
