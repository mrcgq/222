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

type Sender func(data []byte, addr *net.UDPAddr) error

type UnifiedHandler struct {
	crypto  *crypto.Crypto
	cfg     *config.Config
	metrics *metrics.PhantomMetrics

	logLevel int

	connections sync.Map
	sessions    sync.Map

	sender Sender

	stats handlerStats

	ctx    context.Context
	cancel context.CancelFunc
}

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
}

type ClientSession struct {
	Addr       *net.UDPAddr
	LastActive time.Time
	ConnIDs    []uint32
	mu         sync.Mutex
}

// 修复：添加实际统计字段
type handlerStats struct {
	totalConns     uint64
	activeConns    int64
	totalBytes     uint64
	authFailures   uint64 // 认证失败次数
	replayBlocked  uint64 // 重放攻击拦截次数
	decryptErrors  uint64 // 解密错误次数
	heartbeatsRecv uint64 // 收到的心跳数
}

// =============================================================================
// 构造函数
// =============================================================================

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

func (h *UnifiedHandler) SetMetrics(m *metrics.PhantomMetrics) {
	h.metrics = m
}

func (h *UnifiedHandler) SetSender(fn Sender) {
	h.sender = fn
}

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
// 修复：返回实际的统计数据
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
// UDP 数据包处理
// =============================================================================

func (h *UnifiedHandler) HandlePacket(data []byte, from *net.UDPAddr) []byte {
	// 1. 解密数据
	plaintext, err := h.crypto.Decrypt(data)
	if err != nil {
		// 修复：记录解密失败统计
		atomic.AddUint64(&h.stats.decryptErrors, 1)
		
		// 区分不同的错误类型
		errStr := err.Error()
		if contains(errStr, "UserID") {
			atomic.AddUint64(&h.stats.authFailures, 1)
		} else if contains(errStr, "重放") || contains(errStr, "replay") {
			atomic.AddUint64(&h.stats.replayBlocked, 1)
		}
		
		h.log(LogLevelDebug, "解密失败: %v", err)
		return nil
	}

	// 2. 解析协议请求
	req, err := protocol.ParseRequest(plaintext)
	if err != nil {
		h.log(LogLevelDebug, "解析请求失败: %v", err)
		return nil
	}

	// 3. 更新会话信息
	h.updateSession(from, req.ReqID)

	// 4. 根据请求类型分发处理
	switch req.Type {
	case protocol.TypeConnect:
		h.handleUDPConnect(req, from)

	case protocol.TypeData:
		h.handleUDPData(req, from)

	case protocol.TypeClose:
		h.handleUDPClose(req)

	case protocol.TypeHeartbeat:
		// 修复：正确处理心跳包并记录统计
		atomic.AddUint64(&h.stats.heartbeatsRecv, 1)
		h.handleUDPHeartbeat(req, from)

	default:
		h.log(LogLevelDebug, "未知请求类型: 0x%02X", req.Type)
	}

	return nil
}

// handleUDPHeartbeat 处理心跳包
func (h *UnifiedHandler) handleUDPHeartbeat(req *protocol.Request, from *net.UDPAddr) {
	h.log(LogLevelDebug, "收到心跳: ID:%d from %s", req.ReqID, from.String())
	
	// 发送心跳响应
	resp := protocol.BuildHeartbeatResponse(req.ReqID)
	encrypted, err := h.crypto.Encrypt(resp)
	if err != nil {
		h.log(LogLevelError, "加密心跳响应失败: %v", err)
		return
	}
	
	if h.sender != nil {
		h.sender(encrypted, from)
	}
}

func (h *UnifiedHandler) handleUDPConnect(req *protocol.Request, from *net.UDPAddr) {
	network := req.NetworkString()
	target := req.TargetAddr()

	h.log(LogLevelInfo, "UDP Connect: %s %s (ID:%d) from %s",
		network, target, req.ReqID, from.String())

	targetConn, err := net.DialTimeout(network, target, connectTimeout)
	if err != nil {
		h.log(LogLevelDebug, "连接目标失败: %s - %v", target, err)
		h.sendUDPResponse(req.ReqID, StatusError, nil, from)
		return
	}

	h.configureTCPConnection(targetConn)

	conn := &ProxyConnection{
		ID:         req.ReqID,
		Target:     targetConn,
		ClientAddr: from,
		Network:    network,
		TargetAddr: target,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
	}

	h.connections.Store(req.ReqID, conn)
	atomic.AddUint64(&h.stats.totalConns, 1)
	atomic.AddInt64(&h.stats.activeConns, 1)

	if h.metrics != nil {
		h.metrics.IncConnections()
	}

	if len(req.Data) > 0 {
		if err := h.writeToTarget(conn, req.Data); err != nil {
			h.log(LogLevelDebug, "发送初始数据失败: %v", err)
		}
	}

	h.sendUDPResponse(req.ReqID, StatusOK, nil, from)

	go h.udpReadLoop(conn)
}

func (h *UnifiedHandler) handleUDPData(req *protocol.Request, from *net.UDPAddr) {
	conn := h.getConnection(req.ReqID)
	if conn == nil {
		h.log(LogLevelDebug, "连接不存在: ID:%d", req.ReqID)
		return
	}

	conn.mu.Lock()
	conn.LastActive = time.Now()
	conn.ClientAddr = from
	conn.mu.Unlock()

	if len(req.Data) > 0 {
		if err := h.writeToTarget(conn, req.Data); err != nil {
			h.log(LogLevelDebug, "写入目标失败: ID:%d - %v", req.ReqID, err)
			h.closeConnection(req.ReqID)
		}
	}
}

func (h *UnifiedHandler) handleUDPClose(req *protocol.Request) {
	h.log(LogLevelInfo, "UDP Close: ID:%d", req.ReqID)
	h.closeConnection(req.ReqID)
}

func (h *UnifiedHandler) udpReadLoop(conn *ProxyConnection) {
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
		conn.mu.Unlock()

		atomic.AddUint64(&conn.BytesRecv, uint64(n))
		atomic.AddUint64(&h.stats.totalBytes, uint64(n))

		if h.metrics != nil {
			h.metrics.AddBytesReceived(int64(n))
		}

		h.sendUDPResponse(conn.ID, protocol.TypeData, buf[:n], clientAddr)
	}
}

func (h *UnifiedHandler) sendUDPResponse(reqID uint32, status byte, data []byte, to *net.UDPAddr) {
	if h.sender == nil {
		h.log(LogLevelError, "Sender 未设置，无法发送响应")
		return
	}

	resp := protocol.BuildResponse(reqID, status, data)

	encrypted, err := h.crypto.Encrypt(resp)
	if err != nil {
		h.log(LogLevelError, "加密响应失败: %v", err)
		return
	}

	if err := h.sender(encrypted, to); err != nil {
		h.log(LogLevelDebug, "发送响应失败: %v", err)
	} else if h.metrics != nil {
		h.metrics.AddBytesSent(int64(len(encrypted)))
	}
}

// =============================================================================
// TCP 连接处理
// =============================================================================

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
			// 修复：记录解密失败统计
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
			// 修复：处理 TCP 心跳
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
