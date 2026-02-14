// =============================================================================
// 文件: internal/handler/unified_handler.go
// 描述: 统一处理器 - 用户态核心处理中心，负责解析数据包并驱动代理逻辑
// 职责:
//   - 解析所有通过传输层上报的数据包
//   - 管理代理连接的生命周期
//   - 实现 Connect/Data/Close 指令处理
//   - 异步反馈数据给传输层
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

// 日志级别
const (
	LogLevelError = iota
	LogLevelInfo
	LogLevelDebug
)

// 响应状态码 (本地定义，避免依赖 protocol 包的常量)
const (
	StatusOK    byte = 0x00 // 成功
	StatusError byte = 0x01 // 错误
)

// 超时配置
const (
	connectTimeout     = 10 * time.Second  // 连接目标超时
	writeTimeout       = 30 * time.Second  // 写入超时
	readTimeout        = 5 * time.Minute   // 读取超时（空闲）
	connCleanupPeriod  = 30 * time.Second  // 连接清理周期
	connIdleTimeout    = 5 * time.Minute   // 连接空闲超时
	sessionIdleTimeout = 10 * time.Minute  // 会话空闲超时
	readBufferSize     = 32 * 1024         // 读取缓冲区大小
)

// =============================================================================
// 类型定义
// =============================================================================

// Sender 数据发送回调函数类型
type Sender func(data []byte, addr *net.UDPAddr) error

// UnifiedHandler 统一处理器 - 用户态核心处理中心
type UnifiedHandler struct {
	// 依赖注入
	crypto  *crypto.Crypto          // 加密器
	cfg     *config.Config          // 配置
	metrics *metrics.PhantomMetrics // 指标收集器

	// 日志配置
	logLevel int

	// 连接管理 - 使用 sync.Map 实现并发安全
	connections sync.Map // reqID(uint32) -> *ProxyConnection
	sessions    sync.Map // clientAddr(string) -> *ClientSession

	// 发送回调（由传输层设置）
	sender Sender

	// 统计信息
	stats handlerStats

	// 生命周期控制
	ctx    context.Context
	cancel context.CancelFunc
}

// ProxyConnection 代理连接 - 维护 reqID 到目标连接的映射
type ProxyConnection struct {
	ID         uint32       // 请求ID
	Target     net.Conn     // 目标服务器连接
	ClientAddr *net.UDPAddr // 客户端地址（UDP模式）
	Network    string       // 网络类型 (tcp/udp)
	TargetAddr string       // 目标地址
	CreatedAt  time.Time    // 创建时间
	LastActive time.Time    // 最后活跃时间
	BytesSent  uint64       // 发送字节数
	BytesRecv  uint64       // 接收字节数
	closed     int32        // 关闭标志
	mu         sync.Mutex   // 保护 LastActive 和 ClientAddr
}

// ClientSession 客户端会话
type ClientSession struct {
	Addr       *net.UDPAddr // 客户端地址
	LastActive time.Time    // 最后活跃时间
	ConnIDs    []uint32     // 关联的连接ID列表
	mu         sync.Mutex   // 保护会话状态
}

// handlerStats 处理器统计信息
type handlerStats struct {
	totalConns  uint64 // 总连接数
	activeConns int64  // 活跃连接数
	totalBytes  uint64 // 总传输字节数
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

	// 启动后台清理协程
	go h.cleanupLoop()

	return h
}

// parseLogLevel 解析日志级别
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

// SetSender 设置数据发送回调（由传输层调用）
func (h *UnifiedHandler) SetSender(fn Sender) {
	h.sender = fn
}

// Close 关闭处理器
func (h *UnifiedHandler) Close() error {
	h.cancel()

	// 关闭所有活跃连接
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
		"total_conns":  atomic.LoadUint64(&h.stats.totalConns),
		"active_conns": atomic.LoadInt64(&h.stats.activeConns),
		"total_bytes":  atomic.LoadUint64(&h.stats.totalBytes),
	}
}

// GetActiveConns 获取活跃连接数
func (h *UnifiedHandler) GetActiveConns() int64 {
	return atomic.LoadInt64(&h.stats.activeConns)
}

// =============================================================================
// UDP 数据包处理（实现 PacketHandler 接口）
// =============================================================================

// HandlePacket 处理 UDP 数据包
// 实现传输层的 PacketHandler 接口
func (h *UnifiedHandler) HandlePacket(data []byte, from *net.UDPAddr) []byte {
	// 1. 解密数据
	plaintext, err := h.crypto.Decrypt(data)
	if err != nil {
		h.log(LogLevelDebug, "解密失败: %v", err)
		return nil // 静默丢弃无效数据包
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

	default:
		h.log(LogLevelDebug, "未知请求类型: 0x%02X", req.Type)
	}

	// 响应通过 sender 异步发送，此处返回 nil
	return nil
}

// handleUDPConnect 处理 UDP Connect 请求
func (h *UnifiedHandler) handleUDPConnect(req *protocol.Request, from *net.UDPAddr) {
	network := req.NetworkString()
	target := req.TargetAddr()

	h.log(LogLevelInfo, "UDP Connect: %s %s (ID:%d) from %s",
		network, target, req.ReqID, from.String())

	// 建立到目标服务器的连接
	targetConn, err := net.DialTimeout(network, target, connectTimeout)
	if err != nil {
		h.log(LogLevelDebug, "连接目标失败: %s - %v", target, err)
		h.sendUDPResponse(req.ReqID, StatusError, nil, from)
		return
	}

	// 配置 TCP 连接选项
	h.configureTCPConnection(targetConn)

	// 创建代理连接
	conn := &ProxyConnection{
		ID:         req.ReqID,
		Target:     targetConn,
		ClientAddr: from,
		Network:    network,
		TargetAddr: target,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
	}

	// 存储连接映射
	h.connections.Store(req.ReqID, conn)
	atomic.AddUint64(&h.stats.totalConns, 1)
	atomic.AddInt64(&h.stats.activeConns, 1)

	// 更新指标
	if h.metrics != nil {
		h.metrics.IncConnections()
	}

	// 发送初始数据（如果有）
	if len(req.Data) > 0 {
		if err := h.writeToTarget(conn, req.Data); err != nil {
			h.log(LogLevelDebug, "发送初始数据失败: %v", err)
			// 继续处理，不关闭连接
		}
	}

	// 发送成功响应
	h.sendUDPResponse(req.ReqID, StatusOK, nil, from)

	// 启动异步读取循环
	go h.udpReadLoop(conn)
}

// handleUDPData 处理 UDP Data 请求
func (h *UnifiedHandler) handleUDPData(req *protocol.Request, from *net.UDPAddr) {
	// 查找连接
	conn := h.getConnection(req.ReqID)
	if conn == nil {
		h.log(LogLevelDebug, "连接不存在: ID:%d", req.ReqID)
		return
	}

	// 更新活跃时间和客户端地址（可能因NAT变化）
	conn.mu.Lock()
	conn.LastActive = time.Now()
	conn.ClientAddr = from
	conn.mu.Unlock()

	// 转发数据到目标服务器
	if len(req.Data) > 0 {
		if err := h.writeToTarget(conn, req.Data); err != nil {
			h.log(LogLevelDebug, "写入目标失败: ID:%d - %v", req.ReqID, err)
			h.closeConnection(req.ReqID)
		}
	}
}

// handleUDPClose 处理 UDP Close 请求
func (h *UnifiedHandler) handleUDPClose(req *protocol.Request) {
	h.log(LogLevelInfo, "UDP Close: ID:%d", req.ReqID)
	h.closeConnection(req.ReqID)
}

// udpReadLoop UDP模式下从目标服务器读取数据并回传
func (h *UnifiedHandler) udpReadLoop(conn *ProxyConnection) {
	defer h.closeConnection(conn.ID)

	buf := make([]byte, readBufferSize)

	for {
		// 检查连接是否已关闭
		if atomic.LoadInt32(&conn.closed) != 0 {
			return
		}

		// 设置读取超时
		_ = conn.Target.SetReadDeadline(time.Now().Add(readTimeout))

		// 从目标读取数据
		n, err := conn.Target.Read(buf)
		if err != nil {
			if err != io.EOF {
				h.log(LogLevelDebug, "读取目标结束: ID:%d - %v", conn.ID, err)
			}
			return
		}

		// 更新统计和活跃时间
		conn.mu.Lock()
		conn.LastActive = time.Now()
		clientAddr := conn.ClientAddr
		conn.mu.Unlock()

		atomic.AddUint64(&conn.BytesRecv, uint64(n))
		atomic.AddUint64(&h.stats.totalBytes, uint64(n))

		// 更新指标
		if h.metrics != nil {
			h.metrics.AddBytesReceived(int64(n))
		}

		// 发送响应到客户端
		h.sendUDPResponse(conn.ID, protocol.TypeData, buf[:n], clientAddr)
	}
}

// sendUDPResponse 发送 UDP 响应
func (h *UnifiedHandler) sendUDPResponse(reqID uint32, status byte, data []byte, to *net.UDPAddr) {
	if h.sender == nil {
		h.log(LogLevelError, "Sender 未设置，无法发送响应")
		return
	}

	// 构建响应
	resp := protocol.BuildResponse(reqID, status, data)

	// 加密
	encrypted, err := h.crypto.Encrypt(resp)
	if err != nil {
		h.log(LogLevelError, "加密响应失败: %v", err)
		return
	}

	// 通过传输层发送
	if err := h.sender(encrypted, to); err != nil {
		h.log(LogLevelDebug, "发送响应失败: %v", err)
	} else if h.metrics != nil {
		h.metrics.AddBytesSent(int64(len(encrypted)))
	}
}

// =============================================================================
// TCP 连接处理（实现 TCPConnectionHandler 接口）
// =============================================================================

// HandleConnection 处理一个 TCP 客户端连接
func (h *UnifiedHandler) HandleConnection(ctx context.Context, clientConn net.Conn) {
	atomic.AddInt64(&h.stats.activeConns, 1)
	defer atomic.AddInt64(&h.stats.activeConns, -1)

	// 更新指标
	if h.metrics != nil {
		h.metrics.IncConnections()
		defer h.metrics.DecConnections()
	}

	clientAddr := clientConn.RemoteAddr().String()
	h.log(LogLevelDebug, "TCP 新连接: %s", clientAddr)
	defer h.log(LogLevelDebug, "TCP 连接关闭: %s", clientAddr)

	// 创建帧读写器
	reader := transport.NewFrameReader(clientConn, transport.ReadTimeout)
	writer := transport.NewFrameWriter(clientConn, transport.WriteTimeout)

	// 主处理循环
	h.tcpMainLoop(ctx, clientConn, reader, writer, clientAddr)
}

// tcpMainLoop TCP 主处理循环
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

		// 读取加密帧
		encryptedFrame, err := reader.ReadFrame()
		if err != nil {
			if err != io.EOF {
				h.log(LogLevelDebug, "读取帧失败: %s - %v", clientAddr, err)
			}
			return
		}

		// 解密
		plaintext, err := h.crypto.Decrypt(encryptedFrame)
		if err != nil {
			h.log(LogLevelDebug, "解密失败: %s - %v", clientAddr, err)
			return
		}

		// 解析请求
		req, err := protocol.ParseRequest(plaintext)
		if err != nil {
			h.log(LogLevelDebug, "解析请求失败: %s - %v", clientAddr, err)
			continue
		}

		// 处理请求
		switch req.Type {
		case protocol.TypeConnect:
			// Connect 请求后进入代理模式
			h.handleTCPConnect(ctx, req, clientConn, reader, writer)
			return

		case protocol.TypeData:
			h.log(LogLevelDebug, "收到孤立的 Data 请求: %s", clientAddr)
			continue

		case protocol.TypeClose:
			h.log(LogLevelDebug, "收到 Close 请求: %s", clientAddr)
			return

		default:
			h.log(LogLevelDebug, "未知请求类型: 0x%02X", req.Type)
		}
	}
}

// handleTCPConnect 处理 TCP Connect 请求
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

	// 连接目标服务器
	targetConn, err := net.DialTimeout(network, target, connectTimeout)
	if err != nil {
		h.log(LogLevelDebug, "连接目标失败: %s - %v", target, err)
		_ = h.sendTCPResponse(writer, req.ReqID, StatusError, nil)
		return
	}
	defer targetConn.Close()

	// 配置 TCP 连接
	h.configureTCPConnection(targetConn)

	// 发送初始数据（如果有）
	if len(req.Data) > 0 {
		_ = targetConn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := targetConn.Write(req.Data); err != nil {
			h.log(LogLevelDebug, "发送初始数据失败: %v", err)
			_ = h.sendTCPResponse(writer, req.ReqID, StatusError, nil)
			return
		}
	}

	// 发送成功响应
	if err := h.sendTCPResponse(writer, req.ReqID, StatusOK, nil); err != nil {
		h.log(LogLevelDebug, "发送响应失败: %v", err)
		return
	}

	h.log(LogLevelInfo, "TCP 代理建立: %s %s", network, target)

	// 进入双向代理模式
	h.tcpBidirectionalProxy(ctx, req.ReqID, clientConn, targetConn, reader, writer)
}

// tcpBidirectionalProxy TCP 双向代理
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

	// 客户端 -> 目标
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		h.tcpClientToTarget(proxyCtx, reqID, targetConn, reader)
	}()

	// 目标 -> 客户端
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		h.tcpTargetToClient(proxyCtx, reqID, targetConn, writer)
	}()

	wg.Wait()
	h.log(LogLevelInfo, "TCP 代理结束: ID:%d", reqID)
}

// tcpClientToTarget 客户端到目标的数据转发
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

		// 读取加密帧
		encryptedFrame, err := reader.ReadFrame()
		if err != nil {
			if err != io.EOF {
				h.log(LogLevelDebug, "读取客户端失败: ID:%d - %v", reqID, err)
			}
			return
		}

		// 解密
		plaintext, err := h.crypto.Decrypt(encryptedFrame)
		if err != nil {
			h.log(LogLevelDebug, "解密失败: ID:%d - %v", reqID, err)
			return
		}

		// 解析请求
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

// tcpTargetToClient 目标到客户端的数据转发
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

		// 设置读取超时
		_ = targetConn.SetReadDeadline(time.Now().Add(transport.ReadTimeout))

		// 从目标读取
		n, err := targetConn.Read(buf)
		if err != nil {
			if err != io.EOF {
				h.log(LogLevelDebug, "读取目标失败: ID:%d - %v", reqID, err)
			}
			// 发送关闭通知
			_ = h.sendTCPResponse(writer, reqID, protocol.TypeClose, nil)
			return
		}

		// 更新指标
		if h.metrics != nil {
			h.metrics.AddBytesReceived(int64(n))
		}

		// 发送到客户端
		if err := h.sendTCPResponse(writer, reqID, protocol.TypeData, buf[:n]); err != nil {
			h.log(LogLevelDebug, "发送到客户端失败: ID:%d - %v", reqID, err)
			return
		}
	}
}

// sendTCPResponse 发送 TCP 响应
func (h *UnifiedHandler) sendTCPResponse(writer *transport.FrameWriter, reqID uint32, status byte, data []byte) error {
	// 构建响应
	resp := protocol.BuildResponse(reqID, status, data)

	// 加密
	encrypted, err := h.crypto.Encrypt(resp)
	if err != nil {
		return fmt.Errorf("加密失败: %w", err)
	}

	// 发送帧
	if err := writer.WriteFrame(encrypted); err != nil {
		return err
	}

	// 更新指标
	if h.metrics != nil {
		h.metrics.AddBytesSent(int64(len(encrypted)))
	}

	return nil
}

// =============================================================================
// 连接管理
// =============================================================================

// getConnection 获取连接
func (h *UnifiedHandler) getConnection(reqID uint32) *ProxyConnection {
	if v, ok := h.connections.Load(reqID); ok {
		return v.(*ProxyConnection)
	}
	return nil
}

// closeConnection 关闭连接
func (h *UnifiedHandler) closeConnection(reqID uint32) {
	v, ok := h.connections.LoadAndDelete(reqID)
	if !ok {
		return
	}

	conn := v.(*ProxyConnection)

	// 设置关闭标志（防止重复关闭）
	if !atomic.CompareAndSwapInt32(&conn.closed, 0, 1) {
		return
	}

	// 关闭目标连接
	if conn.Target != nil {
		_ = conn.Target.Close()
	}

	// 更新统计
	atomic.AddInt64(&h.stats.activeConns, -1)

	// 更新指标
	if h.metrics != nil {
		h.metrics.DecConnections()
	}

	h.log(LogLevelInfo, "连接关闭: ID:%d %s (sent:%d recv:%d duration:%s)",
		reqID, conn.TargetAddr, conn.BytesSent, conn.BytesRecv,
		time.Since(conn.CreatedAt).Round(time.Second))
}

// writeToTarget 写入数据到目标服务器
func (h *UnifiedHandler) writeToTarget(conn *ProxyConnection, data []byte) error {
	_ = conn.Target.SetWriteDeadline(time.Now().Add(writeTimeout))

	n, err := conn.Target.Write(data)
	if err != nil {
		return err
	}

	atomic.AddUint64(&conn.BytesSent, uint64(n))
	atomic.AddUint64(&h.stats.totalBytes, uint64(n))

	// 更新指标
	if h.metrics != nil {
		h.metrics.AddBytesSent(int64(n))
	}

	return nil
}

// configureTCPConnection 配置 TCP 连接选项
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

// updateSession 更新客户端会话
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

	// 添加连接 ID（去重）
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

// cleanupLoop 定期清理过期连接和会话
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

// cleanup 执行清理
func (h *UnifiedHandler) cleanup() {
	now := time.Now()
	cleanedConns := 0
	cleanedSessions := 0

	// 清理超时连接
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

	// 清理超时会话
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
// 日志
// =============================================================================

// log 输出日志
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
