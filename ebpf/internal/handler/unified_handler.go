


// =============================================================================
// 文件: internal/handler/unified_handler.go
// 描述: 统一处理器 - 整合 UDP 和 TCP 所有传输模式
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
	"github.com/mrcgq/211/internal/protocol"
	"github.com/mrcgq/211/internal/transport"
)

// 日志级别常量
const (
	logError = 0
	logInfo  = 1
	logDebug = 2
)

// UnifiedHandler 统一处理器
type UnifiedHandler struct {
	crypto   *crypto.Crypto
	cfg      *config.Config
	logLevel int

	// 连接管理
	conns    sync.Map // reqID -> *Connection
	sessions sync.Map // clientAddr -> *Session

	// 发送回调 (由 Switcher 设置)
	sender func(data []byte, addr *net.UDPAddr) error

	// 统计
	totalConns  uint64
	activeConns int64
	totalBytes  uint64
}

// Connection 代理连接
type Connection struct {
	ID         uint32
	Target     net.Conn
	ClientAddr *net.UDPAddr
	Network    string
	CreatedAt  time.Time
	LastActive time.Time
	BytesSent  uint64
	BytesRecv  uint64
	mu         sync.Mutex
}

// Session 客户端会话
type Session struct {
	Addr       *net.UDPAddr
	LastActive time.Time
	ConnIDs    []uint32
	mu         sync.Mutex
}

// NewUnifiedHandler 创建统一处理器
func NewUnifiedHandler(c *crypto.Crypto, cfg *config.Config) *UnifiedHandler {
	level := logInfo
	switch cfg.LogLevel {
	case "debug":
		level = logDebug
	case "error":
		level = logError
	}

	h := &UnifiedHandler{
		crypto:   c,
		cfg:      cfg,
		logLevel: level,
	}

	// 启动清理协程
	go h.cleanupLoop()

	return h
}

// SetSender 设置发送函数
func (h *UnifiedHandler) SetSender(fn func(data []byte, addr *net.UDPAddr) error) {
	h.sender = fn
}

// =============================================================================
// UDP 数据包处理 (实现 PacketHandler 接口)
// =============================================================================

// HandlePacket 处理 UDP 数据包
func (h *UnifiedHandler) HandlePacket(data []byte, from *net.UDPAddr) []byte {
	// 解密
	plaintext, err := h.crypto.Decrypt(data)
	if err != nil {
		h.log(logDebug, "解密失败: %v", err)
		return nil // 静默丢弃
	}

	// 解析请求
	req, err := protocol.ParseRequest(plaintext)
	if err != nil {
		h.log(logDebug, "解析失败: %v", err)
		return nil
	}

	// 更新会话
	h.updateSession(from, req.ReqID)

	// 处理请求
	switch req.Type {
	case protocol.TypeConnect:
		h.handleConnect(req, from)
	case protocol.TypeData:
		h.handleData(req, from)
	case protocol.TypeClose:
		h.handleClose(req)
	}

	return nil // 响应通过 sender 异步发送
}

// handleConnect 处理连接请求
func (h *UnifiedHandler) handleConnect(req *protocol.Request, from *net.UDPAddr) {
	network := req.NetworkString()
	target := req.TargetAddr()

	h.log(logInfo, "连接: %s %s (ID:%d) from %s", network, target, req.ReqID, from.String())

	// 建立连接
	conn, err := net.DialTimeout(network, target, 10*time.Second)
	if err != nil {
		h.log(logDebug, "连接失败: %s - %v", target, err)
		h.sendResponse(req.ReqID, 0x01, nil, from)
		return
	}

	// 配置连接
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
	}

	// 保存连接
	c := &Connection{
		ID:         req.ReqID,
		Target:     conn,
		ClientAddr: from,
		Network:    network,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
	}
	h.conns.Store(req.ReqID, c)
	atomic.AddUint64(&h.totalConns, 1)
	atomic.AddInt64(&h.activeConns, 1)

	// 发送初始数据
	if len(req.Data) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := conn.Write(req.Data); err != nil {
			h.log(logDebug, "发送初始数据失败: %v", err)
		}
	}

	// 发送成功响应
	h.sendResponse(req.ReqID, 0x00, nil, from)

	// 启动读取循环
	go h.readLoop(c)
}

// handleData 处理数据请求
func (h *UnifiedHandler) handleData(req *protocol.Request, from *net.UDPAddr) {
	v, ok := h.conns.Load(req.ReqID)
	if !ok {
		return
	}

	c := v.(*Connection)
	c.mu.Lock()
	c.LastActive = time.Now()
	c.mu.Unlock()

	if len(req.Data) > 0 {
		_ = c.Target.SetWriteDeadline(time.Now().Add(30 * time.Second))
		n, err := c.Target.Write(req.Data)
		if err != nil {
			h.log(logDebug, "写入失败: ID:%d - %v", req.ReqID, err)
			h.closeConn(req.ReqID)
			return
		}
		atomic.AddUint64(&c.BytesSent, uint64(n))
		atomic.AddUint64(&h.totalBytes, uint64(n))
	}
}

// handleClose 处理关闭请求
func (h *UnifiedHandler) handleClose(req *protocol.Request) {
	h.closeConn(req.ReqID)
}

// readLoop 读取目标响应
func (h *UnifiedHandler) readLoop(c *Connection) {
	defer h.closeConn(c.ID)

	buf := make([]byte, 32*1024)

	for {
		_ = c.Target.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := c.Target.Read(buf)
		if err != nil {
			if err != io.EOF {
				h.log(logDebug, "读取结束: ID:%d - %v", c.ID, err)
			}
			return
		}

		c.mu.Lock()
		c.LastActive = time.Now()
		addr := c.ClientAddr
		c.mu.Unlock()

		atomic.AddUint64(&c.BytesRecv, uint64(n))
		atomic.AddUint64(&h.totalBytes, uint64(n))

		// 发送响应
		h.sendResponse(c.ID, protocol.TypeData, buf[:n], addr)
	}
}

// sendResponse 发送响应
func (h *UnifiedHandler) sendResponse(reqID uint32, status byte, data []byte, to *net.UDPAddr) {
	if h.sender == nil {
		h.log(logError, "sender 未设置")
		return
	}

	// 构建响应
	resp := protocol.BuildResponse(reqID, status, data)

	// 加密
	encrypted, err := h.crypto.Encrypt(resp)
	if err != nil {
		h.log(logError, "加密失败: %v", err)
		return
	}

	// 发送
	if err := h.sender(encrypted, to); err != nil {
		h.log(logDebug, "发送失败: %v", err)
	}
}

// =============================================================================
// TCP 连接处理 (实现 TCPConnectionHandler 接口)
// =============================================================================

// HandleConnection 处理一个 TCP 客户端连接
func (h *UnifiedHandler) HandleConnection(ctx context.Context, clientConn net.Conn) {
	atomic.AddInt64(&h.activeConns, 1)
	defer atomic.AddInt64(&h.activeConns, -1)

	clientAddr := clientConn.RemoteAddr().String()
	h.log(logDebug, "TCP 新连接: %s", clientAddr)
	defer h.log(logDebug, "TCP 连接关闭: %s", clientAddr)

	// 创建帧读写器
	reader := transport.NewFrameReader(clientConn, transport.ReadTimeout)
	writer := transport.NewFrameWriter(clientConn, transport.WriteTimeout)

	// 读取并处理请求
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
				h.log(logDebug, "读取帧失败: %s - %v", clientAddr, err)
			}
			return
		}

		// 解密
		plaintext, err := h.crypto.Decrypt(encryptedFrame)
		if err != nil {
			h.log(logDebug, "解密失败: %s - %v", clientAddr, err)
			return
		}

		// 解析请求
		req, err := protocol.ParseRequest(plaintext)
		if err != nil {
			h.log(logDebug, "解析请求失败: %s - %v", clientAddr, err)
			continue
		}

		// 处理请求
		switch req.Type {
		case protocol.TypeConnect:
			h.handleTCPConnect(ctx, req, clientConn, reader, writer)
			return

		case protocol.TypeData:
			h.log(logDebug, "收到孤立的 Data 请求: %s", clientAddr)
			continue

		case protocol.TypeClose:
			h.log(logDebug, "收到 Close 请求: %s", clientAddr)
			return
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

	h.log(logInfo, "TCP 连接: %s %s (ID:%d)", network, target, req.ReqID)

	// 连接目标服务器
	targetConn, err := net.DialTimeout(network, target, 10*time.Second)
	if err != nil {
		h.log(logDebug, "连接目标失败: %s - %v", target, err)
		h.sendTCPResponse(writer, req.ReqID, 0x01, nil)
		return
	}
	defer targetConn.Close()

	// 配置目标连接
	if tcpConn, ok := targetConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	// 如果有初始数据，发送到目标
	if len(req.Data) > 0 {
		_ = targetConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := targetConn.Write(req.Data); err != nil {
			h.log(logDebug, "发送初始数据失败: %v", err)
			h.sendTCPResponse(writer, req.ReqID, 0x01, nil)
			return
		}
	}

	// 发送成功响应
	if err := h.sendTCPResponse(writer, req.ReqID, 0x00, nil); err != nil {
		h.log(logDebug, "发送响应失败: %v", err)
		return
	}

	h.log(logInfo, "TCP 已建立: %s %s", network, target)

	// 开始双向代理
	h.tcpProxy(ctx, req.ReqID, clientConn, targetConn, reader, writer)
}

// tcpProxy TCP 双向代理
func (h *UnifiedHandler) tcpProxy(
	ctx context.Context,
	reqID uint32,
	clientConn net.Conn,
	targetConn net.Conn,
	reader *transport.FrameReader,
	writer *transport.FrameWriter,
) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	// 客户端 -> 目标
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		h.tcpClientToTarget(ctx, reqID, clientConn, targetConn, reader)
	}()

	// 目标 -> 客户端
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		h.tcpTargetToClient(ctx, reqID, targetConn, writer)
	}()

	wg.Wait()
	h.log(logInfo, "TCP 代理结束: ID:%d", reqID)
}

// tcpClientToTarget 客户端到目标的数据转发
func (h *UnifiedHandler) tcpClientToTarget(
	ctx context.Context,
	reqID uint32,
	clientConn net.Conn,
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
				h.log(logDebug, "读取客户端数据失败: ID:%d - %v", reqID, err)
			}
			return
		}

		// 解密
		plaintext, err := h.crypto.Decrypt(encryptedFrame)
		if err != nil {
			h.log(logDebug, "解密失败: ID:%d - %v", reqID, err)
			return
		}

		// 解析
		req, err := protocol.ParseRequest(plaintext)
		if err != nil {
			h.log(logDebug, "解析失败: ID:%d - %v", reqID, err)
			continue
		}

		switch req.Type {
		case protocol.TypeData:
			if len(req.Data) > 0 {
				_ = targetConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := targetConn.Write(req.Data); err != nil {
					h.log(logDebug, "写入目标失败: ID:%d - %v", reqID, err)
					return
				}
			}

		case protocol.TypeClose:
			h.log(logDebug, "客户端主动关闭: ID:%d", reqID)
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
	buf := make([]byte, 32*1024)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 从目标读取
		_ = targetConn.SetReadDeadline(time.Now().Add(transport.ReadTimeout))
		n, err := targetConn.Read(buf)
		if err != nil {
			if err != io.EOF {
				h.log(logDebug, "读取目标失败: ID:%d - %v", reqID, err)
			}
			// 发送关闭通知
			_ = h.sendTCPResponse(writer, reqID, protocol.TypeClose, nil)
			return
		}

		// 发送到客户端
		if err := h.sendTCPResponse(writer, reqID, protocol.TypeData, buf[:n]); err != nil {
			h.log(logDebug, "发送到客户端失败: ID:%d - %v", reqID, err)
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
	return writer.WriteFrame(encrypted)
}

// =============================================================================
// 通用方法
// =============================================================================

// updateSession 更新会话
func (h *UnifiedHandler) updateSession(addr *net.UDPAddr, connID uint32) {
	key := addr.String()

	v, _ := h.sessions.LoadOrStore(key, &Session{
		Addr:       addr,
		LastActive: time.Now(),
		ConnIDs:    make([]uint32, 0),
	})

	session := v.(*Session)
	session.mu.Lock()
	session.LastActive = time.Now()

	// 添加连接 ID
	found := false
	for _, id := range session.ConnIDs {
		if id == connID {
			found = true
			break
		}
	}
	if !found {
		session.ConnIDs = append(session.ConnIDs, connID)
	}
	session.mu.Unlock()
}

// closeConn 关闭连接
func (h *UnifiedHandler) closeConn(reqID uint32) {
	if v, ok := h.conns.LoadAndDelete(reqID); ok {
		c := v.(*Connection)
		if c.Target != nil {
			_ = c.Target.Close()
		}
		atomic.AddInt64(&h.activeConns, -1)
		h.log(logInfo, "断开: ID:%d (sent:%d, recv:%d)", reqID, c.BytesSent, c.BytesRecv)
	}
}

// cleanupLoop 清理循环
func (h *UnifiedHandler) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		// 清理超时连接
		h.conns.Range(func(key, value interface{}) bool {
			c := value.(*Connection)
			c.mu.Lock()
			idle := now.Sub(c.LastActive)
			c.mu.Unlock()
			if idle > 5*time.Minute {
				h.closeConn(key.(uint32))
			}
			return true
		})

		// 清理超时会话
		h.sessions.Range(func(key, value interface{}) bool {
			session := value.(*Session)
			session.mu.Lock()
			idle := now.Sub(session.LastActive)
			session.mu.Unlock()
			if idle > 10*time.Minute {
				h.sessions.Delete(key)
			}
			return true
		})
	}
}

// GetStats 获取统计信息
func (h *UnifiedHandler) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total_conns":  atomic.LoadUint64(&h.totalConns),
		"active_conns": atomic.LoadInt64(&h.activeConns),
		"total_bytes":  atomic.LoadUint64(&h.totalBytes),
	}
}

// GetActiveConns 获取活跃连接数
func (h *UnifiedHandler) GetActiveConns() int64 {
	return atomic.LoadInt64(&h.activeConns)
}

func (h *UnifiedHandler) log(level int, format string, args ...interface{}) {
	if level > h.logLevel {
		return
	}
	prefix := map[int]string{logError: "[ERROR]", logInfo: "[INFO]", logDebug: "[DEBUG]"}[level]
	fmt.Printf("%s %s [Handler] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}




