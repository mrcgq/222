// =============================================================================
// 文件: internal/transport/websocket.go
// 描述: WebSocket 传输层 - CDN 友好，修复对称回传问题
// =============================================================================
package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mrcgq/211/internal/handler"
)

// =============================================================================
// 类型定义
// =============================================================================

// WebSocketHandler WebSocket 专用处理器接口
type WebSocketHandler interface {
	HandlePacketWithChannel(data []byte, from *net.UDPAddr, respChan *handler.ResponseChannel)
}

// WebSocketServer WebSocket 服务器
type WebSocketServer struct {
	addr      string
	path      string
	host      string
	useTLS    bool
	certFile  string
	keyFile   string
	handler   WebSocketHandler
	logLevel  int

	httpServer *http.Server
	upgrader   websocket.Upgrader
	conns      sync.Map // remoteAddr string -> *WSSession
	stopCh     chan struct{}
	wg         sync.WaitGroup

	// 统计
	activeConns int64
}

// WSSession WebSocket 会话
type WSSession struct {
	Conn       *websocket.Conn
	Addr       *net.UDPAddr // 模拟 UDP 地址
	RespChan   *handler.ResponseChannel
	LastActive time.Time
	writeMu    sync.Mutex
	closed     int32
}

// =============================================================================
// 构造函数
// =============================================================================

// NewWebSocketServer 创建 WebSocket 服务器
func NewWebSocketServer(addr, path, host string, useTLS bool, certFile, keyFile string, h WebSocketHandler, logLevel string) *WebSocketServer {
	level := 1
	switch logLevel {
	case "debug":
		level = 2
	case "error":
		level = 0
	}

	return &WebSocketServer{
		addr:     addr,
		path:     path,
		host:     host,
		useTLS:   useTLS,
		certFile: certFile,
		keyFile:  keyFile,
		handler:  h,
		logLevel: level,
		stopCh:   make(chan struct{}),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  32 * 1024,
			WriteBufferSize: 32 * 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true // 允许所有来源
			},
		},
	}
}

// =============================================================================
// 服务器生命周期
// =============================================================================

// Start 启动服务器
func (s *WebSocketServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// WebSocket 处理
	mux.HandleFunc(s.path, s.handleWebSocket)

	// 伪装页面
	mux.HandleFunc("/", s.handleFakePage)

	s.httpServer = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		var err error
		if s.useTLS {
			err = s.httpServer.ListenAndServeTLS(s.certFile, s.keyFile)
		} else {
			err = s.httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			s.log(0, "HTTP 服务器错误: %v", err)
		}
	}()

	// 启动清理协程
	s.wg.Add(1)
	go s.cleanupLoop(ctx)

	protocol := "HTTP"
	if s.useTLS {
		protocol = "HTTPS"
	}
	s.log(1, "WebSocket 服务器已启动: %s (%s%s)", s.addr, protocol, s.path)
	return nil
}

// Stop 停止服务器
func (s *WebSocketServer) Stop() {
	close(s.stopCh)

	// 关闭所有 WebSocket 连接
	s.conns.Range(func(key, value interface{}) bool {
		session := value.(*WSSession)
		s.closeSession(session)
		return true
	})

	// 关闭 HTTP 服务器
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(ctx)
	}

	s.wg.Wait()
}

// GetActiveConns 获取活跃连接数
func (s *WebSocketServer) GetActiveConns() int64 {
	return atomic.LoadInt64(&s.activeConns)
}

// =============================================================================
// WebSocket 处理
// =============================================================================

// handleWebSocket 处理 WebSocket 连接
func (s *WebSocketServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// 检查 Host 头 (可选验证)
	if s.host != "" && r.Host != s.host {
		s.log(2, "Host 不匹配: %s != %s", r.Host, s.host)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// 升级连接
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log(2, "WebSocket 升级失败: %v", err)
		return
	}

	atomic.AddInt64(&s.activeConns, 1)

	// 创建模拟 UDP 地址
	remoteAddr, _ := net.ResolveUDPAddr("udp", r.RemoteAddr)
	if remoteAddr == nil {
		// 无法解析，创建一个唯一的模拟地址
		remoteAddr = &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: int(time.Now().UnixNano() % 65535),
		}
	}

	// 创建响应通道
	respChan := handler.NewResponseChannel()

	session := &WSSession{
		Conn:       conn,
		Addr:       remoteAddr,
		RespChan:   respChan,
		LastActive: time.Now(),
	}

	sessionKey := remoteAddr.String()
	s.conns.Store(sessionKey, session)

	s.log(2, "WebSocket 连接: %s", r.RemoteAddr)

	// 启动响应发送协程
	go s.responseSender(session)

	// 读取循环
	s.readLoop(session)

	// 清理
	s.closeSession(session)
	s.conns.Delete(sessionKey)
	atomic.AddInt64(&s.activeConns, -1)
}

// readLoop 读取客户端数据
func (s *WebSocketServer) readLoop(session *WSSession) {
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		if atomic.LoadInt32(&session.closed) != 0 {
			return
		}

		session.Conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		messageType, data, err := session.Conn.ReadMessage()
		if err != nil {
			if err != io.EOF && !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				s.log(2, "WebSocket 读取错误: %v", err)
			}
			return
		}

		if messageType != websocket.BinaryMessage {
			continue
		}

		session.LastActive = time.Now()

		// 调用处理器，响应会通过 respChan 返回
		s.handler.HandlePacketWithChannel(data, session.Addr, session.RespChan)
	}
}

// responseSender 响应发送协程
func (s *WebSocketServer) responseSender(session *WSSession) {
	for {
		select {
		case <-s.stopCh:
			return
		case <-session.RespChan.Done:
			return
		case data := <-session.RespChan.Data:
			if atomic.LoadInt32(&session.closed) != 0 {
				return
			}

			session.writeMu.Lock()
			session.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			err := session.Conn.WriteMessage(websocket.BinaryMessage, data)
			session.writeMu.Unlock()

			if err != nil {
				s.log(2, "WebSocket 写入错误: %v", err)
				return
			}
		}
	}
}

// closeSession 关闭会话
func (s *WebSocketServer) closeSession(session *WSSession) {
	if !atomic.CompareAndSwapInt32(&session.closed, 0, 1) {
		return
	}

	// 关闭响应通道
	close(session.RespChan.Done)

	// 发送关闭帧
	session.writeMu.Lock()
	session.Conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second),
	)
	session.writeMu.Unlock()

	// 关闭连接
	session.Conn.Close()
}

// =============================================================================
// 伪装页面
// =============================================================================

// handleFakePage 伪装页面
func (s *WebSocketServer) handleFakePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
               max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #333; }
        p { color: #666; line-height: 1.6; }
    </style>
</head>
<body>
    <h1>Welcome</h1>
    <p>This server is running normally.</p>
    <p>Server Time: %s</p>
</body>
</html>`, time.Now().Format(time.RFC1123))
}

// =============================================================================
// 后台清理
// =============================================================================

// cleanupLoop 清理循环
func (s *WebSocketServer) cleanupLoop(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

func (s *WebSocketServer) cleanup() {
	now := time.Now()
	cleaned := 0

	s.conns.Range(func(key, value interface{}) bool {
		session := value.(*WSSession)

		if now.Sub(session.LastActive) > 10*time.Minute {
			s.closeSession(session)
			s.conns.Delete(key)
			cleaned++
		}
		return true
	})

	if cleaned > 0 {
		s.log(2, "清理过期 WebSocket 会话: %d", cleaned)
	}
}

// =============================================================================
// 日志
// =============================================================================

func (s *WebSocketServer) log(level int, format string, args ...interface{}) {
	if level > s.logLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [WebSocket] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

// =============================================================================
// 兼容性接口（为了不破坏现有代码）
// =============================================================================

// SendTo 发送数据到指定地址（兼容旧接口）
func (s *WebSocketServer) SendTo(data []byte, addr *net.UDPAddr) error {
	if v, ok := s.conns.Load(addr.String()); ok {
		session := v.(*WSSession)
		if atomic.LoadInt32(&session.closed) == 0 {
			select {
			case session.RespChan.Data <- data:
				return nil
			default:
				return fmt.Errorf("响应通道满")
			}
		}
	}
	return fmt.Errorf("会话不存在: %s", addr.String())
}
