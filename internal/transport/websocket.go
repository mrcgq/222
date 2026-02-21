

// =============================================================================
// 文件: internal/transport/websocket.go
// 描述: WebSocket 传输层 - CDN 友好
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
)

// WebSocketServer WebSocket 服务器
type WebSocketServer struct {
	addr      string
	path      string
	host      string
	useTLS    bool
	certFile  string
	keyFile   string
	handler   PacketHandler
	logLevel  int

	httpServer *http.Server
	upgrader   websocket.Upgrader
	conns      sync.Map // *websocket.Conn -> *WSSession
	stopCh     chan struct{}
	wg         sync.WaitGroup

	// 统计
	activeConns int64
}

// WSSession WebSocket 会话
type WSSession struct {
	Conn       *websocket.Conn
	Addr       *net.UDPAddr // 模拟 UDP 地址
	LastActive time.Time
	mu         sync.Mutex
}

// NewWebSocketServer 创建 WebSocket 服务器
func NewWebSocketServer(addr, path, host string, useTLS bool, certFile, keyFile string, handler PacketHandler, logLevel string) *WebSocketServer {
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
		handler:  handler,
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
	defer atomic.AddInt64(&s.activeConns, -1)

	// 创建模拟 UDP 地址
	remoteAddr, _ := net.ResolveUDPAddr("udp", r.RemoteAddr)
	if remoteAddr == nil {
		remoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	}

	session := &WSSession{
		Conn:       conn,
		Addr:       remoteAddr,
		LastActive: time.Now(),
	}
	s.conns.Store(conn, session)
	defer func() {
		s.conns.Delete(conn)
		conn.Close()
	}()

	s.log(2, "WebSocket 连接: %s", r.RemoteAddr)

	// 读取循环
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		messageType, data, err := conn.ReadMessage()
		if err != nil {
			if err != io.EOF && !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				s.log(2, "WebSocket 读取错误: %v", err)
			}
			return
		}

		if messageType != websocket.BinaryMessage {
			continue
		}

		session.mu.Lock()
		session.LastActive = time.Now()
		session.mu.Unlock()

		// 调用处理器
		response := s.handler.HandlePacket(data, remoteAddr)

		// 发送响应
		if response != nil {
			session.mu.Lock()
			conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			err := conn.WriteMessage(websocket.BinaryMessage, response)
			session.mu.Unlock()
			if err != nil {
				s.log(2, "WebSocket 写入错误: %v", err)
				return
			}
		}
	}
}

// handleFakePage 伪装页面
func (s *WebSocketServer) handleFakePage(w http.ResponseWriter, r *http.Request) {
	// 返回一个看起来像正常网站的页面
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
    <meta charset="utf-8">
</head>
<body>
    <h1>It works!</h1>
    <p>This is the default page.</p>
</body>
</html>`)
}

// SendTo 发送数据到指定地址
func (s *WebSocketServer) SendTo(data []byte, addr *net.UDPAddr) error {
	var targetSession *WSSession

	s.conns.Range(func(key, value interface{}) bool {
		session := value.(*WSSession)
		if session.Addr.String() == addr.String() {
			targetSession = session
			return false
		}
		return true
	})

	if targetSession == nil {
		return fmt.Errorf("会话不存在: %s", addr.String())
	}

	targetSession.mu.Lock()
	defer targetSession.mu.Unlock()

	targetSession.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return targetSession.Conn.WriteMessage(websocket.BinaryMessage, data)
}

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
			now := time.Now()
			s.conns.Range(func(key, value interface{}) bool {
				session := value.(*WSSession)
				session.mu.Lock()
				if now.Sub(session.LastActive) > 10*time.Minute {
					session.mu.Unlock()
					conn := key.(*websocket.Conn)
					conn.Close()
					s.conns.Delete(key)
				} else {
					session.mu.Unlock()
				}
				return true
			})
		}
	}
}

// Stop 停止服务器
func (s *WebSocketServer) Stop() {
	close(s.stopCh)

	// 关闭所有 WebSocket 连接
	s.conns.Range(func(key, value interface{}) bool {
		conn := key.(*websocket.Conn)
		conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
		conn.Close()
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

func (s *WebSocketServer) log(level int, format string, args ...interface{}) {
	if level > s.logLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [WebSocket] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}



