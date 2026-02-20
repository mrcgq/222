// =============================================================================
// 文件: internal/transport/websocket.go
// 描述: WebSocket 传输层
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
// 全局计数器（解决模拟地址碰撞问题）
// =============================================================================

var sessionCounter uint64

// nextSessionID 生成唯一会话 ID
func nextSessionID() uint64 {
	return atomic.AddUint64(&sessionCounter, 1)
}

// =============================================================================
// 接口定义
// =============================================================================

// WebSocketHandler WebSocket 处理器接口
type WebSocketHandler interface {
	HandlePacketWithChannel(data []byte, from *net.UDPAddr, respChan *handler.ResponseChannel)
}

// =============================================================================
// WebSocket 服务器
// =============================================================================

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
	conns      sync.Map
	stopCh     chan struct{}
	wg         sync.WaitGroup

	activeConns int64
}

// WSSession WebSocket 会话
type WSSession struct {
	ID         uint64
	Conn       *websocket.Conn
	Addr       *net.UDPAddr
	RespChan   *handler.ResponseChannel
	LastActive time.Time
	writeMu    sync.Mutex
	closed     int32
}

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
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
	}
}

// Start 启动服务器
func (s *WebSocketServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.path, s.handleWebSocket)
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

	s.wg.Add(1)
	go s.cleanupLoop(ctx)

	protocol := "HTTP"
	if s.useTLS {
		protocol = "HTTPS"
	}
	s.log(1, "WebSocket 服务器已启动: %s (%s%s)", s.addr, protocol, s.path)
	return nil
}

func (s *WebSocketServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Host 验证
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

	// 生成唯一会话 ID
	sessionID := nextSessionID()

	// 解析远程地址，失败则使用唯一的模拟地址
	remoteAddr, err := net.ResolveUDPAddr("udp", r.RemoteAddr)
	if err != nil || remoteAddr == nil {
		// 使用会话 ID 生成唯一的模拟地址
		// IP: 10.sessionID的高16位.sessionID的中8位.sessionID的低8位
		// Port: sessionID % 65535 + 1
		remoteAddr = &net.UDPAddr{
			IP: net.IPv4(
				10,
				byte((sessionID>>16)&0xFF),
				byte((sessionID>>8)&0xFF),
				byte(sessionID&0xFF),
			),
			Port: int(sessionID%65534) + 1,
		}
	}

	// 创建响应通道
	respChan := handler.NewResponseChannel()

	session := &WSSession{
		ID:         sessionID,
		Conn:       conn,
		Addr:       remoteAddr,
		RespChan:   respChan,
		LastActive: time.Now(),
	}

	// 使用会话 ID 作为 key，确保唯一性
	sessionKey := fmt.Sprintf("ws-%d", sessionID)
	s.conns.Store(sessionKey, session)

	s.log(2, "WebSocket 连接: %s (session: %d)", r.RemoteAddr, sessionID)

	// 启动响应发送协程
	go s.responseSender(session)

	// 读取循环（阻塞）
	s.readLoop(session)

	// 清理
	s.closeSession(session)
	s.conns.Delete(sessionKey)
	atomic.AddInt64(&s.activeConns, -1)

	s.log(2, "WebSocket 断开: session %d", sessionID)
}

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
				s.log(2, "WebSocket 读取错误 (session %d): %v", session.ID, err)
			}
			return
		}

		if messageType != websocket.BinaryMessage {
			continue
		}

		session.LastActive = time.Now()

		// 调用处理器
		s.handler.HandlePacketWithChannel(data, session.Addr, session.RespChan)
	}
}

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
				s.log(2, "WebSocket 写入错误 (session %d): %v", session.ID, err)
				return
			}
		}
	}
}

func (s *WebSocketServer) closeSession(session *WSSession) {
	if !atomic.CompareAndSwapInt32(&session.closed, 0, 1) {
		return
	}

	// 关闭响应通道
	session.RespChan.Close()

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

func (s *WebSocketServer) handleFakePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body>
    <h1>Welcome</h1>
    <p>Server Time: %s</p>
</body>
</html>`, time.Now().Format(time.RFC1123))
}

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
				if now.Sub(session.LastActive) > 10*time.Minute {
					s.log(2, "清理过期会话: %d", session.ID)
					s.closeSession(session)
					s.conns.Delete(key)
				}
				return true
			})
		}
	}
}

// Stop 停止服务器
func (s *WebSocketServer) Stop() {
	close(s.stopCh)

	s.conns.Range(func(key, value interface{}) bool {
		session := value.(*WSSession)
		s.closeSession(session)
		return true
	})

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
