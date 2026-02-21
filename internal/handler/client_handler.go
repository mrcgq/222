
// internal/handler/client_handler.go
package handler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mrcgq/211/internal/congestion"
	"github.com/mrcgq/211/internal/crypto"
	"github.com/mrcgq/211/internal/protocol"
	"github.com/mrcgq/211/internal/transport"
)

// Transport 统一传输接口
type Transport interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
}

const (
	StateInit       int32 = 0
	StateConnecting int32 = 1
	StateConnected  int32 = 2
	StateClosed     int32 = 3

	DefaultMTU        = 1400
	MaxPayloadSize    = 1300
	SessionBufferSize = 512

	ConnectTimeout    = 10 * time.Second
	ReadTimeout       = 60 * time.Second
	WriteTimeout      = 30 * time.Second
	HeartbeatInterval = 15 * time.Second
	SessionTimeout    = 120 * time.Second

	// DefaultWSPath 默认 WebSocket 路径，与服务端 config.yaml 的 path 对应
	DefaultWSPath = "/ws"

	// MinEncryptedPacketLen TSKD 加密包最小长度
	// UserID(4) + Timestamp(2) + Nonce(12) + Poly1305_Tag(16) = 34 字节最小头部
	// 修复：原值 18 漏算了 ChaCha20-Poly1305 的 16 字节 MAC Tag
	MinEncryptedPacketLen = 34
)

type Config struct {
	ServerAddr     string
	ServerPort     uint16
	PSK            string
	TimeWindow     time.Duration
	UploadMbps     int
	DownloadMbps   int
	TransportMode  string
	TLSFingerprint string

	// WSPath WebSocket 路径，必须与服务端一致
	// 留空自动使用 "/ws"
	WSPath string
}

// getWSPath 获取实际使用的 WebSocket 路径
func (c *Config) getWSPath() string {
	if c.WSPath == "" {
		return DefaultWSPath
	}
	if !strings.HasPrefix(c.WSPath, "/") {
		return "/" + c.WSPath
	}
	return c.WSPath
}

type Session struct {
	reqID      uint32
	localConn  net.Conn
	targetAddr string
	targetPort uint16
	state      int32
	lastActive time.Time
	recvChan   chan *protocol.ServerResponse
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
}

type PhantomClientHandler struct {
	crypto     *crypto.Crypto
	controller *congestion.Hysteria2Controller
	transport  Transport

	config     *Config
	sessions   map[uint32]*Session
	sessionsMu sync.RWMutex
	nextReqID  uint32

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	stats struct {
		bytesSent     uint64
		bytesReceived uint64
		packetsSent   uint64
		packetsRecv   uint64
	}
}

// ============================================
// WebSocket 适配器
// ============================================

type wsStreamAdapter struct {
	conn    *websocket.Conn
	readBuf []byte
	mu      sync.Mutex
}

func (w *wsStreamAdapter) Read(b []byte) (int, error) {
	if len(w.readBuf) > 0 {
		n := copy(b, w.readBuf)
		w.readBuf = w.readBuf[n:]
		return n, nil
	}

	_, msg, err := w.conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	n := copy(b, msg)
	if n < len(msg) {
		w.readBuf = msg[n:]
	}
	return n, nil
}

func (w *wsStreamAdapter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	err := w.conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsStreamAdapter) Close() error {
	return w.conn.Close()
}

// ============================================
// FakeTCP 适配器
// ============================================

type fakeTCPAdapter struct {
	client  any
	readBuf []byte
}

func (a *fakeTCPAdapter) Write(b []byte) (int, error) {
	if c, ok := a.client.(interface{ Send([]byte) error }); ok {
		return len(b), c.Send(b)
	}
	return 0, errors.New("fakeTCP: Send method not found")
}

func (a *fakeTCPAdapter) Read(b []byte) (int, error) {
	if len(a.readBuf) > 0 {
		n := copy(b, a.readBuf)
		a.readBuf = a.readBuf[n:]
		return n, nil
	}
	if c, ok := a.client.(interface{ Recv(context.Context) ([]byte, error) }); ok {
		data, err := c.Recv(context.Background())
		if err != nil {
			return 0, err
		}
		n := copy(b, data)
		if n < len(data) {
			a.readBuf = data[n:]
		}
		return n, nil
	}
	return 0, errors.New("fakeTCP: Recv method not found")
}

func (a *fakeTCPAdapter) Close() error {
	if c, ok := a.client.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// ============================================
// 核心构造函数
// ============================================

func NewClientHandler(cfg *Config) (*PhantomClientHandler, error) {
	// 修复：清除 PSK 中不可见的空白字符（换行符、空格、制表符）
	// 这是 "UserID 不匹配" 的最常见原因
	cfg.PSK = strings.TrimSpace(cfg.PSK)

	timeWindowSec := int(cfg.TimeWindow.Seconds())
	cry, err := crypto.New(cfg.PSK, timeWindowSec)
	if err != nil {
		return nil, fmt.Errorf("crypto init failed: %w", err)
	}

	controller := congestion.NewHysteria2Controller(cfg.UploadMbps, cfg.DownloadMbps)

	var trans Transport
	serverEndpoint := fmt.Sprintf("%s:%d", cfg.ServerAddr, cfg.ServerPort)

	switch {
	// ========== WSS / WS 模式 ==========
	case cfg.TransportMode == "wss" || cfg.TransportMode == "ws":
		scheme := "ws"
		if cfg.TransportMode == "wss" {
			scheme = "wss"
		}

		wsPath := cfg.getWSPath()
		url := fmt.Sprintf("%s://%s%s", scheme, serverEndpoint, wsPath)

		wsDialer := &websocket.Dialer{
			HandshakeTimeout: ConnectTimeout,
			ReadBufferSize:   65535,
			WriteBufferSize:  65535,
		}

		wsConn, _, err := wsDialer.Dial(url, nil)
		if err != nil {
			return nil, fmt.Errorf("WebSocket 连接失败 (%s): %w", url, err)
		}

		wsConn.SetReadLimit(0)
		trans = &wsStreamAdapter{conn: wsConn}
		fmt.Printf("[Client] WebSocket 隧道已建立: %s\n", url)

	// ========== FakeTCP 模式（仅 Linux）==========
	case cfg.TransportMode == "faketcp" && runtime.GOOS == "linux":
		ftConfig := transport.DefaultFakeTCPConfig()
		ftClient, err := transport.NewFakeTCPClient(serverEndpoint, ftConfig)
		if err != nil {
			return nil, fmt.Errorf("FakeTCP 连接失败: %w", err)
		}
		trans = &fakeTCPAdapter{client: ftClient}
		fmt.Printf("[Client] FakeTCP 隧道已建立: %s\n", serverEndpoint)

	// ========== 默认 UDP 模式 ==========
	default:
		udpAddr, err := net.ResolveUDPAddr("udp", serverEndpoint)
		if err != nil {
			return nil, fmt.Errorf("解析 UDP 地址失败: %w", err)
		}
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return nil, fmt.Errorf("UDP 连接失败: %w", err)
		}
		trans = conn
		fmt.Printf("[Client] UDP 隧道已建立: %s\n", serverEndpoint)
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

	h.wg.Add(2)
	go h.receiveLoop()
	go h.maintenanceLoop()

	return h, nil
}

// ============================================
// 加密发送
// ============================================

func (h *PhantomClientHandler) sendEncryptedPacket(payload []byte) error {
	for !h.controller.CanSend(len(payload)) {
		time.Sleep(h.controller.GetPacingInterval(len(payload)))
	}

	encrypted, err := h.crypto.Encrypt(payload)
	if err != nil {
		return fmt.Errorf("加密失败: %w", err)
	}

	n, err := h.transport.Write(encrypted)
	if err != nil {
		return fmt.Errorf("发送失败: %w", err)
	}

	h.controller.OnPacketSent(0, n, false)
	atomic.AddUint64(&h.stats.bytesSent, uint64(n))
	atomic.AddUint64(&h.stats.packetsSent, 1)

	return nil
}

// ============================================
// 接收循环
// ============================================

func (h *PhantomClientHandler) receiveLoop() {
	defer h.wg.Done()
	buf := make([]byte, 65535)
	for {
		select {
		case <-h.ctx.Done():
			return
		default:
		}

		n, err := h.transport.Read(buf)
		if err != nil {
			return
		}

		// 修复：过滤过短的包（不足以构成有效的 TSKD 加密包）
		// 避免 WebSocket 控制帧等噪音进入解密流程
		// 最小长度 = UserID(4) + Timestamp(2) + Nonce(12) + Tag(16) = 34
		if n < MinEncryptedPacketLen {
			continue
		}

		decrypted, err := h.crypto.Decrypt(buf[:n])
		if err != nil {
			// 解密失败原因：PSK 不一致 / 时间偏差 > TimeWindow / 数据损坏
			// 静默丢弃，不打印日志避免刷屏
			continue
		}

		resp, err := protocol.ParseServerResponse(decrypted)
		if err != nil {
			continue
		}

		atomic.AddUint64(&h.stats.bytesReceived, uint64(n))
		atomic.AddUint64(&h.stats.packetsRecv, 1)

		h.controller.OnPacketAcked(0, 0, time.Millisecond*10)

		h.sessionsMu.RLock()
		session, ok := h.sessions[resp.ReqID]
		h.sessionsMu.RUnlock()
		if ok {
			select {
			case session.recvChan <- resp:
				session.lastActive = time.Now()
			default:
			}
		}
	}
}

// ============================================
// 会话处理入口
// ============================================

func (h *PhantomClientHandler) Handle(conn net.Conn, targetAddr string, targetPort uint16, initData []byte) error {
	reqID := atomic.AddUint32(&h.nextReqID, 1)
	sessionCtx, sessionCancel := context.WithCancel(h.ctx)
	session := &Session{
		reqID:      reqID,
		localConn:  conn,
		targetAddr: targetAddr,
		targetPort: targetPort,
		state:      StateConnecting,
		lastActive: time.Now(),
		recvChan:   make(chan *protocol.ServerResponse, SessionBufferSize),
		ctx:        sessionCtx,
		cancel:     sessionCancel,
	}

	h.sessionsMu.Lock()
	h.sessions[reqID] = session
	h.sessionsMu.Unlock()
	defer h.unregisterSession(reqID)

	payload, err := protocol.BuildClientConnectRequest(reqID, protocol.NetworkTCP, targetAddr, targetPort, initData)
	if err != nil {
		return fmt.Errorf("构建连接请求失败: %w", err)
	}
	if err := h.sendEncryptedPacket(payload); err != nil {
		return fmt.Errorf("发送连接请求失败: %w", err)
	}

	if err := h.waitForConnectAck(session); err != nil {
		return err
	}
	atomic.StoreInt32(&session.state, StateConnected)
	return h.runDataRelay(session)
}

// ============================================
// 等待连接确认
// ============================================

func (h *PhantomClientHandler) waitForConnectAck(session *Session) error {
	timer := time.NewTimer(ConnectTimeout)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return errors.New("connect timeout")
		case <-session.ctx.Done():
			return errors.New("session cancelled")
		case resp := <-session.recvChan:
			if resp.IsConnectAck() && resp.Status == protocol.StatusSuccess {
				return nil
			}
			if resp.IsConnectAck() && resp.Status != protocol.StatusSuccess {
				return fmt.Errorf("connect rejected: status=%d", resp.Status)
			}
		}
	}
}

// ============================================
// 双向数据中继
// ============================================

func (h *PhantomClientHandler) runDataRelay(session *Session) error {
	errChan := make(chan error, 2)

	go func() {
		errChan <- h.relayLocalToRemote(session)
	}()

	go func() {
		errChan <- h.relayRemoteToLocal(session)
	}()

	err := <-errChan
	session.cancel()

	closePacket := protocol.BuildClientCloseRequest(session.reqID)
	h.sendEncryptedPacket(closePacket)

	return err
}

func (h *PhantomClientHandler) relayLocalToRemote(session *Session) error {
	buf := make([]byte, MaxPayloadSize)
	for {
		select {
		case <-session.ctx.Done():
			return nil
		default:
		}

		session.localConn.SetReadDeadline(time.Now().Add(ReadTimeout))
		n, err := session.localConn.Read(buf)
		if err != nil {
			return nil
		}

		session.lastActive = time.Now()
		p := protocol.BuildClientDataRequest(session.reqID, buf[:n])
		if sendErr := h.sendEncryptedPacket(p); sendErr != nil {
			return sendErr
		}
	}
}

func (h *PhantomClientHandler) relayRemoteToLocal(session *Session) error {
	for {
		select {
		case <-session.ctx.Done():
			return nil

		case resp := <-session.recvChan:
			if resp.ReqID != session.reqID {
				continue
			}

			if resp.IsDisconnect() {
				return nil
			}

			if resp.IsDataPacket() && len(resp.Payload) > 0 {
				session.lastActive = time.Now()
				session.localConn.SetWriteDeadline(time.Now().Add(WriteTimeout))
				if _, err := session.localConn.Write(resp.Payload); err != nil {
					return err
				}
			}
		}
	}
}

// ============================================
// 会话管理
// ============================================

func (h *PhantomClientHandler) unregisterSession(reqID uint32) {
	h.sessionsMu.Lock()
	if s, ok := h.sessions[reqID]; ok {
		s.cancel()
		s.localConn.Close()
		delete(h.sessions, reqID)
	}
	h.sessionsMu.Unlock()
}

// ============================================
// 心跳与维护
// ============================================

func (h *PhantomClientHandler) maintenanceLoop() {
	defer h.wg.Done()
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()

	cleanTicker := time.NewTicker(30 * time.Second)
	defer cleanTicker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return

		case <-ticker.C:
			p := protocol.BuildClientHeartbeat(0)
			h.sendEncryptedPacket(p)

		case <-cleanTicker.C:
			h.cleanupStaleSessions()
		}
	}
}

func (h *PhantomClientHandler) cleanupStaleSessions() {
	now := time.Now()
	var staleIDs []uint32

	h.sessionsMu.RLock()
	for id, s := range h.sessions {
		if now.Sub(s.lastActive) > SessionTimeout {
			staleIDs = append(staleIDs, id)
		}
	}
	h.sessionsMu.RUnlock()

	for _, id := range staleIDs {
		h.unregisterSession(id)
	}
}

// ============================================
// 关闭
// ============================================

func (h *PhantomClientHandler) Close() error {
	h.cancel()
	h.wg.Wait()
	return h.transport.Close()
}

// ============================================
// 统计
// ============================================

type Stats struct {
	BytesSent      uint64
	BytesReceived  uint64
	PacketsSent    uint64
	PacketsRecv    uint64
	SessionsTotal  uint64
	SessionsActive int64
}

func (h *PhantomClientHandler) GetStats() Stats {
	h.sessionsMu.RLock()
	activeCount := len(h.sessions)
	h.sessionsMu.RUnlock()

	return Stats{
		BytesSent:      atomic.LoadUint64(&h.stats.bytesSent),
		BytesReceived:  atomic.LoadUint64(&h.stats.bytesReceived),
		PacketsSent:    atomic.LoadUint64(&h.stats.packetsSent),
		PacketsRecv:    atomic.LoadUint64(&h.stats.packetsRecv),
		SessionsActive: int64(activeCount),
	}
}



