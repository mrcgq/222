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

	DefaultWSPath         = "/ws"
	MinEncryptedPacketLen = 34

	// 分片重组相关
	FragmentTimeout     = 10 * time.Second // 分片超时时间
	MaxPendingFragments = 256              // 最大待处理分片组数
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
	WSPath         string
}

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

// =============================================================================
// 分片重组器
// =============================================================================

// fragmentGroup 分片组
type fragmentGroup struct {
	fragments  map[uint8][]byte // 按索引存储的分片
	totalCount uint8            // 总分片数
	received   int              // 已接收分片数
	createdAt  time.Time        // 创建时间
	totalSize  int              // 累计大小
	reqID      uint32           // 请求 ID
}

// FragmentAssembler 分片重组器
type FragmentAssembler struct {
	pending map[uint16]*fragmentGroup // key: fragID
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewFragmentAssembler 创建分片重组器
func NewFragmentAssembler() *FragmentAssembler {
	ctx, cancel := context.WithCancel(context.Background())
	fa := &FragmentAssembler{
		pending: make(map[uint16]*fragmentGroup),
		ctx:     ctx,
		cancel:  cancel,
	}
	go fa.cleanupLoop()
	return fa
}

// ProcessPacket 处理收到的包
// 返回: (完整数据, 是否是分片包)
// 如果是分片包但未完成重组，返回 (nil, true)
func (fa *FragmentAssembler) ProcessPacket(data []byte) ([]byte, bool) {
	// 检查是否是分片包
	if !protocol.IsFragmentPacket(data) {
		return data, false
	}

	// 解析分片包
	frag, err := protocol.ParseFragmentPacket(data)
	if err != nil {
		return nil, true
	}

	fa.mu.Lock()
	defer fa.mu.Unlock()

	// 获取或创建分片组
	group, exists := fa.pending[frag.FragID]
	if !exists {
		// 检查是否超过最大待处理数
		if len(fa.pending) >= MaxPendingFragments {
			// 删除最旧的
			var oldestID uint16
			var oldestTime time.Time
			for id, g := range fa.pending {
				if oldestTime.IsZero() || g.createdAt.Before(oldestTime) {
					oldestID = id
					oldestTime = g.createdAt
				}
			}
			delete(fa.pending, oldestID)
		}

		group = &fragmentGroup{
			fragments:  make(map[uint8][]byte),
			totalCount: frag.FragTotal,
			createdAt:  time.Now(),
			reqID:      frag.ReqID,
		}
		fa.pending[frag.FragID] = group
	}

	// 检查分片是否重复
	if _, duplicate := group.fragments[frag.FragIndex]; duplicate {
		return nil, true
	}

	// 存储分片
	fragData := make([]byte, len(frag.Data))
	copy(fragData, frag.Data)
	group.fragments[frag.FragIndex] = fragData
	group.received++
	group.totalSize += len(frag.Data)

	// 检查是否完整
	if group.received == int(group.totalCount) {
		// 重组数据
		result := make([]byte, 0, group.totalSize)
		for i := uint8(0); i < group.totalCount; i++ {
			if fragPart, ok := group.fragments[i]; ok {
				result = append(result, fragPart...)
			} else {
				// 缺少分片（不应该发生，因为 received == totalCount）
				delete(fa.pending, frag.FragID)
				return nil, true
			}
		}

		// 清理
		delete(fa.pending, frag.FragID)

		return result, true
	}

	return nil, true
}

// cleanupLoop 定期清理超时的分片组
func (fa *FragmentAssembler) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-fa.ctx.Done():
			return
		case <-ticker.C:
			fa.mu.Lock()
			now := time.Now()
			for id, group := range fa.pending {
				if now.Sub(group.createdAt) > FragmentTimeout {
					delete(fa.pending, id)
				}
			}
			fa.mu.Unlock()
		}
	}
}

// Close 关闭重组器
func (fa *FragmentAssembler) Close() {
	fa.cancel()
}

// GetStats 获取统计信息
func (fa *FragmentAssembler) GetStats() map[string]int {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	return map[string]int{
		"pending_groups": len(fa.pending),
	}
}

// =============================================================================
// PhantomClientHandler
// =============================================================================

type PhantomClientHandler struct {
	crypto     *crypto.Crypto
	controller *congestion.Hysteria2Controller
	transport  Transport

	config     *Config
	sessions   map[uint32]*Session
	sessionsMu sync.RWMutex
	nextReqID  uint32

	// 分片重组器
	fragmentAssembler *FragmentAssembler

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	stats struct {
		bytesSent        uint64
		bytesReceived    uint64
		packetsSent      uint64
		packetsRecv      uint64
		fragmentsRecv    uint64 // 新增：接收的分片数
		fragmentsAssembled uint64 // 新增：重组完成的分片组数
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

	case cfg.TransportMode == "faketcp" && runtime.GOOS == "linux":
		ftConfig := transport.DefaultFakeTCPConfig()
		ftClient, err := transport.NewFakeTCPClient(serverEndpoint, ftConfig)
		if err != nil {
			return nil, fmt.Errorf("FakeTCP 连接失败: %w", err)
		}
		trans = &fakeTCPAdapter{client: ftClient}
		fmt.Printf("[Client] FakeTCP 隧道已建立: %s\n", serverEndpoint)

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
		crypto:            cry,
		controller:        controller,
		transport:         trans,
		config:            cfg,
		sessions:          make(map[uint32]*Session),
		fragmentAssembler: NewFragmentAssembler(), // 初始化分片重组器
		ctx:               ctx,
		cancel:            cancel,
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
// 接收循环（修改：支持分片重组）
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

		if n < MinEncryptedPacketLen {
			continue
		}

		decrypted, err := h.crypto.Decrypt(buf[:n])
		if err != nil {
			continue
		}

		atomic.AddUint64(&h.stats.bytesReceived, uint64(n))
		atomic.AddUint64(&h.stats.packetsRecv, 1)

		// 检查是否是分片包并进行重组
		reassembled, isFragment := h.fragmentAssembler.ProcessPacket(decrypted)
		if isFragment {
			atomic.AddUint64(&h.stats.fragmentsRecv, 1)
			if reassembled == nil {
				// 分片未完成，等待更多分片
				continue
			}
			// 分片重组完成
			atomic.AddUint64(&h.stats.fragmentsAssembled, 1)
			decrypted = reassembled
		}

		resp, err := protocol.ParseServerResponse(decrypted)
		if err != nil {
			continue
		}

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

	// 关闭分片重组器
	if h.fragmentAssembler != nil {
		h.fragmentAssembler.Close()
	}

	h.wg.Wait()
	return h.transport.Close()
}

// ============================================
// 统计
// ============================================

type Stats struct {
	BytesSent          uint64
	BytesReceived      uint64
	PacketsSent        uint64
	PacketsRecv        uint64
	FragmentsRecv      uint64
	FragmentsAssembled uint64
	SessionsTotal      uint64
	SessionsActive     int64
}

func (h *PhantomClientHandler) GetStats() Stats {
	h.sessionsMu.RLock()
	activeCount := len(h.sessions)
	h.sessionsMu.RUnlock()

	return Stats{
		BytesSent:          atomic.LoadUint64(&h.stats.bytesSent),
		BytesReceived:      atomic.LoadUint64(&h.stats.bytesReceived),
		PacketsSent:        atomic.LoadUint64(&h.stats.packetsSent),
		PacketsRecv:        atomic.LoadUint64(&h.stats.packetsRecv),
		FragmentsRecv:      atomic.LoadUint64(&h.stats.fragmentsRecv),
		FragmentsAssembled: atomic.LoadUint64(&h.stats.fragmentsAssembled),
		SessionsActive:     int64(activeCount),
	}
}
