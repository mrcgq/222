// internal/handler/client_handler.go
package handler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

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

	config *Config
	sessions   map[uint32]*Session
	sessionsMu sync.RWMutex
	nextReqID  uint32

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	stats struct {
		bytesSent      uint64
		bytesReceived  uint64
		packetsSent    uint64
		packetsRecv    uint64
	}
}

// fakeTCPAdapter 将 FakeTCPClient 包装成满足 Transport 接口的对象
type fakeTCPAdapter struct {
	client interface{} // 使用 interface{} 避免非 Linux 平台编译错误
	readBuf []byte
}

func (a *fakeTCPAdapter) Write(b []byte) (int, error) {
	// 通过反射或类型断言调用 Send
	if c, ok := a.client.(interface{ Send([]byte) error }); ok {
		return len(b), c.Send(b)
	}
	return 0, errors.New("unsupported client type")
}

func (a *fakeTCPAdapter) Read(b []byte) (int, error) {
	if len(a.readBuf) > 0 {
		n := copy(b, a.readBuf)
		a.readBuf = a.readBuf[n:]
		return n, nil
	}
	// 调用 Recv(context.Background())
	if c, ok := a.client.(interface{ Recv(context.Context) ([]byte, error) }); ok {
		data, err := c.Recv(context.Background())
		if err != nil { return 0, err }
		n := copy(b, data)
		if n < len(data) {
			a.readBuf = data[n:]
		}
		return n, nil
	}
	return 0, errors.New("unsupported client type")
}

func (a *fakeTCPAdapter) Close() error {
	if c, ok := a.client.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

func NewClientHandler(cfg *Config) (*PhantomClientHandler, error) {
	timeWindowSec := int(cfg.TimeWindow.Seconds())
	cry, err := crypto.New(cfg.PSK, timeWindowSec)
	if err != nil {
		return nil, fmt.Errorf("crypto init failed: %w", err)
	}

	controller := congestion.NewHysteria2Controller(cfg.UploadMbps, cfg.DownloadMbps)

	var trans Transport
	serverEndpoint := fmt.Sprintf("%s:%d", cfg.ServerAddr, cfg.ServerPort)

	// 平台兼容逻辑
	if cfg.TransportMode == "faketcp" && runtime.GOOS == "linux" {
		// 动态检测并调用，避免 Windows/Mac 下 undefined 错误
		ftConfig := transport.DefaultFakeTCPConfig()
		ftClient, err := transport.NewFakeTCPClient(serverEndpoint, ftConfig)
		if err != nil { return nil, err }
		trans = &fakeTCPAdapter{client: ftClient}
	} else {
		// 默认或非 Linux 平台回退到 UDP
		udpAddr, err := net.ResolveUDPAddr("udp", serverEndpoint)
		if err != nil { return nil, err }
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil { return nil, err }
		trans = conn
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

func (h *PhantomClientHandler) sendEncryptedPacket(payload []byte) error {
	for !h.controller.CanSend(len(payload)) {
		time.Sleep(h.controller.GetPacingInterval(len(payload)))
	}
	encrypted, err := h.crypto.Encrypt(payload)
	if err != nil { return err }
	n, err := h.transport.Write(encrypted)
	if err != nil { return err }
	h.controller.OnPacketSent(0, n, false) 
	atomic.AddUint64(&h.stats.bytesSent, uint64(n))
	atomic.AddUint64(&h.stats.packetsSent, 1)
	return nil
}

func (h *PhantomClientHandler) receiveLoop() {
	defer h.wg.Done()
	buf := make([]byte, 65535)
	for {
		select {
		case <-h.ctx.Done(): return
		default:
		}
		n, err := h.transport.Read(buf)
		if err != nil { return }
		decrypted, err := h.crypto.Decrypt(buf[:n])
		if err != nil { continue }
		resp, err := protocol.ParseServerResponse(decrypted)
		if err != nil { continue }
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

	payload, _ := protocol.BuildClientConnectRequest(reqID, protocol.NetworkTCP, targetAddr, targetPort, initData)
	h.sendEncryptedPacket(payload)

	if err := h.waitForConnectAck(session); err != nil { return err }
	atomic.StoreInt32(&session.state, StateConnected)
	return h.runDataRelay(session)
}

func (h *PhantomClientHandler) waitForConnectAck(session *Session) error {
	timer := time.NewTimer(ConnectTimeout)
	defer timer.Stop()
	for {
		select {
		case <-timer.C: return errors.New("timeout")
		case resp := <-session.recvChan:
			if resp.IsConnectAck() && resp.Status == protocol.StatusSuccess {
				return nil
			}
		}
	}
}

func (h *PhantomClientHandler) runDataRelay(session *Session) error {
	errChan := make(chan error, 2)
	go func() {
		buf := make([]byte, MaxPayloadSize)
		for {
			n, err := session.localConn.Read(buf)
			if err != nil { errChan <- nil; return }
			p := protocol.BuildClientDataRequest(session.reqID, buf[:n])
			h.sendEncryptedPacket(p)
		}
	}()
	go func() {
		for {
			select {
			case <-session.ctx.Done(): errChan <- nil; return
			case resp := <-session.recvChan:
				if resp.IsDataPacket() {
					session.localConn.Write(resp.Payload)
				}
			}
		}
	}()
	return <-errChan
}

func (h *PhantomClientHandler) unregisterSession(reqID uint32) {
	h.sessionsMu.Lock()
	if s, ok := h.sessions[reqID]; ok {
		s.cancel()
		s.localConn.Close()
		delete(h.sessions, reqID)
	}
	h.sessionsMu.Unlock()
}

func (h *PhantomClientHandler) maintenanceLoop() {
	defer h.wg.Done()
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-h.ctx.Done(): return
		case <-ticker.C:
			p := protocol.BuildClientHeartbeat(0)
			h.sendEncryptedPacket(p)
		}
	}
}

func (h *PhantomClientHandler) Close() error {
	h.cancel()
	h.wg.Wait()
	return h.transport.Close()
}

func (h *PhantomClientHandler) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total_sent": atomic.LoadUint64(&h.stats.bytesSent),
		"total_received": atomic.LoadUint64(&h.stats.bytesReceived),
	}
}
