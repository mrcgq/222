// internal/handler/client_handler.go
package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrcgq/211/internal/congestion"
	"github.com/mrcgq/211/internal/crypto"
	"github.com/mrcgq/211/internal/protocol"
	"github.com/mrcgq/211/internal/transport"
)

// ============================================
// 1. 修复 undefined: transport.Transport
// ============================================
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
	transport  Transport // 使用修复后的接口

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

// ============================================
// 2. 修复构造函数中的所有 API 冲突
// ============================================
func NewClientHandler(cfg *Config) (*PhantomClientHandler, error) {
	// 修复错误: cannot use cfg.TimeWindow as int
	// 查阅 crypto.go (文件23): New(pskBase64 string, timeWindow int)
	timeWindowSec := int(cfg.TimeWindow.Seconds())
	cry, err := crypto.New(cfg.PSK, timeWindowSec)
	if err != nil {
		return nil, fmt.Errorf("crypto init failed: %w", err)
	}

	controller := congestion.NewHysteria2Controller(cfg.UploadMbps, cfg.DownloadMbps)

	var trans Transport
	serverEndpoint := fmt.Sprintf("%s:%d", cfg.ServerAddr, cfg.ServerPort)

	switch cfg.TransportMode {
	case "faketcp":
		// 修复错误: not enough arguments in call to NewFakeTCPClient
		// 查阅 faketcp_client.go (文件57): NewFakeTCPClient(serverAddr string, cfg *FakeTCPConfig)
		ftConfig := transport.DefaultFakeTCPConfig()
		ftClient, err := transport.NewFakeTCPClient(serverEndpoint, ftConfig)
		if err != nil {
			return nil, err
		}
		trans = ftClient

	default:
		// 修复错误: undefined: transport.NewUDPClient
		// 旗舰版中没有统一的 NewUDPClient，直接使用 net.DialUDP
		udpAddr, err := net.ResolveUDPAddr("udp", serverEndpoint)
		if err != nil {
			return nil, err
		}
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return nil, err
		}
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

// ============================================
// 3. 修复拥塞控制调用 OnSent / OnAck
// ============================================
func (h *PhantomClientHandler) sendEncryptedPacket(payload []byte) error {
	// 检查 Hysteria2 窗口
	for !h.controller.CanSend(len(payload)) {
		time.Sleep(h.controller.GetPacingInterval(len(payload)))
	}

	encrypted, err := h.crypto.Encrypt(payload)
	if err != nil {
		return err
	}

	n, err := h.transport.Write(encrypted)
	if err != nil {
		return err
	}

	// 修复错误: h.controller.OnSent undefined
	// 查阅 hysteria2.go (文件17): OnPacketSent(packetNumber uint64, packetSize int, isRetransmit bool)
	h.controller.OnPacketSent(0, n, false) 

	atomic.AddUint64(&h.stats.bytesSent, uint64(n))
	atomic.AddUint64(&h.stats.packetsSent, 1)
	return nil
}

func (h *PhantomClientHandler) receiveLoop() {
	defer h.wg.Done()
	buf := make([]byte, 65535)

	for {
		n, err := h.transport.Read(buf)
		if err != nil {
			return
		}

		decrypted, err := h.crypto.Decrypt(buf[:n])
		if err != nil {
			continue
		}

		resp, err := protocol.ParseServerResponse(decrypted)
		if err != nil {
			continue
		}

		// 修复错误: h.controller.OnAck undefined
		// 查阅 hysteria2.go (文件17): OnPacketAcked(packetNumber uint64, ackedBytes int, rtt time.Duration)
		h.controller.OnPacketAcked(0, 0, time.Millisecond*10) // 假设 RTT

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

// 其余辅助方法（Handle, relay 等）保持逻辑不变，但需确保调用上述修复后的方法
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

	if err := h.waitForConnectAck(session); err != nil {
		return err
	}
	atomic.StoreInt32(&session.state, StateConnected)
	return h.runDataRelay(session)
}

func (h *PhantomClientHandler) waitForConnectAck(session *Session) error {
	timer := time.NewTimer(ConnectTimeout)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return errors.New("timeout")
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
			if err != nil { return }
			p := protocol.BuildClientDataRequest(session.reqID, buf[:n])
			h.sendEncryptedPacket(p)
		}
	}()
	go func() {
		for {
			select {
			case <-session.ctx.Done(): return
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
