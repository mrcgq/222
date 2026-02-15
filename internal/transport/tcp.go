// =============================================================================
// 文件: internal/transport/tcp.go
// 描述: TCP 传输层 - 集成 TLS 嗅探和指纹伪装
// =============================================================================
package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/mrcgq/211/internal/config"
)

const (
	// 长度前缀大小（2字节，最大 65535）
	LengthPrefixSize = 2
	// 最大包大小
	MaxPacketSize = 65535
	// 读写超时
	ReadTimeout  = 5 * time.Minute
	WriteTimeout = 30 * time.Second
)

// TCPConnectionHandler TCP 连接处理接口 (唯一定义位置)
type TCPConnectionHandler interface {
	HandleConnection(ctx context.Context, conn net.Conn)
}

// TCPServer TCP 服务器
type TCPServer struct {
	addr     string
	listener net.Listener
	handler  TCPConnectionHandler
	logLevel int

	// TLS 配置
	tlsEnabled  bool
	tlsConfig   *tls.Config
	sniffer     *Sniffer
	certManager TLSCertProvider

	// 连接管理
	conns  sync.Map // net.Conn -> struct{}
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// TLSCertProvider TLS 证书提供者接口
type TLSCertProvider interface {
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
	GetTLSConfig() *tls.Config
}

// TCPServerOption 服务器选项
type TCPServerOption func(*TCPServer)

// WithTLSConfig 设置 TLS 配置
func WithTLSConfig(tlsConfig *tls.Config) TCPServerOption {
	return func(s *TCPServer) {
		s.tlsEnabled = true
		s.tlsConfig = tlsConfig
	}
}

// WithCertManager 设置证书管理器
func WithCertManager(cm TLSCertProvider) TCPServerOption {
	return func(s *TCPServer) {
		s.certManager = cm
	}
}

// WithSniffer 设置嗅探器
func WithSniffer(sniffer *Sniffer) TCPServerOption {
	return func(s *TCPServer) {
		s.sniffer = sniffer
	}
}

// WithTLSEnabled 启用 TLS
func WithTLSEnabled(enabled bool) TCPServerOption {
	return func(s *TCPServer) {
		s.tlsEnabled = enabled
	}
}

// NewTCPServer 创建 TCP 服务器
func NewTCPServer(addr string, handler TCPConnectionHandler, logLevel string, opts ...TCPServerOption) *TCPServer {
	level := 1
	switch logLevel {
	case "debug":
		level = 2
	case "error":
		level = 0
	}

	s := &TCPServer{
		addr:     addr,
		handler:  handler,
		logLevel: level,
		stopCh:   make(chan struct{}),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// NewTCPServerWithTLS 创建带 TLS 的 TCP 服务器
func NewTCPServerWithTLS(addr string, handler TCPConnectionHandler, tlsCfg *config.TLSConfig, certProvider TLSCertProvider, logLevel string) *TCPServer {
	level := 1
	switch logLevel {
	case "debug":
		level = 2
	case "error":
		level = 0
	}

	s := &TCPServer{
		addr:        addr,
		handler:     handler,
		logLevel:    level,
		stopCh:      make(chan struct{}),
		tlsEnabled:  tlsCfg.Enabled,
		certManager: certProvider,
	}

	// 创建嗅探器
	if tlsCfg.FallbackEnabled {
		snifferConfig := &SnifferConfig{
			FallbackEnabled: true,
			FallbackAddr:    tlsCfg.FallbackAddr,
			FallbackTimeout: time.Duration(tlsCfg.FallbackTimeout) * time.Second,
			LogLevel:        level,
		}
		s.sniffer = NewSniffer(snifferConfig)
	}

	// 创建 TLS 配置
	if tlsCfg.Enabled {
		s.tlsConfig = s.createTLSConfig(tlsCfg)
	}

	return s
}

// createTLSConfig 创建 TLS 配置
func (s *TCPServer) createTLSConfig(cfg *config.TLSConfig) *tls.Config {
	tlsConfig := &tls.Config{
		MinVersion: ParseTLSVersion(cfg.MinVersion),
		MaxVersion: ParseTLSVersion(cfg.MaxVersion),
		NextProtos: cfg.ALPN,
	}

	// 使用证书管理器的 GetCertificate
	if s.certManager != nil {
		tlsConfig.GetCertificate = s.certManager.GetCertificate
	} else if cfg.CertFile != "" && cfg.KeyFile != "" {
		// 加载静态证书
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			s.log(0, "加载证书失败: %v", err)
		} else {
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	// 会话票据
	if !cfg.SessionTicket {
		tlsConfig.SessionTicketsDisabled = true
	}

	return tlsConfig
}

// Start 启动服务器
func (s *TCPServer) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("监听失败: %w", err)
	}
	s.listener = listener

	s.wg.Add(1)
	go s.acceptLoop(ctx)

	s.log(1, "TCP 服务器已启动: %s (TLS: %v)", s.addr, s.tlsEnabled)
	return nil
}

// acceptLoop 接受连接循环
func (s *TCPServer) acceptLoop(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		default:
		}

		// 设置 accept 超时
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			_ = tcpListener.SetDeadline(time.Now().Add(time.Second))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-s.stopCh:
				return
			default:
				s.log(2, "Accept 错误: %v", err)
				continue
			}
		}

		// 配置连接
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}

		// 记录连接
		s.conns.Store(conn, struct{}{})

		// 处理连接
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer func() {
				s.conns.Delete(c)
				_ = c.Close()
			}()
			s.handleConnection(ctx, c)
		}(conn)
	}
}

// handleConnection 处理单个连接
func (s *TCPServer) handleConnection(ctx context.Context, conn net.Conn) {
	// 如果启用 TLS 嗅探
	if s.tlsEnabled && s.sniffer != nil {
		err := s.sniffer.HandleWithFallback(conn, func(sniffedConn net.Conn, sni string) error {
			return s.handleTLSConnection(ctx, sniffedConn, sni)
		})
		if err != nil {
			s.log(2, "嗅探处理失败: %v", err)
		}
		return
	}

	// 如果启用 TLS 但没有嗅探器
	if s.tlsEnabled && s.tlsConfig != nil {
		tlsConn := tls.Server(conn, s.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			s.log(2, "TLS 握手失败: %v", err)
			return
		}
		s.handler.HandleConnection(ctx, tlsConn)
		return
	}

	// 普通 TCP 连接
	s.handler.HandleConnection(ctx, conn)
}

// handleTLSConnection 处理 TLS 连接
func (s *TCPServer) handleTLSConnection(ctx context.Context, conn net.Conn, sni string) error {
	// 根据 SNI 选择证书
	tlsConfig := s.tlsConfig.Clone()

	if s.certManager != nil {
		tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// 可以根据 SNI 返回不同证书
			return s.certManager.GetCertificate(hello)
		}
	}

	// 创建 TLS 连接
	tlsConn := tls.Server(conn, tlsConfig)

	// 执行握手
	if err := tlsConn.Handshake(); err != nil {
		s.log(2, "TLS 握手失败 (SNI: %s): %v", sni, err)
		return err
	}

	state := tlsConn.ConnectionState()
	s.log(2, "TLS 连接建立: SNI=%s, ALPN=%s, Version=0x%04x",
		sni, state.NegotiatedProtocol, state.Version)

	// 交给业务处理器
	s.handler.HandleConnection(ctx, tlsConn)
	return nil
}

// Stop 停止服务器
func (s *TCPServer) Stop() {
	close(s.stopCh)

	if s.listener != nil {
		_ = s.listener.Close()
	}

	// 关闭嗅探器
	if s.sniffer != nil {
		s.sniffer.Close()
	}

	// 关闭所有连接
	s.conns.Range(func(key, _ interface{}) bool {
		if conn, ok := key.(net.Conn); ok {
			_ = conn.Close()
		}
		return true
	})

	s.wg.Wait()
}

// GetSnifferStats 获取嗅探器统计
func (s *TCPServer) GetSnifferStats() *SnifferStats {
	if s.sniffer == nil {
		return nil
	}
	stats := s.sniffer.GetStats()
	return &stats
}

func (s *TCPServer) log(level int, format string, args ...interface{}) {
	if level > s.logLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [TCP] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

// =============================================================================
// 帧读写器（保持不变）
// =============================================================================

// FrameReader 帧读取器（处理 TCP 流式数据）
type FrameReader struct {
	conn    net.Conn
	buf     []byte
	timeout time.Duration
}

// NewFrameReader 创建帧读取器
func NewFrameReader(conn net.Conn, timeout time.Duration) *FrameReader {
	return &FrameReader{
		conn:    conn,
		buf:     make([]byte, MaxPacketSize+LengthPrefixSize),
		timeout: timeout,
	}
}

// ReadFrame 读取一个完整的帧
// 格式: Length(2) + Data(Length)
func (r *FrameReader) ReadFrame() ([]byte, error) {
	// 设置读取超时
	if r.timeout > 0 {
		_ = r.conn.SetReadDeadline(time.Now().Add(r.timeout))
	}

	// 读取长度前缀
	lengthBuf := r.buf[:LengthPrefixSize]
	if _, err := io.ReadFull(r.conn, lengthBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(lengthBuf)
	if length == 0 {
		return nil, fmt.Errorf("无效的帧长度: 0")
	}
	if length > MaxPacketSize {
		return nil, fmt.Errorf("帧太大: %d", length)
	}

	// 读取数据
	data := r.buf[LengthPrefixSize : LengthPrefixSize+length]
	if _, err := io.ReadFull(r.conn, data); err != nil {
		return nil, err
	}

	// 返回数据的副本
	result := make([]byte, length)
	copy(result, data)
	return result, nil
}

// FrameWriter 帧写入器
type FrameWriter struct {
	conn    net.Conn
	buf     []byte
	timeout time.Duration
	mu      sync.Mutex
}

// NewFrameWriter 创建帧写入器
func NewFrameWriter(conn net.Conn, timeout time.Duration) *FrameWriter {
	return &FrameWriter{
		conn:    conn,
		buf:     make([]byte, MaxPacketSize+LengthPrefixSize),
		timeout: timeout,
	}
}

// WriteFrame 写入一个帧
func (w *FrameWriter) WriteFrame(data []byte) error {
	if len(data) > MaxPacketSize {
		return fmt.Errorf("数据太大: %d > %d", len(data), MaxPacketSize)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// 设置写入超时
	if w.timeout > 0 {
		_ = w.conn.SetWriteDeadline(time.Now().Add(w.timeout))
	}

	// 构建帧: Length(2) + Data
	binary.BigEndian.PutUint16(w.buf[:LengthPrefixSize], uint16(len(data)))
	copy(w.buf[LengthPrefixSize:], data)

	// 写入
	total := LengthPrefixSize + len(data)
	_, err := w.conn.Write(w.buf[:total])
	return err
}
