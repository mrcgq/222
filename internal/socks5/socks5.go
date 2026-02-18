









// internal/socks5/socks5.go
// SOCKS5 代理服务器 - RFC 1928 标准实现
// 作为 Windows 客户端的流量入口

package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================
// SOCKS5 协议常量
// ============================================

const (
	Version5 = 0x05

	// 认证方法
	AuthNone     = 0x00
	AuthGSSAPI   = 0x01
	AuthPassword = 0x02
	AuthNoAccept = 0xFF

	// 命令类型
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03

	// 地址类型
	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04

	// 回复状态
	RepSuccess             = 0x00
	RepGeneralFailure      = 0x01
	RepConnectionNotAllowed = 0x02
	RepNetworkUnreachable  = 0x03
	RepHostUnreachable     = 0x04
	RepConnectionRefused   = 0x05
	RepTTLExpired          = 0x06
	RepCommandNotSupported = 0x07
	RepAddressNotSupported = 0x08
)

// ============================================
// 接口定义
// ============================================

// ClientHandler 客户端处理器接口
// 由 handler.PhantomClientHandler 实现
type ClientHandler interface {
	// Handle 处理已建立的本地连接
	// conn: 本地 SOCKS5 客户端连接
	// targetAddr: 目标主机地址（IP或域名）
	// targetPort: 目标端口
	// initData: 0-RTT 预读取的初始数据（可为空）
	Handle(conn net.Conn, targetAddr string, targetPort uint16, initData []byte) error
}

// ============================================
// 服务器结构
// ============================================

// Server SOCKS5 代理服务器
type Server struct {
	addr     string
	handler  ClientHandler
	listener net.Listener

	// 配置
	readTimeout  time.Duration
	writeTimeout time.Duration

	// 状态
	closed    int32
	closeOnce sync.Once
	closeChan chan struct{}

	// 统计
	activeConns int64
	totalConns  uint64
}

// Config 服务器配置
type Config struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// ============================================
// 构造函数
// ============================================

// New 创建 SOCKS5 服务器
func New(addr string, handler ClientHandler) *Server {
	return NewWithConfig(&Config{
		Addr:         addr,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}, handler)
}

// NewWithConfig 使用配置创建服务器
func NewWithConfig(cfg *Config, handler ClientHandler) *Server {
	return &Server{
		addr:         cfg.Addr,
		handler:      handler,
		readTimeout:  cfg.ReadTimeout,
		writeTimeout: cfg.WriteTimeout,
		closeChan:    make(chan struct{}),
	}
}

// ============================================
// 服务器生命周期
// ============================================

// Listen 启动监听
func (s *Server) Listen() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("socks5: listen failed: %w", err)
	}
	s.listener = listener

	for {
		select {
		case <-s.closeChan:
			return nil
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			if atomic.LoadInt32(&s.closed) == 1 {
				return nil
			}
			continue
		}

		atomic.AddInt64(&s.activeConns, 1)
		atomic.AddUint64(&s.totalConns, 1)

		go s.handleConnection(conn)
	}
}

// Close 关闭服务器
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		atomic.StoreInt32(&s.closed, 1)
		close(s.closeChan)
		if s.listener != nil {
			err = s.listener.Close()
		}
	})
	return err
}

// Stats 返回统计信息
func (s *Server) Stats() (active int64, total uint64) {
	return atomic.LoadInt64(&s.activeConns), atomic.LoadUint64(&s.totalConns)
}

// GetAddr 返回监听地址
func (s *Server) GetAddr() string {
	return s.addr
}

// ============================================
// 连接处理
// ============================================

// handleConnection 处理单个连接
func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		atomic.AddInt64(&s.activeConns, -1)
	}()

	// 设置读取超时
	if s.readTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	}

	// 1. 协商阶段
	if err := s.handleNegotiation(conn); err != nil {
		return
	}

	// 2. 请求阶段
	targetAddr, targetPort, err := s.handleRequest(conn)
	if err != nil {
		s.sendReply(conn, RepGeneralFailure)
		return
	}

	// 3. 发送成功响应（激活 0-RTT）
	if err := s.sendReply(conn, RepSuccess); err != nil {
		return
	}

	// 4. 尝试 0-RTT 预读取
	initData := s.tryReadInitData(conn)

	// 清除超时，交给 handler 管理
	conn.SetDeadline(time.Time{})

	// 5. 交给 Phantom 协议处理器
	s.handler.Handle(conn, targetAddr, targetPort, initData)
}

// handleNegotiation 处理协商阶段
func (s *Server) handleNegotiation(conn net.Conn) error {
	buf := make([]byte, 258)

	// 读取版本和方法数量
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return err
	}

	// 验证版本
	if buf[0] != Version5 {
		return errors.New("unsupported SOCKS version")
	}

	nMethods := int(buf[1])
	if nMethods == 0 {
		return errors.New("no auth methods")
	}

	// 读取方法列表
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return err
	}

	// 检查是否支持无认证
	hasNoAuth := false
	for i := 0; i < nMethods; i++ {
		if buf[i] == AuthNone {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		conn.Write([]byte{Version5, AuthNoAccept})
		return errors.New("no acceptable auth method")
	}

	// 发送选择无认证
	_, err := conn.Write([]byte{Version5, AuthNone})
	return err
}

// handleRequest 处理请求阶段
func (s *Server) handleRequest(conn net.Conn) (string, uint16, error) {
	buf := make([]byte, 262)

	// 读取请求头
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return "", 0, err
	}

	if buf[0] != Version5 {
		return "", 0, errors.New("invalid version in request")
	}

	cmd := buf[1]
	atyp := buf[3]

	// 只支持 CONNECT
	if cmd != CmdConnect {
		s.sendReply(conn, RepCommandNotSupported)
		return "", 0, errors.New("unsupported command")
	}

	// 解析地址
	var targetAddr string
	switch atyp {
	case AtypIPv4:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return "", 0, err
		}
		targetAddr = net.IP(buf[:4]).String()

	case AtypDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", 0, err
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return "", 0, err
		}
		targetAddr = string(buf[:domainLen])

	case AtypIPv6:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return "", 0, err
		}
		targetAddr = net.IP(buf[:16]).String()

	default:
		s.sendReply(conn, RepAddressNotSupported)
		return "", 0, errors.New("unsupported address type")
	}

	// 读取端口
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", 0, err
	}
	targetPort := binary.BigEndian.Uint16(buf[:2])

	return targetAddr, targetPort, nil
}

// tryReadInitData 尝试 0-RTT 预读取
func (s *Server) tryReadInitData(conn net.Conn) []byte {
	conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	
	conn.SetReadDeadline(time.Time{})
	
	if n > 0 {
		data := make([]byte, n)
		copy(data, buf[:n])
		return data
	}
	return nil
}

// sendReply 发送响应
func (s *Server) sendReply(conn net.Conn, rep byte) error {
	// VER + REP + RSV + ATYP + BND.ADDR + BND.PORT
	reply := []byte{
		Version5,
		rep,
		0x00,     // RSV
		AtypIPv4, // ATYP
		0, 0, 0, 0, // BND.ADDR (0.0.0.0)
		0, 0, // BND.PORT (0)
	}
	_, err := conn.Write(reply)
	return err
}

