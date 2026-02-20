// =============================================================================
// 文件: internal/transport/switcher.go
// 描述: 传输层切换器
// =============================================================================
package transport

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/mrcgq/211/internal/config"
	"github.com/mrcgq/211/internal/handler"
)

// =============================================================================
// 接口定义（与 handler.UnifiedHandler 方法对齐）
// =============================================================================

// PacketHandler 数据包处理器接口（UDP 模式）
type PacketHandler interface {
	HandlePacket(data []byte, from *net.UDPAddr) []byte
}

// ConnectionHandler 连接处理器接口（TCP 模式）
type ConnectionHandler interface {
	HandleConnection(ctx context.Context, conn net.Conn)
}

// SenderSetter 发送器设置接口
type SenderSetter interface {
	SetSender(fn handler.Sender)
}

// UnifiedHandler 统一处理器接口
// 聚合所有传输层需要的方法
type UnifiedHandler interface {
	PacketHandler
	ConnectionHandler
	WebSocketHandler
	SenderSetter
}

// =============================================================================
// TransportSwitcher
// =============================================================================

// TransportSwitcher 传输层切换器
type TransportSwitcher struct {
	cfg     *config.Config
	handler UnifiedHandler

	udpServer *UDPServer
	tcpServer *TCPServer
	wsServer  *WebSocketServer

	ctx    context.Context
	cancel context.CancelFunc

	running int32
}

// NewTransportSwitcher 创建传输层切换器
func NewTransportSwitcher(cfg *config.Config, h UnifiedHandler) *TransportSwitcher {
	ctx, cancel := context.WithCancel(context.Background())

	return &TransportSwitcher{
		cfg:     cfg,
		handler: h,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start 启动传输层
func (s *TransportSwitcher) Start() error {
	if !atomic.CompareAndSwapInt32(&s.running, 0, 1) {
		return fmt.Errorf("传输层已在运行")
	}

	switch s.cfg.Transport {
	case "udp":
		return s.startUDP()

	case "tcp":
		return s.startTCP()

	case "ws", "websocket":
		return s.startWebSocket()

	case "all":
		if err := s.startUDP(); err != nil {
			return fmt.Errorf("启动 UDP 失败: %w", err)
		}
		if err := s.startTCP(); err != nil {
			return fmt.Errorf("启动 TCP 失败: %w", err)
		}
		if err := s.startWebSocket(); err != nil {
			return fmt.Errorf("启动 WebSocket 失败: %w", err)
		}
		return nil

	default:
		// 默认启动 UDP + TCP
		if err := s.startUDP(); err != nil {
			return fmt.Errorf("启动 UDP 失败: %w", err)
		}
		if err := s.startTCP(); err != nil {
			return fmt.Errorf("启动 TCP 失败: %w", err)
		}
		return nil
	}
}

func (s *TransportSwitcher) startUDP() error {
	s.udpServer = NewUDPServer(s.cfg.Listen, s.handler, s.cfg.LogLevel)

	// 设置 sender，使用类型转换确保兼容
	s.handler.SetSender(func(data []byte, addr *net.UDPAddr) error {
		return s.udpServer.SendTo(data, addr)
	})

	return s.udpServer.Start(s.ctx)
}

func (s *TransportSwitcher) startTCP() error {
	s.tcpServer = NewTCPServer(s.cfg.Listen, s.handler, s.cfg.LogLevel)
	return s.tcpServer.Start(s.ctx)
}

func (s *TransportSwitcher) startWebSocket() error {
	wsPath := s.cfg.WSPath
	if wsPath == "" {
		wsPath = "/ws"
	}

	addr := s.cfg.Listen
	if s.cfg.WSPort != "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = "0.0.0.0"
		}
		addr = net.JoinHostPort(host, s.cfg.WSPort)
	}

	s.wsServer = NewWebSocketServer(
		addr,
		wsPath,
		s.cfg.WSHost,
		s.cfg.TLS,
		s.cfg.CertFile,
		s.cfg.KeyFile,
		s.handler,
		s.cfg.LogLevel,
	)

	return s.wsServer.Start(s.ctx)
}

// Stop 停止传输层
func (s *TransportSwitcher) Stop() error {
	if !atomic.CompareAndSwapInt32(&s.running, 1, 0) {
		return nil
	}

	s.cancel()

	if s.udpServer != nil {
		s.udpServer.Stop()
	}
	if s.tcpServer != nil {
		s.tcpServer.Stop()
	}
	if s.wsServer != nil {
		s.wsServer.Stop()
	}

	return nil
}

// GetActiveConns 获取活跃连接数
func (s *TransportSwitcher) GetActiveConns() int64 {
	var total int64
	if s.udpServer != nil {
		total += s.udpServer.GetActiveConns()
	}
	if s.tcpServer != nil {
		total += s.tcpServer.GetActiveConns()
	}
	if s.wsServer != nil {
		total += s.wsServer.GetActiveConns()
	}
	return total
}

// GetTransportStats 获取传输层统计
func (s *TransportSwitcher) GetTransportStats() map[string]interface{} {
	stats := make(map[string]interface{})

	if s.udpServer != nil {
		stats["udp_conns"] = s.udpServer.GetActiveConns()
	}
	if s.tcpServer != nil {
		stats["tcp_conns"] = s.tcpServer.GetActiveConns()
	}
	if s.wsServer != nil {
		stats["ws_conns"] = s.wsServer.GetActiveConns()
	}

	stats["transport_mode"] = s.cfg.Transport
	stats["listen_addr"] = s.cfg.Listen

	return stats
}

// HealthCheck 健康检查
func (s *TransportSwitcher) HealthCheck() error {
	if atomic.LoadInt32(&s.running) != 1 {
		return fmt.Errorf("传输层未运行")
	}

	select {
	case <-s.ctx.Done():
		return fmt.Errorf("传输层上下文已取消")
	default:
	}

	return nil
}
