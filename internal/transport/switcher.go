// =============================================================================
// 文件: internal/transport/switcher.go
// 描述: 传输层切换器 - 统一管理多种传输协议
// =============================================================================
package transport

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/mrcgq/211/internal/config"
	"github.com/mrcgq/211/internal/handler"
)

// =============================================================================
// 类型定义
// =============================================================================

// PacketHandler 数据包处理器接口（用于 UDP）
type PacketHandler interface {
	HandlePacket(data []byte, from *net.UDPAddr) []byte
}

// ConnectionHandler 连接处理器接口（用于 TCP）
type ConnectionHandler interface {
	HandleConnection(ctx context.Context, conn net.Conn)
}

// UnifiedHandler 统一处理器接口
type UnifiedHandler interface {
	PacketHandler
	ConnectionHandler
	WebSocketHandler
	SetSender(fn func(data []byte, addr *net.UDPAddr) error)
}

// TransportSwitcher 传输层切换器
type TransportSwitcher struct {
	cfg     *config.Config
	handler UnifiedHandler

	// 传输层实例
	udpServer *UDPServer
	tcpServer *TCPServer
	wsServer  *WebSocketServer

	ctx    context.Context
	cancel context.CancelFunc

	running int32
}

// =============================================================================
// 构造函数
// =============================================================================

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

// =============================================================================
// 生命周期管理
// =============================================================================

// Start 启动传输层
func (s *TransportSwitcher) Start() error {
	if !atomic.CompareAndSwapInt32(&s.running, 0, 1) {
		return fmt.Errorf("传输层已在运行")
	}

	// 根据配置启动相应的传输层
	switch s.cfg.Transport {
	case "udp":
		return s.startUDP()

	case "tcp":
		return s.startTCP()

	case "ws", "websocket":
		return s.startWebSocket()

	case "all":
		// 启动所有传输层
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
		// 默认启动 UDP 和 TCP
		if err := s.startUDP(); err != nil {
			return fmt.Errorf("启动 UDP 失败: %w", err)
		}
		if err := s.startTCP(); err != nil {
			return fmt.Errorf("启动 TCP 失败: %w", err)
		}
		return nil
	}
}

// startUDP 启动 UDP 服务
func (s *TransportSwitcher) startUDP() error {
	s.udpServer = NewUDPServer(s.cfg.Listen, s.handler, s.cfg.LogLevel)

	// 设置 sender
	s.handler.SetSender(s.udpServer.SendTo)

	return s.udpServer.Start(s.ctx)
}

// startTCP 启动 TCP 服务
func (s *TransportSwitcher) startTCP() error {
	s.tcpServer = NewTCPServer(s.cfg.Listen, s.handler, s.cfg.LogLevel)
	return s.tcpServer.Start(s.ctx)
}

// startWebSocket 启动 WebSocket 服务
func (s *TransportSwitcher) startWebSocket() error {
	wsPath := s.cfg.WSPath
	if wsPath == "" {
		wsPath = "/ws"
	}

	wsHost := s.cfg.WSHost

	// 确定端口
	addr := s.cfg.Listen
	if s.cfg.WSPort != "" {
		// 替换端口
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = "0.0.0.0"
		}
		addr = net.JoinHostPort(host, s.cfg.WSPort)
	}

	s.wsServer = NewWebSocketServer(
		addr,
		wsPath,
		wsHost,
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

// =============================================================================
// 状态查询
// =============================================================================

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

// =============================================================================
// 调试方法
// =============================================================================

// PrintStatus 打印状态
func (s *TransportSwitcher) PrintStatus() {
	fmt.Printf("\n=== 传输层状态 ===\n")
	fmt.Printf("模式: %s\n", s.cfg.Transport)
	fmt.Printf("监听: %s\n", s.cfg.Listen)
	fmt.Printf("运行中: %v\n", atomic.LoadInt32(&s.running) == 1)

	if s.udpServer != nil {
		fmt.Printf("UDP 连接数: %d\n", s.udpServer.GetActiveConns())
	}
	if s.tcpServer != nil {
		fmt.Printf("TCP 连接数: %d\n", s.tcpServer.GetActiveConns())
	}
	if s.wsServer != nil {
		fmt.Printf("WebSocket 连接数: %d\n", s.wsServer.GetActiveConns())
	}
	fmt.Printf("==================\n\n")
}

// =============================================================================
// 健康检查
// =============================================================================

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

// =============================================================================
// 辅助函数
// =============================================================================

func log(level int, configLevel string, format string, args ...interface{}) {
	maxLevel := 1
	switch configLevel {
	case "debug":
		maxLevel = 2
	case "error":
		maxLevel = 0
	}

	if level > maxLevel {
		return
	}

	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [Switcher] %s\n",
		prefix,
		time.Now().Format("15:04:05"),
		fmt.Sprintf(format, args...))
}
