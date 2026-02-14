

// =============================================================================
// 文件: internal/transport/arq_manager.go
// 描述: ARQ 可靠传输 - 连接管理器 (统一版本)
// =============================================================================
package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrcgq/211/internal/congestion"
)

// ARQManager ARQ 连接管理器
type ARQManager struct {
	// 配置
	config     *ARQConnConfig
	congestion *congestion.Hysteria2Controller
	handler    ARQHandler

	// 连接池
	conns sync.Map // remoteAddr.String() -> *ARQConn

	// 统计
	totalConns  uint64
	activeConns int64

	// 控制
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex
}

// NewARQManager 创建 ARQ 管理器
func NewARQManager(
	udpConn *net.UDPConn, // 可以为 nil
	cc *congestion.Hysteria2Controller,
	handler ARQHandler,
) *ARQManager {
	config := DefaultARQConnConfig()

	ctx, cancel := context.WithCancel(context.Background())

	m := &ARQManager{
		config:     config,
		congestion: cc,
		handler:    handler,
		ctx:        ctx,
		cancel:     cancel,
	}

	// 启动清理协程
	m.wg.Add(1)
	go m.cleanupLoop()

	return m
}

// NewARQManagerWithConfig 创建带配置的 ARQ 管理器
func NewARQManagerWithConfig(
	config *ARQConnConfig,
	cc *congestion.Hysteria2Controller,
	handler ARQHandler,
) *ARQManager {
	if config == nil {
		config = DefaultARQConnConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &ARQManager{
		config:     config,
		congestion: cc,
		handler:    handler,
		ctx:        ctx,
		cancel:     cancel,
	}

	// 启动清理协程
	m.wg.Add(1)
	go m.cleanupLoop()

	return m
}

// HandlePacket 处理收到的 ARQ 包
func (m *ARQManager) HandlePacket(data []byte, from *net.UDPAddr, udpConn *net.UDPConn) error {
	// 解码包
	pkt, err := DecodeARQPacket(data)
	if err != nil {
		return fmt.Errorf("解码失败: %w", err)
	}

	key := from.String()

	// 查找或创建连接
	connI, exists := m.conns.Load(key)

	if !exists {
		// 新连接：必须是 SYN 包
		if pkt.Flags&ARQFlagSYN == 0 || pkt.Flags&ARQFlagACK != 0 {
			// 不是 SYN，发送 RST
			rst := NewRstPacket(0)
			rstData := rst.Encode()
			udpConn.WriteToUDP(rstData, from)
			return fmt.Errorf("非 SYN 包来自未知连接")
		}

		// 创建新连接
		conn := NewARQConn(udpConn, from, m.config, m.congestion, m.handler)
		if err := conn.Accept(pkt); err != nil {
			return fmt.Errorf("接受连接失败: %w", err)
		}

		// 存储连接
		actual, loaded := m.conns.LoadOrStore(key, conn)
		if loaded {
			// 另一个协程已创建
			conn.Close()
			conn = actual.(*ARQConn)
		} else {
			// 启动连接
			conn.Start()
			atomic.AddUint64(&m.totalConns, 1)
			atomic.AddInt64(&m.activeConns, 1)
		}

		return nil
	}

	// 现有连接
	conn := connI.(*ARQConn)
	conn.HandlePacket(pkt)

	return nil
}

// GetConn 获取连接
func (m *ARQManager) GetConn(addr *net.UDPAddr) *ARQConn {
	key := addr.String()
	if connI, ok := m.conns.Load(key); ok {
		return connI.(*ARQConn)
	}
	return nil
}

// GetOrCreateConn 获取或创建连接
func (m *ARQManager) GetOrCreateConn(
	udpConn *net.UDPConn,
	remoteAddr *net.UDPAddr,
	ctx context.Context,
) *ARQConn {
	key := remoteAddr.String()

	// 检查是否已存在
	if connI, ok := m.conns.Load(key); ok {
		return connI.(*ARQConn)
	}

	// 创建新连接
	conn := NewARQConn(udpConn, remoteAddr, m.config, m.congestion, m.handler)

	// 存储
	actual, loaded := m.conns.LoadOrStore(key, conn)
	if loaded {
		conn.Close()
		return actual.(*ARQConn)
	}

	atomic.AddUint64(&m.totalConns, 1)
	atomic.AddInt64(&m.activeConns, 1)

	return conn
}




// CreateConn 创建主动连接
func (m *ARQManager) CreateConn(
	udpConn *net.UDPConn,
	remoteAddr *net.UDPAddr,
) (*ARQConn, error) {
	key := remoteAddr.String()

	// 检查是否已存在
	if connI, ok := m.conns.Load(key); ok {
		return connI.(*ARQConn), nil
	}

	// 创建新连接
	conn := NewARQConn(udpConn, remoteAddr, m.config, m.congestion, m.handler)

	// 存储
	actual, loaded := m.conns.LoadOrStore(key, conn)
	if loaded {
		conn.Close()
		return actual.(*ARQConn), nil
	}

	atomic.AddUint64(&m.totalConns, 1)
	atomic.AddInt64(&m.activeConns, 1)

	return conn, nil
}

// RemoveConn 移除连接
func (m *ARQManager) RemoveConn(addr *net.UDPAddr) {
	key := addr.String()
	if connI, ok := m.conns.LoadAndDelete(key); ok {
		conn := connI.(*ARQConn)
		conn.Close()
		atomic.AddInt64(&m.activeConns, -1)
	}
}

// cleanupLoop 清理循环
func (m *ARQManager) cleanupLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

// cleanup 清理过期连接
func (m *ARQManager) cleanup() {
	m.conns.Range(func(key, value interface{}) bool {
		conn := value.(*ARQConn)

		// 检查是否已关闭
		if conn.IsClosed() {
			m.conns.Delete(key)
			atomic.AddInt64(&m.activeConns, -1)
			return true
		}

		// 检查状态
		state := conn.GetState()
		if state == ARQStateClosed || state == ARQStateTimeWait {
			conn.Close()
			m.conns.Delete(key)
			atomic.AddInt64(&m.activeConns, -1)
		}

		return true
	})
}

// GetActiveConns 获取活跃连接数
func (m *ARQManager) GetActiveConns() int64 {
	return atomic.LoadInt64(&m.activeConns)
}

// GetTotalConns 获取总连接数
func (m *ARQManager) GetTotalConns() uint64 {
	return atomic.LoadUint64(&m.totalConns)
}

// GetAllConns 获取所有连接
func (m *ARQManager) GetAllConns() []*ARQConn {
	var conns []*ARQConn
	m.conns.Range(func(key, value interface{}) bool {
		conns = append(conns, value.(*ARQConn))
		return true
	})
	return conns
}

// Broadcast 广播数据到所有连接
func (m *ARQManager) Broadcast(data []byte) int {
	count := 0
	m.conns.Range(func(key, value interface{}) bool {
		conn := value.(*ARQConn)
		if conn.IsEstablished() {
			if err := conn.Send(data); err == nil {
				count++
			}
		}
		return true
	})
	return count
}

// Close 关闭管理器
func (m *ARQManager) Close() {
	m.cancel()

	// 关闭所有连接
	m.conns.Range(func(key, value interface{}) bool {
		conn := value.(*ARQConn)
		conn.Close()
		m.conns.Delete(key)
		return true
	})

	m.wg.Wait()
}

// GetStats 获取统计
func (m *ARQManager) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["total_conns"] = atomic.LoadUint64(&m.totalConns)
	stats["active_conns"] = atomic.LoadInt64(&m.activeConns)

	connStats := make([]map[string]interface{}, 0)
	m.conns.Range(func(key, value interface{}) bool {
		conn := value.(*ARQConn)
		s := conn.GetStats()
		connStats = append(connStats, map[string]interface{}{
			"remote_addr":    key.(string),
			"state":          s.State,
			"bytes_sent":     s.BytesSent,
			"bytes_received": s.BytesReceived,
			"retransmits":    s.Retransmits,
			"rtt_ms":         s.SRTT.Milliseconds(),
		})
		return true
	})
	stats["connections"] = connStats

	return stats
}

