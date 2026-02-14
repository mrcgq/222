



// =============================================================================
// 文件: internal/transport/types.go
// 描述: 传输层统一类型定义 - 消除重复定义
// =============================================================================
package transport

import (
	"net"
)

// PacketHandler 数据包处理接口
type PacketHandler interface {
	HandlePacket(data []byte, from *net.UDPAddr) []byte
}

// ARQHandler ARQ 事件处理接口
type ARQHandler interface {
	OnData(data []byte, from *net.UDPAddr)
	OnConnected(addr *net.UDPAddr)
	OnDisconnected(addr *net.UDPAddr, reason error)
}

// TCPConnectionHandler TCP 连接处理接口
type TCPConnectionHandler interface {
	HandleConnection(ctx context.Context, conn net.Conn)
}



