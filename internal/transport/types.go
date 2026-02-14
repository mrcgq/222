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

// 注意: ARQHandler 已在 arq_types.go 中定义，此处不再重复
// 注意: TCPConnectionHandler 已在 tcp.go 中定义，此处不再重复
