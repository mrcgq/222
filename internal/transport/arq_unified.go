// =============================================================================
// 文件: internal/transport/arq_unified.go
// 描述: ARQ 统一接口适配器 - 解决版本冲突
// =============================================================================
package transport

import (
	"time"

	"github.com/mrcgq/211/internal/congestion"
)

// ARQCongestionAdapter 拥塞控制适配器
// 解决 Hysteria2Controller 和 ARQ 之间的接口差异
type ARQCongestionAdapter struct {
	cc *congestion.Hysteria2Controller
}

// NewARQCongestionAdapter 创建适配器
func NewARQCongestionAdapter(cc *congestion.Hysteria2Controller) *ARQCongestionAdapter {
	return &ARQCongestionAdapter{cc: cc}
}

// OnAck 适配 ARQ 的 OnAck 调用
func (a *ARQCongestionAdapter) OnAck(ackedBytes int, rtt time.Duration) {
	if a.cc != nil {
		// 使用递增的包号（简化处理）
		a.cc.OnPacketAcked(0, ackedBytes, rtt)
	}
}

// OnPacketSent 适配发送
func (a *ARQCongestionAdapter) OnPacketSent(size int) {
	if a.cc != nil {
		pktNum := a.cc.NextPacketNumber()
		a.cc.OnPacketSent(pktNum, size, false)
	}
}

// OnPacketLost 适配丢包
func (a *ARQCongestionAdapter) OnPacketLost(size int) {
	if a.cc != nil {
		a.cc.OnPacketLost(0, size)
	}
}

// CanSend 检查是否可以发送
func (a *ARQCongestionAdapter) CanSend(size int) bool {
	if a.cc != nil {
		return a.cc.CanSend(size)
	}
	return true
}
