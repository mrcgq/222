// =============================================================================
// 文件: internal/congestion/adapter.go
// 描述: 拥塞控制适配器 - 统一接口 (修复版：支持 ARQ 序列号映射)
// =============================================================================
package congestion

import (
	"sync"
	"time"
)

// AdapterPacketInfo 适配器内部使用的数据包信息（与 types.go 中的 PacketInfo 区分）
type AdapterPacketInfo struct {
	PktNum       uint64    // 拥塞控制器的包编号
	Size         int       // 数据包大小
	SentTime     time.Time // 首次发送时间（用于 RTT 计算）
	Retransmit   bool      // 是否为重传包
	RetransCount int       // 重传次数
}

// CongestionAdapter 拥塞控制适配器
// 提供简化接口给 ARQ 和其他组件使用
type CongestionAdapter struct {
	cc *Hysteria2Controller

	// ARQ 序列号 -> 拥塞控制包信息的映射
	seqToPktInfo map[uint32]*AdapterPacketInfo

	// 拥塞控制 pktNum -> ARQ 序列号的反向映射（用于丢包通知）
	pktNumToSeq map[uint64]uint32

	nextPktNum uint64
	mu         sync.Mutex
}

// NewCongestionAdapter 创建适配器
func NewCongestionAdapter(cc *Hysteria2Controller) *CongestionAdapter {
	return &CongestionAdapter{
		cc:           cc,
		seqToPktInfo: make(map[uint32]*AdapterPacketInfo),
		pktNumToSeq:  make(map[uint64]uint32),
		nextPktNum:   1,
	}
}

// OnARQPacketSent ARQ 数据包发送（建立序列号映射）
// seq: ARQ 层的序列号
// size: 数据包大小
// isRetransmit: 是否为重传
// 返回: 拥塞控制器的 pktNum
func (a *CongestionAdapter) OnARQPacketSent(seq uint32, size int, isRetransmit bool) uint64 {
	if a.cc == nil {
		return 0
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()

	// 检查是否已存在该序列号的映射
	if info, exists := a.seqToPktInfo[seq]; exists {
		if isRetransmit {
			// 重传：更新重传计数，但保留首次发送时间
			info.Retransmit = true
			info.RetransCount++
			// 重传包不需要新的 pktNum，使用原有的
			a.cc.OnPacketSent(info.PktNum, size, true)
			return info.PktNum
		}
		// 非重传但序列号已存在，可能是包装（wraparound），清理旧记录
		delete(a.pktNumToSeq, info.PktNum)
	}

	// 新包：分配新的 pktNum
	pktNum := a.nextPktNum
	a.nextPktNum++

	// 建立双向映射
	a.seqToPktInfo[seq] = &AdapterPacketInfo{
		PktNum:       pktNum,
		Size:         size,
		SentTime:     now,
		Retransmit:   false,
		RetransCount: 0,
	}
	a.pktNumToSeq[pktNum] = seq

	// 清理旧记录（防止内存泄漏）
	a.cleanupOldEntries(seq)

	// 通知拥塞控制器
	a.cc.OnPacketSent(pktNum, size, false)

	return pktNum
}

// OnARQPacketAcked ARQ 数据包确认
// ackSeq: 累积确认的序列号（表示该序列号之前的所有包都已收到）
// 返回: 确认的字节数, RTT 样本（如果有效）
func (a *CongestionAdapter) OnARQPacketAcked(ackSeq uint32) (ackedBytes int, rtt time.Duration) {
	if a.cc == nil {
		return 0, 0
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	var validRTT time.Duration
	totalAckedBytes := 0

	// 遍历所有小于 ackSeq 的已发送包
	var toDelete []uint32
	for seq, info := range a.seqToPktInfo {
		// 处理序列号回绕
		if seqLessThan(seq, ackSeq) {
			// 只有非重传包才能用于 RTT 计算（Karn's Algorithm）
			if !info.Retransmit && validRTT == 0 {
				validRTT = now.Sub(info.SentTime)
				// 有效性检查
				if validRTT < 0 || validRTT > 30*time.Second {
					validRTT = 0
				}
			}

			totalAckedBytes += info.Size

			// 通知拥塞控制器
			if validRTT > 0 {
				a.cc.OnPacketAcked(info.PktNum, info.Size, validRTT)
			} else {
				a.cc.OnPacketAcked(info.PktNum, info.Size, 0)
			}

			toDelete = append(toDelete, seq)
		}
	}

	// 删除已确认的映射
	for _, seq := range toDelete {
		if info, exists := a.seqToPktInfo[seq]; exists {
			delete(a.pktNumToSeq, info.PktNum)
			delete(a.seqToPktInfo, seq)
		}
	}

	return totalAckedBytes, validRTT
}

// OnARQPacketSACKed 处理 SACK 确认
// ranges: SACK 区间列表 [(start1, end1), (start2, end2), ...]
func (a *CongestionAdapter) OnARQPacketSACKed(ranges [][2]uint32) (ackedBytes int) {
	if a.cc == nil || len(ranges) == 0 {
		return 0
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	totalAckedBytes := 0

	for _, r := range ranges {
		startSeq, endSeq := r[0], r[1]

		for seq, info := range a.seqToPktInfo {
			// 检查序列号是否在 SACK 区间内
			if seqInRange(seq, startSeq, endSeq) {
				// SACK 确认的包，只计算字节数，不用于 RTT 计算
				totalAckedBytes += info.Size

				// 计算 RTT（仅非重传包）
				var rtt time.Duration
				if !info.Retransmit {
					rtt = now.Sub(info.SentTime)
					if rtt < 0 || rtt > 30*time.Second {
						rtt = 0
					}
				}

				a.cc.OnPacketAcked(info.PktNum, info.Size, rtt)

				// 标记为已确认（稍后删除）
				delete(a.pktNumToSeq, info.PktNum)
				delete(a.seqToPktInfo, seq)
			}
		}
	}

	return totalAckedBytes
}

// OnARQPacketLost ARQ 数据包丢失
// seq: 丢失的序列号
func (a *CongestionAdapter) OnARQPacketLost(seq uint32) {
	if a.cc == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if info, exists := a.seqToPktInfo[seq]; exists {
		a.cc.OnPacketLost(info.PktNum, info.Size)
		delete(a.pktNumToSeq, info.PktNum)
		delete(a.seqToPktInfo, seq)
	}
}

// OnARQPacketRetransmit ARQ 数据包重传（不删除映射，更新状态）
// seq: 重传的序列号
func (a *CongestionAdapter) OnARQPacketRetransmit(seq uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if info, exists := a.seqToPktInfo[seq]; exists {
		info.Retransmit = true
		info.RetransCount++
	}
}

// GetAdapterPktInfo 获取包信息（用于调试）
func (a *CongestionAdapter) GetAdapterPktInfo(seq uint32) *AdapterPacketInfo {
	a.mu.Lock()
	defer a.mu.Unlock()

	if info, exists := a.seqToPktInfo[seq]; exists {
		// 返回副本
		infoCopy := *info
		return &infoCopy
	}
	return nil
}

// cleanupOldEntries 清理旧条目（防止内存泄漏）
func (a *CongestionAdapter) cleanupOldEntries(currentSeq uint32) {
	// 保留最近的 10000 条记录
	const maxEntries = 10000

	if len(a.seqToPktInfo) <= maxEntries {
		return
	}

	// 找出最旧的序列号并删除
	threshold := currentSeq - uint32(maxEntries/2)

	var toDelete []uint32
	for seq := range a.seqToPktInfo {
		if seqLessThan(seq, threshold) {
			toDelete = append(toDelete, seq)
		}
	}

	for _, seq := range toDelete {
		if info, exists := a.seqToPktInfo[seq]; exists {
			delete(a.pktNumToSeq, info.PktNum)
			delete(a.seqToPktInfo, seq)
		}
	}
}

// seqLessThan 序列号比较（处理回绕）
func seqLessThan(a, b uint32) bool {
	// 使用有符号比较处理回绕
	return int32(a-b) < 0
}

// seqInRange 检查序列号是否在区间内（处理回绕）
func seqInRange(seq, start, end uint32) bool {
	// start <= seq <= end，考虑回绕
	return !seqLessThan(seq, start) && !seqLessThan(end, seq)
}

// ===== 以下是保留的旧接口，用于非 ARQ 场景的兼容 =====

// OnPacketSent 数据包发送（旧接口，用于非 ARQ 场景）
func (a *CongestionAdapter) OnPacketSent(size int) uint64 {
	if a.cc == nil {
		return 0
	}

	a.mu.Lock()
	pktNum := a.nextPktNum
	a.nextPktNum++
	a.mu.Unlock()

	a.cc.OnPacketSent(pktNum, size, false)
	return pktNum
}

// OnPacketAcked 数据包确认（旧接口）
func (a *CongestionAdapter) OnPacketAcked(pktNum uint64, rtt time.Duration) {
	if a.cc == nil {
		return
	}

	a.mu.Lock()
	seq, exists := a.pktNumToSeq[pktNum]
	var size int
	if exists {
		if info, ok := a.seqToPktInfo[seq]; ok {
			size = info.Size
			delete(a.seqToPktInfo, seq)
		}
		delete(a.pktNumToSeq, pktNum)
	}
	a.mu.Unlock()

	if exists {
		a.cc.OnPacketAcked(pktNum, size, rtt)
	}
}

// OnPacketLost 数据包丢失（旧接口）
func (a *CongestionAdapter) OnPacketLost(pktNum uint64) {
	if a.cc == nil {
		return
	}

	a.mu.Lock()
	seq, exists := a.pktNumToSeq[pktNum]
	var size int
	if exists {
		if info, ok := a.seqToPktInfo[seq]; ok {
			size = info.Size
			delete(a.seqToPktInfo, seq)
		}
		delete(a.pktNumToSeq, pktNum)
	}
	a.mu.Unlock()

	if exists {
		a.cc.OnPacketLost(pktNum, size)
	}
}

// OnBytesAcked 字节确认（简化接口）
func (a *CongestionAdapter) OnBytesAcked(bytes int, rtt time.Duration) {
	if a.cc == nil {
		return
	}
	a.cc.OnPacketAcked(0, bytes, rtt)
}

// OnBytesLost 字节丢失（简化接口）
func (a *CongestionAdapter) OnBytesLost(bytes int) {
	if a.cc == nil {
		return
	}
	a.cc.OnPacketLost(0, bytes)
}

// CanSend 检查是否可以发送
func (a *CongestionAdapter) CanSend(size int) bool {
	if a.cc == nil {
		return true
	}
	return a.cc.CanSend(size)
}

// GetPacingInterval 获取发包间隔
func (a *CongestionAdapter) GetPacingInterval(size int) time.Duration {
	if a.cc == nil {
		return time.Millisecond
	}
	return a.cc.GetPacingInterval(size)
}

// WaitForSend 等待可以发送
func (a *CongestionAdapter) WaitForSend(size int) {
	if a.cc == nil {
		return
	}
	for !a.cc.CanSend(size) {
		time.Sleep(a.cc.GetPacingInterval(size))
	}
}

// GetController 获取底层控制器
func (a *CongestionAdapter) GetController() *Hysteria2Controller {
	return a.cc
}

// GetStats 获取统计
func (a *CongestionAdapter) GetStats() *CongestionStats {
	if a.cc == nil {
		return nil
	}
	return a.cc.GetStats()
}

// GetMappingStats 获取映射统计（用于调试）
func (a *CongestionAdapter) GetMappingStats() (seqCount, pktNumCount int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.seqToPktInfo), len(a.pktNumToSeq)
}
