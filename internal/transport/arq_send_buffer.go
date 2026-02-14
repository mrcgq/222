

// =============================================================================
// 文件: internal/transport/arq_send_buffer.go
// 描述: ARQ 可靠传输 - 发送缓冲区 (滑动窗口)
// =============================================================================
package transport

import (
	"sync"
	"time"
)

// ARQSendBuffer 发送缓冲区
type ARQSendBuffer struct {
	// 滑动窗口
	entries  []*ARQPacketInfo
	size     int    // 缓冲区大小
	base     uint32 // 窗口基序列号 (最小未确认)
	nextSeq  uint32 // 下一个序列号
	inFlight int64  // 在途字节数

	// 快速重传
	dupAckCount map[uint32]int // seq -> 重复 ACK 计数

	// SACK 处理
	sackBitmap []bool

	// 统计
	totalSent       uint64
	totalRetransmit uint64
	totalAcked      uint64

	mu sync.RWMutex
}

// NewARQSendBuffer 创建发送缓冲区
func NewARQSendBuffer(size int, initialSeq uint32) *ARQSendBuffer {
	return &ARQSendBuffer{
		entries:     make([]*ARQPacketInfo, size),
		size:        size,
		base:        initialSeq,
		nextSeq:     initialSeq,
		dupAckCount: make(map[uint32]int),
		sackBitmap:  make([]bool, size),
	}
}

// Add 添加待发送数据
func (b *ARQSendBuffer) Add(data []byte) (seq uint32, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 检查窗口是否已满
	if b.nextSeq-b.base >= uint32(b.size) {
		return 0, false
	}

	seq = b.nextSeq
	idx := seq % uint32(b.size)

	now := time.Now()
	info := &ARQPacketInfo{
		Seq:       seq,
		Data:      make([]byte, len(data)),
		Size:      len(data),
		SentTime:  now,
		Retries:   0,
		Acked:     false,
		Lost:      false,
		InFlight:  true,
		FirstSent: true,
	}
	copy(info.Data, data)

	b.entries[idx] = info
	b.nextSeq++
	b.inFlight += int64(len(data))
	b.totalSent++

	return seq, true
}

// MarkSent 标记包已发送 (用于重传)
func (b *ARQSendBuffer) MarkSent(seq uint32, rto time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if seq < b.base || seq >= b.nextSeq {
		return
	}

	idx := seq % uint32(b.size)
	info := b.entries[idx]
	if info == nil {
		return
	}

	now := time.Now()
	info.SentTime = now
	info.RetransmitAt = now.Add(rto)
	info.InFlight = true
}

// OnAck 处理累积确认
func (b *ARQSendBuffer) OnAck(ack uint32) (ackedBytes int, rtt time.Duration, newAcks []uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 检查是否是有效 ACK
	if ack <= b.base || ack > b.nextSeq {
		// 可能是重复 ACK
		if ack == b.base {
			b.dupAckCount[ack]++
		}
		return 0, 0, nil
	}

	// 累积确认：ack 之前的所有包都被确认
	for seq := b.base; seq < ack; seq++ {
		idx := seq % uint32(b.size)
		info := b.entries[idx]
		if info != nil && !info.Acked {
			info.Acked = true
			info.InFlight = false
			ackedBytes += info.Size
			b.inFlight -= int64(info.Size)
			b.totalAcked++
			newAcks = append(newAcks, seq)

			// 计算 RTT (只用第一个非重传包)
			if rtt == 0 && !info.IsRetransmit {
				rtt = time.Since(info.SentTime)
			}
		}
		b.entries[idx] = nil // 清理
	}

	// 移动窗口
	b.base = ack

	// 清理重复 ACK 计数
	for seq := range b.dupAckCount {
		if seq < ack {
			delete(b.dupAckCount, seq)
		}
	}

	return ackedBytes, rtt, newAcks
}

// OnSACK 处理选择性确认
func (b *ARQSendBuffer) OnSACK(ranges []SACKRange) (ackedBytes int, sackedSeqs []uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, r := range ranges {
		for seq := r.Start; seq < r.End; seq++ {
			if seq < b.base || seq >= b.nextSeq {
				continue
			}
			idx := seq % uint32(b.size)
			info := b.entries[idx]
			if info != nil && !info.Acked {
				info.Acked = true
				info.InFlight = false
				ackedBytes += info.Size
				b.inFlight -= int64(info.Size)
				sackedSeqs = append(sackedSeqs, seq)

				// 标记 bitmap
				if int(idx) < len(b.sackBitmap) {
					b.sackBitmap[idx] = true
				}
			}
		}
	}

	return ackedBytes, sackedSeqs
}

// GetRetransmitPackets 获取需要超时重传的包
func (b *ARQSendBuffer) GetRetransmitPackets(now time.Time) []*ARQPacketInfo {
	b.mu.Lock()
	defer b.mu.Unlock()

	var retransmits []*ARQPacketInfo

	for seq := b.base; seq < b.nextSeq; seq++ {
		idx := seq % uint32(b.size)
		info := b.entries[idx]
		if info == nil || info.Acked {
			continue
		}

		// 超时重传
		if info.InFlight && now.After(info.RetransmitAt) {
			retransmits = append(retransmits, info)
		}
	}

	return retransmits
}

// GetFastRetransmitPackets 获取快速重传的包 (3 个重复 ACK)
func (b *ARQSendBuffer) GetFastRetransmitPackets() []*ARQPacketInfo {
	b.mu.Lock()
	defer b.mu.Unlock()

	var retransmits []*ARQPacketInfo

	for seq, count := range b.dupAckCount {
		if count >= ARQFastRetransmitThreshold {
			if seq >= b.base && seq < b.nextSeq {
				idx := seq % uint32(b.size)
				info := b.entries[idx]
				if info != nil && !info.Acked && info.InFlight {
					retransmits = append(retransmits, info)
					delete(b.dupAckCount, seq) // 只快速重传一次
				}
			}
		}
	}

	return retransmits
}

// MarkRetransmit 标记重传
func (b *ARQSendBuffer) MarkRetransmit(seq uint32, rto time.Duration) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if seq < b.base || seq >= b.nextSeq {
		return false
	}

	idx := seq % uint32(b.size)
	info := b.entries[idx]
	if info == nil || info.Acked {
		return false
	}

	now := time.Now()
	info.SentTime = now
	info.RetransmitAt = now.Add(rto)
	info.Retries++
	info.IsRetransmit = true
	info.FirstSent = false
	b.totalRetransmit++

	return true
}

// MarkLost 标记丢包
func (b *ARQSendBuffer) MarkLost(seq uint32) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	if seq < b.base || seq >= b.nextSeq {
		return 0
	}

	idx := seq % uint32(b.size)
	info := b.entries[idx]
	if info == nil || info.Acked || info.Lost {
		return 0
	}

	info.Lost = true
	if info.InFlight {
		info.InFlight = false
		b.inFlight -= int64(info.Size)
	}

	return info.Size
}

// GetPacket 获取包信息
func (b *ARQSendBuffer) GetPacket(seq uint32) *ARQPacketInfo {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if seq < b.base || seq >= b.nextSeq {
		return nil
	}

	idx := seq % uint32(b.size)
	return b.entries[idx]
}

// InFlightBytes 获取在途字节数
func (b *ARQSendBuffer) InFlightBytes() int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.inFlight
}

// Available 可用窗口大小
func (b *ARQSendBuffer) Available() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.size - int(b.nextSeq-b.base)
}

// IsFull 窗口是否已满
func (b *ARQSendBuffer) IsFull() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.nextSeq-b.base >= uint32(b.size)
}

// GetBase 获取基序列号
func (b *ARQSendBuffer) GetBase() uint32 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.base
}

// GetNextSeq 获取下一个序列号
func (b *ARQSendBuffer) GetNextSeq() uint32 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.nextSeq
}

// GetUnackedCount 获取未确认包数量
func (b *ARQSendBuffer) GetUnackedCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	count := 0
	for seq := b.base; seq < b.nextSeq; seq++ {
		idx := seq % uint32(b.size)
		if b.entries[idx] != nil && !b.entries[idx].Acked {
			count++
		}
	}
	return count
}

// GetStats 获取统计
func (b *ARQSendBuffer) GetStats() map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return map[string]interface{}{
		"base":             b.base,
		"next_seq":         b.nextSeq,
		"in_flight":        b.inFlight,
		"available":        b.size - int(b.nextSeq-b.base),
		"total_sent":       b.totalSent,
		"total_retransmit": b.totalRetransmit,
		"total_acked":      b.totalAcked,
	}
}

// Reset 重置
func (b *ARQSendBuffer) Reset(initialSeq uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i := range b.entries {
		b.entries[i] = nil
	}
	for i := range b.sackBitmap {
		b.sackBitmap[i] = false
	}
	b.base = initialSeq
	b.nextSeq = initialSeq
	b.inFlight = 0
	b.dupAckCount = make(map[uint32]int)
	b.totalSent = 0
	b.totalRetransmit = 0
	b.totalAcked = 0
}



