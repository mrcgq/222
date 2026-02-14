


// =============================================================================
// 文件: internal/transport/arq_recv_buffer.go
// 描述: ARQ 可靠传输 - 接收缓冲区 (乱序重组)
// =============================================================================
package transport

import (
	"sync"
	"time"
)

// ARQRecvBuffer 接收缓冲区
type ARQRecvBuffer struct {
	// 滑动窗口
	entries     []*ARQRecvPacketInfo
	size        int
	expected    uint32 // 期望的下一个序列号 (累积确认点)
	maxReceived uint32 // 最大已接收序列号

	// 已接收范围 (用于生成 SACK)
	receivedBitmap []bool

	// 统计
	totalReceived   uint64
	totalDelivered  uint64
	totalDuplicate  uint64
	totalOutOfOrder uint64

	mu sync.RWMutex
}

// NewARQRecvBuffer 创建接收缓冲区
func NewARQRecvBuffer(size int, initialSeq uint32) *ARQRecvBuffer {
	return &ARQRecvBuffer{
		entries:        make([]*ARQRecvPacketInfo, size),
		size:           size,
		expected:       initialSeq,
		maxReceived:    initialSeq,
		receivedBitmap: make([]bool, size),
	}
}

// Insert 插入接收到的数据
func (b *ARQRecvBuffer) Insert(seq uint32, data []byte) (isDuplicate bool, isOutOfOrder bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 检查是否在窗口外
	if seq < b.expected {
		// 旧包，丢弃
		b.totalDuplicate++
		return true, false
	}

	if seq >= b.expected+uint32(b.size) {
		// 超出窗口，丢弃
		return false, true
	}

	idx := seq % uint32(b.size)

	// 检查是否重复
	if b.entries[idx] != nil && b.entries[idx].Seq == seq {
		b.totalDuplicate++
		return true, false
	}

	// 插入
	b.entries[idx] = &ARQRecvPacketInfo{
		Seq:        seq,
		Data:       make([]byte, len(data)),
		ReceivedAt: time.Now(),
		Delivered:  false,
	}
	copy(b.entries[idx].Data, data)
	b.receivedBitmap[idx] = true
	b.totalReceived++

	// 更新最大接收序列号
	if seq > b.maxReceived {
		b.maxReceived = seq
	}

	// 检查是否乱序
	isOutOfOrder = seq != b.expected

	if isOutOfOrder {
		b.totalOutOfOrder++
	}

	return false, isOutOfOrder
}

// ReadOrdered 按序读取数据
func (b *ARQRecvBuffer) ReadOrdered() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	var result [][]byte

	for {
		idx := b.expected % uint32(b.size)
		info := b.entries[idx]

		if info == nil || info.Seq != b.expected {
			break
		}

		result = append(result, info.Data)
		info.Delivered = true
		b.entries[idx] = nil
		b.receivedBitmap[idx] = false
		b.expected++
		b.totalDelivered++
	}

	return result
}

// ReadOrderedWithLimit 按序读取数据 (有数量限制)
func (b *ARQRecvBuffer) ReadOrderedWithLimit(maxCount int) [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	var result [][]byte

	for len(result) < maxCount {
		idx := b.expected % uint32(b.size)
		info := b.entries[idx]

		if info == nil || info.Seq != b.expected {
			break
		}

		result = append(result, info.Data)
		info.Delivered = true
		b.entries[idx] = nil
		b.receivedBitmap[idx] = false
		b.expected++
		b.totalDelivered++
	}

	return result
}

// GetExpectedSeq 获取期望的序列号 (用于 ACK)
func (b *ARQRecvBuffer) GetExpectedSeq() uint32 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.expected
}

// GetSACKRanges 获取 SACK 区间
func (b *ARQRecvBuffer) GetSACKRanges() []SACKRange {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var ranges []SACKRange
	var inRange bool
	var rangeStart uint32

	// 从 expected 开始扫描
	for i := 0; i < b.size && len(ranges) < ARQMaxSACKRanges; i++ {
		seq := b.expected + uint32(i)
		idx := seq % uint32(b.size)
		received := b.entries[idx] != nil && b.entries[idx].Seq == seq

		if received && !inRange {
			// 开始新区间
			inRange = true
			rangeStart = seq
		} else if !received && inRange {
			// 结束区间
			inRange = false
			// 只报告不连续的区间 (expected 之后的)
			if rangeStart > b.expected {
				ranges = append(ranges, SACKRange{
					Start: rangeStart,
					End:   seq,
				})
			}
		}
	}

	// 处理最后一个区间
	if inRange && rangeStart > b.expected {
		endSeq := b.expected + uint32(b.size)
		for i := b.size - 1; i >= 0; i-- {
			seq := b.expected + uint32(i)
			idx := seq % uint32(b.size)
			if b.entries[idx] != nil && b.entries[idx].Seq == seq {
				endSeq = seq + 1
				break
			}
		}
		if len(ranges) < ARQMaxSACKRanges {
			ranges = append(ranges, SACKRange{
				Start: rangeStart,
				End:   endSeq,
			})
		}
	}

	return ranges
}

// HasGaps 是否有空洞 (需要 SACK)
func (b *ARQRecvBuffer) HasGaps() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return b.maxReceived > b.expected
}

// GetWindowSize 获取可用接收窗口大小
func (b *ARQRecvBuffer) GetWindowSize() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// 计算已使用的槽位
	used := 0
	for i := 0; i < b.size; i++ {
		if b.entries[i] != nil {
			used++
		}
	}

	return b.size - used
}

// IsFull 缓冲区是否已满
func (b *ARQRecvBuffer) IsFull() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for i := 0; i < b.size; i++ {
		if b.entries[i] == nil {
			return false
		}
	}
	return true
}

// GetPendingCount 获取待交付包数量
func (b *ARQRecvBuffer) GetPendingCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	count := 0
	for i := 0; i < b.size; i++ {
		if b.entries[i] != nil && !b.entries[i].Delivered {
			count++
		}
	}
	return count
}

// GetStats 获取统计
func (b *ARQRecvBuffer) GetStats() map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return map[string]interface{}{
		"expected":           b.expected,
		"max_received":       b.maxReceived,
		"window_size":        b.size - b.GetPendingCount(),
		"total_received":     b.totalReceived,
		"total_delivered":    b.totalDelivered,
		"total_duplicate":    b.totalDuplicate,
		"total_out_of_order": b.totalOutOfOrder,
	}
}

// Reset 重置
func (b *ARQRecvBuffer) Reset(initialSeq uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i := range b.entries {
		b.entries[i] = nil
	}
	for i := range b.receivedBitmap {
		b.receivedBitmap[i] = false
	}
	b.expected = initialSeq
	b.maxReceived = initialSeq
	b.totalReceived = 0
	b.totalDelivered = 0
	b.totalDuplicate = 0
	b.totalOutOfOrder = 0
}




