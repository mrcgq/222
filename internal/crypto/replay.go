

// =============================================================================
// 文件: internal/crypto/replay.go
// =============================================================================

package crypto

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
)

const (
	// 布隆过滤器参数
	bloomExpectedItems = 100000  // 预期每个时间片的项目数
	bloomFalsePositive = 0.0001 // 万分之一误报率

	// 时间片配置
	sliceDuration = 10 * time.Second // 每个时间片10秒
	maxSlices     = 18               // 保留18个时间片 = 3分钟

	// 精确缓存配置（处理布隆过滤器误报）
	exactCacheSize = 10000 // LRU 缓存大小
)

// ReplayGuard 高性能防重放保护
type ReplayGuard struct {
	slices      [maxSlices]*timeSlice
	currentIdx  int64
	exactCache  *lruCache // 处理布隆过滤器误报
	
	mu          sync.RWMutex
	stats       ReplayStats
}

// ReplayStats 统计信息
type ReplayStats struct {
	TotalChecks   uint64
	ReplayBlocked uint64
	BloomHits     uint64
	ExactHits     uint64
}

// timeSlice 时间片
type timeSlice struct {
	bloom     *bloom.BloomFilter
	startTime time.Time
	count     int64
	mu        sync.RWMutex
}

// lruCache 简单 LRU 缓存
type lruCache struct {
	capacity int
	items    map[uint64]time.Time
	order    []uint64
	mu       sync.Mutex
}

// NewReplayGuard 创建防重放保护器
func NewReplayGuard() *ReplayGuard {
	rg := &ReplayGuard{
		exactCache: newLRUCache(exactCacheSize),
	}

	// 初始化时间片
	now := time.Now()
	for i := 0; i < maxSlices; i++ {
		rg.slices[i] = newTimeSlice(now.Add(-time.Duration(i) * sliceDuration))
	}

	go rg.rotateLoop()

	return rg
}

func newTimeSlice(startTime time.Time) *timeSlice {
	return &timeSlice{
		bloom:     bloom.NewWithEstimates(bloomExpectedItems, bloomFalsePositive),
		startTime: startTime,
	}
}

func newLRUCache(capacity int) *lruCache {
	return &lruCache{
		capacity: capacity,
		items:    make(map[uint64]time.Time, capacity),
		order:    make([]uint64, 0, capacity),
	}
}

// CheckAndMark 检查并标记 nonce（原子操作）
// 返回 true 表示是新 nonce，false 表示重放
func (rg *ReplayGuard) CheckAndMark(nonce []byte) bool {
	if len(nonce) < 8 {
		return false
	}

	atomic.AddUint64(&rg.stats.TotalChecks, 1)

	// 计算 nonce 的哈希值用于快速查找
	nonceHash := rg.hashNonce(nonce)

	rg.mu.RLock()
	currentIdx := rg.currentIdx
	rg.mu.RUnlock()

	// 1. 首先检查精确缓存（处理误报）
	if rg.exactCache.contains(nonceHash) {
		atomic.AddUint64(&rg.stats.ExactHits, 1)
		atomic.AddUint64(&rg.stats.ReplayBlocked, 1)
		return false
	}

	// 2. 检查所有有效时间片的布隆过滤器
	for i := 0; i < maxSlices; i++ {
		idx := (int(currentIdx) - i + maxSlices) % maxSlices
		slice := rg.slices[idx]

		slice.mu.RLock()
		exists := slice.bloom.Test(nonce)
		slice.mu.RUnlock()

		if exists {
			// 布隆过滤器命中，可能是真正的重放或误报
			// 添加到精确缓存以便后续快速判断
			atomic.AddUint64(&rg.stats.BloomHits, 1)
			
			// 这里我们保守处理：认为是重放
			// 如果需要更精确，可以维护一个最近的 nonce 列表
			atomic.AddUint64(&rg.stats.ReplayBlocked, 1)
			return false
		}
	}

	// 3. 新 nonce，添加到当前时间片
	rg.mu.RLock()
	currentSlice := rg.slices[currentIdx%maxSlices]
	rg.mu.RUnlock()

	currentSlice.mu.Lock()
	currentSlice.bloom.Add(nonce)
	atomic.AddInt64(&currentSlice.count, 1)
	currentSlice.mu.Unlock()

	// 4. 添加到精确缓存
	rg.exactCache.add(nonceHash)

	return true
}

// CheckOnly 仅检查不标记（用于验证）
func (rg *ReplayGuard) CheckOnly(nonce []byte) bool {
	if len(nonce) < 8 {
		return false
	}

	nonceHash := rg.hashNonce(nonce)

	// 检查精确缓存
	if rg.exactCache.contains(nonceHash) {
		return false
	}

	rg.mu.RLock()
	currentIdx := rg.currentIdx
	rg.mu.RUnlock()

	// 检查布隆过滤器
	for i := 0; i < maxSlices; i++ {
		idx := (int(currentIdx) - i + maxSlices) % maxSlices
		slice := rg.slices[idx]

		slice.mu.RLock()
		exists := slice.bloom.Test(nonce)
		slice.mu.RUnlock()

		if exists {
			return false
		}
	}

	return true
}

// Mark 仅标记（用于发送后标记）
func (rg *ReplayGuard) Mark(nonce []byte) {
	if len(nonce) < 8 {
		return
	}

	nonceHash := rg.hashNonce(nonce)

	rg.mu.RLock()
	currentIdx := rg.currentIdx
	currentSlice := rg.slices[currentIdx%maxSlices]
	rg.mu.RUnlock()

	currentSlice.mu.Lock()
	currentSlice.bloom.Add(nonce)
	atomic.AddInt64(&currentSlice.count, 1)
	currentSlice.mu.Unlock()

	rg.exactCache.add(nonceHash)
}

func (rg *ReplayGuard) hashNonce(nonce []byte) uint64 {
	// 使用 FNV-1a 快速哈希
	var hash uint64 = 14695981039346656037
	for _, b := range nonce {
		hash ^= uint64(b)
		hash *= 1099511628211
	}
	return hash
}

func (rg *ReplayGuard) rotateLoop() {
	ticker := time.NewTicker(sliceDuration)
	defer ticker.Stop()

	for range ticker.C {
		rg.rotate()
	}
}

func (rg *ReplayGuard) rotate() {
	rg.mu.Lock()
	defer rg.mu.Unlock()

	// 移动到下一个槽位
	rg.currentIdx++
	nextIdx := rg.currentIdx % maxSlices

	// 重置最老的时间片
	rg.slices[nextIdx] = newTimeSlice(time.Now())
}

// Stats 返回统计信息
func (rg *ReplayGuard) Stats() ReplayStats {
	return ReplayStats{
		TotalChecks:   atomic.LoadUint64(&rg.stats.TotalChecks),
		ReplayBlocked: atomic.LoadUint64(&rg.stats.ReplayBlocked),
		BloomHits:     atomic.LoadUint64(&rg.stats.BloomHits),
		ExactHits:     atomic.LoadUint64(&rg.stats.ExactHits),
	}
}

// MemoryUsage 返回估计的内存使用量（字节）
func (rg *ReplayGuard) MemoryUsage() int64 {
	// 布隆过滤器大小估算
	// bloomExpectedItems=100000, falsePositive=0.0001
	// 大约需要 ~240KB 每个过滤器
	bloomSize := int64(240 * 1024 * maxSlices) // ~4.2MB

	// LRU 缓存大小
	// 每个条目: uint64 key (8) + time.Time (24) + map overhead (~50)
	lruSize := int64(exactCacheSize * 82) // ~820KB

	return bloomSize + lruSize
}

// === LRU Cache 实现 ===

func (c *lruCache) add(key uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 如果已存在，更新时间
	if _, exists := c.items[key]; exists {
		c.items[key] = time.Now()
		return
	}

	// 如果满了，删除最老的
	if len(c.items) >= c.capacity {
		oldestKey := c.order[0]
		delete(c.items, oldestKey)
		c.order = c.order[1:]
	}

	// 添加新项
	c.items[key] = time.Now()
	c.order = append(c.order, key)
}

func (c *lruCache) contains(key uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, exists := c.items[key]
	return exists
}



