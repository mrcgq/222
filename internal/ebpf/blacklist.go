
// =============================================================================
// 文件: internal/ebpf/blacklist.go
// 描述: eBPF 黑名单管理器 - 无状态版本，直接操作内核 Map
// 修复：删除 Go 端缓存，避免与 LRU Map 的淘汰机制冲突导致内存泄漏
// =============================================================================

package ebpf

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
)

// =============================================================================
// 黑名单标志常量（与 eBPF 端保持一致）
// =============================================================================

const (
	BlockFlagNone      uint8 = 0
	BlockFlagManual    uint8 = 1
	BlockFlagReplay    uint8 = 2
	BlockFlagAuthFail  uint8 = 3
	BlockFlagRateLimit uint8 = 4
	BlockFlagMalformed uint8 = 5
)

// =============================================================================
// 黑名单条目结构（与 C 结构体严格对应，包含显式填充）
// =============================================================================

// BlacklistEntryV4 IPv4 黑名单条目 (32 字节)
type BlacklistEntryV4 struct {
	BlockFlag      uint8
	Severity       uint8
	FailCount      uint16
	FirstSeen      uint32
	LastSeen       uint32
	Pad            uint32 // 显式填充
	BlockedPackets uint64
	BlockedBytes   uint64
}

// BlacklistEntryV6 IPv6 黑名单条目 (32 字节)
type BlacklistEntryV6 struct {
	BlockFlag      uint8
	Severity       uint8
	FailCount      uint16
	FirstSeen      uint32
	LastSeen       uint32
	Pad            uint32 // 显式填充
	BlockedPackets uint64
	BlockedBytes   uint64
}

// =============================================================================
// 黑名单管理器（无状态，直接操作 eBPF Map）
// =============================================================================

// BlacklistManager 黑名单管理器
type BlacklistManager struct {
	blacklistV4 *ebpf.Map
	blacklistV6 *ebpf.Map

	autoUnblockAfter time.Duration
	cleanupTicker    *time.Ticker
	stopChan         chan struct{}
}

// NewBlacklistManager 创建黑名单管理器
// 修复：不再维护本地缓存，完全依赖 eBPF LRU Map
func NewBlacklistManager(v4Map, v6Map *ebpf.Map) *BlacklistManager {
	m := &BlacklistManager{
		blacklistV4:      v4Map,
		blacklistV6:      v6Map,
		autoUnblockAfter: 30 * time.Minute,
		stopChan:         make(chan struct{}),
	}

	// 启动自动清理（频率降低，节约 CPU）
	m.cleanupTicker = time.NewTicker(2 * time.Minute)
	go m.cleanupLoop()

	return m
}

// =============================================================================
// IP 地址转换辅助函数
// 修复：使用字节数组作为 Key，屏蔽大小端问题
// =============================================================================

// ipToV4Key 将 IPv4 转为固定长度字节数组
func ipToV4Key(ip net.IP) [4]byte {
	var key [4]byte
	copy(key[:], ip.To4())
	return key
}

// ipToV6Key 将 IPv6 转为固定长度字节数组
func ipToV6Key(ip net.IP) [16]byte {
	var key [16]byte
	copy(key[:], ip.To16())
	return key
}

// =============================================================================
// 封禁/解封操作
// =============================================================================

// BlockIPv4 封禁 IPv4 地址
func (m *BlacklistManager) BlockIPv4(ip net.IP, reason uint8, severity uint8) error {
	if ip.To4() == nil {
		return fmt.Errorf("不是有效的 IPv4 地址: %s", ip)
	}

	key := ipToV4Key(ip)
	now := uint32(time.Now().Unix())

	entry := BlacklistEntryV4{
		BlockFlag:      reason,
		Severity:       severity,
		FailCount:      1,
		FirstSeen:      now,
		LastSeen:       now,
		BlockedPackets: 0,
		BlockedBytes:   0,
	}

	return m.blacklistV4.Update(&key, &entry, ebpf.UpdateAny)
}

// BlockIPv6 封禁 IPv6 地址
func (m *BlacklistManager) BlockIPv6(ip net.IP, reason uint8, severity uint8) error {
	if ip.To16() == nil || ip.To4() != nil {
		return fmt.Errorf("不是有效的 IPv6 地址: %s", ip)
	}

	key := ipToV6Key(ip)
	now := uint32(time.Now().Unix())

	entry := BlacklistEntryV6{
		BlockFlag:      reason,
		Severity:       severity,
		FailCount:      1,
		FirstSeen:      now,
		LastSeen:       now,
		BlockedPackets: 0,
		BlockedBytes:   0,
	}

	return m.blacklistV6.Update(&key, &entry, ebpf.UpdateAny)
}

// UnblockIPv4 解封 IPv4 地址
func (m *BlacklistManager) UnblockIPv4(ip net.IP) error {
	if ip.To4() == nil {
		return fmt.Errorf("不是有效的 IPv4 地址: %s", ip)
	}

	key := ipToV4Key(ip)
	err := m.blacklistV4.Delete(&key)
	if err != nil && err.Error() != "key does not exist" {
		return err
	}
	return nil
}

// UnblockIPv6 解封 IPv6 地址
func (m *BlacklistManager) UnblockIPv6(ip net.IP) error {
	if ip.To16() == nil || ip.To4() != nil {
		return fmt.Errorf("不是有效的 IPv6 地址: %s", ip)
	}

	key := ipToV6Key(ip)
	err := m.blacklistV6.Delete(&key)
	if err != nil && err.Error() != "key does not exist" {
		return err
	}
	return nil
}

// =============================================================================
// 失败计数与渐进式封禁
// =============================================================================

// IncrementFailCount 增加失败计数并判断是否封禁
// 修复：直接操作 eBPF Map，不使用本地缓存
func (m *BlacklistManager) IncrementFailCount(ip net.IP, reason uint8) (uint16, bool) {
	if ip.To4() != nil {
		return m.incrementFailCountV4(ip, reason)
	}
	return m.incrementFailCountV6(ip, reason)
}

func (m *BlacklistManager) incrementFailCountV4(ip net.IP, reason uint8) (uint16, bool) {
	key := ipToV4Key(ip)
	now := uint32(time.Now().Unix())

	var entry BlacklistEntryV4

	// 直接查内核 Map
	err := m.blacklistV4.Lookup(&key, &entry)
	if err != nil {
		// 首次失败，创建条目但不封禁
		entry = BlacklistEntryV4{
			BlockFlag: BlockFlagNone,
			Severity:  1,
			FailCount: 1,
			FirstSeen: now,
			LastSeen:  now,
		}
		m.blacklistV4.Update(&key, &entry, ebpf.UpdateAny)
		return 1, false
	}

	// 增加失败计数
	entry.FailCount++
	entry.LastSeen = now

	// 渐进式封禁逻辑
	shouldBlock := false
	switch {
	case entry.FailCount >= 100:
		entry.BlockFlag = reason
		entry.Severity = 10
		shouldBlock = true
	case entry.FailCount >= 50:
		entry.BlockFlag = reason
		entry.Severity = 7
		shouldBlock = true
	case entry.FailCount >= 20:
		entry.BlockFlag = reason
		entry.Severity = 5
		shouldBlock = true
	case entry.FailCount >= 10:
		entry.BlockFlag = reason
		entry.Severity = 3
		shouldBlock = true
	}

	// 写回内核
	m.blacklistV4.Update(&key, &entry, ebpf.UpdateAny)

	return entry.FailCount, shouldBlock
}

func (m *BlacklistManager) incrementFailCountV6(ip net.IP, reason uint8) (uint16, bool) {
	key := ipToV6Key(ip)
	now := uint32(time.Now().Unix())

	var entry BlacklistEntryV6

	err := m.blacklistV6.Lookup(&key, &entry)
	if err != nil {
		entry = BlacklistEntryV6{
			BlockFlag: BlockFlagNone,
			Severity:  1,
			FailCount: 1,
			FirstSeen: now,
			LastSeen:  now,
		}
		m.blacklistV6.Update(&key, &entry, ebpf.UpdateAny)
		return 1, false
	}

	entry.FailCount++
	entry.LastSeen = now

	shouldBlock := false
	switch {
	case entry.FailCount >= 100:
		entry.BlockFlag = reason
		entry.Severity = 10
		shouldBlock = true
	case entry.FailCount >= 50:
		entry.BlockFlag = reason
		entry.Severity = 7
		shouldBlock = true
	case entry.FailCount >= 20:
		entry.BlockFlag = reason
		entry.Severity = 5
		shouldBlock = true
	case entry.FailCount >= 10:
		entry.BlockFlag = reason
		entry.Severity = 3
		shouldBlock = true
	}

	m.blacklistV6.Update(&key, &entry, ebpf.UpdateAny)

	return entry.FailCount, shouldBlock
}

// =============================================================================
// 查询接口
// =============================================================================

// IsBlockedV4 检查 IPv4 是否被封禁
func (m *BlacklistManager) IsBlockedV4(ip net.IP) bool {
	if ip.To4() == nil {
		return false
	}

	key := ipToV4Key(ip)
	var entry BlacklistEntryV4

	if err := m.blacklistV4.Lookup(&key, &entry); err == nil {
		return entry.BlockFlag != BlockFlagNone
	}

	return false
}

// IsBlockedV6 检查 IPv6 是否被封禁
func (m *BlacklistManager) IsBlockedV6(ip net.IP) bool {
	if ip.To16() == nil || ip.To4() != nil {
		return false
	}

	key := ipToV6Key(ip)
	var entry BlacklistEntryV6

	if err := m.blacklistV6.Lookup(&key, &entry); err == nil {
		return entry.BlockFlag != BlockFlagNone
	}

	return false
}

// IsBlocked 检查 IP 是否被封禁（自动识别 IPv4/IPv6）
func (m *BlacklistManager) IsBlocked(ip net.IP) bool {
	if ip.To4() != nil {
		return m.IsBlockedV4(ip)
	}
	return m.IsBlockedV6(ip)
}

// =============================================================================
// 自动清理
// =============================================================================

func (m *BlacklistManager) cleanupLoop() {
	for {
		select {
		case <-m.cleanupTicker.C:
			m.cleanupExpired()
		case <-m.stopChan:
			return
		}
	}
}

func (m *BlacklistManager) cleanupExpired() {
	now := uint32(time.Now().Unix())
	expireThreshold := uint32(m.autoUnblockAfter.Seconds())

	// 清理 IPv4
	var v4Key [4]byte
	var v4Entry BlacklistEntryV4
	iter := m.blacklistV4.Iterate()
	for iter.Next(&v4Key, &v4Entry) {
		// 只清理非手动封禁且已过期的条目
		if v4Entry.BlockFlag != BlockFlagNone &&
			v4Entry.BlockFlag != BlockFlagManual &&
			now-v4Entry.LastSeen > expireThreshold {
			m.blacklistV4.Delete(&v4Key)
		}
	}

	// 清理 IPv6
	var v6Key [16]byte
	var v6Entry BlacklistEntryV6
	iter = m.blacklistV6.Iterate()
	for iter.Next(&v6Key, &v6Entry) {
		if v6Entry.BlockFlag != BlockFlagNone &&
			v6Entry.BlockFlag != BlockFlagManual &&
			now-v6Entry.LastSeen > expireThreshold {
			m.blacklistV6.Delete(&v6Key)
		}
	}
}

// =============================================================================
// 统计与管理
// =============================================================================

// BlacklistStats 黑名单统计
type BlacklistStats struct {
	BlockedIPv4Count    int
	BlockedIPv6Count    int
	TotalBlockedPackets uint64
	TotalBlockedBytes   uint64
}

// GetStats 获取黑名单统计
// 注意：此方法需要遍历 Map，在大量条目时可能较慢
func (m *BlacklistManager) GetStats() BlacklistStats {
	var stats BlacklistStats

	// 统计 IPv4
	var v4Key [4]byte
	var v4Entry BlacklistEntryV4
	iter := m.blacklistV4.Iterate()
	for iter.Next(&v4Key, &v4Entry) {
		if v4Entry.BlockFlag != BlockFlagNone {
			stats.BlockedIPv4Count++
			stats.TotalBlockedPackets += v4Entry.BlockedPackets
			stats.TotalBlockedBytes += v4Entry.BlockedBytes
		}
	}

	// 统计 IPv6
	var v6Key [16]byte
	var v6Entry BlacklistEntryV6
	iter = m.blacklistV6.Iterate()
	for iter.Next(&v6Key, &v6Entry) {
		if v6Entry.BlockFlag != BlockFlagNone {
			stats.BlockedIPv6Count++
			stats.TotalBlockedPackets += v6Entry.BlockedPackets
			stats.TotalBlockedBytes += v6Entry.BlockedBytes
		}
	}

	return stats
}

// SetAutoUnblockDuration 设置自动解封时间
func (m *BlacklistManager) SetAutoUnblockDuration(d time.Duration) {
	m.autoUnblockAfter = d
}

// Close 关闭黑名单管理器
func (m *BlacklistManager) Close() {
	close(m.stopChan)
	m.cleanupTicker.Stop()
}







