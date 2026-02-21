//go:build linux

// =============================================================================
// 文件: internal/transport/ebpf_stats.go
// 描述: eBPF 统计和事件类型定义及辅助方法
// =============================================================================

package transport

// =============================================================================
// 类型别名 - 兼容旧代码
// =============================================================================

// EBPFStats eBPF 统计 (PhantomStatsCounter 的别名)
type EBPFStats = PhantomStatsCounter

// EBPFSessionKey 会话键别名
type EBPFSessionKey = PhantomSessionKey

// EBPFSessionValue 会话值别名
type EBPFSessionValue = PhantomSessionValue

// =============================================================================
// 简化的包事件 (用于用户态处理)
// =============================================================================

// EBPFPacketEvent 简化的包事件 (用于内部处理)
type EBPFPacketEvent struct {
	Timestamp uint64 // 时间戳
	SrcIP     uint32 // 源 IP (IPv4)
	DstIP     uint32 // 目的 IP (IPv4)
	SrcPort   uint16 // 源端口
	DstPort   uint16 // 目的端口
	Protocol  uint8  // 协议
	Action    uint8  // 动作
	Flags     uint8  // 标志
	Pad       uint8  // 填充
}

// =============================================================================
// EBPFLoader 的 Map 访问方法
// =============================================================================

// GetMaps 获取所有 Map 的引用
func (l *EBPFLoader) GetMaps() map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()

	maps := make(map[string]interface{})

	if l.objs.Sessions != nil {
		maps["sessions"] = l.objs.Sessions
	}
	if l.objs.ListenPorts != nil {
		maps["listen_ports"] = l.objs.ListenPorts
	}
	if l.objs.Config != nil {
		maps["config"] = l.objs.Config
	}
	if l.objs.Stats != nil {
		maps["stats"] = l.objs.Stats
	}
	if l.objs.Events != nil {
		maps["events"] = l.objs.Events
	}
	if l.objs.BlacklistV4 != nil {
		maps["blacklist_v4"] = l.objs.BlacklistV4
	}
	if l.objs.BlacklistV6 != nil {
		maps["blacklist_v6"] = l.objs.BlacklistV6
	}
	if l.objs.RatelimitV4 != nil {
		maps["ratelimit_v4"] = l.objs.RatelimitV4
	}
	if l.objs.RatelimitV6 != nil {
		maps["ratelimit_v6"] = l.objs.RatelimitV6
	}
	if l.objs.TxPorts != nil {
		maps["tx_ports"] = l.objs.TxPorts
	}

	return maps
}

// =============================================================================
// 黑名单管理方法
// =============================================================================

// AddToBlacklistV4 添加 IPv4 地址到黑名单
func (l *EBPFLoader) AddToBlacklistV4(ip uint32, entry *PhantomBlacklistEntryV4) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.objs.BlacklistV4 == nil {
		return nil
	}

	return l.objs.BlacklistV4.Put(&ip, entry)
}

// RemoveFromBlacklistV4 从黑名单移除 IPv4 地址
func (l *EBPFLoader) RemoveFromBlacklistV4(ip uint32) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.objs.BlacklistV4 == nil {
		return nil
	}

	return l.objs.BlacklistV4.Delete(&ip)
}

// GetBlacklistV4Entry 获取 IPv4 黑名单条目
func (l *EBPFLoader) GetBlacklistV4Entry(ip uint32) (*PhantomBlacklistEntryV4, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.objs.BlacklistV4 == nil {
		return nil, nil
	}

	var entry PhantomBlacklistEntryV4
	if err := l.objs.BlacklistV4.Lookup(&ip, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

// AddToBlacklistV6 添加 IPv6 地址到黑名单
func (l *EBPFLoader) AddToBlacklistV6(ip *PhantomIpAddr, entry *PhantomBlacklistEntryV6) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.objs.BlacklistV6 == nil {
		return nil
	}

	return l.objs.BlacklistV6.Put(ip, entry)
}

// RemoveFromBlacklistV6 从黑名单移除 IPv6 地址
func (l *EBPFLoader) RemoveFromBlacklistV6(ip *PhantomIpAddr) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.objs.BlacklistV6 == nil {
		return nil
	}

	return l.objs.BlacklistV6.Delete(ip)
}

// =============================================================================
// 速率限制管理方法
// =============================================================================

// GetRatelimitV4Entry 获取 IPv4 速率限制条目
func (l *EBPFLoader) GetRatelimitV4Entry(ip uint32) (*PhantomRatelimitEntry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.objs.RatelimitV4 == nil {
		return nil, nil
	}

	var entry PhantomRatelimitEntry
	if err := l.objs.RatelimitV4.Lookup(&ip, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

// ClearRatelimitV4 清除 IPv4 速率限制条目
func (l *EBPFLoader) ClearRatelimitV4(ip uint32) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.objs.RatelimitV4 == nil {
		return nil
	}

	return l.objs.RatelimitV4.Delete(&ip)
}

// =============================================================================
// 统计信息扩展方法
// =============================================================================

// GetBlacklistStats 获取黑名单统计
func (l *EBPFLoader) GetBlacklistStats() (v4Count, v6Count int, err error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.objs.BlacklistV4 != nil {
		var key uint32
		var value PhantomBlacklistEntryV4
		iter := l.objs.BlacklistV4.Iterate()
		for iter.Next(&key, &value) {
			v4Count++
		}
		if iter.Err() != nil {
			err = iter.Err()
		}
	}

	if l.objs.BlacklistV6 != nil {
		var key PhantomIpAddr
		var value PhantomBlacklistEntryV6
		iter := l.objs.BlacklistV6.Iterate()
		for iter.Next(&key, &value) {
			v6Count++
		}
		if iter.Err() != nil && err == nil {
			err = iter.Err()
		}
	}

	return
}

// GetRatelimitStats 获取速率限制统计
func (l *EBPFLoader) GetRatelimitStats() (v4Count, v6Count int, err error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.objs.RatelimitV4 != nil {
		var key uint32
		var value PhantomRatelimitEntry
		iter := l.objs.RatelimitV4.Iterate()
		for iter.Next(&key, &value) {
			v4Count++
		}
		if iter.Err() != nil {
			err = iter.Err()
		}
	}

	if l.objs.RatelimitV6 != nil {
		var key PhantomIpAddr
		var value PhantomRatelimitEntry
		iter := l.objs.RatelimitV6.Iterate()
		for iter.Next(&key, &value) {
			v6Count++
		}
		if iter.Err() != nil && err == nil {
			err = iter.Err()
		}
	}

	return
}
