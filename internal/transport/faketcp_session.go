//go:build linux

// =============================================================================
// 文件: internal/transport/faketcp_session.go
// 描述: FakeTCP 伪装 - 会话管理 (支持 IPv4/IPv6 双栈)
// =============================================================================
package transport

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// FakeTCPSessionManager 会话管理器
type FakeTCPSessionManager struct {
	// 使用 sync.Map，键为 SessionKey (string)，值为 *FakeTCPSession
	sessions sync.Map

	config *FakeTCPConfig

	// 统计
	stats FakeTCPStats

	// 本地地址
	localAddr *net.UDPAddr

	mu sync.RWMutex
}

// NewFakeTCPSessionManager 创建会话管理器
func NewFakeTCPSessionManager(config *FakeTCPConfig, localAddr *net.UDPAddr) *FakeTCPSessionManager {
	if config == nil {
		config = DefaultFakeTCPConfig()
	}

	return &FakeTCPSessionManager{
		config:    config,
		localAddr: localAddr,
	}
}

// GetOrCreateSession 获取或创建会话
func (m *FakeTCPSessionManager) GetOrCreateSession(remoteAddr *net.UDPAddr) *FakeTCPSession {
	key := NewSessionKey(m.localAddr, remoteAddr)

	// 尝试获取现有会话
	if sessionI, ok := m.sessions.Load(key); ok {
		session := sessionI.(*FakeTCPSession)
		session.mu.Lock()
		session.LastActive = time.Now()
		session.mu.Unlock()
		return session
	}

	// 创建新会话
	session := m.createSession(remoteAddr)
	actual, loaded := m.sessions.LoadOrStore(key, session)
	if loaded {
		return actual.(*FakeTCPSession)
	}

	atomic.AddUint64(&m.stats.TotalSessions, 1)

	// 更新 IPv4/IPv6 统计
	if session.IsIPv6 {
		atomic.AddUint64(&m.stats.IPv6Sessions, 1)
	} else {
		atomic.AddUint64(&m.stats.IPv4Sessions, 1)
	}

	return session
}

// GetSession 获取会话
func (m *FakeTCPSessionManager) GetSession(remoteAddr *net.UDPAddr) *FakeTCPSession {
	key := NewSessionKey(m.localAddr, remoteAddr)
	if sessionI, ok := m.sessions.Load(key); ok {
		return sessionI.(*FakeTCPSession)
	}
	return nil
}

// GetSessionByKey 通过键获取会话
func (m *FakeTCPSessionManager) GetSessionByKey(key SessionKey) *FakeTCPSession {
	if sessionI, ok := m.sessions.Load(key); ok {
		return sessionI.(*FakeTCPSession)
	}
	return nil
}

// createSession 创建新会话
func (m *FakeTCPSessionManager) createSession(remoteAddr *net.UDPAddr) *FakeTCPSession {
	now := time.Now()
	isIPv6 := IsIPv6Addr(remoteAddr)

	session := &FakeTCPSession{
		LocalAddr:     m.localAddr,
		RemoteAddr:    remoteAddr,
		IsIPv6:        isIPv6,
		State:         TCPStateClosed,
		LocalSeq:      m.generateISN(),
		LocalWindow:   m.config.WindowSize,
		MSS:           m.config.GetMSSForVersion(isIPv6),
		WindowScale:   m.config.WindowScale,
		SACKPermitted: m.config.EnableSACK,
		Timestamps:    m.config.EnableTimestamps,
		RTO:           m.config.RetransmitMin,
		CreatedAt:     now,
		LastActive:    now,
	}

	return session
}

// generateISN 生成初始序列号
func (m *FakeTCPSessionManager) generateISN() uint32 {
	if m.config.RandomizeISN {
		var buf [4]byte
		rand.Read(buf[:])
		return binary.BigEndian.Uint32(buf[:])
	}
	return uint32(time.Now().UnixNano() & 0xFFFFFFFF)
}

// RemoveSession 删除会话
func (m *FakeTCPSessionManager) RemoveSession(remoteAddr *net.UDPAddr) {
	key := NewSessionKey(m.localAddr, remoteAddr)
	m.sessions.Delete(key)
}

// RemoveSessionByKey 通过键删除会话
func (m *FakeTCPSessionManager) RemoveSessionByKey(key SessionKey) {
	m.sessions.Delete(key)
}

// HandleIncoming 处理收到的 TCP 包
func (m *FakeTCPSessionManager) HandleIncoming(
	session *FakeTCPSession,
	tcpHeader *TCPHeader,
	payload []byte,
) (response *FakeTCPPacket, data []byte, err error) {
	session.mu.Lock()
	defer session.mu.Unlock()

	session.LastActive = time.Now()
	session.PacketsRecv++

	// 根据状态和标志处理
	switch {
	case tcpHeader.Flags&TCPFlagRST != 0:
		return m.handleRST(session, tcpHeader)

	case tcpHeader.Flags&TCPFlagSYN != 0:
		if tcpHeader.Flags&TCPFlagACK != 0 {
			return m.handleSYNACK(session, tcpHeader)
		}
		return m.handleSYN(session, tcpHeader)

	case tcpHeader.Flags&TCPFlagFIN != 0:
		return m.handleFIN(session, tcpHeader, payload)

	case tcpHeader.Flags&TCPFlagACK != 0:
		return m.handleACK(session, tcpHeader, payload)

	default:
		return nil, nil, fmt.Errorf("unexpected flags: 0x%02x", tcpHeader.Flags)
	}
}

// handleSYN 处理 SYN 包 (被动打开)
func (m *FakeTCPSessionManager) handleSYN(session *FakeTCPSession, tcpHeader *TCPHeader) (*FakeTCPPacket, []byte, error) {
	if session.State != TCPStateClosed && session.State != TCPStateListen {
		return nil, nil, fmt.Errorf("unexpected SYN in state %s", session.State)
	}

	// 记录远程信息
	session.RemoteSeq = tcpHeader.SeqNum
	session.LocalAck = tcpHeader.SeqNum + 1
	session.RemoteWindow = tcpHeader.Window

	// 解析选项
	if mss, ok := GetTCPMSS(tcpHeader.Options); ok {
		// 使用较小的 MSS
		if mss < session.MSS {
			session.MSS = mss
		}
	}
	if wscale, ok := GetTCPWindowScale(tcpHeader.Options); ok {
		session.WindowScale = wscale
	}
	session.SACKPermitted = HasTCPOption(tcpHeader.Options, TCPOptSACKPerm)
	session.Timestamps = HasTCPOption(tcpHeader.Options, TCPOptTimestamp)

	if session.Timestamps {
		if tsVal, _, found := GetTCPTimestamp(tcpHeader.Options); found {
			session.LastTSVal = tsVal
		}
	}

	session.State = TCPStateSynReceived

	// 构建 SYN-ACK 响应
	response := m.buildSYNACK(session)
	session.LocalSeq++ // SYN 消耗一个序列号

	return response, nil, nil
}

// handleSYNACK 处理 SYN-ACK 包 (主动打开)
func (m *FakeTCPSessionManager) handleSYNACK(session *FakeTCPSession, tcpHeader *TCPHeader) (*FakeTCPPacket, []byte, error) {
	if session.State != TCPStateSynSent {
		return nil, nil, fmt.Errorf("unexpected SYN-ACK in state %s", session.State)
	}

	// 验证 ACK
	if tcpHeader.AckNum != session.LocalSeq {
		return nil, nil, fmt.Errorf("invalid ACK: expected %d, got %d", session.LocalSeq, tcpHeader.AckNum)
	}

	session.RemoteSeq = tcpHeader.SeqNum
	session.LocalAck = tcpHeader.SeqNum + 1
	session.RemoteWindow = tcpHeader.Window
	session.RemoteAck = tcpHeader.AckNum

	// 解析选项
	if mss, ok := GetTCPMSS(tcpHeader.Options); ok {
		if mss < session.MSS {
			session.MSS = mss
		}
	}

	session.State = TCPStateEstablished
	session.EstablishedAt = time.Now()
	atomic.AddUint64(&m.stats.SuccessHandshakes, 1)

	// 发送 ACK 完成三次握手
	response := m.buildACK(session, nil)

	return response, nil, nil
}

// handleACK 处理 ACK 包
func (m *FakeTCPSessionManager) handleACK(session *FakeTCPSession, tcpHeader *TCPHeader, payload []byte) (*FakeTCPPacket, []byte, error) {
	// 更新远程确认号和窗口
	if tcpHeader.AckNum > session.RemoteAck {
		session.RemoteAck = tcpHeader.AckNum
	}
	session.RemoteWindow = tcpHeader.Window

	// 更新时间戳
	if session.Timestamps {
		if tsVal, _, found := GetTCPTimestamp(tcpHeader.Options); found {
			session.LastTSVal = tsVal
		}
	}

	switch session.State {
	case TCPStateSynReceived:
		// 三次握手完成
		session.State = TCPStateEstablished
		session.EstablishedAt = time.Now()
		atomic.AddUint64(&m.stats.SuccessHandshakes, 1)

	case TCPStateEstablished:
		// 数据传输
		if len(payload) > 0 {
			// 检查序列号
			if tcpHeader.SeqNum == session.LocalAck {
				session.LocalAck += uint32(len(payload))
				session.BytesReceived += uint64(len(payload))

				// 发送 ACK
				response := m.buildACK(session, nil)
				return response, payload, nil
			}
			// 乱序包，发送重复 ACK
			response := m.buildACK(session, nil)
			return response, nil, nil
		}

	case TCPStateFinWait1:
		session.State = TCPStateFinWait2

	case TCPStateClosing:
		session.State = TCPStateTimeWait
		go m.timeWait(session)

	case TCPStateLastAck:
		session.State = TCPStateClosed
		m.RemoveSession(session.RemoteAddr)
	}

	return nil, nil, nil
}

// handleFIN 处理 FIN 包
func (m *FakeTCPSessionManager) handleFIN(session *FakeTCPSession, tcpHeader *TCPHeader, payload []byte) (*FakeTCPPacket, []byte, error) {
	session.LocalAck = tcpHeader.SeqNum + 1
	if len(payload) > 0 {
		session.LocalAck += uint32(len(payload))
	}

	var response *FakeTCPPacket

	switch session.State {
	case TCPStateEstablished:
		session.State = TCPStateCloseWait
		// 发送 ACK
		response = m.buildACK(session, nil)
		// 然后发送 FIN
		session.State = TCPStateLastAck
		finResponse := m.buildFIN(session)
		session.LocalSeq++
		// 这里简化处理，只返回 FIN-ACK
		finResponse.TCPHeader.Flags |= TCPFlagACK
		response = finResponse

	case TCPStateFinWait1:
		if tcpHeader.Flags&TCPFlagACK != 0 {
			session.State = TCPStateTimeWait
		} else {
			session.State = TCPStateClosing
		}
		response = m.buildACK(session, nil)
		go m.timeWait(session)

	case TCPStateFinWait2:
		session.State = TCPStateTimeWait
		response = m.buildACK(session, nil)
		go m.timeWait(session)
	}

	return response, payload, nil
}

// handleRST 处理 RST 包
func (m *FakeTCPSessionManager) handleRST(session *FakeTCPSession, tcpHeader *TCPHeader) (*FakeTCPPacket, []byte, error) {
	session.State = TCPStateClosed
	m.RemoveSession(session.RemoteAddr)
	return nil, nil, nil
}

// timeWait TIME_WAIT 状态处理
func (m *FakeTCPSessionManager) timeWait(session *FakeTCPSession) {
	time.Sleep(TCPTimeWaitDuration)
	session.mu.Lock()
	session.State = TCPStateClosed
	session.mu.Unlock()
	m.RemoveSession(session.RemoteAddr)
}

// =============================================================================
// 数据包构建 (支持 IPv4/IPv6)
// =============================================================================

// buildSYNACK 构建 SYN-ACK 包
func (m *FakeTCPSessionManager) buildSYNACK(session *FakeTCPSession) *FakeTCPPacket {
	// 构建选项
	var tsVal, tsEcr uint32
	if session.Timestamps {
		tsVal = uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
		tsEcr = session.LastTSVal
		session.TSVal = tsVal
	}

	options := BuildTCPOptions(
		session.MSS,
		session.WindowScale,
		session.SACKPermitted,
		session.Timestamps,
		tsVal, tsEcr,
	)

	tcpHeader := &TCPHeader{
		SrcPort: uint16(session.LocalAddr.Port),
		DstPort: uint16(session.RemoteAddr.Port),
		SeqNum:  session.LocalSeq,
		AckNum:  session.LocalAck,
		Flags:   TCPFlagSYN | TCPFlagACK,
		Window:  session.LocalWindow,
		Options: options,
	}

	pkt := &FakeTCPPacket{
		TCPHeader: tcpHeader,
	}

	// 根据会话类型设置 IP 头部
	m.setIPHeaders(pkt, session)

	return pkt
}

// buildACK 构建 ACK 包
func (m *FakeTCPSessionManager) buildACK(session *FakeTCPSession, payload []byte) *FakeTCPPacket {
	var options []TCPOption
	if session.Timestamps {
		tsVal := uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
		session.TSVal = tsVal
		data := make([]byte, 8)
		binary.BigEndian.PutUint32(data[0:4], tsVal)
		binary.BigEndian.PutUint32(data[4:8], session.LastTSVal)
		options = append(options, TCPOption{
			Kind:   TCPOptTimestamp,
			Length: 10,
			Data:   data,
		})
	}

	flags := uint8(TCPFlagACK)
	if len(payload) > 0 {
		flags |= TCPFlagPSH
	}

	tcpHeader := &TCPHeader{
		SrcPort: uint16(session.LocalAddr.Port),
		DstPort: uint16(session.RemoteAddr.Port),
		SeqNum:  session.LocalSeq,
		AckNum:  session.LocalAck,
		Flags:   flags,
		Window:  session.LocalWindow,
		Options: options,
	}

	pkt := &FakeTCPPacket{
		TCPHeader: tcpHeader,
		Payload:   payload,
	}

	m.setIPHeaders(pkt, session)

	return pkt
}

// buildFIN 构建 FIN 包
func (m *FakeTCPSessionManager) buildFIN(session *FakeTCPSession) *FakeTCPPacket {
	tcpHeader := &TCPHeader{
		SrcPort: uint16(session.LocalAddr.Port),
		DstPort: uint16(session.RemoteAddr.Port),
		SeqNum:  session.LocalSeq,
		AckNum:  session.LocalAck,
		Flags:   TCPFlagFIN | TCPFlagACK,
		Window:  session.LocalWindow,
	}

	pkt := &FakeTCPPacket{
		TCPHeader: tcpHeader,
	}

	m.setIPHeaders(pkt, session)

	return pkt
}

// buildRST 构建 RST 包
func (m *FakeTCPSessionManager) buildRST(session *FakeTCPSession) *FakeTCPPacket {
	tcpHeader := &TCPHeader{
		SrcPort: uint16(session.LocalAddr.Port),
		DstPort: uint16(session.RemoteAddr.Port),
		SeqNum:  session.LocalSeq,
		Flags:   TCPFlagRST,
		Window:  0,
	}

	pkt := &FakeTCPPacket{
		TCPHeader: tcpHeader,
	}

	m.setIPHeaders(pkt, session)

	return pkt
}

// setIPHeaders 设置 IP 头部 (根据会话类型自动选择 IPv4/IPv6)
func (m *FakeTCPSessionManager) setIPHeaders(pkt *FakeTCPPacket, session *FakeTCPSession) {
	if session.IsIPv6 {
		pkt.IPv6Header = &IPv6Header{
			Version:      6,
			TrafficClass: m.config.TrafficClass,
			FlowLabel:    m.config.FlowLabel,
			NextHeader:   ProtocolTCP,
			HopLimit:     m.config.HopLimit,
			SrcIP:        session.LocalAddr.IP.To16(),
			DstIP:        session.RemoteAddr.IP.To16(),
		}
	} else {
		pkt.IPHeader = &IPHeader{
			Version:  4,
			IHL:      5,
			TOS:      m.config.TOS,
			TTL:      m.config.TTL,
			Protocol: ProtocolTCP,
			SrcIP:    session.LocalAddr.IP.To4(),
			DstIP:    session.RemoteAddr.IP.To4(),
		}
	}
}

// =============================================================================
// 主动操作
// =============================================================================

// InitiateConnection 发起主动连接 (发送 SYN)
func (m *FakeTCPSessionManager) InitiateConnection(session *FakeTCPSession) *FakeTCPPacket {
	session.mu.Lock()
	defer session.mu.Unlock()

	session.State = TCPStateSynSent

	// 构建选项
	var tsVal uint32
	if session.Timestamps {
		tsVal = uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
		session.TSVal = tsVal
	}

	options := BuildTCPOptions(
		session.MSS,
		session.WindowScale,
		session.SACKPermitted,
		session.Timestamps,
		tsVal, 0,
	)

	tcpHeader := &TCPHeader{
		SrcPort: uint16(session.LocalAddr.Port),
		DstPort: uint16(session.RemoteAddr.Port),
		SeqNum:  session.LocalSeq,
		AckNum:  0,
		Flags:   TCPFlagSYN,
		Window:  session.LocalWindow,
		Options: options,
	}

	session.LocalSeq++ // SYN 消耗一个序列号

	pkt := &FakeTCPPacket{
		TCPHeader: tcpHeader,
	}

	m.setIPHeaders(pkt, session)

	return pkt
}

// SendData 发送数据
func (m *FakeTCPSessionManager) SendData(session *FakeTCPSession, data []byte) *FakeTCPPacket {
	session.mu.Lock()
	defer session.mu.Unlock()

	// 对于简化的 FakeTCP，允许在非 ESTABLISHED 状态发送
	// 实际会话状态可能还未完全建立
	if session.State == TCPStateClosed {
		session.State = TCPStateEstablished
	}

	// 分片
	mss := int(session.GetMSS())
	if mss == 0 {
		mss = DefaultMSS
	}
	if len(data) > mss {
		data = data[:mss]
	}

	pkt := m.buildACKWithoutLock(session, data)
	session.LocalSeq += uint32(len(data))
	session.BytesSent += uint64(len(data))
	session.PacketsSent++

	return pkt
}

// buildACKWithoutLock 构建 ACK 包 (不加锁版本，供内部使用)
func (m *FakeTCPSessionManager) buildACKWithoutLock(session *FakeTCPSession, payload []byte) *FakeTCPPacket {
	var options []TCPOption
	if session.Timestamps {
		tsVal := uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
		session.TSVal = tsVal
		data := make([]byte, 8)
		binary.BigEndian.PutUint32(data[0:4], tsVal)
		binary.BigEndian.PutUint32(data[4:8], session.LastTSVal)
		options = append(options, TCPOption{
			Kind:   TCPOptTimestamp,
			Length: 10,
			Data:   data,
		})
	}

	flags := uint8(TCPFlagACK)
	if len(payload) > 0 {
		flags |= TCPFlagPSH
	}

	window := session.LocalWindow
	if window == 0 {
		window = DefaultTCPWindow
	}

	tcpHeader := &TCPHeader{
		SrcPort:    uint16(session.LocalAddr.Port),
		DstPort:    uint16(session.RemoteAddr.Port),
		SeqNum:     session.LocalSeq,
		AckNum:     session.LocalAck,
		DataOffset: 5,
		Flags:      flags,
		Window:     window,
		Options:    options,
	}

	pkt := &FakeTCPPacket{
		TCPHeader: tcpHeader,
		Payload:   payload,
	}

	m.setIPHeaders(pkt, session)

	return pkt
}

// CloseConnection 关闭连接
func (m *FakeTCPSessionManager) CloseConnection(session *FakeTCPSession) *FakeTCPPacket {
	session.mu.Lock()
	defer session.mu.Unlock()

	if session.State != TCPStateEstablished && session.State != TCPStateCloseWait {
		return nil
	}

	session.State = TCPStateFinWait1
	pkt := m.buildFIN(session)
	session.LocalSeq++

	return pkt
}

// =============================================================================
// 统计与清理
// =============================================================================

// GetStats 获取统计
func (m *FakeTCPSessionManager) GetStats() *FakeTCPStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := m.stats
	m.sessions.Range(func(key, value interface{}) bool {
		stats.ActiveSessions++
		return true
	})

	return &stats
}

// Cleanup 清理超时会话
func (m *FakeTCPSessionManager) Cleanup() {
	now := time.Now()
	var toRemove []SessionKey

	m.sessions.Range(func(key, value interface{}) bool {
		session := value.(*FakeTCPSession)
		session.mu.RLock()
		idle := now.Sub(session.LastActive)
		state := session.State
		session.mu.RUnlock()

		if idle > m.config.IdleTimeout || state == TCPStateClosed {
			toRemove = append(toRemove, key.(SessionKey))
		}
		return true
	})

	for _, key := range toRemove {
		m.sessions.Delete(key)
	}
}

// CleanupPeriodic 周期性清理
func (m *FakeTCPSessionManager) CleanupPeriodic(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.Cleanup()
		case <-stop:
			return
		}
	}
}

// GetAllSessions 获取所有会话 (用于调试)
func (m *FakeTCPSessionManager) GetAllSessions() []*FakeTCPSession {
	var sessions []*FakeTCPSession
	m.sessions.Range(func(key, value interface{}) bool {
		sessions = append(sessions, value.(*FakeTCPSession))
		return true
	})
	return sessions
}

// GetSessionCount 获取会话数量
func (m *FakeTCPSessionManager) GetSessionCount() int {
	count := 0
	m.sessions.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// GetIPv6SessionCount 获取 IPv6 会话数量
func (m *FakeTCPSessionManager) GetIPv6SessionCount() int {
	count := 0
	m.sessions.Range(func(key, value interface{}) bool {
		session := value.(*FakeTCPSession)
		if session.IsIPv6 {
			count++
		}
		return true
	})
	return count
}
