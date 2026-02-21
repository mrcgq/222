


// =============================================================================
// 文件: internal/transport/arq_conn.go
// 描述: ARQ 可靠传输 - 连接管理 (修复版：资源泄露风险修复)
// =============================================================================
package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrcgq/211/internal/congestion"
)

// 错误定义
var (
	ErrConnClosed    = fmt.Errorf("连接已关闭")
	ErrConnNotReady  = fmt.Errorf("连接未建立")
	ErrSendQueueFull = fmt.Errorf("发送队列已满")
	ErrRecvQueueFull = fmt.Errorf("接收队列已满")
	ErrConnTimeout   = fmt.Errorf("连接超时")
	ErrInvalidState  = fmt.Errorf("无效状态")
)

// ARQConn ARQ 连接
type ARQConn struct {
	// 底层 UDP
	udpConn    *net.UDPConn
	remoteAddr *net.UDPAddr
	localAddr  *net.UDPAddr

	// 配置
	config *ARQConnConfig

	// 发送/接收缓冲区
	sendBuf *ARQSendBuffer
	recvBuf *ARQRecvBuffer

	// 序列号
	localSeq  uint32 // 本地发送序列号
	remoteSeq uint32 // 远程期望序列号

	// 拥塞控制适配器
	ccAdapter *congestion.CongestionAdapter

	// RTT 估算
	srtt   time.Duration
	rttVar time.Duration
	rto    time.Duration
	minRTT time.Duration

	// 窗口
	localWindow  uint16 // 本地接收窗口
	remoteWindow uint16 // 远程接收窗口

	// 状态
	state         ARQState
	established   chan struct{}
	establishedMu sync.Mutex // 保护 established channel 的关闭
	closed        int32
	closeOnce     sync.Once
	closeErr      error // 关闭原因

	// 延迟 ACK
	ackPending  bool
	ackDeadline time.Time

	// 心跳
	lastSend time.Time
	lastRecv time.Time
	lastPing time.Time
	pingSeq  uint32

	// 数据通道
	recvQueue chan []byte
	sendQueue chan *sendItem // 改为结构体，支持取消

	// 回调
	handler ARQHandler

	// 控制
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex

	// 统计
	stats     ARQStats
	startTime time.Time

	// 清理标记
	cleanupDone int32
}

// sendItem 发送项（支持取消和错误反馈）
type sendItem struct {
	data   []byte
	ctx    context.Context
	result chan error
}

// NewARQConn 创建 ARQ 连接
func NewARQConn(
	udpConn *net.UDPConn,
	remoteAddr *net.UDPAddr,
	config *ARQConnConfig,
	cc *congestion.Hysteria2Controller,
	handler ARQHandler,
) *ARQConn {
	if config == nil {
		config = DefaultARQConnConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	// 随机初始序列号
	initialSeq := uint32(time.Now().UnixNano() & 0xFFFFFFFF)

	c := &ARQConn{
		udpConn:     udpConn,
		remoteAddr:  remoteAddr,
		config:      config,
		sendBuf:     NewARQSendBuffer(config.MaxWindowSize, initialSeq),
		recvBuf:     NewARQRecvBuffer(ARQRecvBufferSize, 1),
		localSeq:    initialSeq,
		remoteSeq:   0,
		ccAdapter:   congestion.NewCongestionAdapter(cc),
		rto:         config.RTOInit,
		localWindow: uint16(config.MaxWindowSize),
		state:       ARQStateClosed,
		established: make(chan struct{}),
		recvQueue:   make(chan []byte, ARQRecvQueueSize),
		sendQueue:   make(chan *sendItem, ARQSendBufferSize),
		handler:     handler,
		ctx:         ctx,
		cancel:      cancel,
		startTime:   time.Now(),
	}

	if udpConn != nil {
		c.localAddr = udpConn.LocalAddr().(*net.UDPAddr)
	}

	return c
}

// Connect 主动连接 (发送 SYN)
func (c *ARQConn) Connect(ctx context.Context) error {
	c.mu.Lock()
	if c.state != ARQStateClosed {
		state := c.state
		c.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrInvalidState, state)
	}
	c.state = ARQStateSynSent
	c.mu.Unlock()

	// 发送 SYN
	syn := NewSynPacket(c.localSeq, c.localWindow)
	if err := c.sendPacket(syn); err != nil {
		c.mu.Lock()
		c.state = ARQStateClosed
		c.mu.Unlock()
		return fmt.Errorf("发送 SYN 失败: %w", err)
	}
	c.localSeq++

	// 等待 SYN-ACK，使用多路选择避免泄露
	select {
	case <-ctx.Done():
		c.mu.Lock()
		c.state = ARQStateClosed
		c.mu.Unlock()
		return ctx.Err()
	case <-c.ctx.Done():
		// 连接被关闭
		return ErrConnClosed
	case <-c.established:
		return nil
	case <-time.After(10 * time.Second):
		c.mu.Lock()
		c.state = ARQStateClosed
		c.mu.Unlock()
		return ErrConnTimeout
	}
}

// Accept 被动接受连接 (收到 SYN 后调用)
func (c *ARQConn) Accept(synPacket *ARQPacket) error {
	c.mu.Lock()
	if c.state != ARQStateClosed && c.state != ARQStateListen {
		state := c.state
		c.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrInvalidState, state)
	}

	c.remoteSeq = synPacket.Seq + 1
	c.recvBuf.Reset(c.remoteSeq)
	c.state = ARQStateSynReceived
	c.mu.Unlock()

	// 发送 SYN-ACK
	synAck := NewSynAckPacket(c.localSeq, c.remoteSeq, c.localWindow)
	if err := c.sendPacket(synAck); err != nil {
		c.mu.Lock()
		c.state = ARQStateClosed
		c.mu.Unlock()
		return fmt.Errorf("发送 SYN-ACK 失败: %w", err)
	}
	c.localSeq++

	return nil
}

// Start 启动连接处理循环
func (c *ARQConn) Start() {
	c.wg.Add(4)
	go c.sendLoop()
	go c.retransmitLoop()
	go c.ackLoop()
	go c.keepaliveLoop()
}

// HandlePacket 处理收到的 ARQ 包
func (c *ARQConn) HandlePacket(pkt *ARQPacket) {
	// 检查连接是否已关闭
	if c.IsClosed() {
		return
	}

	c.mu.Lock()
	c.lastRecv = time.Now()
	c.remoteWindow = pkt.Window
	c.mu.Unlock()

	// 更新统计
	atomic.AddUint64(&c.stats.PacketsReceived, 1)

	// 根据标志位处理
	if pkt.Flags&ARQFlagRST != 0 {
		c.handleRst(pkt)
		return
	}

	if pkt.Flags&ARQFlagSYN != 0 {
		c.handleSyn(pkt)
		return
	}

	if pkt.Flags&ARQFlagFIN != 0 {
		c.handleFin(pkt)
		return
	}

	if pkt.Flags&ARQFlagPING != 0 {
		c.handlePing(pkt)
		return
	}

	if pkt.Flags&ARQFlagPONG != 0 {
		c.handlePong(pkt)
		return
	}

	if pkt.Flags&ARQFlagACK != 0 {
		c.handleAck(pkt)
	}

	if pkt.Flags&ARQFlagDATA != 0 {
		c.handleData(pkt)
	}
}

// handleSyn 处理 SYN
func (c *ARQConn) handleSyn(pkt *ARQPacket) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if pkt.Flags&ARQFlagACK != 0 {
		// SYN-ACK
		if c.state == ARQStateSynSent {
			c.remoteSeq = pkt.Seq + 1
			c.recvBuf.Reset(c.remoteSeq)
			c.state = ARQStateEstablished

			// 发送 ACK
			ack := NewAckPacket(c.remoteSeq, c.localWindow, nil)
			c.sendPacketLocked(ack)

			// 安全关闭 established channel
			c.closeEstablishedChannel()

			if c.handler != nil {
				go c.handler.OnConnected(c.remoteAddr)
			}
		}
	}
}

// closeEstablishedChannel 安全关闭 established channel
func (c *ARQConn) closeEstablishedChannel() {
	c.establishedMu.Lock()
	defer c.establishedMu.Unlock()

	select {
	case <-c.established:
		// 已经关闭
	default:
		close(c.established)
	}
}

// handleAck 处理 ACK
func (c *ARQConn) handleAck(pkt *ARQPacket) {
	// 使用适配器处理累积确认
	ackedBytes, rtt := c.ccAdapter.OnARQPacketAcked(pkt.Ack)

	if ackedBytes > 0 {
		atomic.AddUint64(&c.stats.AcksReceived, 1)
		atomic.AddInt64(&c.stats.BytesInFlight, -int64(ackedBytes))

		if rtt > 0 {
			c.updateRTT(rtt)
		}
	}

	// 同步发送缓冲区状态
	c.sendBuf.OnAck(pkt.Ack)

	// 处理 SACK
	if pkt.Flags&ARQFlagSACK != 0 && len(pkt.SACKRanges) > 0 {
		ranges := make([][2]uint32, len(pkt.SACKRanges))
		for i, r := range pkt.SACKRanges {
			ranges[i] = [2]uint32{r.Start, r.End}
		}
		sackedBytes := c.ccAdapter.OnARQPacketSACKed(ranges)
		if sackedBytes > 0 {
			atomic.AddInt64(&c.stats.BytesInFlight, -int64(sackedBytes))
		}
		c.sendBuf.OnSACK(pkt.SACKRanges)
	}

	// 状态机
	c.mu.Lock()
	if c.state == ARQStateSynReceived {
		c.state = ARQStateEstablished
		c.closeEstablishedChannel()
		if c.handler != nil {
			go c.handler.OnConnected(c.remoteAddr)
		}
	}
	c.mu.Unlock()
}

// handleData 处理数据
func (c *ARQConn) handleData(pkt *ARQPacket) {
	if len(pkt.Data) == 0 {
		return
	}

	// 插入接收缓冲区
	isDup, _ := c.recvBuf.Insert(pkt.Seq, pkt.Data)
	if isDup {
		atomic.AddUint64(&c.stats.DupAcks, 1)
	} else {
		atomic.AddUint64(&c.stats.BytesReceived, uint64(len(pkt.Data)))
	}

	// 读取有序数据
	orderedData := c.recvBuf.ReadOrdered()
	for _, data := range orderedData {
		// 修复：完全非阻塞入队
		// 当队列满时直接丢弃，依靠 ARQ 机制让对端重传
		// 彻底消除极端流量下的 Goroutine 泄漏风险
		if !c.tryEnqueueRecv(data) {
			atomic.AddUint64(&c.stats.RecvQueueDrops, 1)
		}
	}

	// 标记需要发送 ACK
	c.mu.Lock()
	c.ackPending = true
	if c.ackDeadline.IsZero() {
		c.ackDeadline = time.Now().Add(c.config.AckDelay)
	}
	c.mu.Unlock()
}

// tryEnqueueRecv 尝试入队接收数据
// 修复：完全非阻塞，队列满时直接返回 false
// 这是 ARQ (可靠传输)，丢弃后对方没有收到 ACK 会自动重传
// 绝对不能在这里阻塞 Goroutine，否则在 DDoS 或极大吞吐时会耗尽资源
func (c *ARQConn) tryEnqueueRecv(data []byte) bool {
	select {
	case c.recvQueue <- data:
		return true
	default:
		// 核心修复：队列满时直接丢弃！
		// 因为这是 ARQ (可靠传输)，丢弃后对方没有收到 ACK 会自动重传
		// 绝对不能在这里阻塞 Goroutine
		return false
	}
}

// handleFin 处理 FIN
func (c *ARQConn) handleFin(pkt *ARQPacket) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch c.state {
	case ARQStateEstablished:
		c.state = ARQStateCloseWait
		c.remoteSeq = pkt.Seq + 1
		fin := NewFinPacket(c.localSeq, c.remoteSeq)
		c.sendPacketLocked(fin)
		c.localSeq++
		c.state = ARQStateLastAck

	case ARQStateFinWait1:
		c.remoteSeq = pkt.Seq + 1
		ack := NewAckPacket(c.remoteSeq, 0, nil)
		c.sendPacketLocked(ack)
		c.state = ARQStateClosing

	case ARQStateFinWait2:
		c.remoteSeq = pkt.Seq + 1
		ack := NewAckPacket(c.remoteSeq, 0, nil)
		c.sendPacketLocked(ack)
		c.state = ARQStateTimeWait
		go c.timeWait()
	}
}

// handleRst 处理 RST
func (c *ARQConn) handleRst(pkt *ARQPacket) {
	c.close(fmt.Errorf("收到 RST"))
}

// handlePing 处理 PING
func (c *ARQConn) handlePing(pkt *ARQPacket) {
	if c.IsClosed() {
		return
	}
	pong := NewPongPacket(c.recvBuf.GetExpectedSeq(), pkt.Timestamp)
	c.sendPacket(pong)
}

// handlePong 处理 PONG
func (c *ARQConn) handlePong(pkt *ARQPacket) {
	rtt := CalculateRTT(pkt.Timestamp)
	if rtt > 0 && rtt < 30*time.Second {
		c.updateRTT(rtt)
	}
}

// sendLoop 发送循环
func (c *ARQConn) sendLoop() {
	defer c.wg.Done()
	defer c.drainSendQueue()

	for {
		select {
		case <-c.ctx.Done():
			return
		case item := <-c.sendQueue:
			if item == nil {
				continue
			}
			err := c.sendDataWithContext(item.ctx, item.data)
			// 发送结果反馈
			if item.result != nil {
				select {
				case item.result <- err:
				default:
				}
				close(item.result)
			}
		}
	}
}

// drainSendQueue 清空发送队列
func (c *ARQConn) drainSendQueue() {
	for {
		select {
		case item := <-c.sendQueue:
			if item != nil && item.result != nil {
				select {
				case item.result <- ErrConnClosed:
				default:
				}
				close(item.result)
			}
		default:
			return
		}
	}
}

// sendDataWithContext 发送数据，支持取消
func (c *ARQConn) sendDataWithContext(ctx context.Context, data []byte) error {
	// 分片
	for len(data) > 0 {
		// 检查取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.ctx.Done():
			return ErrConnClosed
		default:
		}

		chunkSize := len(data)
		if chunkSize > ARQMaxPayloadSize {
			chunkSize = ARQMaxPayloadSize
		}
		chunk := data[:chunkSize]
		data = data[chunkSize:]

		// 等待窗口可用，带超时和取消
		if err := c.waitForWindow(ctx, chunkSize); err != nil {
			return err
		}

		// 添加到发送缓冲区
		seq, ok := c.sendBuf.Add(chunk)
		if !ok {
			continue
		}

		// 创建并发送数据包
		pkt := NewDataPacket(seq, c.recvBuf.GetExpectedSeq(), c.localWindow, chunk)
		if err := c.sendPacket(pkt); err != nil {
			continue
		}

		// 标记发送时间
		c.sendBuf.MarkSent(seq, c.rto)

		// 通过适配器记录发送
		c.ccAdapter.OnARQPacketSent(seq, len(chunk)+ARQHeaderSize, false)

		atomic.AddUint64(&c.stats.PacketsSent, 1)
		atomic.AddUint64(&c.stats.BytesSent, uint64(len(chunk)))
		atomic.AddInt64(&c.stats.BytesInFlight, int64(len(chunk)))
	}

	return nil
}

// waitForWindow 等待发送窗口可用
func (c *ARQConn) waitForWindow(ctx context.Context, size int) error {
	// 快速路径
	if !c.sendBuf.IsFull() && c.canSend(size) {
		return nil
	}

	// 带超时的等待
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	timeout := time.NewTimer(30 * time.Second) // 最大等待时间
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.ctx.Done():
			return ErrConnClosed
		case <-timeout.C:
			return fmt.Errorf("等待发送窗口超时")
		case <-ticker.C:
			if !c.sendBuf.IsFull() && c.canSend(size) {
				return nil
			}
		}
	}
}

// retransmitLoop 重传循环
func (c *ARQConn) retransmitLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.rto / 4)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.processRetransmits()
		}
	}
}

// processRetransmits 处理重传
func (c *ARQConn) processRetransmits() {
	if c.IsClosed() {
		return
	}

	now := time.Now()

	// 快速重传
	fastRetransmits := c.sendBuf.GetFastRetransmitPackets()
	for _, info := range fastRetransmits {
		if c.IsClosed() {
			return
		}

		if info.Retries >= c.config.MaxRetries {
			c.sendBuf.MarkLost(info.Seq)
			c.ccAdapter.OnARQPacketLost(info.Seq)
			atomic.AddUint64(&c.stats.PacketsLost, 1)
			continue
		}

		pkt := NewDataPacket(info.Seq, c.recvBuf.GetExpectedSeq(), c.localWindow, info.Data)
		if err := c.sendPacket(pkt); err == nil {
			c.sendBuf.MarkRetransmit(info.Seq, c.rto)
			c.ccAdapter.OnARQPacketRetransmit(info.Seq)
			atomic.AddUint64(&c.stats.FastRetransmits, 1)
			atomic.AddUint64(&c.stats.Retransmits, 1)
		}
	}

	// 超时重传
	timeoutRetransmits := c.sendBuf.GetRetransmitPackets(now)
	for _, info := range timeoutRetransmits {
		if c.IsClosed() {
			return
		}

		if info.Retries >= c.config.MaxRetries {
			c.sendBuf.MarkLost(info.Seq)
			c.ccAdapter.OnARQPacketLost(info.Seq)
			atomic.AddUint64(&c.stats.PacketsLost, 1)
			continue
		}

		pkt := NewDataPacket(info.Seq, c.recvBuf.GetExpectedSeq(), c.localWindow, info.Data)
		if err := c.sendPacket(pkt); err == nil {
			newRTO := c.rto * 2
			if newRTO > c.config.RTOMax {
				newRTO = c.config.RTOMax
			}
			c.sendBuf.MarkRetransmit(info.Seq, newRTO)
			c.ccAdapter.OnARQPacketRetransmit(info.Seq)
			atomic.AddUint64(&c.stats.TimeoutRetransmits, 1)
			atomic.AddUint64(&c.stats.Retransmits, 1)
		}
	}
}

// ackLoop ACK 发送循环
func (c *ARQConn) ackLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.AckDelay)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.maybeSendAck()
		}
	}
}

// maybeSendAck 可能发送 ACK
func (c *ARQConn) maybeSendAck() {
	if c.IsClosed() {
		return
	}

	c.mu.Lock()
	if !c.ackPending {
		c.mu.Unlock()
		return
	}

	if time.Now().Before(c.ackDeadline) && !c.recvBuf.HasGaps() {
		c.mu.Unlock()
		return
	}

	c.ackPending = false
	c.ackDeadline = time.Time{}
	c.mu.Unlock()

	var sackRanges []SACKRange
	if c.config.EnableSACK && c.recvBuf.HasGaps() {
		sackRanges = c.recvBuf.GetSACKRanges()
	}

	ack := NewAckPacket(c.recvBuf.GetExpectedSeq(), uint16(c.recvBuf.GetWindowSize()), sackRanges)
	c.sendPacket(ack)
	atomic.AddUint64(&c.stats.AcksSent, 1)
}

// keepaliveLoop 心跳循环
func (c *ARQConn) keepaliveLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.Keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.checkKeepalive()
		}
	}
}

// checkKeepalive 检查心跳
func (c *ARQConn) checkKeepalive() {
	if c.IsClosed() {
		return
	}

	c.mu.RLock()
	lastRecv := c.lastRecv
	state := c.state
	lastSend := c.lastSend
	c.mu.RUnlock()

	if state != ARQStateEstablished {
		return
	}

	if time.Since(lastRecv) > c.config.IdleTimeout {
		c.close(fmt.Errorf("空闲超时"))
		return
	}

	if time.Since(lastSend) > c.config.Keepalive/2 {
		ping := NewPingPacket(c.localSeq, c.recvBuf.GetExpectedSeq())
		c.sendPacket(ping)
		c.mu.Lock()
		c.lastPing = time.Now()
		c.pingSeq = c.localSeq
		c.mu.Unlock()
	}
}

// Send 发送数据 (非阻塞)
func (c *ARQConn) Send(data []byte) error {
	return c.SendWithContext(context.Background(), data)
}

// SendWithContext 发送数据，支持取消
func (c *ARQConn) SendWithContext(ctx context.Context, data []byte) error {
	if c.IsClosed() {
		return ErrConnClosed
	}

	c.mu.RLock()
	if c.state != ARQStateEstablished {
		state := c.state
		c.mu.RUnlock()
		return fmt.Errorf("%w: %s", ErrConnNotReady, state)
	}
	c.mu.RUnlock()

	// 复制数据
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	item := &sendItem{
		data:   dataCopy,
		ctx:    ctx,
		result: make(chan error, 1),
	}

	select {
	case c.sendQueue <- item:
		// 等待发送结果
		select {
		case err := <-item.result:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-c.ctx.Done():
			return ErrConnClosed
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return ErrConnClosed
	default:
		return ErrSendQueueFull
	}
}

// SendAsync 异步发送数据 (非阻塞，不等待结果)
func (c *ARQConn) SendAsync(data []byte) error {
	if c.IsClosed() {
		return ErrConnClosed
	}

	c.mu.RLock()
	if c.state != ARQStateEstablished {
		state := c.state
		c.mu.RUnlock()
		return fmt.Errorf("%w: %s", ErrConnNotReady, state)
	}
	c.mu.RUnlock()

	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	item := &sendItem{
		data:   dataCopy,
		ctx:    c.ctx,
		result: nil, // 不等待结果
	}

	select {
	case c.sendQueue <- item:
		return nil
	default:
		return ErrSendQueueFull
	}
}

// Recv 接收数据 (阻塞)
func (c *ARQConn) Recv(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		// 连接关闭，但先检查是否还有数据
		select {
		case data := <-c.recvQueue:
			return data, nil
		default:
			return nil, ErrConnClosed
		}
	case data := <-c.recvQueue:
		return data, nil
	}
}

// RecvNonblock 接收数据 (非阻塞)
func (c *ARQConn) RecvNonblock() ([]byte, bool) {
	select {
	case data := <-c.recvQueue:
		return data, true
	default:
		return nil, false
	}
}

// Close 关闭连接
func (c *ARQConn) Close() error {
	return c.close(nil)
}

// close 内部关闭
func (c *ARQConn) close(reason error) error {
	c.closeOnce.Do(func() {
		atomic.StoreInt32(&c.closed, 1)
		c.closeErr = reason

		c.mu.Lock()
		oldState := c.state

		if oldState == ARQStateEstablished {
			c.state = ARQStateFinWait1
			fin := NewFinPacket(c.localSeq, c.recvBuf.GetExpectedSeq())
			c.sendPacketLocked(fin)
			c.localSeq++
		} else {
			c.state = ARQStateClosed
		}
		c.mu.Unlock()

		// 确保 established channel 已关闭
		c.closeEstablishedChannel()

		// 通知处理器
		if c.handler != nil && oldState == ARQStateEstablished {
			go c.handler.OnDisconnected(c.remoteAddr, reason)
		}

		// 取消上下文
		c.cancel()

		// 等待 goroutine 退出
		c.wg.Wait()

		// 清理资源
		c.cleanup()
	})

	return nil
}

// cleanup 清理资源
func (c *ARQConn) cleanup() {
	if !atomic.CompareAndSwapInt32(&c.cleanupDone, 0, 1) {
		return
	}

	// 清空接收队列
	for {
		select {
		case <-c.recvQueue:
		default:
			return
		}
	}
}

// timeWait TIME_WAIT 状态
func (c *ARQConn) timeWait() {
	select {
	case <-time.After(2 * c.rto):
	case <-c.ctx.Done():
	}

	c.mu.Lock()
	c.state = ARQStateClosed
	c.mu.Unlock()
}

// sendPacket 发送包
func (c *ARQConn) sendPacket(pkt *ARQPacket) error {
	if c.IsClosed() {
		return ErrConnClosed
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sendPacketLocked(pkt)
}

// sendPacketLocked 发送包 (需要持有锁)
func (c *ARQConn) sendPacketLocked(pkt *ARQPacket) error {
	if c.udpConn == nil {
		return fmt.Errorf("UDP 连接为空")
	}

	data := pkt.Encode()
	_, err := c.udpConn.WriteToUDP(data, c.remoteAddr)
	if err == nil {
		c.lastSend = time.Now()
	}
	return err
}

// canSend 检查是否可以发送
func (c *ARQConn) canSend(size int) bool {
	c.mu.RLock()
	remoteWnd := c.remoteWindow
	c.mu.RUnlock()

	if c.sendBuf.InFlightBytes() >= int64(remoteWnd)*int64(c.config.MTU) {
		return false
	}

	return c.ccAdapter.CanSend(size + ARQHeaderSize)
}

// updateRTT 更新 RTT
func (c *ARQConn) updateRTT(sample time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// RFC 6298 算法
	if c.srtt == 0 {
		c.srtt = sample
		c.rttVar = sample / 2
	} else {
		diff := c.srtt - sample
		if diff < 0 {
			diff = -diff
		}
		c.rttVar = time.Duration(float64(c.rttVar)*0.75 + float64(diff)*0.25)
		c.srtt = time.Duration(float64(c.srtt)*0.875 + float64(sample)*0.125)
	}

	if c.minRTT == 0 || sample < c.minRTT {
		c.minRTT = sample
	}

	c.rto = c.srtt + 4*c.rttVar
	if c.rto < c.config.RTOMin {
		c.rto = c.config.RTOMin
	}
	if c.rto > c.config.RTOMax {
		c.rto = c.config.RTOMax
	}

	c.stats.SRTT = c.srtt
	c.stats.RTTVar = c.rttVar
	c.stats.RTO = c.rto
	c.stats.MinRTT = c.minRTT
}

// GetState 获取状态
func (c *ARQConn) GetState() ARQState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// GetRemoteAddr 获取远程地址
func (c *ARQConn) GetRemoteAddr() *net.UDPAddr {
	return c.remoteAddr
}

// GetStats 获取统计
func (c *ARQConn) GetStats() *ARQStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := c.stats
	stats.State = c.state.String()
	stats.LastActivity = c.lastRecv
	stats.Uptime = time.Since(c.startTime)
	stats.SendWindow = c.sendBuf.Available()
	stats.RecvWindow = c.recvBuf.GetWindowSize()

	return &stats
}

// IsEstablished 是否已建立
func (c *ARQConn) IsEstablished() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state == ARQStateEstablished
}

// IsClosed 是否已关闭
func (c *ARQConn) IsClosed() bool {
	return atomic.LoadInt32(&c.closed) != 0
}

// GetCongestionAdapter 获取拥塞控制适配器
func (c *ARQConn) GetCongestionAdapter() *congestion.CongestionAdapter {
	return c.ccAdapter
}

// GetCloseError 获取关闭原因
func (c *ARQConn) GetCloseError() error {
	return c.closeErr
}

// WaitEstablished 等待连接建立
func (c *ARQConn) WaitEstablished(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return ErrConnClosed
	case <-c.established:
		return nil
	}
}





