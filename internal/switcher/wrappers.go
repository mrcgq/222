// =============================================================================
// 文件: internal/switcher/wrappers.go
// 描述: 智能链路切换 - 传输层包装器 (完整修复版)
// =============================================================================
package switcher

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrcgq/211/internal/transport"
)

// =============================================================================
// UDP 包装器
// =============================================================================

type udpTransportWrapper struct {
	server  *transport.UDPServer
	running int32
}

func NewUDPTransportWrapper(server *transport.UDPServer) *udpTransportWrapper {
	return &udpTransportWrapper{server: server, running: 1}
}

func (w *udpTransportWrapper) Start() error {
	atomic.StoreInt32(&w.running, 1)
	return nil
}

func (w *udpTransportWrapper) Stop() error {
	atomic.StoreInt32(&w.running, 0)
	w.server.Stop()
	return nil
}

func (w *udpTransportWrapper) IsRunning() bool {
	if atomic.LoadInt32(&w.running) != 1 {
		return false
	}
	return w.server.IsRunning()
}

func (w *udpTransportWrapper) Send(data []byte, addr *net.UDPAddr) error {
	return w.server.SendTo(data, addr)
}

func (w *udpTransportWrapper) GetState() TransportState {
	if w.IsRunning() {
		return StateRunning
	}
	return StateStopped
}

func (w *udpTransportWrapper) GetQuality() *LinkQuality {
	stats := w.server.GetStats()

	quality := &LinkQuality{
		Available:    w.IsRunning(),
		State:        w.GetState(),
		TotalPackets: stats["packets_recv"],
	}

	if ccStats := w.server.GetCongestionStats(); ccStats != nil {
		quality.RTT = ccStats.SmoothedRTT
		quality.MinRTT = ccStats.MinRTT
		quality.LossRate = ccStats.LossRate
	}

	if arqMgr := w.server.GetARQManager(); arqMgr != nil {
		quality.ActiveConns = int(arqMgr.GetActiveConns())
	}

	return quality
}

func (w *udpTransportWrapper) GetStats() map[string]interface{} {
	stats := w.server.GetStats()
	result := make(map[string]interface{})
	for k, v := range stats {
		result[k] = v
	}
	return result
}

func (w *udpTransportWrapper) Probe(addr *net.UDPAddr) (time.Duration, error) {
	if ccStats := w.server.GetCongestionStats(); ccStats != nil && ccStats.SmoothedRTT > 0 {
		return ccStats.SmoothedRTT, nil
	}
	return 10 * time.Millisecond, nil
}

// =============================================================================
// TCP 包装器 (完整修复版 - 支持连接映射)
// =============================================================================

type tcpTransportWrapper struct {
	server  *transport.TCPServer
	running int32

	// 连接映射: UDP 地址 -> TCP 连接
	connMap     map[string]net.Conn
	connMapLock sync.RWMutex

	// 反向映射: TCP 连接 -> UDP 地址 (用于接收时路由回去)
	reverseMap     map[net.Conn]*net.UDPAddr
	reverseMapLock sync.RWMutex

	// 待发送队列 (连接建立前的数据)
	pendingData     map[string][][]byte
	pendingDataLock sync.Mutex

	// 数据处理回调
	dataHandler func(data []byte, addr *net.UDPAddr)

	// 配置
	dialTimeout    time.Duration
	maxPendingSize int
}

// TCPWrapperConfig TCP 包装器配置
type TCPWrapperConfig struct {
	DialTimeout    time.Duration
	MaxPendingSize int
}

func NewTCPTransportWrapper(server *transport.TCPServer) *tcpTransportWrapper {
	return NewTCPTransportWrapperWithConfig(server, TCPWrapperConfig{
		DialTimeout:    5 * time.Second,
		MaxPendingSize: 100,
	})
}

func NewTCPTransportWrapperWithConfig(server *transport.TCPServer, cfg TCPWrapperConfig) *tcpTransportWrapper {
	w := &tcpTransportWrapper{
		server:         server,
		running:        1,
		connMap:        make(map[string]net.Conn),
		reverseMap:     make(map[net.Conn]*net.UDPAddr),
		pendingData:    make(map[string][][]byte),
		dialTimeout:    cfg.DialTimeout,
		maxPendingSize: cfg.MaxPendingSize,
	}

	return w
}

// SetDataHandler 设置数据处理回调
func (w *tcpTransportWrapper) SetDataHandler(handler func(data []byte, addr *net.UDPAddr)) {
	w.dataHandler = handler
}

func (w *tcpTransportWrapper) Start() error {
	atomic.StoreInt32(&w.running, 1)
	return nil
}

func (w *tcpTransportWrapper) Stop() error {
	atomic.StoreInt32(&w.running, 0)

	// 关闭所有映射的连接
	w.connMapLock.Lock()
	for _, conn := range w.connMap {
		conn.Close()
	}
	w.connMap = make(map[string]net.Conn)
	w.connMapLock.Unlock()

	w.reverseMapLock.Lock()
	w.reverseMap = make(map[net.Conn]*net.UDPAddr)
	w.reverseMapLock.Unlock()

	w.server.Stop()
	return nil
}

func (w *tcpTransportWrapper) IsRunning() bool {
	return atomic.LoadInt32(&w.running) == 1
}

// Send 通过 TCP 发送数据到指定地址
// 核心修复: 维护 UDP 地址到 TCP 连接的映射
func (w *tcpTransportWrapper) Send(data []byte, addr *net.UDPAddr) error {
	if !w.IsRunning() {
		return fmt.Errorf("TCP transport not running")
	}

	addrKey := addr.String()

	// 1. 尝试获取现有连接
	w.connMapLock.RLock()
	conn, exists := w.connMap[addrKey]
	w.connMapLock.RUnlock()

	if exists && conn != nil {
		// 使用现有连接发送
		return w.sendViaConn(conn, data, addr)
	}

	// 2. 连接不存在，需要建立新连接
	return w.sendWithNewConnection(data, addr, addrKey)
}

// sendViaConn 通过现有连接发送数据
func (w *tcpTransportWrapper) sendViaConn(conn net.Conn, data []byte, addr *net.UDPAddr) error {
	// 设置写超时
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	// TCP 需要长度前缀来处理粘包
	// 格式: [4字节长度][数据]
	lengthBuf := make([]byte, 4)
	length := uint32(len(data))
	lengthBuf[0] = byte(length >> 24)
	lengthBuf[1] = byte(length >> 16)
	lengthBuf[2] = byte(length >> 8)
	lengthBuf[3] = byte(length)

	// 合并发送
	packet := append(lengthBuf, data...)

	n, err := conn.Write(packet)
	if err != nil {
		// 连接失败，移除映射
		w.removeConnection(addr.String(), conn)
		return fmt.Errorf("TCP write failed: %w", err)
	}

	if n != len(packet) {
		return fmt.Errorf("TCP partial write: %d/%d", n, len(packet))
	}

	return nil
}

// sendWithNewConnection 建立新连接并发送数据
func (w *tcpTransportWrapper) sendWithNewConnection(data []byte, addr *net.UDPAddr, addrKey string) error {
	// 加入待发送队列
	w.pendingDataLock.Lock()
	if len(w.pendingData[addrKey]) >= w.maxPendingSize {
		w.pendingDataLock.Unlock()
		return fmt.Errorf("pending queue full for %s", addrKey)
	}

	// 复制数据
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	w.pendingData[addrKey] = append(w.pendingData[addrKey], dataCopy)

	// 检查是否已在建立连接
	needDial := len(w.pendingData[addrKey]) == 1
	w.pendingDataLock.Unlock()

	if needDial {
		// 异步建立连接
		go w.dialAndFlush(addr, addrKey)
	}

	return nil // 数据已加入队列
}

// dialAndFlush 建立连接并发送待发送的数据
func (w *tcpTransportWrapper) dialAndFlush(addr *net.UDPAddr, addrKey string) {
	// 建立 TCP 连接
	tcpAddr := &net.TCPAddr{
		IP:   addr.IP,
		Port: addr.Port,
	}

	conn, err := net.DialTimeout("tcp", tcpAddr.String(), w.dialTimeout)
	if err != nil {
		// 连接失败，清空待发送队列
		w.pendingDataLock.Lock()
		delete(w.pendingData, addrKey)
		w.pendingDataLock.Unlock()
		return
	}

	// 保存连接映射
	w.connMapLock.Lock()
	w.connMap[addrKey] = conn
	w.connMapLock.Unlock()

	w.reverseMapLock.Lock()
	w.reverseMap[conn] = addr
	w.reverseMapLock.Unlock()

	// 发送所有待发送数据
	w.pendingDataLock.Lock()
	pending := w.pendingData[addrKey]
	delete(w.pendingData, addrKey)
	w.pendingDataLock.Unlock()

	for _, data := range pending {
		if err := w.sendViaConn(conn, data, addr); err != nil {
			// 发送失败，后续数据也可能失败，但我们继续尝试
			continue
		}
	}

	// 启动接收协程
	go w.receiveLoop(conn, addr)
}

// receiveLoop 接收循环
func (w *tcpTransportWrapper) receiveLoop(conn net.Conn, addr *net.UDPAddr) {
	defer func() {
		conn.Close()
		w.removeConnection(addr.String(), conn)
	}()

	lengthBuf := make([]byte, 4)
	for w.IsRunning() {
		// 读取长度
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_, err := readFull(conn, lengthBuf)
		if err != nil {
			return
		}

		length := uint32(lengthBuf[0])<<24 | uint32(lengthBuf[1])<<16 |
			uint32(lengthBuf[2])<<8 | uint32(lengthBuf[3])

		if length > 65535 {
			return // 无效长度
		}

		// 读取数据
		data := make([]byte, length)
		_, err = readFull(conn, data)
		if err != nil {
			return
		}

		// 将数据转发给处理回调
		if w.dataHandler != nil {
			w.dataHandler(data, addr)
		}
	}
}

// readFull 完整读取指定字节数
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// removeConnection 移除连接映射
func (w *tcpTransportWrapper) removeConnection(addrKey string, conn net.Conn) {
	w.connMapLock.Lock()
	if existing, ok := w.connMap[addrKey]; ok && existing == conn {
		delete(w.connMap, addrKey)
	}
	w.connMapLock.Unlock()

	w.reverseMapLock.Lock()
	delete(w.reverseMap, conn)
	w.reverseMapLock.Unlock()
}

// HandleIncomingConnection 处理新的入站连接
func (w *tcpTransportWrapper) HandleIncomingConnection(conn net.Conn) {
	// 对于入站连接，我们需要等待第一个数据包来确定客户端身份
	// 或者通过 TCP 连接的远程地址建立映射
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	udpAddr := &net.UDPAddr{
		IP:   remoteAddr.IP,
		Port: remoteAddr.Port,
	}
	addrKey := udpAddr.String()

	w.connMapLock.Lock()
	w.connMap[addrKey] = conn
	w.connMapLock.Unlock()

	w.reverseMapLock.Lock()
	w.reverseMap[conn] = udpAddr
	w.reverseMapLock.Unlock()

	go w.receiveLoop(conn, udpAddr)
}

// RegisterConnection 显式注册 UDP 地址到 TCP 连接的映射
// 用于 Switcher 在切换时提前建立连接映射
func (w *tcpTransportWrapper) RegisterConnection(udpAddr *net.UDPAddr, conn net.Conn) {
	addrKey := udpAddr.String()

	w.connMapLock.Lock()
	w.connMap[addrKey] = conn
	w.connMapLock.Unlock()

	w.reverseMapLock.Lock()
	w.reverseMap[conn] = udpAddr
	w.reverseMapLock.Unlock()
}

// GetConnection 获取指定地址的 TCP 连接
func (w *tcpTransportWrapper) GetConnection(addr *net.UDPAddr) (net.Conn, bool) {
	w.connMapLock.RLock()
	defer w.connMapLock.RUnlock()
	conn, exists := w.connMap[addr.String()]
	return conn, exists
}

// GetActiveConnections 获取活跃连接数
func (w *tcpTransportWrapper) GetActiveConnections() int {
	w.connMapLock.RLock()
	defer w.connMapLock.RUnlock()
	return len(w.connMap)
}

func (w *tcpTransportWrapper) GetState() TransportState {
	if w.IsRunning() {
		return StateRunning
	}
	return StateStopped
}

func (w *tcpTransportWrapper) GetQuality() *LinkQuality {
	return &LinkQuality{
		Available:   w.IsRunning(),
		State:       w.GetState(),
		ActiveConns: w.GetActiveConnections(),
		RTT:         w.estimateRTT(),
	}
}

// estimateRTT 估算 RTT (可通过心跳探测实现)
func (w *tcpTransportWrapper) estimateRTT() time.Duration {
	// TODO: 实现基于心跳的 RTT 测量
	return 20 * time.Millisecond
}

func (w *tcpTransportWrapper) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"mode":          "tcp",
		"active_conns":  w.GetActiveConnections(),
		"pending_dials": w.getPendingCount(),
	}
}

func (w *tcpTransportWrapper) getPendingCount() int {
	w.pendingDataLock.Lock()
	defer w.pendingDataLock.Unlock()
	return len(w.pendingData)
}

func (w *tcpTransportWrapper) Probe(addr *net.UDPAddr) (time.Duration, error) {
	start := time.Now()

	tcpAddr := &net.TCPAddr{IP: addr.IP, Port: addr.Port}
	conn, err := net.DialTimeout("tcp", tcpAddr.String(), 3*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	return time.Since(start), nil
}

// =============================================================================
// FakeTCP 包装器
// =============================================================================

type fakeTCPTransportWrapper struct {
	server  *transport.FakeTCPServer
	running int32
}

func NewFakeTCPTransportWrapper(server *transport.FakeTCPServer) *fakeTCPTransportWrapper {
	return &fakeTCPTransportWrapper{server: server, running: 1}
}

func (w *fakeTCPTransportWrapper) Start() error {
	atomic.StoreInt32(&w.running, 1)
	return nil
}

func (w *fakeTCPTransportWrapper) Stop() error {
	atomic.StoreInt32(&w.running, 0)
	w.server.Stop()
	return nil
}

func (w *fakeTCPTransportWrapper) IsRunning() bool {
	if atomic.LoadInt32(&w.running) != 1 {
		return false
	}
	return w.server.IsRunning()
}

func (w *fakeTCPTransportWrapper) Send(data []byte, addr *net.UDPAddr) error {
	return w.server.SendTo(data, addr)
}

func (w *fakeTCPTransportWrapper) GetState() TransportState {
	if w.IsRunning() {
		return StateRunning
	}
	return StateStopped
}

func (w *fakeTCPTransportWrapper) GetQuality() *LinkQuality {
	stats := w.server.GetStats()
	return &LinkQuality{
		Available:    w.IsRunning(),
		State:        w.GetState(),
		ActiveConns:  int(stats.ActiveSessions),
		TotalPackets: stats.PacketsReceived,
	}
}

func (w *fakeTCPTransportWrapper) GetStats() map[string]interface{} {
	stats := w.server.GetStats()
	return map[string]interface{}{
		"active_sessions":  stats.ActiveSessions,
		"total_sessions":   stats.TotalSessions,
		"packets_sent":     stats.PacketsSent,
		"packets_received": stats.PacketsReceived,
	}
}

func (w *fakeTCPTransportWrapper) Probe(addr *net.UDPAddr) (time.Duration, error) {
	return 25 * time.Millisecond, nil
}

// =============================================================================
// WebSocket 包装器
// =============================================================================

type wsTransportWrapper struct {
	server  *transport.WebSocketServer
	running int32
}

func NewWSTransportWrapper(server *transport.WebSocketServer) *wsTransportWrapper {
	return &wsTransportWrapper{server: server, running: 1}
}

func (w *wsTransportWrapper) Start() error {
	atomic.StoreInt32(&w.running, 1)
	return nil
}

func (w *wsTransportWrapper) Stop() error {
	atomic.StoreInt32(&w.running, 0)
	w.server.Stop()
	return nil
}

func (w *wsTransportWrapper) IsRunning() bool {
	return atomic.LoadInt32(&w.running) == 1
}

func (w *wsTransportWrapper) Send(data []byte, addr *net.UDPAddr) error {
	return w.server.SendTo(data, addr)
}

func (w *wsTransportWrapper) GetState() TransportState {
	if w.IsRunning() {
		return StateRunning
	}
	return StateStopped
}

func (w *wsTransportWrapper) GetQuality() *LinkQuality {
	return &LinkQuality{
		Available:   w.IsRunning(),
		State:       w.GetState(),
		ActiveConns: int(w.server.GetActiveConns()),
	}
}

func (w *wsTransportWrapper) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"active_conns": w.server.GetActiveConns(),
	}
}

func (w *wsTransportWrapper) Probe(addr *net.UDPAddr) (time.Duration, error) {
	return 50 * time.Millisecond, nil
}

// =============================================================================
// eBPF 包装器
// =============================================================================

type ebpfTransportWrapper struct {
	accel   *transport.EBPFAccelerator
	running int32
}

func NewEBPFTransportWrapper(accel *transport.EBPFAccelerator) *ebpfTransportWrapper {
	return &ebpfTransportWrapper{accel: accel, running: 1}
}

func (w *ebpfTransportWrapper) Start() error {
	atomic.StoreInt32(&w.running, 1)
	return nil
}

func (w *ebpfTransportWrapper) Stop() error {
	atomic.StoreInt32(&w.running, 0)
	w.accel.Stop()
	return nil
}

func (w *ebpfTransportWrapper) IsRunning() bool {
	if atomic.LoadInt32(&w.running) != 1 {
		return false
	}
	return w.accel.IsActive()
}

func (w *ebpfTransportWrapper) Send(data []byte, addr *net.UDPAddr) error {
	return w.accel.SendTo(data, addr)
}

func (w *ebpfTransportWrapper) GetState() TransportState {
	if w.IsRunning() {
		return StateRunning
	}
	return StateFailed
}

func (w *ebpfTransportWrapper) GetQuality() *LinkQuality {
	stats := w.accel.GetStats()
	return &LinkQuality{
		Available:    w.IsRunning(),
		State:        w.GetState(),
		TotalPackets: stats.PacketsRX,
	}
}

func (w *ebpfTransportWrapper) GetStats() map[string]interface{} {
	stats := w.accel.GetStats()
	return map[string]interface{}{
		"packets_rx": stats.PacketsRX,
		"packets_tx": stats.PacketsTX,
		"bytes_rx":   stats.BytesRX,
		"bytes_tx":   stats.BytesTX,
	}
}

func (w *ebpfTransportWrapper) Probe(addr *net.UDPAddr) (time.Duration, error) {
	return 5 * time.Millisecond, nil
}
