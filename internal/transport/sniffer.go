// =============================================================================
// 文件: internal/transport/sniffer.go
// 描述: TLS 流量嗅探器 - 服务端"门卫"模块，区分合法流量和探测流量
// 功能:
//   - 非破坏性 Peek 机制预览握手数据
//   - 识别 TLS ClientHello 和普通 HTTP 请求
//   - 非法流量透明回落到真实 Web 服务器
//   - 提取 SNI 用于证书选择
// =============================================================================
package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// 常量定义
// =============================================================================

const (
	// TLS 记录类型
	TLSRecordTypeChangeCipherSpec = 0x14
	TLSRecordTypeAlert            = 0x15
	TLSRecordTypeHandshake        = 0x16
	TLSRecordTypeApplicationData  = 0x17

	// TLS 握手类型
	TLSHandshakeTypeClientHello = 0x01

	// 嗅探缓冲区大小
	snifferBufferSize = 4096
	snifferPeekSize   = 5 // TLS 记录头大小

	// 超时配置
	snifferReadTimeout     = 10 * time.Second
	snifferFallbackTimeout = 30 * time.Second
)

// TrafficType 流量类型
type TrafficType int

const (
	TrafficUnknown TrafficType = iota
	TrafficTLS                 // TLS 流量
	TrafficHTTP                // HTTP 流量
	TrafficBinary              // 二进制流量（可能是探测）
)

// String 返回流量类型字符串
func (t TrafficType) String() string {
	switch t {
	case TrafficTLS:
		return "TLS"
	case TrafficHTTP:
		return "HTTP"
	case TrafficBinary:
		return "Binary"
	default:
		return "Unknown"
	}
}

// =============================================================================
// 嗅探器配置
// =============================================================================

// SnifferConfig 嗅探器配置
type SnifferConfig struct {
	// 回落配置
	FallbackEnabled bool          // 是否启用回落
	FallbackAddr    string        // 回落地址
	FallbackTimeout time.Duration // 回落超时

	// TLS 配置
	TLSConfig *tls.Config // TLS 配置（包含证书等）

	// 日志级别
	LogLevel int

	// 统计
	EnableStats bool
}

// DefaultSnifferConfig 默认嗅探器配置
func DefaultSnifferConfig() *SnifferConfig {
	return &SnifferConfig{
		FallbackEnabled: true,
		FallbackAddr:    "127.0.0.1:80",
		FallbackTimeout: snifferFallbackTimeout,
		LogLevel:        1,
		EnableStats:     true,
	}
}

// =============================================================================
// 嗅探连接包装器
// =============================================================================

// SniffedConn 嗅探后的连接包装器
// 实现 net.Conn 接口，可以重新读取已嗅探的数据
type SniffedConn struct {
	net.Conn
	reader      *bufio.Reader
	peekedBuf   []byte // 已嗅探的数据
	readIndex   int    // 当前读取位置
	peekedDone  bool   // 嗅探数据是否已读完
	mu          sync.Mutex
}

// NewSniffedConn 创建嗅探连接包装器
func NewSniffedConn(conn net.Conn, peeked []byte) *SniffedConn {
	return &SniffedConn{
		Conn:       conn,
		reader:     bufio.NewReaderSize(conn, snifferBufferSize),
		peekedBuf:  peeked,
		readIndex:  0,
		peekedDone: len(peeked) == 0,
	}
}

// Read 读取数据（先读取已嗅探的数据，再读取连接数据）
func (c *SniffedConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 如果还有未读取的嗅探数据
	if !c.peekedDone && c.readIndex < len(c.peekedBuf) {
		n := copy(b, c.peekedBuf[c.readIndex:])
		c.readIndex += n
		if c.readIndex >= len(c.peekedBuf) {
			c.peekedDone = true
			c.peekedBuf = nil // 释放内存
		}
		return n, nil
	}

	// 嗅探数据已读完，从连接读取
	return c.Conn.Read(b)
}

// Write 写入数据
func (c *SniffedConn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}

// Close 关闭连接
func (c *SniffedConn) Close() error {
	return c.Conn.Close()
}

// LocalAddr 返回本地地址
func (c *SniffedConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// RemoteAddr 返回远程地址
func (c *SniffedConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

// SetDeadline 设置截止时间
func (c *SniffedConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline 设置读取截止时间
func (c *SniffedConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline 设置写入截止时间
func (c *SniffedConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// =============================================================================
// TLS 流量嗅探器
// =============================================================================

// Sniffer TLS 流量嗅探器
type Sniffer struct {
	config *SnifferConfig

	// 统计信息
	stats SnifferStats

	// 控制
	ctx    context.Context
	cancel context.CancelFunc
}

// SnifferStats 嗅探器统计
type SnifferStats struct {
	TotalConnections    uint64 // 总连接数
	TLSConnections      uint64 // TLS 连接数
	HTTPConnections     uint64 // HTTP 连接数
	FallbackConnections uint64 // 回落连接数
	InvalidConnections  uint64 // 无效连接数
	SniffErrors         uint64 // 嗅探错误数
}

// NewSniffer 创建嗅探器
func NewSniffer(config *SnifferConfig) *Sniffer {
	if config == nil {
		config = DefaultSnifferConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Sniffer{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
}

// SniffResult 嗅探结果
type SniffResult struct {
	Type       TrafficType // 流量类型
	Conn       net.Conn    // 处理后的连接
	SNI        string      // 提取的 SNI (TLS 流量)
	Host       string      // 提取的 Host (HTTP 流量)
	PeekedData []byte      // 已嗅探的数据
	IsFallback bool        // 是否已回落
	Error      error       // 错误信息
}

// Sniff 嗅探连接，判断流量类型
func (s *Sniffer) Sniff(conn net.Conn) *SniffResult {
	atomic.AddUint64(&s.stats.TotalConnections, 1)

	result := &SniffResult{
		Type: TrafficUnknown,
		Conn: conn,
	}

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(snifferReadTimeout))
	defer conn.SetReadDeadline(time.Time{}) // 清除超时

	// 创建带缓冲的读取器
	reader := bufio.NewReaderSize(conn, snifferBufferSize)

	// 预览前几个字节
	peeked, err := reader.Peek(snifferPeekSize)
	if err != nil {
		if err == io.EOF {
			result.Error = fmt.Errorf("连接已关闭")
		} else {
			result.Error = fmt.Errorf("嗅探失败: %w", err)
		}
		atomic.AddUint64(&s.stats.SniffErrors, 1)
		return result
	}

	// 保存嗅探数据
	result.PeekedData = make([]byte, len(peeked))
	copy(result.PeekedData, peeked)

	// 判断流量类型
	if s.isTLSClientHello(peeked) {
		result.Type = TrafficTLS
		atomic.AddUint64(&s.stats.TLSConnections, 1)

		// 尝试提取 SNI
		if sni, err := s.extractSNI(reader); err == nil {
			result.SNI = sni
		}

		// 创建嗅探连接（包含已读取的数据）
		result.Conn = s.createSniffedConn(conn, reader)

	} else if s.isHTTPRequest(peeked) {
		result.Type = TrafficHTTP
		atomic.AddUint64(&s.stats.HTTPConnections, 1)

		// 尝试提取 Host
		if host, err := s.extractHTTPHost(reader); err == nil {
			result.Host = host
		}

		// 创建嗅探连接
		result.Conn = s.createSniffedConn(conn, reader)

	} else {
		result.Type = TrafficBinary
		atomic.AddUint64(&s.stats.InvalidConnections, 1)

		// 创建嗅探连接
		result.Conn = s.createSniffedConn(conn, reader)
	}

	return result
}

// isTLSClientHello 判断是否为 TLS ClientHello
func (s *Sniffer) isTLSClientHello(data []byte) bool {
	if len(data) < 5 {
		return false
	}

	// 检查记录类型
	if data[0] != TLSRecordTypeHandshake {
		return false
	}

	// 检查版本 (TLS 1.0 = 0x0301, TLS 1.1 = 0x0302, TLS 1.2 = 0x0303, TLS 1.3 也用 0x0303)
	majorVersion := data[1]
	minorVersion := data[2]
	if majorVersion != 0x03 || minorVersion > 0x04 {
		return false
	}

	// 检查长度是否合理
	length := int(data[3])<<8 | int(data[4])
	if length < 4 || length > 16384 {
		return false
	}

	return true
}

// isHTTPRequest 判断是否为 HTTP 请求
func (s *Sniffer) isHTTPRequest(data []byte) bool {
	if len(data) < 3 {
		return false
	}

	// 检查常见 HTTP 方法
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
	dataStr := string(data)

	for _, method := range methods {
		if len(method) >= len(dataStr) {
			if strings.HasPrefix(method, dataStr) {
				return true
			}
		} else {
			if strings.HasPrefix(dataStr, method[:len(dataStr)]) {
				return true
			}
		}
	}

	return false
}

// extractSNI 从 TLS ClientHello 提取 SNI
func (s *Sniffer) extractSNI(reader *bufio.Reader) (string, error) {
	// 读取 TLS 记录头 (5 字节)
	recordHeader, err := reader.Peek(5)
	if err != nil {
		return "", fmt.Errorf("读取记录头失败: %w", err)
	}

	// 解析记录长度
	recordLength := int(recordHeader[3])<<8 | int(recordHeader[4])
	if recordLength > 16384 {
		return "", fmt.Errorf("TLS 记录过长: %d", recordLength)
	}

	// 尝试读取完整的 ClientHello
	totalLen := 5 + recordLength
	fullRecord, err := reader.Peek(totalLen)
	if err != nil {
		// 可能数据还没到齐，返回空
		return "", fmt.Errorf("读取完整记录失败: %w", err)
	}

	// 解析 ClientHello
	return s.parseSNIFromClientHello(fullRecord[5:])
}

// parseSNIFromClientHello 从 ClientHello 数据中解析 SNI
func (s *Sniffer) parseSNIFromClientHello(data []byte) (string, error) {
	if len(data) < 34 {
		return "", fmt.Errorf("ClientHello 数据太短: %d", len(data))
	}

	// 检查握手类型
	if data[0] != TLSHandshakeTypeClientHello {
		return "", fmt.Errorf("不是 ClientHello: 0x%02x", data[0])
	}

	// 跳过握手类型 (1) + 长度 (3) + 版本 (2) + 随机数 (32)
	offset := 1 + 3 + 2 + 32

	if offset >= len(data) {
		return "", fmt.Errorf("数据不完整")
	}

	// Session ID
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	if offset+2 > len(data) {
		return "", fmt.Errorf("数据不完整: session ID")
	}

	// Cipher Suites
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuitesLen

	if offset >= len(data) {
		return "", fmt.Errorf("数据不完整: cipher suites")
	}

	// Compression Methods
	compressionMethodsLen := int(data[offset])
	offset += 1 + compressionMethodsLen

	if offset+2 > len(data) {
		return "", fmt.Errorf("没有扩展字段")
	}

	// Extensions
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	extensionsEnd := offset + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	// 解析扩展
	for offset+4 <= extensionsEnd {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if offset+extLen > extensionsEnd {
			break
		}

		// SNI 扩展类型为 0
		if extType == 0 {
			return s.parseSNIExtension(data[offset : offset+extLen])
		}

		offset += extLen
	}

	return "", fmt.Errorf("未找到 SNI 扩展")
}

// parseSNIExtension 解析 SNI 扩展
func (s *Sniffer) parseSNIExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("SNI 扩展数据太短")
	}

	// SNI 列表长度
	sniListLen := int(data[0])<<8 | int(data[1])
	if sniListLen+2 > len(data) {
		return "", fmt.Errorf("SNI 列表长度无效")
	}

	offset := 2
	for offset+3 <= 2+sniListLen {
		nameType := data[offset]
		nameLen := int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3

		if offset+nameLen > 2+sniListLen {
			break
		}

		// 类型 0 是主机名
		if nameType == 0 {
			return string(data[offset : offset+nameLen]), nil
		}

		offset += nameLen
	}

	return "", fmt.Errorf("未找到主机名")
}

// extractHTTPHost 从 HTTP 请求提取 Host
func (s *Sniffer) extractHTTPHost(reader *bufio.Reader) (string, error) {
	// 读取 HTTP 请求头（最多读取 4KB）
	var lines []string
	for i := 0; i < 50; i++ { // 最多读 50 行头
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("读取 HTTP 头失败: %w", err)
		}

		lines = append(lines, line)

		// 空行表示头部结束
		if line == "\r\n" || line == "\n" {
			break
		}

		// 查找 Host 头
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host := strings.TrimSpace(line[5:])
			host = strings.TrimSuffix(host, "\r")
			host = strings.TrimSuffix(host, "\n")
			return host, nil
		}
	}

	return "", fmt.Errorf("未找到 Host 头")
}

// createSniffedConn 创建嗅探连接
func (s *Sniffer) createSniffedConn(conn net.Conn, reader *bufio.Reader) net.Conn {
	// 获取缓冲区中的所有数据
	buffered := reader.Buffered()
	if buffered == 0 {
		return conn
	}

	peeked, err := reader.Peek(buffered)
	if err != nil {
		return conn
	}

	peekedCopy := make([]byte, len(peeked))
	copy(peekedCopy, peeked)

	return NewSniffedConn(conn, peekedCopy)
}

// HandleWithFallback 处理连接，非法流量回落
func (s *Sniffer) HandleWithFallback(conn net.Conn, tlsHandler func(net.Conn, string) error) error {
	result := s.Sniff(conn)

	switch result.Type {
	case TrafficTLS:
		// 合法 TLS 流量，交给 TLS 处理器
		s.log(2, "TLS 流量: SNI=%s, 来源=%s", result.SNI, conn.RemoteAddr())
		return tlsHandler(result.Conn, result.SNI)

	case TrafficHTTP:
		// HTTP 流量，执行回落
		if s.config.FallbackEnabled {
			s.log(1, "HTTP 流量回落: Host=%s, 来源=%s", result.Host, conn.RemoteAddr())
			return s.doFallback(result.Conn, result.PeekedData)
		}
		s.log(2, "HTTP 流量，关闭连接: Host=%s", result.Host)
		return fmt.Errorf("非 TLS 流量: HTTP")

	case TrafficBinary:
		// 二进制流量（可能是探测），执行回落
		if s.config.FallbackEnabled {
			s.log(1, "二进制流量回落: 来源=%s", conn.RemoteAddr())
			return s.doFallback(result.Conn, result.PeekedData)
		}
		s.log(2, "二进制流量，关闭连接")
		return fmt.Errorf("非 TLS 流量: Binary")

	default:
		if result.Error != nil {
			return result.Error
		}
		return fmt.Errorf("未知流量类型")
	}
}

// doFallback 执行回落 - 将流量透明转发到回落服务器
func (s *Sniffer) doFallback(conn net.Conn, peekedData []byte) error {
	atomic.AddUint64(&s.stats.FallbackConnections, 1)

	// 连接回落服务器
	dialer := &net.Dialer{
		Timeout: s.config.FallbackTimeout,
	}

	fallbackConn, err := dialer.DialContext(s.ctx, "tcp", s.config.FallbackAddr)
	if err != nil {
		s.log(0, "连接回落服务器失败: %s - %v", s.config.FallbackAddr, err)
		return fmt.Errorf("连接回落服务器失败: %w", err)
	}
	defer fallbackConn.Close()

	s.log(2, "已连接回落服务器: %s", s.config.FallbackAddr)

	// 先发送已嗅探的数据
	if len(peekedData) > 0 {
		if _, err := fallbackConn.Write(peekedData); err != nil {
			s.log(0, "发送嗅探数据失败: %v", err)
			return fmt.Errorf("发送嗅探数据失败: %w", err)
		}
	}

	// 双向转发
	return s.bidirectionalCopy(conn, fallbackConn)
}

// bidirectionalCopy 双向复制
func (s *Sniffer) bidirectionalCopy(conn1, conn2 net.Conn) error {
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once

	setErr := func(err error) {
		if err != nil && err != io.EOF {
			errOnce.Do(func() {
				firstErr = err
			})
		}
	}

	// conn1 -> conn2
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(conn2, conn1)
		setErr(err)
		// 关闭写方向
		if tcpConn, ok := conn2.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// conn2 -> conn1
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(conn1, conn2)
		setErr(err)
		// 关闭写方向
		if tcpConn, ok := conn1.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// 等待完成
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// 带超时等待
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case <-time.After(s.config.FallbackTimeout):
		return fmt.Errorf("回落超时")
	case <-done:
		return firstErr
	}
}

// GetStats 获取统计信息
func (s *Sniffer) GetStats() SnifferStats {
	return SnifferStats{
		TotalConnections:    atomic.LoadUint64(&s.stats.TotalConnections),
		TLSConnections:      atomic.LoadUint64(&s.stats.TLSConnections),
		HTTPConnections:     atomic.LoadUint64(&s.stats.HTTPConnections),
		FallbackConnections: atomic.LoadUint64(&s.stats.FallbackConnections),
		InvalidConnections:  atomic.LoadUint64(&s.stats.InvalidConnections),
		SniffErrors:         atomic.LoadUint64(&s.stats.SniffErrors),
	}
}

// ResetStats 重置统计信息
func (s *Sniffer) ResetStats() {
	atomic.StoreUint64(&s.stats.TotalConnections, 0)
	atomic.StoreUint64(&s.stats.TLSConnections, 0)
	atomic.StoreUint64(&s.stats.HTTPConnections, 0)
	atomic.StoreUint64(&s.stats.FallbackConnections, 0)
	atomic.StoreUint64(&s.stats.InvalidConnections, 0)
	atomic.StoreUint64(&s.stats.SniffErrors, 0)
}

// Close 关闭嗅探器
func (s *Sniffer) Close() {
	if s.cancel != nil {
		s.cancel()
	}
}

// log 日志输出
func (s *Sniffer) log(level int, format string, args ...interface{}) {
	if level > s.config.LogLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [Sniffer] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}
