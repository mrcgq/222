// =============================================================================
// 文件: internal/transport/utls.go
// 描述: uTLS 客户端封装 - 实现 TLS 指纹模拟、ECH、SNI 混淆
// 功能:
//   - 支持 Chrome/Firefox/Safari/iOS/Android 等浏览器指纹
//   - 支持 ECH (Encrypted Client Hello)
//   - 支持 ClientHello 分片 (绕过 DPI)
//   - 支持 TLS 记录填充
// 依赖: github.com/refraction-networking/utls
// =============================================================================
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

// =============================================================================
// 常量和类型定义
// =============================================================================

// Fingerprint 浏览器指纹类型
type Fingerprint string

const (
	FingerprintChrome  Fingerprint = "chrome"
	FingerprintFirefox Fingerprint = "firefox"
	FingerprintSafari  Fingerprint = "safari"
	FingerprintIOS     Fingerprint = "ios"
	FingerprintAndroid Fingerprint = "android"
	FingerprintEdge    Fingerprint = "edge"
	FingerprintQQ      Fingerprint = "qq"
	Fingerprint360     Fingerprint = "360"
	FingerprintRandom  Fingerprint = "random"
	FingerprintCustom  Fingerprint = "custom"
)

// =============================================================================
// uTLS 客户端配置
// =============================================================================

// UTLSConfig uTLS 客户端配置
type UTLSConfig struct {
	// 基础配置
	ServerName  string      // SNI 域名
	Fingerprint Fingerprint // 浏览器指纹

	// ECH 配置
	EnableECH  bool     // 是否启用 ECH
	ECHConfigs [][]byte // ECH 配置列表 (DER 编码)

	// 证书验证
	InsecureSkipVerify bool                              // 跳过证书验证
	RootCAs            *x509.CertPool                    // 根证书池
	VerifyConnection   func(tls.ConnectionState) error   // 自定义验证

	// 高级配置
	ALPN         []string // ALPN 协议列表
	SessionCache utls.ClientSessionCache
	MinVersion   uint16 // 最低 TLS 版本
	MaxVersion   uint16 // 最高 TLS 版本

	// 分片配置 (绕过 DPI)
	FragmentEnabled bool // 启用 ClientHello 分片
	FragmentSize    int  // 分片大小
	FragmentSleepMs int  // 分片间隔

	// 填充配置
	PaddingEnabled bool // 启用 TLS 记录填充
	PaddingMinSize int  // 最小填充
	PaddingMaxSize int  // 最大填充

	// 超时
	HandshakeTimeout time.Duration

	// 日志级别
	LogLevel int
}

// DefaultUTLSConfig 默认配置
func DefaultUTLSConfig() *UTLSConfig {
	return &UTLSConfig{
		Fingerprint:        FingerprintChrome,
		InsecureSkipVerify: true,
		ALPN:               []string{"h2", "http/1.1"},
		MinVersion:         utls.VersionTLS12,
		MaxVersion:         utls.VersionTLS13,
		HandshakeTimeout:   10 * time.Second,
		FragmentEnabled:    false,
		FragmentSize:       40,
		FragmentSleepMs:    10,
		PaddingEnabled:     false,
		PaddingMinSize:     16,
		PaddingMaxSize:     256,
		LogLevel:           1,
	}
}

// =============================================================================
// uTLS 客户端
// =============================================================================

// UTLSClient uTLS 客户端
type UTLSClient struct {
	config *UTLSConfig

	// 统计
	stats UTLSStats
}

// UTLSStats 统计信息
type UTLSStats struct {
	TotalConnections   uint64
	SuccessConnections uint64
	FailedConnections  uint64
	ECHUsed            uint64
}

// NewUTLSClient 创建 uTLS 客户端
func NewUTLSClient(config *UTLSConfig) *UTLSClient {
	if config == nil {
		config = DefaultUTLSConfig()
	}

	// 初始化随机种子
	rand.Seed(time.Now().UnixNano())

	return &UTLSClient{
		config: config,
	}
}

// =============================================================================
// 指纹映射
// =============================================================================

// getClientHelloID 获取 uTLS ClientHelloID
func (c *UTLSClient) getClientHelloID() utls.ClientHelloID {
	switch c.config.Fingerprint {
	case FingerprintChrome:
		return utls.HelloChrome_Auto
	case FingerprintFirefox:
		return utls.HelloFirefox_Auto
	case FingerprintSafari:
		return utls.HelloSafari_Auto
	case FingerprintIOS:
		return utls.HelloIOS_Auto
	case FingerprintAndroid:
		return utls.HelloAndroid_11_OkHttp
	case FingerprintEdge:
		return utls.HelloEdge_Auto
	case FingerprintQQ:
		return utls.HelloQQ_Auto
	case Fingerprint360:
		return utls.Hello360_Auto
	case FingerprintRandom:
		return c.getRandomClientHelloID()
	default:
		return utls.HelloChrome_Auto
	}
}

// getRandomClientHelloID 随机选择指纹
func (c *UTLSClient) getRandomClientHelloID() utls.ClientHelloID {
	options := []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
		utls.HelloSafari_Auto,
		utls.HelloEdge_Auto,
		utls.HelloIOS_Auto,
	}
	return options[rand.Intn(len(options))]
}

// =============================================================================
// 连接方法
// =============================================================================

// Dial 建立 TLS 连接
func (c *UTLSClient) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return c.DialWithConn(ctx, nil, network, addr)
}

// DialWithConn 使用已有连接建立 TLS
func (c *UTLSClient) DialWithConn(ctx context.Context, conn net.Conn, network, addr string) (net.Conn, error) {
	atomic.AddUint64(&c.stats.TotalConnections, 1)

	var err error

	// 如果没有提供底层连接，创建新连接
	if conn == nil {
		dialer := &net.Dialer{
			Timeout: c.config.HandshakeTimeout,
		}
		conn, err = dialer.DialContext(ctx, network, addr)
		if err != nil {
			atomic.AddUint64(&c.stats.FailedConnections, 1)
			return nil, fmt.Errorf("连接失败: %w", err)
		}
	}

	// 获取 SNI
	serverName := c.config.ServerName
	if serverName == "" {
		host, _, _ := net.SplitHostPort(addr)
		serverName = host
	}

	// 创建 uTLS 配置
	tlsConfig := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: c.config.InsecureSkipVerify,
		RootCAs:            c.config.RootCAs,
		NextProtos:         c.config.ALPN,
		MinVersion:         c.config.MinVersion,
		MaxVersion:         c.config.MaxVersion,
		ClientSessionCache: c.config.SessionCache,
	}

	// 如果启用 ECH 且有配置
    if c.config.EnableECH && len(c.config.ECHConfigs) > 0 {
    // uTLS 中对应的字段名称是 ECHConfigs
    tlsConfig.ECHConfigs = c.config.ECHConfigs
    atomic.AddUint64(&c.stats.ECHUsed, 1)
    }

	// 创建 uTLS 连接
	clientHelloID := c.getClientHelloID()
	utlsConn := utls.UClient(conn, tlsConfig, clientHelloID)

	// 选择握手方式
	if c.config.FragmentEnabled {
		err = c.fragmentedHandshake(ctx, utlsConn, conn)
	} else {
		err = c.normalHandshake(ctx, utlsConn)
	}

	if err != nil {
		conn.Close()
		atomic.AddUint64(&c.stats.FailedConnections, 1)
		return nil, fmt.Errorf("TLS 握手失败: %w", err)
	}

	atomic.AddUint64(&c.stats.SuccessConnections, 1)

	c.log(2, "TLS 连接建立: SNI=%s, Fingerprint=%s, ALPN=%s, Version=0x%04x",
		serverName, c.config.Fingerprint,
		utlsConn.ConnectionState().NegotiatedProtocol,
		utlsConn.ConnectionState().Version)

	// 包装连接（如果启用填充）
	if c.config.PaddingEnabled {
		return NewPaddedConn(utlsConn, c.config.PaddingMinSize, c.config.PaddingMaxSize), nil
	}

	return utlsConn, nil
}

// normalHandshake 普通握手
func (c *UTLSClient) normalHandshake(ctx context.Context, conn *utls.UConn) error {
	errChan := make(chan error, 1)

	go func() {
		errChan <- conn.Handshake()
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(c.config.HandshakeTimeout):
		return fmt.Errorf("握手超时")
	}
}

// fragmentedHandshake 分片握手 (绕过 DPI)
func (c *UTLSClient) fragmentedHandshake(ctx context.Context, utlsConn *utls.UConn, rawConn net.Conn) error {
	c.log(2, "使用分片握手, 分片大小=%d, 间隔=%dms",
		c.config.FragmentSize, c.config.FragmentSleepMs)

	// 构建 ClientHello
	if err := utlsConn.BuildHandshakeState(); err != nil {
		return fmt.Errorf("构建握手状态失败: %w", err)
	}

	// 获取原始 ClientHello
	clientHello := utlsConn.HandshakeState.Hello.Raw
	if len(clientHello) == 0 {
		return fmt.Errorf("ClientHello 为空")
	}

	c.log(2, "ClientHello 大小: %d 字节", len(clientHello))

	// 分片发送
	fragmentSize := c.config.FragmentSize
	if fragmentSize <= 0 {
		fragmentSize = 40
	}

	for i := 0; i < len(clientHello); i += fragmentSize {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		end := i + fragmentSize
		if end > len(clientHello) {
			end = len(clientHello)
		}

		fragment := clientHello[i:end]

		// 包装为 TLS 记录
		record := c.wrapTLSRecord(fragment, TLSRecordTypeHandshake)

		_, err := rawConn.Write(record)
		if err != nil {
			return fmt.Errorf("发送分片 %d 失败: %w", i/fragmentSize, err)
		}

		c.log(2, "发送分片 %d: %d 字节", i/fragmentSize, len(fragment))

		// 分片间隔（除了最后一个分片）
		if c.config.FragmentSleepMs > 0 && end < len(clientHello) {
			time.Sleep(time.Duration(c.config.FragmentSleepMs) * time.Millisecond)
		}
	}

	// 标记 ClientHello 已发送
	utlsConn.HandshakeState.Hello.Raw = nil

	// 完成剩余握手
	errChan := make(chan error, 1)
	go func() {
		errChan <- utlsConn.Handshake()
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(c.config.HandshakeTimeout):
		return fmt.Errorf("分片握手超时")
	}
}

// wrapTLSRecord 包装 TLS 记录
func (c *UTLSClient) wrapTLSRecord(data []byte, contentType byte) []byte {
	record := make([]byte, 5+len(data))
	record[0] = contentType
	record[1] = 0x03 // TLS 1.0+ major version
	record[2] = 0x01 // TLS 1.0 minor version (握手时使用)
	record[3] = byte(len(data) >> 8)
	record[4] = byte(len(data))
	copy(record[5:], data)
	return record
}

// WrapConn 包装已有连接为 TLS 连接
func (c *UTLSClient) WrapConn(conn net.Conn, serverName string) (net.Conn, error) {
	if serverName != "" {
		c.config.ServerName = serverName
	}
	return c.DialWithConn(context.Background(), conn, "tcp", serverName+":443")
}

// GetStats 获取统计信息
func (c *UTLSClient) GetStats() UTLSStats {
	return UTLSStats{
		TotalConnections:   atomic.LoadUint64(&c.stats.TotalConnections),
		SuccessConnections: atomic.LoadUint64(&c.stats.SuccessConnections),
		FailedConnections:  atomic.LoadUint64(&c.stats.FailedConnections),
		ECHUsed:            atomic.LoadUint64(&c.stats.ECHUsed),
	}
}

// log 日志输出
func (c *UTLSClient) log(level int, format string, args ...interface{}) {
	if level > c.config.LogLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [uTLS] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

// =============================================================================
// TLS 记录填充连接
// =============================================================================

// PaddedConn TLS 记录填充连接
type PaddedConn struct {
	net.Conn
	minPadding int
	maxPadding int
	mu         sync.Mutex
	randSrc    *rand.Rand
}

// NewPaddedConn 创建填充连接
func NewPaddedConn(conn net.Conn, minPadding, maxPadding int) *PaddedConn {
	return &PaddedConn{
		Conn:       conn,
		minPadding: minPadding,
		maxPadding: maxPadding,
		randSrc:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Write 写入数据（可选添加填充）
func (c *PaddedConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 注意：实际的 TLS 记录填充需要在 TLS 层实现
	// 这里只是简单的示例，实际填充需要在 TLS 握手后的加密层处理

	return c.Conn.Write(b)
}

// Read 读取数据
func (c *PaddedConn) Read(b []byte) (int, error) {
	return c.Conn.Read(b)
}

// Close 关闭连接
func (c *PaddedConn) Close() error {
	return c.Conn.Close()
}

// =============================================================================
// FakeTCP 适配器
// =============================================================================

// FakeConnAdapter FakeTCP 连接适配器
// 将 FakeTCP 的包操作适配为流式 net.Conn 接口
type FakeConnAdapter struct {
	client     FakeTCPClientInterface
	readBuf    []byte
	readOffset int
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	closed     int32
}

// FakeTCPClientInterface FakeTCP 客户端接口
type FakeTCPClientInterface interface {
	Send(data []byte) error
	Recv(ctx context.Context) ([]byte, error)
	Close() error
	GetLocalAddr() *net.UDPAddr
	IsConnected() bool
}

// NewFakeConnAdapter 创建适配器
func NewFakeConnAdapter(client FakeTCPClientInterface) *FakeConnAdapter {
	ctx, cancel := context.WithCancel(context.Background())
	return &FakeConnAdapter{
		client: client,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Read 实现 net.Conn 接口
func (a *FakeConnAdapter) Read(b []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if atomic.LoadInt32(&a.closed) == 1 {
		return 0, io.EOF
	}

	// 如果缓冲区有数据
	if a.readOffset < len(a.readBuf) {
		n := copy(b, a.readBuf[a.readOffset:])
		a.readOffset += n
		if a.readOffset >= len(a.readBuf) {
			a.readBuf = nil
			a.readOffset = 0
		}
		return n, nil
	}

	// 从 FakeTCP 接收数据
	data, err := a.client.Recv(a.ctx)
	if err != nil {
		return 0, err
	}

	n := copy(b, data)
	if n < len(data) {
		a.readBuf = make([]byte, len(data)-n)
		copy(a.readBuf, data[n:])
		a.readOffset = 0
	}

	return n, nil
}

// Write 实现 net.Conn 接口
func (a *FakeConnAdapter) Write(b []byte) (int, error) {
	if atomic.LoadInt32(&a.closed) == 1 {
		return 0, fmt.Errorf("连接已关闭")
	}

	if err := a.client.Send(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close 实现 net.Conn 接口
func (a *FakeConnAdapter) Close() error {
	if !atomic.CompareAndSwapInt32(&a.closed, 0, 1) {
		return nil // 已关闭
	}
	a.cancel()
	return a.client.Close()
}

// LocalAddr 实现 net.Conn 接口
func (a *FakeConnAdapter) LocalAddr() net.Addr {
	return a.client.GetLocalAddr()
}

// RemoteAddr 实现 net.Conn 接口
func (a *FakeConnAdapter) RemoteAddr() net.Addr {
	// FakeTCP 客户端需要返回服务器地址
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// SetDeadline 实现 net.Conn 接口
func (a *FakeConnAdapter) SetDeadline(t time.Time) error {
	return nil // FakeTCP 不支持 deadline
}

// SetReadDeadline 实现 net.Conn 接口
func (a *FakeConnAdapter) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline 实现 net.Conn 接口
func (a *FakeConnAdapter) SetWriteDeadline(t time.Time) error {
	return nil
}

// =============================================================================
// ECH 配置获取
// =============================================================================

// ECHConfigFetcher ECH 配置获取器
type ECHConfigFetcher struct {
	cache    map[string][]byte
	cacheMu  sync.RWMutex
	cacheExp map[string]time.Time
	logLevel int
}

// NewECHConfigFetcher 创建 ECH 配置获取器
func NewECHConfigFetcher() *ECHConfigFetcher {
	return &ECHConfigFetcher{
		cache:    make(map[string][]byte),
		cacheExp: make(map[string]time.Time),
		logLevel: 1,
	}
}

// GetCached 获取缓存的 ECH 配置
func (f *ECHConfigFetcher) GetCached(domain string) ([]byte, bool) {
	f.cacheMu.RLock()
	defer f.cacheMu.RUnlock()

	config, ok := f.cache[domain]
	if !ok {
		return nil, false
	}

	// 检查是否过期
	if exp, exists := f.cacheExp[domain]; exists && time.Now().After(exp) {
		return nil, false
	}

	return config, true
}

// SetCached 设置缓存的 ECH 配置
func (f *ECHConfigFetcher) SetCached(domain string, config []byte, ttl time.Duration) {
	f.cacheMu.Lock()
	defer f.cacheMu.Unlock()

	f.cache[domain] = config
	f.cacheExp[domain] = time.Now().Add(ttl)
}

// ClearCache 清除缓存
func (f *ECHConfigFetcher) ClearCache() {
	f.cacheMu.Lock()
	defer f.cacheMu.Unlock()

	f.cache = make(map[string][]byte)
	f.cacheExp = make(map[string]time.Time)
}

// =============================================================================
// 辅助函数
// =============================================================================

// ParseTLSVersion 解析 TLS 版本字符串
func ParseTLSVersion(version string) uint16 {
	switch version {
	case "tls10", "TLS10", "1.0":
		return tls.VersionTLS10
	case "tls11", "TLS11", "1.1":
		return tls.VersionTLS11
	case "tls12", "TLS12", "1.2":
		return tls.VersionTLS12
	case "tls13", "TLS13", "1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

// ParseFingerprint 解析指纹字符串
func ParseFingerprint(fp string) Fingerprint {
	switch fp {
	case "chrome", "Chrome", "CHROME":
		return FingerprintChrome
	case "firefox", "Firefox", "FIREFOX":
		return FingerprintFirefox
	case "safari", "Safari", "SAFARI":
		return FingerprintSafari
	case "ios", "iOS", "IOS":
		return FingerprintIOS
	case "android", "Android", "ANDROID":
		return FingerprintAndroid
	case "edge", "Edge", "EDGE":
		return FingerprintEdge
	case "qq", "QQ":
		return FingerprintQQ
	case "360":
		return Fingerprint360
	case "random", "Random", "RANDOM":
		return FingerprintRandom
	default:
		return FingerprintChrome
	}
}

// TLSCertProvider TLS 证书提供者接口（在 tcp.go 中也有定义，这里作为备用）
type TLSCertProviderInterface interface {
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
	GetTLSConfig() *tls.Config
}
