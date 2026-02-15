// =============================================================================
// 文件: internal/tunnel/cert_manager.go
// 描述: 证书管理器 - 使用 Go 原生 ACME 客户端，支持 Cloudflare 隧道验证
// =============================================================================
package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// =============================================================================
// 证书模式常量
// =============================================================================

// CertMode 证书模式
type CertMode string

const (
	CertAuto       CertMode = "auto"       // CF 自动提供（临时隧道）
	CertSelfSigned CertMode = "selfsigned" // 自签名证书
	CertACME       CertMode = "acme"       // ACME 自动证书（Let's Encrypt/ZeroSSL）
	CertCFOrigin   CertMode = "cforigin"   // Cloudflare Origin 证书
	CertCustom     CertMode = "custom"     // 自定义证书
)

// ACMEProvider ACME 提供商
type ACMEProvider string

const (
	ACMELetsEncrypt        ACMEProvider = "letsencrypt"
	ACMELetsEncryptStaging ACMEProvider = "letsencrypt-staging"
	ACMEZeroSSL            ACMEProvider = "zerossl"
)

// ACME 目录 URL
const (
	LetsEncryptProductionURL = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStagingURL    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	ZeroSSLProductionURL     = "https://acme.zerossl.com/v2/DV90"
)

// =============================================================================
// 证书配置
// =============================================================================

// CertConfig 证书配置
type CertConfig struct {
	Mode     CertMode `yaml:"mode"`
	CertFile string   `yaml:"cert_file"`
	KeyFile  string   `yaml:"key_file"`
	CertDir  string   `yaml:"cert_dir"`

	// ACME 配置
	ACME ACMEConfig `yaml:"acme"`

	// Cloudflare Origin 配置
	CFToken string `yaml:"cf_token"`
}

// ACMEConfig ACME 配置
type ACMEConfig struct {
	Provider      ACMEProvider `yaml:"provider"`
	Email         string       `yaml:"email"`
	Domains       []string     `yaml:"domains"`
	AcceptTOS     bool         `yaml:"accept_tos"`
	ChallengeType string       `yaml:"challenge_type"` // http-01, tls-alpn-01
	HTTPPort      int          `yaml:"http_port"`      // HTTP-01 挑战端口
	TLSPort       int          `yaml:"tls_port"`       // TLS-ALPN-01 挑战端口

	// ZeroSSL 特定
	EABKeyID   string `yaml:"eab_key_id"`
	EABHMACKey string `yaml:"eab_hmac_key"`

	// 隧道验证配置
	UseTunnelForValidation bool `yaml:"use_tunnel_for_validation"` // 使用隧道进行验证
}

// DefaultCertConfig 默认证书配置
func DefaultCertConfig() *CertConfig {
	return &CertConfig{
		Mode:    CertAuto,
		CertDir: filepath.Join(os.TempDir(), "phantom-certs"),
		ACME: ACMEConfig{
			Provider:               ACMELetsEncrypt,
			AcceptTOS:              true,
			ChallengeType:          "http-01",
			HTTPPort:               80,
			TLSPort:                443,
			UseTunnelForValidation: true,
		},
	}
}

// =============================================================================
// ACME 验证隧道接口
// =============================================================================

// ACMEValidationTunnel ACME 验证隧道接口
type ACMEValidationTunnel interface {
	// StartValidationTunnel 启动验证隧道
	// localPort: 本地 HTTP 服务端口
	// domain: 要验证的域名
	StartValidationTunnel(ctx context.Context, localPort int, domain string) error

	// StopValidationTunnel 停止验证隧道
	StopValidationTunnel() error

	// IsValidationTunnelRunning 检查验证隧道是否运行中
	IsValidationTunnelRunning() bool

	// GetValidationTunnelURL 获取验证隧道 URL
	GetValidationTunnelURL() string
}

// =============================================================================
// 证书管理器
// =============================================================================

// CertManager 证书管理器
type CertManager struct {
	config *CertConfig

	// autocert 管理器
	autocertManager *autocert.Manager

	// 自定义 ACME 客户端（用于更多控制）
	acmeClient *acme.Client
	acmeKey    *ecdsa.PrivateKey

	// 当前证书
	certPath string
	keyPath  string
	cert     *tls.Certificate

	// HTTP 服务器（用于 HTTP-01 挑战）
	httpServer     *http.Server
	httpServerAddr string

	// 验证隧道
	validationTunnel ACMEValidationTunnel

	// 证书获取通道
	certReady     chan struct{}
	certReadyOnce sync.Once

	// 控制
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.RWMutex
	logLevel int

	// 回调
	onCertObtained func(domains []string)
	onCertRenewed  func(domains []string)
	onError        func(err error)
}

// CertManagerOption 配置选项
type CertManagerOption func(*CertManager)

// WithValidationTunnel 设置验证隧道
func WithValidationTunnel(tunnel ACMEValidationTunnel) CertManagerOption {
	return func(m *CertManager) {
		m.validationTunnel = tunnel
	}
}

// WithCertLogLevel 设置日志级别
func WithCertLogLevel(level int) CertManagerOption {
	return func(m *CertManager) {
		m.logLevel = level
	}
}

// WithOnCertObtained 设置证书获取回调
func WithOnCertObtained(fn func(domains []string)) CertManagerOption {
	return func(m *CertManager) {
		m.onCertObtained = fn
	}
}

// WithOnCertRenewed 设置证书续期回调
func WithOnCertRenewed(fn func(domains []string)) CertManagerOption {
	return func(m *CertManager) {
		m.onCertRenewed = fn
	}
}

// WithOnCertError 设置错误回调
func WithOnCertError(fn func(err error)) CertManagerOption {
	return func(m *CertManager) {
		m.onError = fn
	}
}

// NewCertManager 创建证书管理器
func NewCertManager(cfg *CertConfig, opts ...CertManagerOption) *CertManager {
	if cfg == nil {
		cfg = DefaultCertConfig()
	}

	// 确保证书目录存在
	os.MkdirAll(cfg.CertDir, 0700)

	m := &CertManager{
		config:    cfg,
		logLevel:  1,
		certReady: make(chan struct{}),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Start 启动证书管理器
func (m *CertManager) Start(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)

	switch m.config.Mode {
	case CertAuto:
		m.log(1, "使用 Cloudflare 自动证书")
		m.signalCertReady()
		return nil

	case CertSelfSigned:
		return m.generateSelfSignedCert()

	case CertACME:
		return m.setupACME()

	case CertCFOrigin:
		return m.setupCFOriginCert()

	case CertCustom:
		return m.loadCustomCert()

	default:
		return fmt.Errorf("未知的证书模式: %s", m.config.Mode)
	}
}

// Stop 停止证书管理器
func (m *CertManager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}

	if m.httpServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.httpServer.Shutdown(shutdownCtx)
	}

	// 停止验证隧道
	if m.validationTunnel != nil {
		m.validationTunnel.StopValidationTunnel()
	}
}

// WaitForCert 等待证书就绪
func (m *CertManager) WaitForCert(timeout time.Duration) error {
	select {
	case <-m.certReady:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("等待证书超时")
	case <-m.ctx.Done():
		return m.ctx.Err()
	}
}

// signalCertReady 发送证书就绪信号
func (m *CertManager) signalCertReady() {
	m.certReadyOnce.Do(func() {
		close(m.certReady)
	})
}

// =============================================================================
// 自签名证书
// =============================================================================

// generateSelfSignedCert 生成自签名证书
func (m *CertManager) generateSelfSignedCert() error {
	m.certPath = filepath.Join(m.config.CertDir, "selfsigned.crt")
	m.keyPath = filepath.Join(m.config.CertDir, "selfsigned.key")

	// 检查现有证书是否有效
	if m.isCertValid(m.certPath, 30*24*time.Hour) {
		m.log(1, "使用现有自签名证书")
		if err := m.loadCertFromFiles(); err != nil {
			return err
		}
		m.signalCertReady()
		return nil
	}

	m.log(1, "生成新的自签名证书...")

	// 生成私钥（使用 ECDSA P-256，更现代更安全）
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("生成私钥失败: %w", err)
	}

	// 准备证书模板
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("生成序列号失败: %w", err)
	}

	domains := m.config.ACME.Domains
	if len(domains) == 0 {
		domains = []string{"localhost"}
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Phantom Server"},
			CommonName:   domains[0],
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0), // 1 年有效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 添加 SAN
	for _, domain := range domains {
		if ip := net.ParseIP(domain); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, domain)
		}
	}

	// 添加常用本地地址
	template.IPAddresses = append(template.IPAddresses,
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"),
	)

	// 创建证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("创建证书失败: %w", err)
	}

	// 保存证书
	certFile, err := os.OpenFile(m.certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建证书文件失败: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("写入证书失败: %w", err)
	}

	// 保存私钥
	keyFile, err := os.OpenFile(m.keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建私钥文件失败: %w", err)
	}
	defer keyFile.Close()

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("编码私钥失败: %w", err)
	}

	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("写入私钥失败: %w", err)
	}

	m.log(1, "自签名证书已生成: %s", m.certPath)

	if err := m.loadCertFromFiles(); err != nil {
		return err
	}

	m.signalCertReady()

	if m.onCertObtained != nil {
		m.onCertObtained(domains)
	}

	return nil
}

// =============================================================================
// ACME 证书 (Let's Encrypt / ZeroSSL)
// =============================================================================

// setupACME 设置 ACME 自动证书
func (m *CertManager) setupACME() error {
	cfg := m.config.ACME

	if len(cfg.Domains) == 0 {
		return fmt.Errorf("ACME 需要至少一个域名")
	}

	if cfg.Email == "" {
		return fmt.Errorf("ACME 需要邮箱地址")
	}

	m.log(1, "配置 ACME 证书: %v", cfg.Domains)

	// 获取 ACME 目录 URL
	directoryURL := m.getACMEDirectoryURL()

	// 创建或加载账户密钥
	if err := m.loadOrCreateACMEKey(); err != nil {
		return fmt.Errorf("加载 ACME 密钥失败: %w", err)
	}

	// 创建 ACME 客户端
	m.acmeClient = &acme.Client{
		DirectoryURL: directoryURL,
		Key:          m.acmeKey,
	}

	// 如果是 ZeroSSL 且需要 EAB
	if cfg.Provider == ACMEZeroSSL && cfg.EABKeyID != "" {
		if err := m.registerZeroSSLAccount(); err != nil {
			return fmt.Errorf("ZeroSSL 账户注册失败: %w", err)
		}
	}

	// 创建 autocert 管理器
	m.autocertManager = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(m.config.CertDir),
		HostPolicy: autocert.HostWhitelist(cfg.Domains...),
		Email:      cfg.Email,
		Client:     m.acmeClient,
	}

	// 根据挑战类型启动相应服务
	switch cfg.ChallengeType {
	case "http-01":
		return m.startHTTP01Challenge()
	case "tls-alpn-01":
		return m.startTLSALPN01Challenge()
	default:
		return m.startHTTP01Challenge()
	}
}

// loadOrCreateACMEKey 加载或创建 ACME 账户密钥
func (m *CertManager) loadOrCreateACMEKey() error {
	keyPath := filepath.Join(m.config.CertDir, "acme_account.key")

	// 尝试加载现有密钥
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil && block.Type == "EC PRIVATE KEY" {
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				m.acmeKey = key
				m.log(2, "加载现有 ACME 账户密钥")
				return nil
			}
		}
	}

	// 生成新密钥
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("生成 ACME 密钥失败: %w", err)
	}

	// 保存密钥
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("编码 ACME 密钥失败: %w", err)
	}

	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建 ACME 密钥文件失败: %w", err)
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("保存 ACME 密钥失败: %w", err)
	}

	m.acmeKey = key
	m.log(1, "生成新的 ACME 账户密钥")
	return nil
}

// registerZeroSSLAccount 注册 ZeroSSL 账户（需要 EAB）
func (m *CertManager) registerZeroSSLAccount() error {
	cfg := m.config.ACME

	m.log(1, "注册 ZeroSSL 账户 (EAB)...")

	// 解码 HMAC 密钥
	hmacKey, err := base64.RawURLEncoding.DecodeString(cfg.EABHMACKey)
	if err != nil {
		return fmt.Errorf("解码 EAB HMAC 密钥失败: %w", err)
	}

	account := &acme.Account{
		Contact: []string{"mailto:" + cfg.Email},
		ExternalAccountBinding: &acme.ExternalAccountBinding{
			KID: cfg.EABKeyID,
			Key: hmacKey,
		},
	}

	registerCtx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()

	_, err = m.acmeClient.Register(registerCtx, account, func(tosURL string) bool {
		m.log(1, "接受 ZeroSSL 服务条款: %s", tosURL)
		return cfg.AcceptTOS
	})

	if err != nil && err != acme.ErrAccountAlreadyExists {
		return fmt.Errorf("注册 ZeroSSL 账户失败: %w", err)
	}

	m.log(1, "ZeroSSL 账户注册成功")
	return nil
}

// getACMEDirectoryURL 获取 ACME 目录 URL
func (m *CertManager) getACMEDirectoryURL() string {
	switch m.config.ACME.Provider {
	case ACMELetsEncryptStaging:
		return LetsEncryptStagingURL
	case ACMEZeroSSL:
		return ZeroSSLProductionURL
	default:
		return LetsEncryptProductionURL
	}
}

// startHTTP01Challenge 启动 HTTP-01 挑战服务
func (m *CertManager) startHTTP01Challenge() error {
	cfg := m.config.ACME
	port := cfg.HTTPPort
	if port == 0 {
		port = 80
	}

	m.httpServerAddr = fmt.Sprintf(":%d", port)

	// 创建 HTTP 处理器
	handler := m.autocertManager.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 非 ACME 请求返回 404
		http.NotFound(w, r)
	}))

	m.httpServer = &http.Server{
		Addr:         m.httpServerAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// 启动 HTTP 服务器
	go func() {
		m.log(1, "启动 ACME HTTP-01 挑战服务: %s", m.httpServerAddr)
		if err := m.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			m.log(0, "HTTP-01 服务错误: %v", err)
			if m.onError != nil {
				m.onError(err)
			}
		}
	}()

	// 如果配置了使用隧道验证，启动验证隧道
	if cfg.UseTunnelForValidation && m.validationTunnel != nil {
		if err := m.startValidationTunnel(); err != nil {
			m.log(0, "启动验证隧道失败: %v (尝试直接验证)", err)
		}
	}

	// 预获取证书
	go m.prefetchCertificates()

	return nil
}

// startValidationTunnel 启动 ACME 验证隧道
func (m *CertManager) startValidationTunnel() error {
	cfg := m.config.ACME

	if m.validationTunnel == nil {
		return fmt.Errorf("验证隧道未配置")
	}

	port := cfg.HTTPPort
	if port == 0 {
		port = 80
	}

	// 为每个域名启动验证
	// 注意：实际上 Cloudflare 隧道会自动处理所有请求
	domain := cfg.Domains[0] // 主域名

	m.log(1, "启动 ACME 验证隧道: %s -> localhost:%d", domain, port)

	if err := m.validationTunnel.StartValidationTunnel(m.ctx, port, domain); err != nil {
		return fmt.Errorf("启动验证隧道失败: %w", err)
	}

	m.log(1, "验证隧道已启动，等待 URL...")

	// 等待隧道就绪
	time.Sleep(3 * time.Second)

	if m.validationTunnel.IsValidationTunnelRunning() {
		m.log(1, "验证隧道 URL: %s", m.validationTunnel.GetValidationTunnelURL())
	}

	return nil
}

// startTLSALPN01Challenge 启动 TLS-ALPN-01 挑战
func (m *CertManager) startTLSALPN01Challenge() error {
	// TLS-ALPN-01 通过 GetCertificate 自动处理
	m.log(1, "TLS-ALPN-01 挑战已配置，将在 TLS 握手时自动处理")

	// 预获取证书
	go m.prefetchCertificates()

	return nil
}

// prefetchCertificates 预获取证书
func (m *CertManager) prefetchCertificates() {
	// 等待服务启动
	time.Sleep(2 * time.Second)

	cfg := m.config.ACME
	allSuccess := true

	for _, domain := range cfg.Domains {
		m.log(1, "获取证书: %s", domain)

		certCtx, cancel := context.WithTimeout(m.ctx, 5*time.Minute)

		cert, err := m.autocertManager.GetCertificate(&tls.ClientHelloInfo{
			ServerName: domain,
		})
		cancel()

		if err != nil {
			m.log(0, "获取证书失败 %s: %v", domain, err)
			allSuccess = false
			if m.onError != nil {
				m.onError(fmt.Errorf("获取证书失败 %s: %w", domain, err))
			}
		} else {
			m.log(1, "证书获取成功: %s", domain)

			// 保存证书引用
			m.mu.Lock()
			m.cert = cert
			m.mu.Unlock()

			if m.onCertObtained != nil {
				m.onCertObtained([]string{domain})
			}
		}

		// 检查是否被取消
		select {
		case <-m.ctx.Done():
			return
		case <-certCtx.Done():
			// certCtx 超时但主 ctx 未取消，继续下一个
		default:
			// 正常继续
		}
	}

	// 所有证书获取完成后，停止验证隧道
	if m.validationTunnel != nil && m.validationTunnel.IsValidationTunnelRunning() {
		m.log(1, "证书获取完成，停止验证隧道")
		m.validationTunnel.StopValidationTunnel()
	}

	if allSuccess {
		m.signalCertReady()
	}
}

// =============================================================================
// 手动 ACME 流程（用于更多控制）
// =============================================================================

// ObtainCertificateManual 手动获取证书（完整控制流程）
func (m *CertManager) ObtainCertificateManual(domains []string) error {
	if m.acmeClient == nil {
		return fmt.Errorf("ACME 客户端未初始化")
	}

	m.log(1, "手动获取 ACME 证书: %v", domains)

	// 1. 创建订单
	orderCtx, orderCancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer orderCancel()

	order, err := m.acmeClient.AuthorizeOrder(orderCtx, acme.DomainIDs(domains...))
	if err != nil {
		return fmt.Errorf("创建订单失败: %w", err)
	}

	m.log(2, "订单已创建: %s", order.URI)

	// 2. 完成所有授权
	for _, authzURL := range order.AuthzURLs {
		if err := m.completeAuthorization(authzURL); err != nil {
			return fmt.Errorf("授权失败: %w", err)
		}
	}

	// 3. 等待订单就绪
	waitCtx, waitCancel := context.WithTimeout(m.ctx, 5*time.Minute)
	defer waitCancel()

	order, err = m.acmeClient.WaitOrder(waitCtx, order.URI)
	if err != nil {
		return fmt.Errorf("等待订单失败: %w", err)
	}

	if order.Status != acme.StatusReady {
		return fmt.Errorf("订单状态异常: %s", order.Status)
	}

	// 4. 生成证书密钥
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("生成证书密钥失败: %w", err)
	}

	// 5. 创建 CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domains[0]},
	}, certKey)
	if err != nil {
		return fmt.Errorf("创建 CSR 失败: %w", err)
	}

	// 6. 完成订单
	finalizeCtx, finalizeCancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer finalizeCancel()

	certDER, _, err := m.acmeClient.CreateOrderCert(finalizeCtx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("获取证书失败: %w", err)
	}

	// 7. 保存证书和密钥
	m.certPath = filepath.Join(m.config.CertDir, "acme.crt")
	m.keyPath = filepath.Join(m.config.CertDir, "acme.key")

	// 保存证书
	certFile, err := os.OpenFile(m.certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建证书文件失败: %w", err)
	}
	defer certFile.Close()

	for _, der := range certDER {
		if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return fmt.Errorf("写入证书失败: %w", err)
		}
	}

	// 保存私钥
	keyFile, err := os.OpenFile(m.keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建私钥文件失败: %w", err)
	}
	defer keyFile.Close()

	keyBytes, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return fmt.Errorf("编码私钥失败: %w", err)
	}

	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("保存私钥失败: %w", err)
	}

	m.log(1, "ACME 证书已保存: %s", m.certPath)

	// 加载证书
	if err := m.loadCertFromFiles(); err != nil {
		return err
	}

	m.signalCertReady()

	if m.onCertObtained != nil {
		m.onCertObtained(domains)
	}

	return nil
}

// completeAuthorization 完成单个授权
func (m *CertManager) completeAuthorization(authzURL string) error {
	authzCtx, authzCancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer authzCancel()

	authz, err := m.acmeClient.GetAuthorization(authzCtx, authzURL)
	if err != nil {
		return fmt.Errorf("获取授权失败: %w", err)
	}

	if authz.Status == acme.StatusValid {
		return nil // 已经验证过
	}

	// 查找 HTTP-01 挑战
	var challenge *acme.Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "http-01" {
			challenge = ch
			break
		}
	}

	if challenge == nil {
		return fmt.Errorf("未找到 HTTP-01 挑战")
	}

	// 接受挑战
	acceptCtx, acceptCancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer acceptCancel()

	if _, err := m.acmeClient.Accept(acceptCtx, challenge); err != nil {
		return fmt.Errorf("接受挑战失败: %w", err)
	}

	// 等待授权完成
	waitCtx, waitCancel := context.WithTimeout(m.ctx, 5*time.Minute)
	defer waitCancel()

	if _, err := m.acmeClient.WaitAuthorization(waitCtx, authzURL); err != nil {
		return fmt.Errorf("等待授权失败: %w", err)
	}

	return nil
}

// =============================================================================
// Cloudflare Origin 证书
// =============================================================================

// setupCFOriginCert 设置 Cloudflare Origin 证书
func (m *CertManager) setupCFOriginCert() error {
	if m.config.CFToken == "" {
		return fmt.Errorf("Cloudflare Origin 证书需要 API Token")
	}

	m.certPath = filepath.Join(m.config.CertDir, "cforigin.crt")
	m.keyPath = filepath.Join(m.config.CertDir, "cforigin.key")

	// 检查现有证书
	if m.isCertValid(m.certPath, 30*24*time.Hour) {
		m.log(1, "使用现有 Cloudflare Origin 证书")
		if err := m.loadCertFromFiles(); err != nil {
			return err
		}
		m.signalCertReady()
		return nil
	}

	// 需要通过 Cloudflare API 获取
	m.log(1, "Cloudflare Origin 证书需要通过 Cloudflare Dashboard 或 API 获取")
	m.log(1, "请将证书文件放置到: %s", m.certPath)
	m.log(1, "请将私钥文件放置到: %s", m.keyPath)

	return fmt.Errorf("请手动配置 Cloudflare Origin 证书")
}

// =============================================================================
// 自定义证书
// =============================================================================

// loadCustomCert 加载自定义证书
func (m *CertManager) loadCustomCert() error {
	m.certPath = m.config.CertFile
	m.keyPath = m.config.KeyFile

	if m.certPath == "" || m.keyPath == "" {
		return fmt.Errorf("自定义证书模式需要指定 cert_file 和 key_file")
	}

	if _, err := os.Stat(m.certPath); os.IsNotExist(err) {
		return fmt.Errorf("证书文件不存在: %s", m.certPath)
	}

	if _, err := os.Stat(m.keyPath); os.IsNotExist(err) {
		return fmt.Errorf("私钥文件不存在: %s", m.keyPath)
	}

	if !m.isCertValid(m.certPath, 7*24*time.Hour) {
		return fmt.Errorf("证书已过期或即将过期")
	}

	if err := m.loadCertFromFiles(); err != nil {
		return err
	}

	m.signalCertReady()
	return nil
}

// =============================================================================
// 辅助方法
// =============================================================================

// loadCertFromFiles 从文件加载证书
func (m *CertManager) loadCertFromFiles() error {
	cert, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
	if err != nil {
		return fmt.Errorf("加载证书失败: %w", err)
	}

	m.mu.Lock()
	m.cert = &cert
	m.mu.Unlock()

	m.log(1, "证书已加载: %s", m.certPath)
	return nil
}

// isCertValid 检查证书是否有效
func (m *CertManager) isCertValid(certPath string, minValidity time.Duration) bool {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	// 检查是否在有效期内且有足够的剩余时间
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false
	}

	return now.Add(minValidity).Before(cert.NotAfter)
}

// GetCertificate 获取 TLS 证书（用于 tls.Config）
func (m *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// 如果使用 autocert，优先使用它
	if m.autocertManager != nil {
		return m.autocertManager.GetCertificate(hello)
	}

	// 否则返回预加载的证书
	m.mu.RLock()
	cert := m.cert
	m.mu.RUnlock()

	if cert == nil {
		return nil, fmt.Errorf("证书未加载")
	}

	return cert, nil
}

// GetTLSConfig 获取 TLS 配置
func (m *CertManager) GetTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		NextProtos: []string{"h2", "http/1.1", "acme-tls/1"}, // 支持 TLS-ALPN-01
	}
}

// GetCertPaths 获取证书文件路径
func (m *CertManager) GetCertPaths() (certPath, keyPath string) {
	return m.certPath, m.keyPath
}

// GetAutocertManager 获取 autocert 管理器（用于集成）
func (m *CertManager) GetAutocertManager() *autocert.Manager {
	return m.autocertManager
}

// GetHTTPHandler 获取 HTTP 处理器（用于 ACME 挑战）
func (m *CertManager) GetHTTPHandler() http.Handler {
	if m.autocertManager != nil {
		return m.autocertManager.HTTPHandler(nil)
	}
	return nil
}

// log 日志输出
func (m *CertManager) log(level int, format string, args ...interface{}) {
	if level > m.logLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [CertManager] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

// =============================================================================
// 证书续期监控
// =============================================================================

// StartRenewalMonitor 启动证书续期监控
func (m *CertManager) StartRenewalMonitor(ctx context.Context) {
	if m.config.Mode != CertACME && m.config.Mode != CertSelfSigned {
		return
	}

	go func() {
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.checkAndRenew()
			}
		}
	}()
}

// checkAndRenew 检查并续期证书
func (m *CertManager) checkAndRenew() {
	switch m.config.Mode {
	case CertSelfSigned:
		if !m.isCertValid(m.certPath, 7*24*time.Hour) {
			m.log(1, "自签名证书即将过期，重新生成...")
			if err := m.generateSelfSignedCert(); err != nil {
				m.log(0, "重新生成证书失败: %v", err)
			} else if m.onCertRenewed != nil {
				m.onCertRenewed(m.config.ACME.Domains)
			}
		}

	case CertACME:
		// autocert 自动处理续期
		for _, domain := range m.config.ACME.Domains {
			// 检查缓存中的证书
			cachePath := filepath.Join(m.config.CertDir, domain)
			if m.isCertValid(cachePath, 30*24*time.Hour) {
				m.log(2, "证书有效: %s", domain)
			} else {
				m.log(1, "证书需要续期: %s（将自动处理）", domain)
				// autocert 会在下次 GetCertificate 时自动续期
			}
		}
	}
}

// GetCertInfo 获取当前证书信息
func (m *CertManager) GetCertInfo() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	info := map[string]interface{}{
		"mode":      string(m.config.Mode),
		"cert_path": m.certPath,
		"key_path":  m.keyPath,
	}

	if m.cert != nil && len(m.cert.Certificate) > 0 {
		if cert, err := x509.ParseCertificate(m.cert.Certificate[0]); err == nil {
			info["subject"] = cert.Subject.CommonName
			info["issuer"] = cert.Issuer.CommonName
			info["not_before"] = cert.NotBefore
			info["not_after"] = cert.NotAfter
			info["dns_names"] = cert.DNSNames
			info["valid"] = time.Now().Before(cert.NotAfter) && time.Now().After(cert.NotBefore)
			info["expires_in"] = cert.NotAfter.Sub(time.Now()).String()
		}
	}

	return info
}








// =============================================================================
// 以下内容添加到 cert_manager.go 文件末尾
// =============================================================================

// =============================================================================
// 实现 TLSCertProvider 接口
// =============================================================================

// 确保 CertManager 实现 transport.TLSCertProvider 接口
// var _ transport.TLSCertProvider = (*CertManager)(nil)

// GetCertificateForSNI 根据 SNI 获取证书
func (m *CertManager) GetCertificateForSNI(sni string) (*tls.Certificate, error) {
	m.log(2, "请求证书: SNI=%s", sni)

	// 首先检查是否有 autocert 管理器
	if m.autocertManager != nil {
		cert, err := m.autocertManager.GetCertificate(&tls.ClientHelloInfo{
			ServerName: sni,
		})
		if err == nil {
			return cert, nil
		}
		m.log(2, "autocert 获取证书失败: %v", err)
	}

	// 返回预加载的证书
	m.mu.RLock()
	cert := m.cert
	m.mu.RUnlock()

	if cert == nil {
		// 如果没有预加载证书，尝试生成自签名证书
		m.log(1, "没有预加载证书，为 %s 生成自签名证书", sni)
		return m.GenerateSelfSignedCertForSNI(sni)
	}

	return cert, nil
}

// GetTLSConfigForServer 获取服务端 TLS 配置
func (m *CertManager) GetTLSConfigForServer() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		MaxVersion:     tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
		// 启用会话复用
		SessionTicketsDisabled: false,
	}
}

// GenerateSelfSignedCertForSNI 为指定 SNI 生成自签名证书
func (m *CertManager) GenerateSelfSignedCertForSNI(sni string) (*tls.Certificate, error) {
	m.log(2, "为 SNI 生成自签名证书: %s", sni)

	// 生成私钥
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成私钥失败: %w", err)
	}

	// 准备证书模板
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("生成序列号失败: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Phantom Server"},
			CommonName:   sni,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{sni},
	}

	// 如果 SNI 看起来像 IP，也添加到 IP 地址列表
	if ip := net.ParseIP(sni); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	// 创建证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("创建证书失败: %w", err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	// 解析证书以填充 Leaf
	cert.Leaf, _ = x509.ParseCertificate(certDER)

	m.log(1, "自签名证书已生成: SNI=%s, 有效期至=%s", sni, template.NotAfter.Format("2006-01-02"))

	return cert, nil
}

// SNICertificateCache SNI 证书缓存
type SNICertificateCache struct {
	cache   map[string]*tls.Certificate
	mu      sync.RWMutex
	manager *CertManager
}

// NewSNICertificateCache 创建 SNI 证书缓存
func NewSNICertificateCache(manager *CertManager) *SNICertificateCache {
	return &SNICertificateCache{
		cache:   make(map[string]*tls.Certificate),
		manager: manager,
	}
}

// GetCertificate 获取或生成证书
func (c *SNICertificateCache) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := hello.ServerName

	// 先检查缓存
	c.mu.RLock()
	cert, ok := c.cache[sni]
	c.mu.RUnlock()

	if ok {
		return cert, nil
	}

	// 尝试从 CertManager 获取
	if c.manager != nil {
		cert, err := c.manager.GetCertificateForSNI(sni)
		if err == nil {
			c.mu.Lock()
			c.cache[sni] = cert
			c.mu.Unlock()
			return cert, nil
		}
	}

	return nil, fmt.Errorf("无法获取证书: %s", sni)
}

// Clear 清除缓存
func (c *SNICertificateCache) Clear() {
	c.mu.Lock()
	c.cache = make(map[string]*tls.Certificate)
	c.mu.Unlock()
}

// Size 返回缓存大小
func (c *SNICertificateCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}
