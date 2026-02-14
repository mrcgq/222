// =============================================================================
// 文件: internal/tunnel/cert_manager.go
// 描述: 证书管理器 - 使用 Go 原生 ACME 客户端
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
}

// DefaultCertConfig 默认证书配置
func DefaultCertConfig() *CertConfig {
	return &CertConfig{
		Mode:    CertAuto,
		CertDir: filepath.Join(os.TempDir(), "phantom-certs"),
		ACME: ACMEConfig{
			Provider:      ACMELetsEncrypt,
			AcceptTOS:     true,
			ChallengeType: "http-01",
			HTTPPort:      80,
			TLSPort:       443,
		},
	}
}

// =============================================================================
// 证书管理器
// =============================================================================

// CertManager 证书管理器
type CertManager struct {
	config *CertConfig

	// autocert 管理器
	autocertManager *autocert.Manager

	// 当前证书
	certPath string
	keyPath  string
	cert     *tls.Certificate

	// 控制
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.RWMutex
	logLevel int

	// HTTP 服务器（用于 HTTP-01 挑战）
	httpServer *http.Server
}

// NewCertManager 创建证书管理器
func NewCertManager(cfg *CertConfig) *CertManager {
	if cfg == nil {
		cfg = DefaultCertConfig()
	}

	// 确保证书目录存在
	os.MkdirAll(cfg.CertDir, 0700)

	return &CertManager{
		config:   cfg,
		logLevel: 1,
	}
}

// Start 启动证书管理器
func (m *CertManager) Start(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)

	switch m.config.Mode {
	case CertAuto:
		m.log(1, "使用 Cloudflare 自动证书")
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
		return m.loadCertFromFiles()
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
	return m.loadCertFromFiles()
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

	// 获取 ACME 目录 URL
	directoryURL := m.getACMEDirectoryURL()

	// 创建 ACME 客户端
	client := &acme.Client{
		DirectoryURL: directoryURL,
	}

	// 创建 autocert 管理器
	m.autocertManager = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(m.config.CertDir),
		HostPolicy: autocert.HostWhitelist(cfg.Domains...),
		Email:      cfg.Email,
		Client:     client,
	}

	// 如果是 ZeroSSL，需要外部账户绑定 (EAB)
	if cfg.Provider == ACMEZeroSSL && cfg.EABKeyID != "" {
		m.log(1, "配置 ZeroSSL EAB...")
		// autocert 不直接支持 EAB，需要自定义处理
		// 这里使用自定义 ACME 流程
		return m.setupZeroSSLWithEAB()
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

	addr := fmt.Sprintf(":%d", cfg.HTTPPort)

	m.httpServer = &http.Server{
		Addr:    addr,
		Handler: m.autocertManager.HTTPHandler(nil),
	}

	go func() {
		m.log(1, "启动 HTTP-01 挑战服务: %s", addr)
		if err := m.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			m.log(0, "HTTP-01 服务错误: %v", err)
		}
	}()

	// 预获取证书
	go m.prefetchCertificates()

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

	for _, domain := range m.config.ACME.Domains {
		m.log(1, "预获取证书: %s", domain)

		fetchCtx, cancel := context.WithTimeout(m.ctx, 5*time.Minute)
		_, err := m.autocertManager.GetCertificate(&tls.ClientHelloInfo{
			ServerName: domain,
		})
		cancel()

		if err != nil {
			m.log(0, "获取证书失败 %s: %v", domain, err)
		} else {
			m.log(1, "证书获取成功: %s", domain)
		}

		// 使用 fetchCtx 检查是否被取消
		select {
		case <-fetchCtx.Done():
			// context 已完成，继续下一个
		default:
			// 正常继续
		}
	}
}

// setupZeroSSLWithEAB 使用 EAB 设置 ZeroSSL
func (m *CertManager) setupZeroSSLWithEAB() error {
	cfg := m.config.ACME

	m.log(1, "使用 EAB 配置 ZeroSSL...")

	// 创建自定义 ACME 客户端
	client := &acme.Client{
		DirectoryURL: ZeroSSLProductionURL,
	}

	// 获取目录
	discoverCtx, discoverCancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer discoverCancel()

	dir, err := client.Discover(discoverCtx)
	if err != nil {
		return fmt.Errorf("获取 ACME 目录失败: %w", err)
	}

	// 创建带 EAB 的账户
	account := &acme.Account{
		Contact: []string{"mailto:" + cfg.Email},
		ExternalAccountBinding: &acme.ExternalAccountBinding{
			KID: cfg.EABKeyID,
			Key: []byte(cfg.EABHMACKey),
		},
	}

	// 生成账户密钥
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("生成账户密钥失败: %w", err)
	}
	client.Key = accountKey

	// 注册账户
	registerCtx, registerCancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer registerCancel()

	_, err = client.Register(registerCtx, account, func(tosURL string) bool {
		m.log(1, "接受服务条款: %s", tosURL)
		return cfg.AcceptTOS
	})
	if err != nil && err != acme.ErrAccountAlreadyExists {
		return fmt.Errorf("注册账户失败: %w", err)
	}

	// 使用标准 autocert，但配置了自定义客户端
	m.autocertManager = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(m.config.CertDir),
		HostPolicy: autocert.HostWhitelist(cfg.Domains...),
		Email:      cfg.Email,
		Client:     client,
	}

	m.log(1, "ZeroSSL EAB 配置完成")
	_ = dir // 使用目录信息（避免未使用警告）

	return m.startHTTP01Challenge()
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
		return m.loadCertFromFiles()
	}

	// 需要通过 Cloudflare API 获取
	// 这里提供占位实现，实际需要调用 CF API
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

	return m.loadCertFromFiles()
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
			m.generateSelfSignedCert()
		}

	case CertACME:
		// autocert 自动处理续期，这里只做日志
		for _, domain := range m.config.ACME.Domains {
			cachePath := filepath.Join(m.config.CertDir, domain)
			if m.isCertValid(cachePath, 30*24*time.Hour) {
				m.log(2, "证书有效: %s", domain)
			} else {
				m.log(1, "证书需要续期: %s（将自动处理）", domain)
			}
		}
	}
}
