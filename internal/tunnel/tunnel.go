// =============================================================================
// 文件: internal/tunnel/tunnel.go
// 描述: 隧道管理器 - 整合 Cloudflare 隧道、证书管理和 DDNS
// =============================================================================
package tunnel

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/mrcgq/211/internal/config"
)

// =============================================================================
// 域名模式常量 (TunnelMode 已在 runner.go 中定义)
// =============================================================================

// DomainMode 域名模式
type DomainMode string

const (
	DomainAuto    DomainMode = "auto"    // 自动（由 CF 提供）
	DomainSSLIP   DomainMode = "sslip"   // sslip.io
	DomainNIP     DomainMode = "nip"     // nip.io
	DomainDuckDNS DomainMode = "duckdns" // DuckDNS
	DomainFreeDNS DomainMode = "freedns" // FreeDNS
	DomainCustom  DomainMode = "custom"  // 自定义域名
)

// =============================================================================
// 隧道配置
// =============================================================================

// TunnelConfig 隧道配置
type TunnelConfig struct {
	Enabled    bool       `yaml:"enabled"`
	Mode       TunnelMode `yaml:"mode"`
	DomainMode DomainMode `yaml:"domain_mode"`
	Domain     string     `yaml:"domain"`

	// 证书配置
	Cert CertConfig `yaml:"cert"`

	// 本地服务配置
	LocalAddr string `yaml:"local_addr"`
	LocalPort int    `yaml:"local_port"`
	Protocol  string `yaml:"protocol"` // http, https

	// Cloudflare 配置
	CFToken    string `yaml:"cf_token"`
	CFTunnelID string `yaml:"cf_tunnel_id"`

	// DuckDNS 配置
	DuckDNSToken  string `yaml:"duckdns_token"`
	DuckDNSDomain string `yaml:"duckdns_domain"`

	// DuckDNS 结构体配置
	DuckDNS struct {
		Token   string `yaml:"token"`
		Domains string `yaml:"domains"`
	} `yaml:"duckdns"`

	// FreeDNS 配置
	FreeDNS struct {
		Token  string `yaml:"token"`
		Domain string `yaml:"domain"`
	} `yaml:"freedns"`

	// DDNS 完整配置
	DDNS *DDNSConfig `yaml:"ddns"`

	// 日志级别
	LogLevel string `yaml:"log_level"`
}

// DefaultTunnelConfig 默认隧道配置
func DefaultTunnelConfig() *TunnelConfig {
	return &TunnelConfig{
		Enabled:    false,
		Mode:       ModeTempTunnel,
		DomainMode: DomainAuto,
		Cert:       *DefaultCertConfig(),
		LocalAddr:  "127.0.0.1",
		LocalPort:  54321,
		Protocol:   "http",
		LogLevel:   "info",
	}
}

// FromConfigTunnelConfig 从 config.TunnelConfig 转换
func FromConfigTunnelConfig(cfg *config.TunnelConfig) *TunnelConfig {
	if cfg == nil {
		return DefaultTunnelConfig()
	}

	tc := &TunnelConfig{
		Enabled:       cfg.Enabled,
		Mode:          TunnelMode(cfg.Mode),
		DomainMode:    DomainMode(cfg.DomainMode),
		Domain:        cfg.Domain,
		LocalAddr:     cfg.LocalAddr,
		LocalPort:     cfg.LocalPort,
		Protocol:      cfg.Protocol,
		CFToken:       cfg.CFToken,
		CFTunnelID:    cfg.CFTunnelID,
		DuckDNSToken:  cfg.GetDuckDNSToken(),
		DuckDNSDomain: cfg.GetDuckDNSDomain(),
		LogLevel:      cfg.LogLevel,
	}

	// 复制 DuckDNS 结构体配置
	tc.DuckDNS.Token = cfg.DuckDNS.Token
	tc.DuckDNS.Domains = cfg.DuckDNS.Domains

	// 复制 FreeDNS 配置
	tc.FreeDNS.Token = cfg.FreeDNS.Token
	tc.FreeDNS.Domain = cfg.FreeDNS.Domain

	// 转换 DDNS 配置
	if cfg.DDNS != nil && cfg.DDNS.Enabled {
		tc.DDNS = convertDDNSConfig(cfg.DDNS)
	}

	// 转换证书配置
	tc.Cert = CertConfig{
		Mode:     CertMode(cfg.CertMode),
		CertFile: cfg.CertFile,
		KeyFile:  cfg.KeyFile,
		CertDir:  cfg.CertDir,
		ACME: ACMEConfig{
			Provider:               ACMEProvider(cfg.ACMEProvider),
			Email:                  cfg.ACMEEmail,
			Domains:                cfg.ACMEDomains,
			AcceptTOS:              true,
			ChallengeType:          cfg.ACMEChallengeType,
			HTTPPort:               cfg.ACMEHTTPPort,
			EABKeyID:               cfg.ACMEEABKeyID,
			EABHMACKey:             cfg.ACMEEABHMACKey,
			UseTunnelForValidation: cfg.ACMEUseTunnel,
		},
	}

	// 设置默认值
	if tc.Mode == "" {
		tc.Mode = ModeTempTunnel
	}
	if tc.DomainMode == "" {
		tc.DomainMode = DomainAuto
	}
	if tc.LocalAddr == "" {
		tc.LocalAddr = "127.0.0.1"
	}
	if tc.LocalPort == 0 {
		tc.LocalPort = 54321
	}
	if tc.Protocol == "" {
		tc.Protocol = "http"
	}
	if tc.Cert.Mode == "" {
		tc.Cert.Mode = CertAuto
	}
	if tc.Cert.CertDir == "" {
		tc.Cert.CertDir = DefaultCertConfig().CertDir
	}
	if tc.Cert.ACME.HTTPPort == 0 {
		tc.Cert.ACME.HTTPPort = 80
	}

	return tc
}

// convertDDNSConfig 转换 DDNS 配置
func convertDDNSConfig(cfg *config.DDNSConfig) *DDNSConfig {
	if cfg == nil {
		return nil
	}

	ddns := &DDNSConfig{
		Enabled:        cfg.Enabled,
		Provider:       DDNSProvider(cfg.Provider),
		UpdateInterval: parseDuration(cfg.UpdateInterval, 5*time.Minute),
		Token:          cfg.Token,
		Domains:        cfg.Domains,
	}

	// DuckDNS
	ddns.DuckDNS = DuckDNSConfig{
		Token:   cfg.DuckDNS.Token,
		Domains: cfg.DuckDNS.Domains,
	}

	// FreeDNS
	ddns.FreeDNS = FreeDNSConfig{
		Token:  cfg.FreeDNS.Token,
		Domain: cfg.FreeDNS.Domain,
	}

	// No-IP
	ddns.NoIP = NoIPConfig{
		Username: cfg.NoIP.Username,
		Password: cfg.NoIP.Password,
		Hostname: cfg.NoIP.Hostname,
	}

	return ddns
}

// parseDuration 解析时间间隔
func parseDuration(s string, defaultVal time.Duration) time.Duration {
	if s == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultVal
	}
	return d
}

// =============================================================================
// 隧道管理器
// =============================================================================

// TunnelManager 隧道管理器
type TunnelManager struct {
	config *TunnelConfig

	// 子组件
	downloader  *BinaryDownloader
	privManager *PrivilegeManager
	runner      *CloudflaredRunner
	certManager *CertManager
	ddnsManager *DDNSManager // DDNS 管理器

	// 验证隧道（用于 ACME）
	validationRunner    *CloudflaredRunner
	validationTunnelURL string // 缓存验证隧道 URL

	// 状态
	running   bool
	tunnelURL string
	domain    string
	startTime time.Time

	// 同步
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.RWMutex
	logLevel int
}

// NewTunnelManager 创建隧道管理器
func NewTunnelManager(cfg *TunnelConfig) *TunnelManager {
	if cfg == nil {
		cfg = DefaultTunnelConfig()
	}

	logLevel := 1
	switch cfg.LogLevel {
	case "debug":
		logLevel = 2
	case "error":
		logLevel = 0
	}

	return &TunnelManager{
		config:   cfg,
		logLevel: logLevel,
	}
}

// Start 启动隧道管理器
func (tm *TunnelManager) Start(ctx context.Context) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if !tm.config.Enabled {
		tm.log(1, "隧道已禁用")
		return nil
	}

	tm.ctx, tm.cancel = context.WithCancel(ctx)
	tm.startTime = time.Now()

	// 0. 启动 DDNS（如果配置了）
	if err := tm.startDDNS(); err != nil {
		tm.log(0, "DDNS 启动失败: %v (继续运行)", err)
		// 不阻止启动
	}

	// 1. 设置域名
	if err := tm.setupDomain(); err != nil {
		return fmt.Errorf("设置域名失败: %w", err)
	}

	// 2. 设置证书
	if err := tm.setupCertificate(); err != nil {
		return fmt.Errorf("设置证书失败: %w", err)
	}

	// 3. 根据模式启动隧道
	switch tm.config.Mode {
	case ModeTempTunnel:
		return tm.startTempTunnel()
	case ModeFixedTunnel:
		return tm.startFixedTunnel()
	case ModeDirectTCP:
		return tm.startDirectMode()
	default:
		return fmt.Errorf("未知的隧道模式: %s", tm.config.Mode)
	}
}

// Stop 停止隧道管理器
func (tm *TunnelManager) Stop() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.cancel != nil {
		tm.cancel()
	}

	// 停止 DDNS 管理器
	if tm.ddnsManager != nil {
		tm.ddnsManager.Stop()
	}

	// 停止主隧道
	if tm.runner != nil {
		if err := tm.runner.Stop(); err != nil {
			tm.log(0, "停止主隧道失败: %v", err)
		}
	}

	// 停止验证隧道
	if tm.validationRunner != nil {
		if err := tm.validationRunner.Stop(); err != nil {
			tm.log(0, "停止验证隧道失败: %v", err)
		}
	}

	// 停止证书管理器
	if tm.certManager != nil {
		tm.certManager.Stop()
	}

	tm.running = false
	tm.tunnelURL = ""
	tm.domain = ""
	tm.validationTunnelURL = ""
}

// =============================================================================
// DDNS 启动
// =============================================================================

// startDDNS 启动 DDNS 管理器
func (tm *TunnelManager) startDDNS() error {
	// 检查是否需要 DDNS
	needsDDNS := tm.config.DomainMode == DomainDuckDNS ||
		tm.config.DomainMode == DomainFreeDNS ||
		(tm.config.DDNS != nil && tm.config.DDNS.Enabled)

	if !needsDDNS {
		return nil
	}

	// 构建 DDNS 配置
	var ddnsCfg *DDNSConfig

	if tm.config.DDNS != nil && tm.config.DDNS.Enabled {
		// 使用完整 DDNS 配置
		ddnsCfg = tm.config.DDNS
	} else {
		// 根据域名模式构建 DDNS 配置
		ddnsCfg = &DDNSConfig{
			Enabled:        true,
			UpdateInterval: 5 * time.Minute,
			LogLevel:       tm.logLevel,
		}

		switch tm.config.DomainMode {
		case DomainDuckDNS:
			ddnsCfg.Provider = DDNSProviderDuckDNS
			// 优先使用简化配置
			token := tm.config.DuckDNSToken
			if token == "" {
				token = tm.config.DuckDNS.Token
			}
			domains := tm.config.DuckDNSDomain
			if domains == "" {
				domains = tm.config.DuckDNS.Domains
			}
			ddnsCfg.DuckDNS = DuckDNSConfig{
				Token:   token,
				Domains: splitDomains(domains),
			}

		case DomainFreeDNS:
			ddnsCfg.Provider = DDNSProviderFreeDNS
			ddnsCfg.FreeDNS = FreeDNSConfig{
				Token:  tm.config.FreeDNS.Token,
				Domain: tm.config.FreeDNS.Domain,
			}
		}
	}

	// 验证配置
	if ddnsCfg.Provider == "" {
		return fmt.Errorf("DDNS 提供商未配置")
	}

	// 创建 DDNS 管理器
	tm.ddnsManager = NewDDNSManager(ddnsCfg)

	// 设置回调
	tm.ddnsManager.onIPChanged = func(oldIP, newIP string) {
		tm.log(1, "公网 IP 已变更: %s -> %s", oldIP, newIP)
	}
	tm.ddnsManager.onUpdateError = func(err error) {
		tm.log(0, "DDNS 更新错误: %v", err)
	}

	// 启动 DDNS 管理器
	tm.log(1, "启动 DDNS 管理器 (提供商: %s)", ddnsCfg.Provider)
	return tm.ddnsManager.Start(tm.ctx)
}

// splitDomains 分割域名字符串
func splitDomains(s string) []string {
	if s == "" {
		return nil
	}
	var domains []string
	current := ""
	for _, c := range s {
		if c == ',' || c == ' ' {
			if current != "" {
				domains = append(domains, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		domains = append(domains, current)
	}
	return domains
}

// =============================================================================
// 域名设置
// =============================================================================

// setupDomain 设置域名
func (tm *TunnelManager) setupDomain() error {
	switch tm.config.DomainMode {
	case DomainAuto:
		// 自动模式不预设域名，由 Cloudflare 提供
		tm.log(1, "使用 Cloudflare 自动域名")
		return nil

	case DomainSSLIP:
		// 使用 sslip.io
		ip, err := tm.getPublicIP()
		if err != nil {
			return fmt.Errorf("获取公网 IP 失败: %w", err)
		}
		tm.domain = fmt.Sprintf("%s.sslip.io", ipToDomain(ip))
		tm.log(1, "使用 sslip.io 域名: %s", tm.domain)
		return nil

	case DomainNIP:
		// 使用 nip.io
		ip, err := tm.getPublicIP()
		if err != nil {
			return fmt.Errorf("获取公网 IP 失败: %w", err)
		}
		tm.domain = fmt.Sprintf("%s.nip.io", ipToDomain(ip))
		tm.log(1, "使用 nip.io 域名: %s", tm.domain)
		return nil

	case DomainDuckDNS:
		// 使用 DuckDNS
		token := tm.config.DuckDNSToken
		if token == "" {
			token = tm.config.DuckDNS.Token
		}
		domain := tm.config.DuckDNSDomain
		if domain == "" {
			domain = tm.config.DuckDNS.Domains
		}

		if token == "" || domain == "" {
			return fmt.Errorf("DuckDNS 需要配置 token 和 domain")
		}

		// 设置域名（DDNS 管理器会自动更新 IP）
		tm.domain = GetDuckDNSDomain(domain)
		tm.log(1, "使用 DuckDNS 域名: %s", tm.domain)

		// 如果 DDNS 管理器还没有更新过，等待首次更新
		if tm.ddnsManager != nil && tm.ddnsManager.GetCurrentIP() == "" {
			tm.log(1, "等待 DDNS 首次更新...")
			if err := tm.ddnsManager.ForceUpdate(); err != nil {
				tm.log(0, "DuckDNS 首次更新失败: %v (继续运行)", err)
			}
		}
		return nil

	case DomainFreeDNS:
		// 使用 FreeDNS
		if tm.config.FreeDNS.Token == "" {
			return fmt.Errorf("FreeDNS 需要配置 token")
		}

		tm.domain = tm.config.FreeDNS.Domain
		if tm.domain == "" {
			return fmt.Errorf("FreeDNS 需要配置 domain")
		}
		tm.log(1, "使用 FreeDNS 域名: %s", tm.domain)

		// 触发 DDNS 更新
		if tm.ddnsManager != nil && tm.ddnsManager.GetCurrentIP() == "" {
			if err := tm.ddnsManager.ForceUpdate(); err != nil {
				tm.log(0, "FreeDNS 首次更新失败: %v (继续运行)", err)
			}
		}
		return nil

	case DomainCustom:
		if tm.config.Domain == "" {
			return fmt.Errorf("自定义域名模式需要配置 domain")
		}
		tm.domain = tm.config.Domain
		tm.log(1, "使用自定义域名: %s", tm.domain)
		return nil

	default:
		return fmt.Errorf("未知的域名模式: %s", tm.config.DomainMode)
	}
}

// =============================================================================
// 证书设置
// =============================================================================

// setupCertificate 设置证书
func (tm *TunnelManager) setupCertificate() error {
	certCfg := &tm.config.Cert

	// 如果是 ACME 模式且有域名，设置域名
	if certCfg.Mode == CertACME && tm.domain != "" && len(certCfg.ACME.Domains) == 0 {
		certCfg.ACME.Domains = []string{tm.domain}
	}

	// 如果是自动模式（临时隧道），不需要本地证书
	if certCfg.Mode == CertAuto {
		tm.log(1, "使用 Cloudflare 自动 TLS")
		return nil
	}

	// 创建证书管理器
	tm.certManager = NewCertManager(certCfg,
		WithCertLogLevel(tm.logLevel),
		WithValidationTunnel(tm), // TunnelManager 实现验证隧道接口
		WithOnCertObtained(func(domains []string) {
			tm.log(1, "证书获取成功: %v", domains)
		}),
		WithOnCertRenewed(func(domains []string) {
			tm.log(1, "证书续期成功: %v", domains)
		}),
		WithOnCertError(func(err error) {
			tm.log(0, "证书错误: %v", err)
		}),
	)

	// 启动证书管理器
	if err := tm.certManager.Start(tm.ctx); err != nil {
		return fmt.Errorf("启动证书管理器失败: %w", err)
	}

	// 对于 ACME，等待证书就绪
	if certCfg.Mode == CertACME {
		tm.log(1, "等待 ACME 证书...")
		if err := tm.certManager.WaitForCert(5 * time.Minute); err != nil {
			tm.log(0, "等待证书超时: %v", err)
			// 不阻止启动，证书可能稍后获取成功
		}
	}

	// 启动续期监控
	tm.certManager.StartRenewalMonitor(tm.ctx)

	return nil
}

// =============================================================================
// 隧道启动
// =============================================================================

// startTempTunnel 启动临时隧道
func (tm *TunnelManager) startTempTunnel() error {
	tm.log(1, "启动 Cloudflare 临时隧道...")

	// 确保 cloudflared 可用
	binaryPath, err := tm.ensureCloudflared()
	if err != nil {
		return err
	}

	// 创建运行器配置
	runnerCfg := &RunnerConfig{
		BinaryPath:  binaryPath,
		Mode:        ModeTempTunnel,
		LocalAddr:   tm.config.LocalAddr,
		LocalPort:   tm.config.LocalPort,
		Protocol:    tm.config.Protocol,
		PrivManager: tm.privManager,
		AutoRestart: true,
		LogLevel:    tm.logLevel,

		OnURLReady: func(tunnelURL string) {
			tm.mu.Lock()
			tm.tunnelURL = tunnelURL
			if tm.domain == "" {
				tm.domain = extractDomainFromURL(tunnelURL)
			}
			tm.mu.Unlock()
			tm.log(1, "隧道 URL: %s", tunnelURL)
		},
		OnError: func(err error) {
			tm.log(0, "隧道错误: %v", err)
		},
		OnStateChange: func(running bool) {
			tm.mu.Lock()
			tm.running = running
			tm.mu.Unlock()
		},
	}

	tm.runner, err = NewCloudflaredRunner(runnerCfg)
	if err != nil {
		return fmt.Errorf("创建运行器失败: %w", err)
	}

	if err := tm.runner.Start(tm.ctx); err != nil {
		return fmt.Errorf("启动隧道失败: %w", err)
	}

	tm.running = true

	// 等待 URL 就绪
	go func() {
		tunnelURL, err := tm.runner.WaitForURL(30 * time.Second)
		if err != nil {
			tm.log(0, "等待隧道 URL 失败: %v", err)
		} else {
			tm.log(1, "临时隧道已建立: %s", tunnelURL)
		}
	}()

	return nil
}

// startFixedTunnel 启动固定隧道
func (tm *TunnelManager) startFixedTunnel() error {
	if tm.config.CFToken == "" {
		return fmt.Errorf("固定隧道需要 Cloudflare Token")
	}

	tm.log(1, "启动 Cloudflare 固定隧道...")

	// 确保 cloudflared 可用
	binaryPath, err := tm.ensureCloudflared()
	if err != nil {
		return err
	}

	// 创建运行器配置
	runnerCfg := &RunnerConfig{
		BinaryPath:  binaryPath,
		Mode:        ModeFixedTunnel,
		LocalAddr:   tm.config.LocalAddr,
		LocalPort:   tm.config.LocalPort,
		Protocol:    tm.config.Protocol,
		CFToken:     tm.config.CFToken,
		CFTunnelID:  tm.config.CFTunnelID,
		PrivManager: tm.privManager,
		AutoRestart: true,
		LogLevel:    tm.logLevel,

		OnURLReady: func(tunnelURL string) {
			tm.mu.Lock()
			tm.tunnelURL = tunnelURL
			tm.mu.Unlock()
		},
		OnError: func(err error) {
			tm.log(0, "隧道错误: %v", err)
		},
		OnStateChange: func(running bool) {
			tm.mu.Lock()
			tm.running = running
			tm.mu.Unlock()
		},
	}

	tm.runner, err = NewCloudflaredRunner(runnerCfg)
	if err != nil {
		return fmt.Errorf("创建运行器失败: %w", err)
	}

	if err := tm.runner.Start(tm.ctx); err != nil {
		return fmt.Errorf("启动隧道失败: %w", err)
	}

	tm.running = true

	// 设置 URL
	if tm.domain != "" {
		tm.tunnelURL = fmt.Sprintf("https://%s", tm.domain)
	}

	return nil
}

// startDirectMode 启动直接模式（不使用 Cloudflare 隧道）
func (tm *TunnelManager) startDirectMode() error {
	tm.log(1, "启动直接模式...")

	// 直接模式只需要证书，不需要 Cloudflare 隧道
	if tm.domain != "" {
		protocol := "http"
		if tm.config.Protocol == "https" || tm.certManager != nil {
			protocol = "https"
		}
		tm.tunnelURL = fmt.Sprintf("%s://%s:%d", protocol, tm.domain, tm.config.LocalPort)
	} else {
		tm.tunnelURL = fmt.Sprintf("http://%s:%d", tm.config.LocalAddr, tm.config.LocalPort)
	}

	tm.running = true
	tm.log(1, "直接模式已启动: %s", tm.tunnelURL)

	return nil
}

// =============================================================================
// ACME 验证隧道实现 (ACMEValidationTunnel 接口)
// =============================================================================

// StartValidationTunnel 启动 ACME 验证隧道
func (tm *TunnelManager) StartValidationTunnel(ctx context.Context, localPort int, domain string) error {
	tm.log(1, "启动 ACME 验证隧道: %s -> localhost:%d", domain, localPort)

	// 确保 cloudflared 可用
	binaryPath, err := tm.ensureCloudflared()
	if err != nil {
		return err
	}

	// 创建验证隧道配置
	// 使用临时隧道模式，因为我们只需要一个临时的 HTTP 入口
	runnerCfg := &RunnerConfig{
		BinaryPath:  binaryPath,
		Mode:        ModeTempTunnel,
		LocalAddr:   "127.0.0.1",
		LocalPort:   localPort,
		Protocol:    "http", // ACME HTTP-01 使用 HTTP
		AutoRestart: false,  // 验证隧道不需要自动重启
		LogLevel:    tm.logLevel,

		OnURLReady: func(tunnelURL string) {
			tm.mu.Lock()
			tm.validationTunnelURL = tunnelURL
			tm.mu.Unlock()
			tm.log(1, "验证隧道 URL: %s", tunnelURL)
		},
		OnError: func(err error) {
			tm.log(0, "验证隧道错误: %v", err)
		},
	}

	tm.validationRunner, err = NewCloudflaredRunner(runnerCfg)
	if err != nil {
		return fmt.Errorf("创建验证隧道运行器失败: %w", err)
	}

	if err := tm.validationRunner.Start(ctx); err != nil {
		return fmt.Errorf("启动验证隧道失败: %w", err)
	}

	return nil
}

// StopValidationTunnel 停止验证隧道
func (tm *TunnelManager) StopValidationTunnel() error {
	if tm.validationRunner == nil {
		return nil
	}

	tm.log(1, "停止 ACME 验证隧道")
	err := tm.validationRunner.Stop()
	tm.validationRunner = nil

	tm.mu.Lock()
	tm.validationTunnelURL = ""
	tm.mu.Unlock()

	return err
}

// IsValidationTunnelRunning 检查验证隧道是否运行中
func (tm *TunnelManager) IsValidationTunnelRunning() bool {
	return tm.validationRunner != nil && tm.validationRunner.IsRunning()
}

// GetValidationTunnelURL 获取验证隧道 URL
func (tm *TunnelManager) GetValidationTunnelURL() string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.validationTunnelURL
}

// =============================================================================
// 辅助方法
// =============================================================================

// ensureCloudflared 确保 cloudflared 可用
func (tm *TunnelManager) ensureCloudflared() (string, error) {
	if tm.downloader == nil {
		tm.downloader = NewBinaryDownloader("",
			WithLogLevel(tm.logLevel),
			WithProgressCallback(func(downloaded, total int64) {
				if total > 0 {
					percent := float64(downloaded) / float64(total) * 100
					fmt.Printf("\r下载 cloudflared: %.1f%%", percent)
				}
			}),
		)
	}

	path, err := tm.downloader.EnsureCloudflared()
	if err != nil {
		return "", fmt.Errorf("获取 cloudflared 失败: %w", err)
	}

	fmt.Println() // 换行

	// 初始化权限管理器
	if tm.privManager == nil {
		privCfg := DefaultPrivilegeConfig()
		tm.privManager, err = NewPrivilegeManager(privCfg)
		if err != nil {
			tm.log(1, "权限管理器初始化失败: %v (继续)", err)
		}
	}

	return path, nil
}

// getPublicIP 获取公网 IP
func (tm *TunnelManager) getPublicIP() (string, error) {
	// 如果 DDNS 管理器有缓存的 IP，优先使用
	if tm.ddnsManager != nil {
		if ip := tm.ddnsManager.GetCurrentIP(); ip != "" {
			return ip, nil
		}
	}

	// 否则重新获取
	return GetPublicIP(nil)
}

// ipToDomain 将 IP 转换为域名格式（用于 sslip.io, nip.io）
func ipToDomain(ip string) string {
	// 将点替换为连字符
	result := ""
	for _, c := range ip {
		if c == '.' {
			result += "-"
		} else {
			result += string(c)
		}
	}
	return result
}

// extractDomainFromURL 从 URL 提取域名
func extractDomainFromURL(urlStr string) string {
	// 移除协议前缀
	for _, prefix := range []string{"https://", "http://"} {
		if len(urlStr) > len(prefix) && urlStr[:len(prefix)] == prefix {
			urlStr = urlStr[len(prefix):]
			break
		}
	}

	// 移除路径和端口
	for i, c := range urlStr {
		if c == '/' || c == ':' {
			return urlStr[:i]
		}
	}

	return urlStr
}

// fetchURL 获取 URL 内容
func fetchURL(reqURL string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	return string(body[:n]), nil
}

// trimSpace 去除字符串首尾空白字符
func trimSpace(s string) string {
	start := 0
	end := len(s)

	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}

	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}

	return s[start:end]
}

// =============================================================================
// Getter 方法
// =============================================================================

// IsRunning 检查是否运行中
func (tm *TunnelManager) IsRunning() bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.running
}

// GetTunnelURL 获取隧道 URL
func (tm *TunnelManager) GetTunnelURL() string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.tunnelURL
}

// GetDomain 获取域名
func (tm *TunnelManager) GetDomain() string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.domain
}

// GetCertPaths 获取证书路径
func (tm *TunnelManager) GetCertPaths() (certPath, keyPath string) {
	if tm.certManager != nil {
		return tm.certManager.GetCertPaths()
	}
	return "", ""
}

// GetCertManager 获取证书管理器
func (tm *TunnelManager) GetCertManager() *CertManager {
	return tm.certManager
}

// GetDDNSManager 获取 DDNS 管理器
func (tm *TunnelManager) GetDDNSManager() *DDNSManager {
	return tm.ddnsManager
}

// GetStatus 获取状态
func (tm *TunnelManager) GetStatus() map[string]interface{} {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	status := map[string]interface{}{
		"running":     tm.running,
		"mode":        string(tm.config.Mode),
		"domain_mode": string(tm.config.DomainMode),
	}

	if tm.running {
		status["uptime"] = time.Since(tm.startTime).String()
	}

	if tm.tunnelURL != "" {
		status["url"] = tm.tunnelURL
	}

	if tm.domain != "" {
		status["domain"] = tm.domain
	}

	if tm.runner != nil {
		status["pid"] = tm.runner.GetPID()
	}

	if tm.certManager != nil {
		status["cert"] = tm.certManager.GetCertInfo()
	}

	// DDNS 状态
	if tm.ddnsManager != nil && tm.ddnsManager.IsRunning() {
		status["ddns"] = tm.ddnsManager.GetStats()
	}

	return status
}

// log 日志输出
func (tm *TunnelManager) log(level int, format string, args ...interface{}) {
	if level > tm.logLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [Tunnel] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}
