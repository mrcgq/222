// =============================================================================
// 文件: internal/tunnel/tunnel.go
// 描述: 隧道管理器 - 整合 Cloudflare 隧道和证书管理
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

	// 验证隧道（用于 ACME）
	validationRunner *CloudflaredRunner

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
		if tm.config.DuckDNSToken == "" || tm.config.DuckDNSDomain == "" {
			return fmt.Errorf("DuckDNS 需要配置 token 和 domain")
		}
		if err := tm.updateDuckDNS(); err != nil {
			return fmt.Errorf("更新 DuckDNS 失败: %w", err)
		}
		tm.domain = tm.config.DuckDNSDomain + ".duckdns.org"
		tm.log(1, "使用 DuckDNS 域名: %s", tm.domain)
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

		OnURLReady: func(url string) {
			tm.mu.Lock()
			tm.tunnelURL = url
			if tm.domain == "" {
				tm.domain = extractDomainFromURL(url)
			}
			tm.mu.Unlock()
			tm.log(1, "隧道 URL: %s", url)
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
		url, err := tm.runner.WaitForURL(30 * time.Second)
		if err != nil {
			tm.log(0, "等待隧道 URL 失败: %v", err)
		} else {
			tm.log(1, "临时隧道已建立: %s", url)
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

		OnURLReady: func(url string) {
			tm.mu.Lock()
			tm.tunnelURL = url
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

		OnURLReady: func(url string) {
			tm.log(1, "验证隧道 URL: %s", url)
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
	return err
}

// IsValidationTunnelRunning 检查验证隧道是否运行中
func (tm *TunnelManager) IsValidationTunnelRunning() bool {
	return tm.validationRunner != nil && tm.validationRunner.IsRunning()
}

// GetValidationTunnelURL 获取验证隧道 URL
func (tm *TunnelManager) GetValidationTunnelURL() string {
	if tm.validationRunner == nil {
		return ""
	}
	// 使用 WaitForURL 的同步方式或者从状态中获取
	tm.validationRunner.mu.RLock()
	url := tm.validationRunner.tunnelURL
	tm.validationRunner.mu.RUnlock()
	return url
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
	// 使用多个服务尝试获取 IP
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}

	for _, svc := range services {
		ip, err := fetchURL(svc, 5*time.Second)
		if err == nil && ip != "" {
			return trimSpace(ip), nil
		}
	}

	return "", fmt.Errorf("无法获取公网 IP")
}

// updateDuckDNS 更新 DuckDNS
func (tm *TunnelManager) updateDuckDNS() error {
	url := fmt.Sprintf("https://www.duckdns.org/update?domains=%s&token=%s",
		tm.config.DuckDNSDomain, tm.config.DuckDNSToken)

	resp, err := fetchURL(url, 10*time.Second)
	if err != nil {
		return err
	}

	resp = trimSpace(resp)
	if resp != "OK" {
		return fmt.Errorf("DuckDNS 更新失败: %s", resp)
	}

	return nil
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
func extractDomainFromURL(url string) string {
	// 移除协议前缀
	for _, prefix := range []string{"https://", "http://"} {
		if len(url) > len(prefix) && url[:len(prefix)] == prefix {
			url = url[len(prefix):]
			break
		}
	}

	// 移除路径和端口
	for i, c := range url {
		if c == '/' || c == ':' {
			return url[:i]
		}
	}

	return url
}

// fetchURL 获取 URL 内容
func fetchURL(url string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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
