// =============================================================================
// 文件: internal/tunnel/tunnel_test.go
// 描述: 隧道管理器单元测试 - 包含 ACME 测试
// =============================================================================
package tunnel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrcgq/211/internal/config"
)

// =============================================================================
// TunnelManager 基础测试
// =============================================================================

func TestTunnelManager_NewManager(t *testing.T) {
	tm := NewTunnelManager(nil)

	if tm.config == nil {
		t.Fatal("配置不应为空")
	}

	if tm.config.Mode != ModeTempTunnel {
		t.Errorf("默认模式应该是 temp, 实际: %s", tm.config.Mode)
	}

	if tm.config.DomainMode != DomainAuto {
		t.Errorf("默认域名模式应该是 auto, 实际: %s", tm.config.DomainMode)
	}
}

func TestTunnelManager_NewManagerWithConfig(t *testing.T) {
	cfg := &TunnelConfig{
		Enabled:    true,
		Mode:       ModeFixedTunnel,
		DomainMode: DomainCustom,
		Domain:     "test.example.com",
		LocalAddr:  "0.0.0.0",
		LocalPort:  8080,
	}

	tm := NewTunnelManager(cfg)

	if tm.config.Mode != ModeFixedTunnel {
		t.Errorf("模式不匹配: %s", tm.config.Mode)
	}

	if tm.config.Domain != "test.example.com" {
		t.Errorf("域名不匹配: %s", tm.config.Domain)
	}
}

func TestTunnelManager_IsRunning(t *testing.T) {
	tm := NewTunnelManager(nil)

	if tm.IsRunning() {
		t.Error("新创建的管理器不应该是运行状态")
	}
}

func TestTunnelManager_StartDisabled(t *testing.T) {
	cfg := &TunnelConfig{
		Enabled: false,
	}

	tm := NewTunnelManager(cfg)
	ctx := context.Background()

	// 禁用状态下应该直接返回成功
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("禁用的隧道启动失败: %v", err)
	}

	if tm.IsRunning() {
		t.Error("禁用的隧道不应该标记为运行中")
	}
}

func TestTunnelManager_StopNotStarted(t *testing.T) {
	tm := NewTunnelManager(nil)

	// 未启动时停止不应 panic
	tm.Stop()

	if tm.IsRunning() {
		t.Error("未启动的隧道不应该是运行状态")
	}
}

func TestTunnelManager_GettersEmpty(t *testing.T) {
	tm := NewTunnelManager(nil)

	if tm.GetTunnelURL() != "" {
		t.Error("未启动时 URL 应该为空")
	}

	if tm.GetDomain() != "" {
		t.Error("未启动时域名应该为空")
	}

	certPath, keyPath := tm.GetCertPaths()
	if certPath != "" || keyPath != "" {
		t.Error("未启动时证书路径应该为空")
	}
}

func TestTunnelManager_LogLevel(t *testing.T) {
	testCases := []struct {
		logLevel string
		expected int
	}{
		{"debug", 2},
		{"info", 1},
		{"error", 0},
		{"", 1}, // 默认
	}

	for _, tc := range testCases {
		cfg := &TunnelConfig{
			LogLevel: tc.logLevel,
		}
		tm := NewTunnelManager(cfg)

		if tm.logLevel != tc.expected {
			t.Errorf("LogLevel %s: 期望 %d, 实际 %d",
				tc.logLevel, tc.expected, tm.logLevel)
		}
	}
}

// =============================================================================
// 配置转换测试
// =============================================================================

func TestTunnelManager_FromConfigTunnelConfig(t *testing.T) {
	cfgConfig := &config.TunnelConfig{
		Enabled:      true,
		Mode:         "fixed",
		DomainMode:   "custom",
		Domain:       "api.example.com",
		CertMode:     "acme",
		ACMEProvider: "letsencrypt",
		ACMEEmail:    "test@example.com",
		ACMEDomains:  []string{"api.example.com"},
		LocalAddr:    "127.0.0.1",
		LocalPort:    3000,
		Protocol:     "https",
	}

	tc := FromConfigTunnelConfig(cfgConfig)

	if tc.Mode != ModeFixedTunnel {
		t.Errorf("模式转换错误: %s", tc.Mode)
	}

	if tc.DomainMode != DomainCustom {
		t.Errorf("域名模式转换错误: %s", tc.DomainMode)
	}

	if tc.Cert.Mode != CertACME {
		t.Errorf("证书模式转换错误: %s", tc.Cert.Mode)
	}

	if tc.Cert.ACME.Provider != ACMELetsEncrypt {
		t.Errorf("ACME 提供商转换错误: %s", tc.Cert.ACME.Provider)
	}

	if tc.Cert.ACME.Email != "test@example.com" {
		t.Errorf("ACME 邮箱转换错误: %s", tc.Cert.ACME.Email)
	}

	if len(tc.Cert.ACME.Domains) != 1 || tc.Cert.ACME.Domains[0] != "api.example.com" {
		t.Errorf("ACME 域名转换错误: %v", tc.Cert.ACME.Domains)
	}

	if tc.Domain != "api.example.com" {
		t.Errorf("域名转换错误: %s", tc.Domain)
	}
}

func TestTunnelManager_FromConfigTunnelConfig_SelfSigned(t *testing.T) {
	cfgConfig := &config.TunnelConfig{
		Enabled:    true,
		Mode:       "fixed",
		DomainMode: "custom",
		Domain:     "api.example.com",
		CertMode:   "selfsigned",
		LocalAddr:  "127.0.0.1",
		LocalPort:  3000,
		Protocol:   "https",
	}

	tc := FromConfigTunnelConfig(cfgConfig)

	if tc.Cert.Mode != CertSelfSigned {
		t.Errorf("证书模式转换错误: %s", tc.Cert.Mode)
	}
}

func TestTunnelManager_FromConfigTunnelConfig_Nil(t *testing.T) {
	tc := FromConfigTunnelConfig(nil)

	if tc == nil {
		t.Fatal("返回值不应为空")
	}

	// 应该返回默认配置
	if tc.Mode != ModeTempTunnel {
		t.Errorf("nil 配置应返回默认值")
	}
}

// =============================================================================
// 默认配置测试
// =============================================================================

func TestDefaultTunnelConfig(t *testing.T) {
	cfg := DefaultTunnelConfig()

	if cfg.Enabled {
		t.Error("默认应该禁用")
	}

	if cfg.Mode != ModeTempTunnel {
		t.Errorf("默认模式应该是 temp: %s", cfg.Mode)
	}

	if cfg.DomainMode != DomainAuto {
		t.Errorf("默认域名模式应该是 auto: %s", cfg.DomainMode)
	}

	if cfg.LocalAddr != "127.0.0.1" {
		t.Errorf("默认本地地址应该是 127.0.0.1: %s", cfg.LocalAddr)
	}

	if cfg.LocalPort != 54321 {
		t.Errorf("默认本地端口应该是 54321: %d", cfg.LocalPort)
	}

	if cfg.Protocol != "http" {
		t.Errorf("默认协议应该是 http: %s", cfg.Protocol)
	}

	if cfg.Cert.ACME.HTTPPort != 80 {
		t.Errorf("默认 ACME HTTP 端口应该是 80: %d", cfg.Cert.ACME.HTTPPort)
	}

	if !cfg.Cert.ACME.UseTunnelForValidation {
		t.Error("默认应该使用隧道验证")
	}
}

// =============================================================================
// 常量测试
// =============================================================================

func TestTunnelMode_Constants(t *testing.T) {
	if ModeTempTunnel != "temp" {
		t.Error("ModeTempTunnel 值错误")
	}
	if ModeFixedTunnel != "fixed" {
		t.Error("ModeFixedTunnel 值错误")
	}
	if ModeDirect != "direct" {
		t.Error("ModeDirect 值错误")
	}
}

func TestDomainMode_Constants(t *testing.T) {
	if DomainAuto != "auto" {
		t.Error("DomainAuto 值错误")
	}
	if DomainSSLIP != "sslip" {
		t.Error("DomainSSLIP 值错误")
	}
	if DomainNIP != "nip" {
		t.Error("DomainNIP 值错误")
	}
	if DomainDuckDNS != "duckdns" {
		t.Error("DomainDuckDNS 值错误")
	}
	if DomainFreeDNS != "freedns" {
		t.Error("DomainFreeDNS 值错误")
	}
	if DomainCustom != "custom" {
		t.Error("DomainCustom 值错误")
	}
}

func TestCertMode_Constants(t *testing.T) {
	if CertAuto != "auto" {
		t.Error("CertAuto 值错误")
	}
	if CertSelfSigned != "selfsigned" {
		t.Error("CertSelfSigned 值错误")
	}
	if CertACME != "acme" {
		t.Error("CertACME 值错误")
	}
	if CertCFOrigin != "cforigin" {
		t.Error("CertCFOrigin 值错误")
	}
	if CertCustom != "custom" {
		t.Error("CertCustom 值错误")
	}
}

func TestACMEProvider_Constants(t *testing.T) {
	if ACMELetsEncrypt != "letsencrypt" {
		t.Error("ACMELetsEncrypt 值错误")
	}
	if ACMELetsEncryptStaging != "letsencrypt-staging" {
		t.Error("ACMELetsEncryptStaging 值错误")
	}
	if ACMEZeroSSL != "zerossl" {
		t.Error("ACMEZeroSSL 值错误")
	}
}

// =============================================================================
// 域名设置测试
// =============================================================================

func TestTunnelManager_SetupDomain_Custom(t *testing.T) {
	cfg := &TunnelConfig{
		Enabled:    true,
		Mode:       ModeDirect,
		DomainMode: DomainCustom,
		Domain:     "custom.example.com",
		Cert: CertConfig{
			Mode: CertAuto,
		},
	}

	tm := NewTunnelManager(cfg)
	tm.ctx, tm.cancel = context.WithCancel(context.Background())
	defer tm.cancel()

	if err := tm.setupDomain(); err != nil {
		t.Fatalf("设置域名失败: %v", err)
	}

	if tm.domain != "custom.example.com" {
		t.Errorf("域名设置错误: %s", tm.domain)
	}
}

func TestTunnelManager_SetupDomain_Auto(t *testing.T) {
	cfg := &TunnelConfig{
		DomainMode: DomainAuto,
	}

	tm := NewTunnelManager(cfg)
	tm.ctx, tm.cancel = context.WithCancel(context.Background())
	defer tm.cancel()

	// Auto 模式不设置域名，由 Cloudflare 提供
	if err := tm.setupDomain(); err != nil {
		t.Fatalf("设置域名失败: %v", err)
	}

	// 域名应该为空（等待隧道提供）
	if tm.domain != "" {
		t.Errorf("Auto 模式不应预设域名: %s", tm.domain)
	}
}

func TestTunnelManager_SetupDomain_Invalid(t *testing.T) {
	cfg := &TunnelConfig{
		DomainMode: "invalid_mode",
	}

	tm := NewTunnelManager(cfg)
	tm.ctx, tm.cancel = context.WithCancel(context.Background())
	defer tm.cancel()

	err := tm.setupDomain()
	if err == nil {
		t.Error("无效的域名模式应该返回错误")
	}
}

// =============================================================================
// 证书管理器测试
// =============================================================================

func TestCertManager_NewManager(t *testing.T) {
	cm := NewCertManager(nil)

	if cm.config == nil {
		t.Fatal("配置不应为空")
	}

	if cm.config.Mode != CertAuto {
		t.Errorf("默认模式应该是 auto: %s", cm.config.Mode)
	}
}

func TestCertManager_SelfSigned(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Domains: []string{"localhost", "127.0.0.1"},
		},
	}

	cm := NewCertManager(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := cm.Start(ctx); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer cm.Stop()

	// 验证证书文件生成
	certPath, keyPath := cm.GetCertPaths()
	if certPath == "" || keyPath == "" {
		t.Error("证书路径不应为空")
	}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("证书文件不存在: %s", certPath)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("私钥文件不存在: %s", keyPath)
	}

	// 验证证书有效性
	if !cm.isCertValid(certPath, time.Hour) {
		t.Error("证书应该有效")
	}

	// 等待证书就绪
	if err := cm.WaitForCert(5 * time.Second); err != nil {
		t.Errorf("等待证书失败: %v", err)
	}
}

func TestCertManager_SelfSigned_Reuse(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Domains: []string{"localhost"},
		},
	}

	// 第一次创建证书
	cm1 := NewCertManager(cfg)
	ctx1, cancel1 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel1()

	if err := cm1.Start(ctx1); err != nil {
		t.Fatalf("第一次启动失败: %v", err)
	}
	cm1.Stop()

	// 记录证书文件的修改时间
	certPath := filepath.Join(tmpDir, "selfsigned.crt")
	info1, _ := os.Stat(certPath)
	modTime1 := info1.ModTime()

	// 等待一小段时间
	time.Sleep(100 * time.Millisecond)

	// 第二次应该复用现有证书
	cm2 := NewCertManager(cfg)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()

	if err := cm2.Start(ctx2); err != nil {
		t.Fatalf("第二次启动失败: %v", err)
	}
	defer cm2.Stop()

	// 证书文件应该没有被修改
	info2, _ := os.Stat(certPath)
	modTime2 := info2.ModTime()

	if !modTime1.Equal(modTime2) {
		t.Error("应该复用现有证书，而不是重新生成")
	}
}

func TestCertManager_GetCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Domains: []string{"localhost"},
		},
	}

	cm := NewCertManager(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := cm.Start(ctx); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer cm.Stop()

	// 获取证书
	cert, err := cm.GetCertificate(nil)
	if err != nil {
		t.Fatalf("获取证书失败: %v", err)
	}

	if cert == nil {
		t.Error("证书不应为空")
	}
}

func TestCertManager_GetCertificate_NotLoaded(t *testing.T) {
	cm := NewCertManager(nil)

	// 未启动时获取证书应该返回错误
	_, err := cm.GetCertificate(nil)
	if err == nil {
		t.Error("未加载证书时应该返回错误")
	}
}

func TestCertManager_GetTLSConfig(t *testing.T) {
	cm := NewCertManager(nil)

	tlsConfig := cm.GetTLSConfig()

	if tlsConfig == nil {
		t.Fatal("TLS 配置不应为空")
	}

	if tlsConfig.GetCertificate == nil {
		t.Error("GetCertificate 不应为空")
	}

	if tlsConfig.MinVersion == 0 {
		t.Error("MinVersion 应该被设置")
	}

	// 验证支持 ACME TLS-ALPN-01
	hasACMEProtocol := false
	for _, proto := range tlsConfig.NextProtos {
		if proto == "acme-tls/1" {
			hasACMEProtocol = true
			break
		}
	}
	if !hasACMEProtocol {
		t.Error("应该支持 acme-tls/1 协议")
	}
}

func TestCertManager_GetCertInfo(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Domains: []string{"test.local"},
		},
	}

	cm := NewCertManager(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := cm.Start(ctx); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer cm.Stop()

	info := cm.GetCertInfo()

	if info["mode"] != "selfsigned" {
		t.Errorf("模式不正确: %v", info["mode"])
	}

	if info["valid"] != true {
		t.Error("证书应该有效")
	}

	if _, ok := info["expires_in"]; !ok {
		t.Error("应该包含过期时间")
	}

	if _, ok := info["subject"]; !ok {
		t.Error("应该包含主题")
	}

	if _, ok := info["dns_names"]; !ok {
		t.Error("应该包含 DNS 名称")
	}
}

func TestCertManager_GetCertInfo_NotLoaded(t *testing.T) {
	cm := NewCertManager(nil)

	info := cm.GetCertInfo()

	// 未加载证书时应该只有基本信息
	if info["mode"] != "auto" {
		t.Errorf("模式不正确: %v", info["mode"])
	}

	// 不应该有证书详细信息
	if _, ok := info["valid"]; ok {
		t.Error("未加载证书时不应有 valid 字段")
	}
}

// =============================================================================
// ACME 配置测试
// =============================================================================

func TestCertManager_ACMEConfig(t *testing.T) {
	cfg := &CertConfig{
		Mode:    CertACME,
		CertDir: t.TempDir(),
		ACME: ACMEConfig{
			Provider:               ACMELetsEncryptStaging,
			Email:                  "test@example.com",
			Domains:                []string{"test.example.com"},
			AcceptTOS:              true,
			ChallengeType:          "http-01",
			HTTPPort:               8080,
			UseTunnelForValidation: false,
		},
	}

	cm := NewCertManager(cfg)

	// 验证目录 URL
	url := cm.getACMEDirectoryURL()
	if url != LetsEncryptStagingURL {
		t.Errorf("ACME 目录 URL 错误: %s", url)
	}
}

func TestCertManager_ACMEDirectoryURL(t *testing.T) {
	testCases := []struct {
		provider ACMEProvider
		expected string
	}{
		{ACMELetsEncrypt, LetsEncryptProductionURL},
		{ACMELetsEncryptStaging, LetsEncryptStagingURL},
		{ACMEZeroSSL, ZeroSSLProductionURL},
		{"", LetsEncryptProductionURL}, // 默认
	}

	for _, tc := range testCases {
		cfg := &CertConfig{
			Mode: CertACME,
			ACME: ACMEConfig{
				Provider: tc.provider,
			},
		}
		cm := NewCertManager(cfg)
		url := cm.getACMEDirectoryURL()
		if url != tc.expected {
			t.Errorf("Provider %s: 期望 %s, 实际 %s",
				tc.provider, tc.expected, url)
		}
	}
}

func TestCertManager_LoadOrCreateACMEKey(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CertConfig{
		Mode:    CertACME,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Email:   "test@example.com",
			Domains: []string{"test.example.com"},
		},
	}

	cm := NewCertManager(cfg)
	cm.ctx, cm.cancel = context.WithCancel(context.Background())
	defer cm.cancel()

	// 第一次应该创建新密钥
	if err := cm.loadOrCreateACMEKey(); err != nil {
		t.Fatalf("创建 ACME 密钥失败: %v", err)
	}

	if cm.acmeKey == nil {
		t.Error("ACME 密钥不应为空")
	}

	// 验证密钥文件存在
	keyPath := filepath.Join(tmpDir, "acme_account.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("ACME 密钥文件应该存在")
	}

	// 保存第一个密钥的公钥 X 坐标用于比较
	firstKeyX := cm.acmeKey.X.Bytes()

	// 第二次应该加载现有密钥
	cm2 := NewCertManager(cfg)
	cm2.ctx, cm2.cancel = context.WithCancel(context.Background())
	defer cm2.cancel()

	if err := cm2.loadOrCreateACMEKey(); err != nil {
		t.Fatalf("加载 ACME 密钥失败: %v", err)
	}

	if cm2.acmeKey == nil {
		t.Error("ACME 密钥不应为空")
	}

	// 验证加载的是同一个密钥
	secondKeyX := cm2.acmeKey.X.Bytes()
	if string(firstKeyX) != string(secondKeyX) {
		t.Error("应该加载相同的密钥")
	}
}

// =============================================================================
// 自定义证书测试
// =============================================================================

func TestCertManager_CustomCert_Missing(t *testing.T) {
	cfg := &CertConfig{
		Mode:     CertCustom,
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}

	cm := NewCertManager(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := cm.Start(ctx)
	if err == nil {
		t.Error("应该返回文件不存在错误")
	}
}

func TestCertManager_CustomCert_MissingConfig(t *testing.T) {
	cfg := &CertConfig{
		Mode: CertCustom,
		// 缺少 CertFile 和 KeyFile
	}

	cm := NewCertManager(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := cm.Start(ctx)
	if err == nil {
		t.Error("缺少证书路径配置时应该返回错误")
	}
}

// =============================================================================
// 回调测试
// =============================================================================

func TestCertManager_Callbacks(t *testing.T) {
	tmpDir := t.TempDir()

	obtainedCalled := false
	obtainedDomains := []string{}
	errorCalled := false

	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Domains: []string{"localhost", "test.local"},
		},
	}

	cm := NewCertManager(cfg,
		WithOnCertObtained(func(domains []string) {
			obtainedCalled = true
			obtainedDomains = domains
		}),
		WithOnCertError(func(err error) {
			errorCalled = true
		}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := cm.Start(ctx); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer cm.Stop()

	if !obtainedCalled {
		t.Error("OnCertObtained 回调应该被调用")
	}

	if len(obtainedDomains) == 0 {
		t.Error("回调应该收到域名列表")
	}

	if errorCalled {
		t.Error("OnCertError 回调不应该被调用")
	}
}

func TestCertManager_WithLogLevel(t *testing.T) {
	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: t.TempDir(),
	}

	cm := NewCertManager(cfg, WithCertLogLevel(2))

	if cm.logLevel != 2 {
		t.Errorf("日志级别设置错误: %d", cm.logLevel)
	}
}

// =============================================================================
// ACME 验证隧道接口测试
// =============================================================================

type mockValidationTunnel struct {
	running   bool
	url       string
	startErr  error
	localPort int
	domain    string
}

func (m *mockValidationTunnel) StartValidationTunnel(ctx context.Context, localPort int, domain string) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.running = true
	m.localPort = localPort
	m.domain = domain
	m.url = "https://mock-tunnel.trycloudflare.com"
	return nil
}

func (m *mockValidationTunnel) StopValidationTunnel() error {
	m.running = false
	m.url = ""
	return nil
}

func (m *mockValidationTunnel) IsValidationTunnelRunning() bool {
	return m.running
}

func (m *mockValidationTunnel) GetValidationTunnelURL() string {
	return m.url
}

func TestCertManager_WithValidationTunnel(t *testing.T) {
	mock := &mockValidationTunnel{}

	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: t.TempDir(),
		ACME: ACMEConfig{
			Domains:                []string{"test.example.com"},
			UseTunnelForValidation: true,
		},
	}

	cm := NewCertManager(cfg, WithValidationTunnel(mock))

	if cm.validationTunnel == nil {
		t.Error("验证隧道应该被设置")
	}
}

func TestMockValidationTunnel(t *testing.T) {
	mock := &mockValidationTunnel{}

	ctx := context.Background()

	// 测试启动
	if err := mock.StartValidationTunnel(ctx, 8080, "test.example.com"); err != nil {
		t.Fatalf("启动失败: %v", err)
	}

	if !mock.IsValidationTunnelRunning() {
		t.Error("应该是运行状态")
	}

	if mock.GetValidationTunnelURL() == "" {
		t.Error("URL 不应为空")
	}

	if mock.localPort != 8080 {
		t.Errorf("端口错误: %d", mock.localPort)
	}

	if mock.domain != "test.example.com" {
		t.Errorf("域名错误: %s", mock.domain)
	}

	// 测试停止
	if err := mock.StopValidationTunnel(); err != nil {
		t.Fatalf("停止失败: %v", err)
	}

	if mock.IsValidationTunnelRunning() {
		t.Error("不应该是运行状态")
	}

	if mock.GetValidationTunnelURL() != "" {
		t.Error("URL 应该为空")
	}
}

func TestMockValidationTunnel_StartError(t *testing.T) {
	mock := &mockValidationTunnel{
		startErr: context.DeadlineExceeded,
	}

	ctx := context.Background()
	err := mock.StartValidationTunnel(ctx, 8080, "test.example.com")

	if err == nil {
		t.Error("应该返回错误")
	}

	if mock.IsValidationTunnelRunning() {
		t.Error("失败后不应该是运行状态")
	}
}

// =============================================================================
// TunnelManager 实现 ACMEValidationTunnel 接口测试
// =============================================================================

func TestTunnelManager_ImplementsACMEValidationTunnel(t *testing.T) {
	tm := NewTunnelManager(nil)

	// 验证 TunnelManager 实现了 ACMEValidationTunnel 接口
	var _ ACMEValidationTunnel = tm
}

func TestTunnelManager_ValidationTunnelMethods(t *testing.T) {
	tm := NewTunnelManager(nil)

	// 未启动时
	if tm.IsValidationTunnelRunning() {
		t.Error("验证隧道不应该在运行")
	}

	if tm.GetValidationTunnelURL() != "" {
		t.Error("验证隧道 URL 应该为空")
	}

	// 停止不存在的隧道不应该出错
	if err := tm.StopValidationTunnel(); err != nil {
		t.Errorf("停止不存在的验证隧道不应出错: %v", err)
	}
}

// =============================================================================
// 辅助函数测试
// =============================================================================

func TestExtractDomainFromURL(t *testing.T) {
	testCases := []struct {
		url      string
		expected string
	}{
		{"https://example.com", "example.com"},
		{"http://test.example.com/path", "test.example.com"},
		{"https://sub.domain.com:8080/", "sub.domain.com"},
		{"example.com", "example.com"},
		{"https://a.b.c.d.example.com/api/v1", "a.b.c.d.example.com"},
		{"http://localhost:3000", "localhost"},
	}

	for _, tc := range testCases {
		result := extractDomainFromURL(tc.url)
		if result != tc.expected {
			t.Errorf("extractDomainFromURL(%s) = %s, 期望 %s",
				tc.url, result, tc.expected)
		}
	}
}

func TestIpToDomain(t *testing.T) {
	testCases := []struct {
		ip       string
		expected string
	}{
		{"192.168.1.1", "192-168-1-1"},
		{"10.0.0.1", "10-0-0-1"},
		{"127.0.0.1", "127-0-0-1"},
		{"8.8.8.8", "8-8-8-8"},
	}

	for _, tc := range testCases {
		result := ipToDomain(tc.ip)
		if result != tc.expected {
			t.Errorf("ipToDomain(%s) = %s, 期望 %s",
				tc.ip, result, tc.expected)
		}
	}
}

// =============================================================================
// 证书有效性测试
// =============================================================================

func TestCertManager_IsCertValid(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Domains: []string{"localhost"},
		},
	}

	cm := NewCertManager(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := cm.Start(ctx); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer cm.Stop()

	certPath, _ := cm.GetCertPaths()

	// 证书应该在 1 小时后仍然有效
	if !cm.isCertValid(certPath, time.Hour) {
		t.Error("证书应该在 1 小时后仍然有效")
	}

	// 证书应该在 30 天后仍然有效
	if !cm.isCertValid(certPath, 30*24*time.Hour) {
		t.Error("证书应该在 30 天后仍然有效")
	}

	// 证书不应该在 400 天后仍然有效（自签名证书有效期 1 年）
	if cm.isCertValid(certPath, 400*24*time.Hour) {
		t.Error("证书不应该在 400 天后仍然有效")
	}
}

func TestCertManager_IsCertValid_NonExistent(t *testing.T) {
	cm := NewCertManager(nil)

	if cm.isCertValid("/nonexistent/path.crt", time.Hour) {
		t.Error("不存在的证书不应该有效")
	}
}

func TestCertManager_IsCertValid_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	invalidCertPath := filepath.Join(tmpDir, "invalid.crt")

	// 写入无效的 PEM 数据
	os.WriteFile(invalidCertPath, []byte("invalid pem data"), 0600)

	cm := NewCertManager(nil)

	if cm.isCertValid(invalidCertPath, time.Hour) {
		t.Error("无效的 PEM 不应该有效")
	}
}

// =============================================================================
// WaitForCert 测试
// =============================================================================

func TestCertManager_WaitForCert_Timeout(t *testing.T) {
	cfg := &CertConfig{
		Mode:    CertACME, // ACME 模式不会立即完成
		CertDir: t.TempDir(),
		ACME: ACMEConfig{
			Provider: ACMELetsEncryptStaging,
			Email:    "test@example.com",
			Domains:  []string{"nonexistent.example.com"},
		},
	}

	cm := NewCertManager(cfg)
	cm.ctx, cm.cancel = context.WithCancel(context.Background())
	defer cm.cancel()

	// 不启动，直接等待应该超时
	err := cm.WaitForCert(100 * time.Millisecond)
	if err == nil {
		t.Error("应该返回超时错误")
	}
}

func TestCertManager_WaitForCert_ContextCanceled(t *testing.T) {
	cfg := &CertConfig{
		Mode:    CertACME,
		CertDir: t.TempDir(),
		ACME: ACMEConfig{
			Email:   "test@example.com",
			Domains: []string{"test.example.com"},
		},
	}

	cm := NewCertManager(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	cm.ctx = ctx
	cm.cancel = cancel

	// 立即取消
	cancel()

	err := cm.WaitForCert(5 * time.Second)
	if err == nil {
		t.Error("应该返回 context 取消错误")
	}
}

// =============================================================================
// 集成测试
// =============================================================================

func TestTunnelManager_DirectMode_WithCert(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &TunnelConfig{
		Enabled:    true,
		Mode:       ModeDirect,
		DomainMode: DomainCustom,
		Domain:     "localhost",
		Cert: CertConfig{
			Mode:    CertSelfSigned,
			CertDir: tmpDir,
			ACME: ACMEConfig{
				Domains: []string{"localhost"},
			},
		},
		LocalAddr: "127.0.0.1",
		LocalPort: 54321,
	}

	tm := NewTunnelManager(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := tm.Start(ctx); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer tm.Stop()

	// 验证证书管理器被创建
	if tm.GetCertManager() == nil {
		t.Error("证书管理器应该被创建")
	}

	// 验证证书路径
	certPath, keyPath := tm.GetCertPaths()
	if certPath == "" || keyPath == "" {
		t.Error("证书路径不应为空")
	}

	// 验证隧道 URL
	tunnelURL := tm.GetTunnelURL()
	if tunnelURL == "" {
		t.Error("隧道 URL 不应为空")
	}

	// 验证运行状态
	if !tm.IsRunning() {
		t.Error("隧道应该是运行状态")
	}
}

func TestTunnelManager_DirectMode_WithSelfSignedCert(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过集成测试")
	}

	tmpDir := t.TempDir()

	cfg := &TunnelConfig{
		Enabled:    true,
		Mode:       ModeDirect,
		DomainMode: DomainCustom,
		Domain:     "localhost",
		Cert: CertConfig{
			Mode:    CertSelfSigned,
			CertDir: tmpDir,
			ACME: ACMEConfig{
				Domains: []string{"localhost"},
			},
		},
		LocalAddr: "127.0.0.1",
		LocalPort: 54321,
		Protocol:  "https",
	}

	tm := NewTunnelManager(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := tm.Start(ctx); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer tm.Stop()

	// 验证证书管理器被创建
	if tm.GetCertManager() == nil {
		t.Error("证书管理器应该被创建")
	}

	// 验证证书路径
	certPath, keyPath := tm.GetCertPaths()
	if certPath == "" || keyPath == "" {
		t.Error("证书路径不应为空")
	}

	// 验证隧道 URL
	tunnelURL := tm.GetTunnelURL()
	if tunnelURL == "" {
		t.Error("隧道 URL 不应为空")
	}

	// 验证运行状态
	if !tm.IsRunning() {
		t.Error("隧道应该是运行状态")
	}

	// 验证状态信息
	status := tm.GetStatus()
	if status["running"] != true {
		t.Error("状态应该显示运行中")
	}

	if _, ok := status["cert"]; !ok {
		t.Error("状态应该包含证书信息")
	}
}

// =============================================================================
// GetStatus 测试
// =============================================================================

func TestTunnelManager_GetStatus_NotRunning(t *testing.T) {
	tm := NewTunnelManager(nil)

	status := tm.GetStatus()

	if status["running"] != false {
		t.Error("状态应该显示未运行")
	}

	if _, ok := status["uptime"]; ok {
		t.Error("未运行时不应有 uptime")
	}
}

func TestTunnelManager_GetStatus_Running(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &TunnelConfig{
		Enabled:    true,
		Mode:       ModeDirect,
		DomainMode: DomainCustom,
		Domain:     "localhost",
		Cert: CertConfig{
			Mode:    CertSelfSigned,
			CertDir: tmpDir,
		},
		LocalAddr: "127.0.0.1",
		LocalPort: 54321,
	}

	tm := NewTunnelManager(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := tm.Start(ctx); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer tm.Stop()

	status := tm.GetStatus()

	if status["running"] != true {
		t.Error("状态应该显示运行中")
	}

	if _, ok := status["uptime"]; !ok {
		t.Error("运行时应有 uptime")
	}

	if status["mode"] != string(ModeDirect) {
		t.Errorf("模式错误: %v", status["mode"])
	}

	if status["domain_mode"] != string(DomainCustom) {
		t.Errorf("域名模式错误: %v", status["domain_mode"])
	}
}
