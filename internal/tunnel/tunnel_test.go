

// =============================================================================
// 文件: internal/tunnel/tunnel_test.go
// 描述: 隧道管理器单元测试
// =============================================================================
package tunnel

import (
	"context"
	"testing"
	"time"

	"github.com/mrcgq/211/internal/config"
)

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

func TestTunnelManager_FromConfigTunnelConfig(t *testing.T) {
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

	if tc.Mode != ModeFixedTunnel {
		t.Errorf("模式转换错误: %s", tc.Mode)
	}

	if tc.DomainMode != DomainCustom {
		t.Errorf("域名模式转换错误: %s", tc.DomainMode)
	}

	if tc.Cert.Mode != CertSelfSigned {
		t.Errorf("证书模式转换错误: %s", tc.Cert.Mode)
	}

	if tc.Domain != "api.example.com" {
		t.Errorf("域名转换错误: %s", tc.Domain)
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

func TestTunnelManager_IsRunning(t *testing.T) {
	tm := NewTunnelManager(nil)

	if tm.IsRunning() {
		t.Error("新创建的管理器不应该是运行状态")
	}
}

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
}

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
// 域名设置测试（模拟）
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



