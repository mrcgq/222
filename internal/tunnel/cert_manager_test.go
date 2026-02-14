


// =============================================================================
// 文件: internal/tunnel/cert_manager_test.go
// 描述: 证书管理器单元测试
// =============================================================================
package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertManager_SelfSigned(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Domains: []string{"localhost", "test.local"},
		},
	}

	cm := NewCertManager(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := cm.Start(ctx); err != nil {
		t.Fatalf("启动证书管理器失败: %v", err)
	}
	defer cm.Stop()

	// 验证证书文件存在
	certPath, keyPath := cm.GetCertPaths()
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("证书文件不存在: %s", certPath)
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("私钥文件不存在: %s", keyPath)
	}

	// 验证可以获取证书
	hello := &tls.ClientHelloInfo{
		ServerName: "localhost",
	}
	cert, err := cm.GetCertificate(hello)
	if err != nil {
		t.Fatalf("获取证书失败: %v", err)
	}
	if cert == nil {
		t.Fatal("证书为空")
	}

	// 验证 TLS 配置
	tlsConfig := cm.GetTLSConfig()
	if tlsConfig == nil {
		t.Fatal("TLS 配置为空")
	}
	if tlsConfig.GetCertificate == nil {
		t.Error("TLS 配置缺少 GetCertificate")
	}
}

func TestCertManager_SelfSignedCertContent(t *testing.T) {
	tmpDir := t.TempDir()

	domains := []string{"example.com", "*.example.com", "localhost"}

	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Domains: domains,
		},
	}

	cm := NewCertManager(cfg)
	ctx := context.Background()

	if err := cm.Start(ctx); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer cm.Stop()

	certPath, _ := cm.GetCertPaths()

	// 读取并解析证书
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("PEM 解码失败")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("解析证书失败: %v", err)
	}

	// 验证 DNS 名称
	for _, domain := range domains {
		found := false
		for _, san := range cert.DNSNames {
			if san == domain {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("证书缺少域名: %s", domain)
		}
	}

	// 验证有效期
	if cert.NotBefore.After(time.Now()) {
		t.Error("证书尚未生效")
	}
	if cert.NotAfter.Before(time.Now()) {
		t.Error("证书已过期")
	}

	// 验证密钥用途
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("证书缺少 DigitalSignature 密钥用途")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("证书缺少 KeyEncipherment 密钥用途")
	}

	// 验证扩展密钥用途
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		t.Error("证书缺少 ServerAuth 扩展密钥用途")
	}
}

func TestCertManager_CertValidity(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Domains: []string{"test.example.com"},
		},
	}

	cm := NewCertManager(cfg)

	ctx := context.Background()
	if err := cm.Start(ctx); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer cm.Stop()

	certPath, _ := cm.GetCertPaths()

	// 检查证书有效性
	if !cm.isCertValid(certPath, 7*24*time.Hour) {
		t.Error("新生成的证书应该有效")
	}

	// 检查长期有效性
	if !cm.isCertValid(certPath, 300*24*time.Hour) {
		t.Error("证书应该至少有效 300 天")
	}

	// 检查不存在的证书
	if cm.isCertValid("/nonexistent/cert.pem", time.Hour) {
		t.Error("不存在的证书不应该被认为有效")
	}
}

func TestCertManager_CustomCert(t *testing.T) {
	tmpDir := t.TempDir()

	// 先生成一个自签名证书用于测试
	selfSignedCfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Domains: []string{"custom.example.com"},
		},
	}

	cm1 := NewCertManager(selfSignedCfg)
	ctx := context.Background()
	if err := cm1.Start(ctx); err != nil {
		t.Fatalf("生成自签名证书失败: %v", err)
	}
	certPath, keyPath := cm1.GetCertPaths()
	cm1.Stop()

	// 使用自定义证书模式加载
	customCfg := &CertConfig{
		Mode:     CertCustom,
		CertFile: certPath,
		KeyFile:  keyPath,
		CertDir:  tmpDir,
	}

	cm2 := NewCertManager(customCfg)
	if err := cm2.Start(ctx); err != nil {
		t.Fatalf("加载自定义证书失败: %v", err)
	}
	defer cm2.Stop()

	// 验证可以获取证书
	cert, err := cm2.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "custom.example.com",
	})
	if err != nil {
		t.Fatalf("获取证书失败: %v", err)
	}
	if cert == nil {
		t.Fatal("证书为空")
	}
}

func TestCertManager_InvalidCustomCert(t *testing.T) {
	tmpDir := t.TempDir()

	// 测试不存在的证书文件
	cfg := &CertConfig{
		Mode:     CertCustom,
		CertFile: filepath.Join(tmpDir, "nonexistent.crt"),
		KeyFile:  filepath.Join(tmpDir, "nonexistent.key"),
		CertDir:  tmpDir,
	}

	cm := NewCertManager(cfg)
	ctx := context.Background()

	err := cm.Start(ctx)
	if err == nil {
		cm.Stop()
		t.Fatal("应该返回错误")
	}
}

func TestCertManager_MissingCustomCertConfig(t *testing.T) {
	tmpDir := t.TempDir()

	// 测试缺少配置
	cfg := &CertConfig{
		Mode:    CertCustom,
		CertDir: tmpDir,
		// CertFile 和 KeyFile 都为空
	}

	cm := NewCertManager(cfg)
	ctx := context.Background()

	err := cm.Start(ctx)
	if err == nil {
		cm.Stop()
		t.Fatal("缺少证书路径应该返回错误")
	}
}

func TestCertManager_AutoMode(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CertConfig{
		Mode:    CertAuto,
		CertDir: tmpDir,
	}

	cm := NewCertManager(cfg)
	ctx := context.Background()

	// Auto 模式应该直接成功（用于 Cloudflare 隧道）
	if err := cm.Start(ctx); err != nil {
		t.Fatalf("Auto 模式启动失败: %v", err)
	}
	defer cm.Stop()
}

func TestCertManager_ReuseExistingCert(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Domains: []string{"reuse.example.com"},
		},
	}

	// 第一次创建
	cm1 := NewCertManager(cfg)
	ctx := context.Background()
	if err := cm1.Start(ctx); err != nil {
		t.Fatalf("第一次启动失败: %v", err)
	}

	certPath1, _ := cm1.GetCertPaths()
	stat1, _ := os.Stat(certPath1)
	modTime1 := stat1.ModTime()
	cm1.Stop()

	// 等待一秒确保时间戳不同
	time.Sleep(time.Second)

	// 第二次使用相同配置
	cm2 := NewCertManager(cfg)
	if err := cm2.Start(ctx); err != nil {
		t.Fatalf("第二次启动失败: %v", err)
	}
	defer cm2.Stop()

	certPath2, _ := cm2.GetCertPaths()
	stat2, _ := os.Stat(certPath2)
	modTime2 := stat2.ModTime()

	// 证书应该被复用（修改时间相同）
	if !modTime1.Equal(modTime2) {
		t.Error("证书应该被复用而不是重新生成")
	}
}

func TestCertManager_TLSServer(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Domains: []string{"localhost"},
		},
	}

	cm := NewCertManager(cfg)
	ctx := context.Background()

	if err := cm.Start(ctx); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer cm.Stop()

	// 创建测试服务器
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	server.TLS = cm.GetTLSConfig()
	server.StartTLS()
	defer server.Close()

	// 创建忽略证书验证的客户端（因为是自签名）
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("状态码错误: %d", resp.StatusCode)
	}
}

func TestDefaultCertConfig(t *testing.T) {
	cfg := DefaultCertConfig()

	if cfg.Mode != CertAuto {
		t.Errorf("默认模式应该是 auto, 实际: %s", cfg.Mode)
	}

	if cfg.ACME.Provider != ACMELetsEncrypt {
		t.Errorf("默认 ACME 提供商应该是 letsencrypt, 实际: %s", cfg.ACME.Provider)
	}

	if !cfg.ACME.AcceptTOS {
		t.Error("默认应该接受服务条款")
	}

	if cfg.ACME.HTTPPort != 80 {
		t.Errorf("默认 HTTP 端口应该是 80, 实际: %d", cfg.ACME.HTTPPort)
	}

	if cfg.ACME.TLSPort != 443 {
		t.Errorf("默认 TLS 端口应该是 443, 实际: %d", cfg.ACME.TLSPort)
	}
}

func TestACMEDirectoryURLs(t *testing.T) {
	testCases := []struct {
		provider    ACMEProvider
		expectedURL string
	}{
		{ACMELetsEncrypt, LetsEncryptProductionURL},
		{ACMELetsEncryptStaging, LetsEncryptStagingURL},
		{ACMEZeroSSL, ZeroSSLProductionURL},
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

		if url != tc.expectedURL {
			t.Errorf("Provider %s: 期望 URL %s, 实际 %s",
				tc.provider, tc.expectedURL, url)
		}
	}
}

func TestCertManager_ConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Domains: []string{"concurrent.example.com"},
		},
	}

	cm := NewCertManager(cfg)
	ctx := context.Background()

	if err := cm.Start(ctx); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer cm.Stop()

	// 并发访问证书
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_, err := cm.GetCertificate(&tls.ClientHelloInfo{
					ServerName: "concurrent.example.com",
				})
				if err != nil {
					t.Errorf("并发获取证书失败: %v", err)
				}
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// =============================================================================
// Benchmark 测试
// =============================================================================

func BenchmarkCertManager_GetCertificate(b *testing.B) {
	tmpDir := b.TempDir()

	cfg := &CertConfig{
		Mode:    CertSelfSigned,
		CertDir: tmpDir,
		ACME: ACMEConfig{
			Domains: []string{"bench.example.com"},
		},
	}

	cm := NewCertManager(cfg)
	ctx := context.Background()
	cm.Start(ctx)
	defer cm.Stop()

	hello := &tls.ClientHelloInfo{
		ServerName: "bench.example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cm.GetCertificate(hello)
	}
}

func BenchmarkCertManager_GenerateSelfSigned(b *testing.B) {
	for i := 0; i < b.N; i++ {
		tmpDir := b.TempDir()

		cfg := &CertConfig{
			Mode:    CertSelfSigned,
			CertDir: tmpDir,
			ACME: ACMEConfig{
				Domains: []string{"bench.example.com"},
			},
		}

		cm := NewCertManager(cfg)
		ctx := context.Background()
		cm.Start(ctx)
		cm.Stop()
	}
}
