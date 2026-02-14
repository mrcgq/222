

// =============================================================================
// 文件: internal/tunnel/integration_test.go
// 描述: 隧道模块集成测试
// =============================================================================
//go:build integration

package tunnel

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// 集成测试需要使用 -tags=integration 运行
// go test -tags=integration -v ./internal/tunnel/...

func TestIntegration_TempTunnel(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过集成测试")
	}

	cfg := &TunnelConfig{
		Enabled:    true,
		Mode:       ModeTempTunnel,
		DomainMode: DomainAuto,
		Cert: CertConfig{
			Mode: CertAuto,
		},
		LocalAddr: "127.0.0.1",
		LocalPort: 8080,
		Protocol:  "http",
		LogLevel:  "debug",
	}

	tm := NewTunnelManager(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// 启动本地 HTTP 服务
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	go server.ListenAndServe()
	defer server.Shutdown(context.Background())

	// 等待服务启动
	time.Sleep(time.Second)

	// 启动隧道
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("启动隧道失败: %v", err)
	}
	defer tm.Stop()

	// 等待隧道就绪
	time.Sleep(5 * time.Second)

	// 获取隧道 URL
	tunnelURL := tm.GetTunnelURL()
	if tunnelURL == "" {
		t.Fatal("隧道 URL 为空")
	}

	t.Logf("隧道 URL: %s", tunnelURL)

	// 通过隧道访问
	resp, err := http.Get(tunnelURL + "/health")
	if err != nil {
		t.Fatalf("通过隧道访问失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("状态码错误: %d", resp.StatusCode)
	}
}

func TestIntegration_DirectMode_HTTPS(t *testing.T) {
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
		LocalPort: 8443,
		Protocol:  "https",
		LogLevel:  "debug",
	}

	tm := NewTunnelManager(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// 启动隧道（这会生成证书）
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer tm.Stop()

	// 获取 TLS 配置
	certManager := tm.GetCertManager()
	if certManager == nil {
		t.Fatal("证书管理器为空")
	}

	tlsConfig := certManager.GetTLSConfig()
	if tlsConfig == nil {
		t.Fatal("TLS 配置为空")
	}

	// 启动 HTTPS 服务
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("HTTPS OK"))
	})

	server := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	certPath, keyPath := certManager.GetCertPaths()

	go func() {
		if err := server.ListenAndServeTLS(certPath, keyPath); err != http.ErrServerClosed {
			t.Logf("HTTPS 服务错误: %v", err)
		}
	}()
	defer server.Shutdown(context.Background())

	// 等待服务启动
	time.Sleep(2 * time.Second)

	// 使用自定义客户端（忽略证书验证）
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Get("https://localhost:8443/")
	if err != nil {
		t.Fatalf("HTTPS 请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("状态码错误: %d", resp.StatusCode)
	}
}





