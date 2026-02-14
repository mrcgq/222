


// =============================================================================
// 文件: internal/config/config_test.go
// 描述: 配置鲁棒性测试 - 确保错误配置能在启动前被拦截
// =============================================================================
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// 默认值测试
// =============================================================================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	t.Run("基础配置默认值", func(t *testing.T) {
		if cfg.Listen != ":54321" {
			t.Errorf("Listen 默认值错误: got %s, want :54321", cfg.Listen)
		}
		if cfg.TimeWindow != 30 {
			t.Errorf("TimeWindow 默认值错误: got %d, want 30", cfg.TimeWindow)
		}
		if cfg.LogLevel != "info" {
			t.Errorf("LogLevel 默认值错误: got %s, want info", cfg.LogLevel)
		}
		if cfg.Mode != "auto" {
			t.Errorf("Mode 默认值错误: got %s, want auto", cfg.Mode)
		}
	})

	t.Run("ARQ配置默认值", func(t *testing.T) {
		if !cfg.ARQ.Enabled {
			t.Error("ARQ.Enabled 默认应为 true")
		}
		if cfg.ARQ.WindowSize != 256 {
			t.Errorf("ARQ.WindowSize 默认值错误: got %d, want 256", cfg.ARQ.WindowSize)
		}
		if cfg.ARQ.MaxRetries != 10 {
			t.Errorf("ARQ.MaxRetries 默认值错误: got %d, want 10", cfg.ARQ.MaxRetries)
		}
		if cfg.ARQ.RTOMinMs != 100 {
			t.Errorf("ARQ.RTOMinMs 默认值错误: got %d, want 100", cfg.ARQ.RTOMinMs)
		}
		if cfg.ARQ.RTOMaxMs != 10000 {
			t.Errorf("ARQ.RTOMaxMs 默认值错误: got %d, want 10000", cfg.ARQ.RTOMaxMs)
		}
		if !cfg.ARQ.EnableSACK {
			t.Error("ARQ.EnableSACK 默认应为 true")
		}
		if !cfg.ARQ.EnableTimestamp {
			t.Error("ARQ.EnableTimestamp 默认应为 true")
		}
	})

	t.Run("Hysteria2配置默认值", func(t *testing.T) {
		if !cfg.Hysteria2.Enabled {
			t.Error("Hysteria2.Enabled 默认应为 true")
		}
		if cfg.Hysteria2.UpMbps != 100 {
			t.Errorf("Hysteria2.UpMbps 默认值错误: got %d, want 100", cfg.Hysteria2.UpMbps)
		}
		if cfg.Hysteria2.DownMbps != 100 {
			t.Errorf("Hysteria2.DownMbps 默认值错误: got %d, want 100", cfg.Hysteria2.DownMbps)
		}
		if cfg.Hysteria2.InitialWindow != 32 {
			t.Errorf("Hysteria2.InitialWindow 默认值错误: got %d, want 32", cfg.Hysteria2.InitialWindow)
		}
		if cfg.Hysteria2.MaxWindow != 512 {
			t.Errorf("Hysteria2.MaxWindow 默认值错误: got %d, want 512", cfg.Hysteria2.MaxWindow)
		}
		if cfg.Hysteria2.LossThreshold != 0.1 {
			t.Errorf("Hysteria2.LossThreshold 默认值错误: got %f, want 0.1", cfg.Hysteria2.LossThreshold)
		}
	})

	t.Run("FakeTCP配置默认值", func(t *testing.T) {
		if cfg.FakeTCP.Enabled {
			t.Error("FakeTCP.Enabled 默认应为 false")
		}
		if cfg.FakeTCP.Listen != ":54322" {
			t.Errorf("FakeTCP.Listen 默认值错误: got %s, want :54322", cfg.FakeTCP.Listen)
		}
		if cfg.FakeTCP.UseEBPF {
			t.Error("FakeTCP.UseEBPF 默认应为 false")
		}
	})

	t.Run("WebSocket配置默认值", func(t *testing.T) {
		if cfg.WebSocket.Enabled {
			t.Error("WebSocket.Enabled 默认应为 false")
		}
		if cfg.WebSocket.Listen != ":54323" {
			t.Errorf("WebSocket.Listen 默认值错误: got %s, want :54323", cfg.WebSocket.Listen)
		}
		if cfg.WebSocket.Path != "/ws" {
			t.Errorf("WebSocket.Path 默认值错误: got %s, want /ws", cfg.WebSocket.Path)
		}
	})

	t.Run("EBPF配置默认值", func(t *testing.T) {
		if cfg.EBPF.Enabled {
			t.Error("EBPF.Enabled 默认应为 false")
		}
		if cfg.EBPF.XDPMode != "generic" {
			t.Errorf("EBPF.XDPMode 默认值错误: got %s, want generic", cfg.EBPF.XDPMode)
		}
		if cfg.EBPF.MapSize != 65536 {
			t.Errorf("EBPF.MapSize 默认值错误: got %d, want 65536", cfg.EBPF.MapSize)
		}
	})

	t.Run("Switcher配置默认值", func(t *testing.T) {
		if !cfg.Switcher.Enabled {
			t.Error("Switcher.Enabled 默认应为 true")
		}
		if cfg.Switcher.CheckInterval != 1000 {
			t.Errorf("Switcher.CheckInterval 默认值错误: got %d, want 1000", cfg.Switcher.CheckInterval)
		}
		if cfg.Switcher.FailThreshold != 3 {
			t.Errorf("Switcher.FailThreshold 默认值错误: got %d, want 3", cfg.Switcher.FailThreshold)
		}
		if cfg.Switcher.RecoverThreshold != 5 {
			t.Errorf("Switcher.RecoverThreshold 默认值错误: got %d, want 5", cfg.Switcher.RecoverThreshold)
		}
		expectedPriority := []string{"ebpf", "faketcp", "udp", "websocket"}
		if len(cfg.Switcher.Priority) != len(expectedPriority) {
			t.Errorf("Switcher.Priority 长度错误: got %d, want %d", len(cfg.Switcher.Priority), len(expectedPriority))
		}
		for i, p := range expectedPriority {
			if i < len(cfg.Switcher.Priority) && cfg.Switcher.Priority[i] != p {
				t.Errorf("Switcher.Priority[%d] 错误: got %s, want %s", i, cfg.Switcher.Priority[i], p)
			}
		}
	})

	t.Run("Metrics配置默认值", func(t *testing.T) {
		if !cfg.Metrics.Enabled {
			t.Error("Metrics.Enabled 默认应为 true")
		}
		if cfg.Metrics.Listen != ":9100" {
			t.Errorf("Metrics.Listen 默认值错误: got %s, want :9100", cfg.Metrics.Listen)
		}
		if cfg.Metrics.Path != "/metrics" {
			t.Errorf("Metrics.Path 默认值错误: got %s, want /metrics", cfg.Metrics.Path)
		}
		if cfg.Metrics.HealthPath != "/health" {
			t.Errorf("Metrics.HealthPath 默认值错误: got %s, want /health", cfg.Metrics.HealthPath)
		}
	})

	t.Run("Tunnel配置默认值", func(t *testing.T) {
		if cfg.Tunnel.Enabled {
			t.Error("Tunnel.Enabled 默认应为 false")
		}
		if cfg.Tunnel.Mode != "temp" {
			t.Errorf("Tunnel.Mode 默认值错误: got %s, want temp", cfg.Tunnel.Mode)
		}
		if cfg.Tunnel.DomainMode != "auto" {
			t.Errorf("Tunnel.DomainMode 默认值错误: got %s, want auto", cfg.Tunnel.DomainMode)
		}
		if cfg.Tunnel.CertMode != "auto" {
			t.Errorf("Tunnel.CertMode 默认值错误: got %s, want auto", cfg.Tunnel.CertMode)
		}
		if cfg.Tunnel.LocalAddr != "127.0.0.1" {
			t.Errorf("Tunnel.LocalAddr 默认值错误: got %s, want 127.0.0.1", cfg.Tunnel.LocalAddr)
		}
		if cfg.Tunnel.Protocol != "http" {
			t.Errorf("Tunnel.Protocol 默认值错误: got %s, want http", cfg.Tunnel.Protocol)
		}
	})
}

// =============================================================================
// 端口冲突检测测试
// =============================================================================

func TestPortConflictDetection(t *testing.T) {
	t.Run("UDP与FakeTCP端口冲突", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.Listen = ":54321"
		cfg.FakeTCP.Enabled = true
		cfg.FakeTCP.Listen = ":54321" // 与主端口冲突

		err := cfg.Validate()
		if err == nil {
			t.Error("应该检测到端口冲突")
		}
		if !strings.Contains(err.Error(), "冲突") {
			t.Errorf("错误信息应包含'冲突': %v", err)
		}
	})

	t.Run("UDP与WebSocket端口冲突", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.Listen = ":54321"
		cfg.WebSocket.Enabled = true
		cfg.WebSocket.Listen = ":54321" // 与主端口冲突

		err := cfg.Validate()
		if err == nil {
			t.Error("应该检测到端口冲突")
		}
		if !strings.Contains(err.Error(), "冲突") {
			t.Errorf("错误信息应包含'冲突': %v", err)
		}
	})

	t.Run("FakeTCP与WebSocket端口冲突", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.Listen = ":54321"
		cfg.FakeTCP.Enabled = true
		cfg.FakeTCP.Listen = ":54322"
		cfg.WebSocket.Enabled = true
		cfg.WebSocket.Listen = ":54322" // 与FakeTCP冲突

		err := cfg.Validate()
		if err == nil {
			t.Error("应该检测到端口冲突")
		}
		if !strings.Contains(err.Error(), "冲突") {
			t.Errorf("错误信息应包含'冲突': %v", err)
		}
	})

	t.Run("Metrics与主端口冲突", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.Listen = ":9100"
		cfg.Metrics.Enabled = true
		cfg.Metrics.Listen = ":9100" // 与主端口冲突

		err := cfg.Validate()
		if err == nil {
			t.Error("应该检测到端口冲突")
		}
		if !strings.Contains(err.Error(), "冲突") {
			t.Errorf("错误信息应包含'冲突': %v", err)
		}
	})

	t.Run("无端口冲突情况", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.Listen = ":54321"
		cfg.FakeTCP.Enabled = true
		cfg.FakeTCP.Listen = ":54322"
		cfg.WebSocket.Enabled = true
		cfg.WebSocket.Listen = ":54323"
		cfg.Metrics.Enabled = true
		cfg.Metrics.Listen = ":9100"

		err := cfg.Validate()
		if err != nil {
			t.Errorf("不应该有冲突错误: %v", err)
		}
	})

	t.Run("禁用模块不检测冲突", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.Listen = ":54321"
		cfg.FakeTCP.Enabled = false      // 禁用
		cfg.FakeTCP.Listen = ":54321"    // 虽然端口相同
		cfg.WebSocket.Enabled = false    // 禁用
		cfg.WebSocket.Listen = ":54321"  // 虽然端口相同

		err := cfg.Validate()
		if err != nil {
			t.Errorf("禁用模块不应检测冲突: %v", err)
		}
	})
}

// =============================================================================
// ARQ边界值测试
// =============================================================================

func TestARQBoundaryValues(t *testing.T) {
	t.Run("窗口大小为0", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.ARQ.Enabled = true
		cfg.ARQ.WindowSize = 0

		err := cfg.Validate()
		if err == nil {
			t.Error("窗口大小为0应该报错")
		}
		if !strings.Contains(err.Error(), "window_size") {
			t.Errorf("错误信息应包含'window_size': %v", err)
		}
	})

	t.Run("窗口大小过大_10000", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.ARQ.Enabled = true
		cfg.ARQ.WindowSize = 10000

		err := cfg.Validate()
		if err == nil {
			t.Error("窗口大小为10000应该报错")
		}
		if !strings.Contains(err.Error(), "window_size") {
			t.Errorf("错误信息应包含'window_size': %v", err)
		}
	})

	t.Run("窗口大小边界值_16", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.ARQ.Enabled = true
		cfg.ARQ.WindowSize = 16 // 最小合法值

		err := cfg.Validate()
		if err != nil {
			t.Errorf("窗口大小16应该合法: %v", err)
		}
	})

	t.Run("窗口大小边界值_4096", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.ARQ.Enabled = true
		cfg.ARQ.WindowSize = 4096 // 最大合法值

		err := cfg.Validate()
		if err != nil {
			t.Errorf("窗口大小4096应该合法: %v", err)
		}
	})

	t.Run("窗口大小边界值_15_非法", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.ARQ.Enabled = true
		cfg.ARQ.WindowSize = 15 // 略低于最小值

		err := cfg.Validate()
		if err == nil {
			t.Error("窗口大小15应该报错")
		}
	})

	t.Run("窗口大小边界值_4097_非法", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.ARQ.Enabled = true
		cfg.ARQ.WindowSize = 4097 // 略高于最大值

		err := cfg.Validate()
		if err == nil {
			t.Error("窗口大小4097应该报错")
		}
	})

	t.Run("最大重试次数为0", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.ARQ.Enabled = true
		cfg.ARQ.MaxRetries = 0

		err := cfg.Validate()
		if err == nil {
			t.Error("最大重试次数为0应该报错")
		}
		if !strings.Contains(err.Error(), "max_retries") {
			t.Errorf("错误信息应包含'max_retries': %v", err)
		}
	})

	t.Run("最大重试次数过大_100", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.ARQ.Enabled = true
		cfg.ARQ.MaxRetries = 100

		err := cfg.Validate()
		if err == nil {
			t.Error("最大重试次数为100应该报错")
		}
		if !strings.Contains(err.Error(), "max_retries") {
			t.Errorf("错误信息应包含'max_retries': %v", err)
		}
	})

	t.Run("最大重试次数边界值_1", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.ARQ.Enabled = true
		cfg.ARQ.MaxRetries = 1 // 最小合法值

		err := cfg.Validate()
		if err != nil {
			t.Errorf("最大重试次数1应该合法: %v", err)
		}
	})

	t.Run("最大重试次数边界值_50", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.ARQ.Enabled = true
		cfg.ARQ.MaxRetries = 50 // 最大合法值

		err := cfg.Validate()
		if err != nil {
			t.Errorf("最大重试次数50应该合法: %v", err)
		}
	})

	t.Run("禁用ARQ时不检查参数", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.ARQ.Enabled = false
		cfg.ARQ.WindowSize = 0      // 非法值
		cfg.ARQ.MaxRetries = 10000  // 非法值

		err := cfg.Validate()
		if err != nil {
			t.Errorf("禁用ARQ时不应检查参数: %v", err)
		}
	})
}

// =============================================================================
// PSK验证测试
// =============================================================================

func TestPSKValidation(t *testing.T) {
	t.Run("PSK为空", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = ""

		err := cfg.Validate()
		if err == nil {
			t.Error("PSK为空应该报错")
		}
		if !strings.Contains(err.Error(), "psk") {
			t.Errorf("错误信息应包含'psk': %v", err)
		}
	})

	t.Run("PSK有效", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "valid-psk-12345"

		err := cfg.Validate()
		if err != nil {
			t.Errorf("有效PSK不应报错: %v", err)
		}
	})
}

// =============================================================================
// TimeWindow验证测试
// =============================================================================

func TestTimeWindowValidation(t *testing.T) {
	t.Run("TimeWindow为0", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.TimeWindow = 0

		err := cfg.Validate()
		if err == nil {
			t.Error("TimeWindow为0应该报错")
		}
		if !strings.Contains(err.Error(), "time_window") {
			t.Errorf("错误信息应包含'time_window': %v", err)
		}
	})

	t.Run("TimeWindow过大_500", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.TimeWindow = 500

		err := cfg.Validate()
		if err == nil {
			t.Error("TimeWindow为500应该报错")
		}
		if !strings.Contains(err.Error(), "time_window") {
			t.Errorf("错误信息应包含'time_window': %v", err)
		}
	})

	t.Run("TimeWindow边界值_1", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.TimeWindow = 1

		err := cfg.Validate()
		if err != nil {
			t.Errorf("TimeWindow为1应该合法: %v", err)
		}
	})

	t.Run("TimeWindow边界值_300", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.TimeWindow = 300

		err := cfg.Validate()
		if err != nil {
			t.Errorf("TimeWindow为300应该合法: %v", err)
		}
	})
}

// =============================================================================
// Switcher Priority验证测试
// =============================================================================

func TestSwitcherPriorityValidation(t *testing.T) {
	t.Run("Priority包含ARQ应报错", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.Switcher.Priority = []string{"udp", "arq", "websocket"}

		err := cfg.Validate()
		if err == nil {
			t.Error("Priority包含ARQ应该报错")
		}
		if !strings.Contains(err.Error(), "arq") {
			t.Errorf("错误信息应包含'arq': %v", err)
		}
	})

	t.Run("Priority包含ARQ大写", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.Switcher.Priority = []string{"udp", "ARQ", "websocket"}

		err := cfg.Validate()
		if err == nil {
			t.Error("Priority包含ARQ(大写)应该报错")
		}
	})

	t.Run("正常Priority", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.Switcher.Priority = []string{"ebpf", "faketcp", "udp", "websocket"}

		err := cfg.Validate()
		if err != nil {
			t.Errorf("正常Priority不应报错: %v", err)
		}
	})
}

// =============================================================================
// Tunnel配置关联测试
// =============================================================================

func TestTunnelConfigSync(t *testing.T) {
	t.Run("Tunnel端口不一致", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.Listen = ":54321"
		cfg.Tunnel.Enabled = true
		cfg.Tunnel.LocalPort = 12345 // 与主端口不一致

		err := cfg.Validate()
		if err == nil {
			t.Error("Tunnel端口不一致应该报错")
		}
		if !strings.Contains(err.Error(), "tunnel.local_port") {
			t.Errorf("错误信息应包含'tunnel.local_port': %v", err)
		}
	})

	t.Run("Tunnel端口为0自动同步", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.Listen = ":54321"
		cfg.Tunnel.Enabled = true
		cfg.Tunnel.LocalPort = 0 // 应该自动同步

		err := cfg.Validate()
		if err != nil {
			t.Errorf("Tunnel端口为0不应报错: %v", err)
		}

		cfg.syncRelatedConfig()
		if cfg.Tunnel.LocalPort != 54321 {
			t.Errorf("Tunnel端口应同步为54321: got %d", cfg.Tunnel.LocalPort)
		}
	})

	t.Run("Tunnel端口一致", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.Listen = ":54321"
		cfg.Tunnel.Enabled = true
		cfg.Tunnel.LocalPort = 54321

		err := cfg.Validate()
		if err != nil {
			t.Errorf("Tunnel端口一致不应报错: %v", err)
		}
	})
}

// =============================================================================
// 配置同步测试
// =============================================================================

func TestConfigSync(t *testing.T) {
	t.Run("EBPF_TC_FakeTCP同步", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.EBPF.Enabled = true
		cfg.EBPF.TCFakeTCP = true

		cfg.syncRelatedConfig()

		if !cfg.FakeTCP.UseEBPF {
			t.Error("FakeTCP.UseEBPF 应该同步为 true")
		}
	})

	t.Run("网卡配置同步", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.EBPF.Interface = "eth0"
		cfg.FakeTCP.Interface = ""

		cfg.syncRelatedConfig()

		if cfg.FakeTCP.Interface != "eth0" {
			t.Errorf("FakeTCP.Interface 应该同步为 eth0: got %s", cfg.FakeTCP.Interface)
		}
	})

	t.Run("LocalAddr默认值同步", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk-12345"
		cfg.Tunnel.Enabled = true
		cfg.Tunnel.LocalAddr = ""

		cfg.syncRelatedConfig()

		if cfg.Tunnel.LocalAddr != "127.0.0.1" {
			t.Errorf("Tunnel.LocalAddr 应该同步为 127.0.0.1: got %s", cfg.Tunnel.LocalAddr)
		}
	})
}

// =============================================================================
// 端口解析测试
// =============================================================================

func TestParsePort(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		want    int
		wantErr bool
	}{
		{"冒号前缀", ":54321", 54321, false},
		{"完整地址", "0.0.0.0:8080", 8080, false},
		{"IPv6地址", "[::]:9000", 9000, false},
		{"仅端口号", "12345", 12345, false},
		{"无效格式", "invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePort(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePort(%s) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parsePort(%s) = %d, want %d", tt.addr, got, tt.want)
			}
		})
	}
}

// =============================================================================
// GetListenPort测试
// =============================================================================

func TestGetListenPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Listen = ":54321"

	port := cfg.GetListenPort()
	if port != 54321 {
		t.Errorf("GetListenPort() = %d, want 54321", port)
	}

	cfg.Listen = "0.0.0.0:8080"
	port = cfg.GetListenPort()
	if port != 8080 {
		t.Errorf("GetListenPort() = %d, want 8080", port)
	}
}

// =============================================================================
// 配置文件加载测试
// =============================================================================

func TestLoad(t *testing.T) {
	t.Run("文件不存在", func(t *testing.T) {
		_, err := Load("/nonexistent/path/config.yaml")
		if err == nil {
			t.Error("加载不存在的文件应该报错")
		}
	})

	t.Run("有效配置文件", func(t *testing.T) {
		// 创建临时配置文件
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		configContent := `
listen: ":54321"
psk: "test-psk-12345"
time_window: 30
log_level: "info"
mode: "auto"

arq:
  enabled: true
  window_size: 256
  max_retries: 10
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		if err != nil {
			t.Fatalf("创建临时配置文件失败: %v", err)
		}

		cfg, err := Load(configPath)
		if err != nil {
			t.Fatalf("加载配置文件失败: %v", err)
		}

		if cfg.PSK != "test-psk-12345" {
			t.Errorf("PSK 错误: got %s, want test-psk-12345", cfg.PSK)
		}
		if cfg.Listen != ":54321" {
			t.Errorf("Listen 错误: got %s, want :54321", cfg.Listen)
		}
	})

	t.Run("无效YAML格式", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "invalid.yaml")

		invalidContent := `
listen: ":54321"
  invalid: indentation
`
		err := os.WriteFile(configPath, []byte(invalidContent), 0644)
		if err != nil {
			t.Fatalf("创建临时配置文件失败: %v", err)
		}

		_, err = Load(configPath)
		if err == nil {
			t.Error("解析无效YAML应该报错")
		}
	})

	t.Run("缺少PSK的配置文件", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "no_psk.yaml")

		content := `
listen: ":54321"
time_window: 30
`
		err := os.WriteFile(configPath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("创建临时配置文件失败: %v", err)
		}

		_, err = Load(configPath)
		if err == nil {
			t.Error("缺少PSK应该验证失败")
		}
		if !strings.Contains(err.Error(), "psk") {
			t.Errorf("错误信息应包含'psk': %v", err)
		}
	})
}

// =============================================================================
// ToTunnelConfig测试
// =============================================================================

func TestToTunnelConfig(t *testing.T) {
	cfg := &TunnelConfig{
		Enabled:    true,
		Mode:       "temp",
		DomainMode: "auto",
		LocalAddr:  "127.0.0.1",
		LocalPort:  54321,
	}

	result := cfg.ToTunnelConfig()
	if result == nil {
		t.Error("ToTunnelConfig() 不应返回 nil")
	}

	// 验证返回的是同一个对象
	if result != cfg {
		t.Error("ToTunnelConfig() 应返回自身引用")
	}
}

// =============================================================================
// 完整配置文件集成测试
// =============================================================================

func TestFullConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "full_config.yaml")

	fullConfig := `
listen: ":54321"
psk: "test-psk-integration"
time_window: 30
log_level: "info"
mode: "auto"

tunnel:
  enabled: true
  mode: "temp"
  domain_mode: "auto"
  local_addr: "127.0.0.1"
  local_port: 54321

hysteria2:
  enabled: true
  up_mbps: 100
  down_mbps: 100
  initial_window: 32
  max_window: 512
  loss_threshold: 0.1

faketcp:
  enabled: true
  listen: ":54322"
  interface: "eth0"

websocket:
  enabled: true
  listen: ":54323"
  path: "/ws"

ebpf:
  enabled: false
  interface: "eth0"
  xdp_mode: "generic"

switcher:
  enabled: true
  check_interval_ms: 1000
  fail_threshold: 3
  recover_threshold: 5
  priority:
    - "ebpf"
    - "faketcp"
    - "udp"
    - "websocket"

metrics:
  enabled: true
  listen: ":9100"
  path: "/metrics"
  health_path: "/health"

arq:
  enabled: true
  window_size: 256
  max_retries: 10
  rto_min_ms: 100
  rto_max_ms: 10000
  enable_sack: true
  enable_timestamp: true
`
	err := os.WriteFile(configPath, []byte(fullConfig), 0644)
	if err != nil {
		t.Fatalf("创建完整配置文件失败: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("加载完整配置文件失败: %v", err)
	}

	// 验证关键配置项
	if cfg.PSK != "test-psk-integration" {
		t.Errorf("PSK 错误: got %s", cfg.PSK)
	}
	if !cfg.Tunnel.Enabled {
		t.Error("Tunnel 应该启用")
	}
	if !cfg.Hysteria2.Enabled {
		t.Error("Hysteria2 应该启用")
	}
	if !cfg.FakeTCP.Enabled {
		t.Error("FakeTCP 应该启用")
	}
	if !cfg.WebSocket.Enabled {
		t.Error("WebSocket 应该启用")
	}
	if !cfg.ARQ.Enabled {
		t.Error("ARQ 应该启用")
	}
	if !cfg.Metrics.Enabled {
		t.Error("Metrics 应该启用")
	}
}

// =============================================================================
// 边界情况综合测试
// =============================================================================

func TestEdgeCases(t *testing.T) {
	t.Run("空配置结构", func(t *testing.T) {
		cfg := &Config{}
		err := cfg.Validate()
		if err == nil {
			t.Error("空配置应该验证失败")
		}
	})

	t.Run("只有PSK的最小配置", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "minimal-psk"

		err := cfg.Validate()
		if err != nil {
			t.Errorf("最小有效���置不应报错: %v", err)
		}
	})

	t.Run("负数端口", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk"
		cfg.Listen = ":-1"

		// parsePort 会返回 -1，但这不一定会被 Validate 捕获
		// 取决于具体实现
		port, err := parsePort(cfg.Listen)
		if err == nil && port == -1 {
			// 负数端口在解析层面成功，但语义上无效
			t.Log("负数端口解析成功，值为:", port)
		}
	})

	t.Run("超大端口号", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.PSK = "test-psk"
		cfg.Listen = ":70000"

		port, _ := parsePort(cfg.Listen)
		if port == 70000 {
			t.Log("超大端口号解析成功:", port)
		}
	})
}

