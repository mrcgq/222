


// =============================================================================
// 文件: internal/config/config.go
// 描述: 配置管理 - 修复配置隐性关联、端口冲突检测、ARQ 优先级验证
// =============================================================================
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 主配置
type Config struct {
	Listen     string `yaml:"listen"`
	PSK        string `yaml:"psk"`
	TimeWindow int    `yaml:"time_window"`
	LogLevel   string `yaml:"log_level"`
	Mode       string `yaml:"mode"`

	Tunnel    TunnelConfig    `yaml:"tunnel"`
	Hysteria2 Hysteria2Config `yaml:"hysteria2"`
	FakeTCP   FakeTCPConfig   `yaml:"faketcp"`
	WebSocket WebSocketConfig `yaml:"websocket"`
	EBPF      EBPFConfig      `yaml:"ebpf"`
	Switcher  SwitcherConfig  `yaml:"switcher"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	ARQ       ARQConfig       `yaml:"arq"`
}

// ARQConfig ARQ 增强层配置 (不是独立模式，是 UDP 的增强层)
type ARQConfig struct {
	Enabled         bool `yaml:"enabled"`
	WindowSize      int  `yaml:"window_size"`
	MaxRetries      int  `yaml:"max_retries"`
	RTOMinMs        int  `yaml:"rto_min_ms"`
	RTOMaxMs        int  `yaml:"rto_max_ms"`
	EnableSACK      bool `yaml:"enable_sack"`
	EnableTimestamp bool `yaml:"enable_timestamp"`
}

// MetricsConfig 监控配置
type MetricsConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Listen      string `yaml:"listen"`
	Path        string `yaml:"path"`
	HealthPath  string `yaml:"health_path"`
	EnablePprof bool   `yaml:"enable_pprof"`
}

// Hysteria2Config Hysteria2 拥塞控制配置
type Hysteria2Config struct {
	Enabled       bool    `yaml:"enabled"`
	UpMbps        int     `yaml:"up_mbps"`
	DownMbps      int     `yaml:"down_mbps"`
	DisableMTU    bool    `yaml:"disable_mtu"`
	InitialWindow int     `yaml:"initial_window"`
	MaxWindow     int     `yaml:"max_window"`
	MinRTT        int     `yaml:"min_rtt_ms"`
	MaxRTT        int     `yaml:"max_rtt_ms"`
	LossThreshold float64 `yaml:"loss_threshold"`
}

// FakeTCPConfig FakeTCP 配置
type FakeTCPConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Listen     string `yaml:"listen"`
	Interface  string `yaml:"interface"`
	SequenceID uint32 `yaml:"sequence_id"`
	UseEBPF    bool   `yaml:"use_ebpf"`
}

// WebSocketConfig WebSocket 配置
type WebSocketConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Listen   string `yaml:"listen"`
	Path     string `yaml:"path"`
	Host     string `yaml:"host"`
	TLS      bool   `yaml:"tls"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CDN      bool   `yaml:"cdn"`
}

// EBPFConfig eBPF 配置
type EBPFConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Interface   string `yaml:"interface"`
	XDPMode     string `yaml:"xdp_mode"`
	ProgramPath string `yaml:"program_path"`
	MapSize     int    `yaml:"map_size"`
	EnableStats bool   `yaml:"enable_stats"`
	EnableTC    bool   `yaml:"enable_tc"`
	TCFakeTCP   bool   `yaml:"tc_faketcp"`
}

// SwitcherConfig 链路切换配置
type SwitcherConfig struct {
	Enabled          bool     `yaml:"enabled"`
	CheckInterval    int      `yaml:"check_interval_ms"`
	FailThreshold    int      `yaml:"fail_threshold"`
	RecoverThreshold int      `yaml:"recover_threshold"`
	RTTThreshold     int      `yaml:"rtt_threshold_ms"`
	LossThreshold    float64  `yaml:"loss_threshold"`
	Priority         []string `yaml:"priority"`
}

// TunnelConfig 隧道配置 - 与 tunnel 包兼容
type TunnelConfig struct {
	// 基础配置
	Enabled    bool   `yaml:"enabled"`
	Mode       string `yaml:"mode"`        // temp, fixed, direct
	DomainMode string `yaml:"domain_mode"` // auto, sslip, nip, duckdns, freedns, custom
	Domain     string `yaml:"domain"`
	Subdomain  string `yaml:"subdomain"`

	// 证书配置
	CertMode string `yaml:"cert_mode"` // auto, selfsigned, letsencrypt, zerossl, cforigin, custom
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	// Cloudflare 配置
	CFToken    string `yaml:"cf_token"`
	CFTunnelID string `yaml:"cf_tunnel_id"`

	// 免费域名 API 配置
	DuckDNS DuckDNSConfig `yaml:"duckdns"`
	FreeDNS FreeDNSConfig `yaml:"freedns"`

	// Let's Encrypt 配置
	LetsEncrypt LetsEncryptConfig `yaml:"letsencrypt"`

	// 本地服务配置
	LocalAddr   string `yaml:"local_addr"`
	LocalPort   int    `yaml:"local_port"`
	Protocol    string `yaml:"protocol"` // http, https, tcp
	NoTLSVerify bool   `yaml:"no_tls_verify"`
	Metrics     string `yaml:"metrics"`
	LogLevel    string `yaml:"log_level"`
}

// DuckDNSConfig DuckDNS 配置
type DuckDNSConfig struct {
	Token   string `yaml:"token"`
	Domains string `yaml:"domains"`
}

// FreeDNSConfig FreeDNS 配置
type FreeDNSConfig struct {
	Token  string `yaml:"token"`
	Domain string `yaml:"domain"`
}

// LetsEncryptConfig Let's Encrypt 配置
type LetsEncryptConfig struct {
	Email       string `yaml:"email"`
	Staging     bool   `yaml:"staging"`
	DNSProvider string `yaml:"dns_provider"`
	DNSToken    string `yaml:"dns_token"`
}

// Load 加载配置
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置失败: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	cfg.syncRelatedConfig()

	return cfg, nil
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		Listen:     ":54321",
		TimeWindow: 30,
		LogLevel:   "info",
		Mode:       "auto",

		ARQ: ARQConfig{
			Enabled:         true,
			WindowSize:      256,
			MaxRetries:      10,
			RTOMinMs:        100,
			RTOMaxMs:        10000,
			EnableSACK:      true,
			EnableTimestamp: true,
		},

		Hysteria2: Hysteria2Config{
			Enabled:       true,
			UpMbps:        100,
			DownMbps:      100,
			InitialWindow: 32,
			MaxWindow:     512,
			MinRTT:        20,
			MaxRTT:        500,
			LossThreshold: 0.1,
		},

		FakeTCP: FakeTCPConfig{
			Enabled: false,
			Listen:  ":54322",
			UseEBPF: false,
		},

		WebSocket: WebSocketConfig{
			Enabled: false,
			Listen:  ":54323",
			Path:    "/ws",
		},

		EBPF: EBPFConfig{
			Enabled:     false,
			XDPMode:     "generic",
			MapSize:     65536,
			EnableTC:    false,
			TCFakeTCP:   false,
		},

		Switcher: SwitcherConfig{
			Enabled:          true,
			CheckInterval:    1000,
			FailThreshold:    3,
			RecoverThreshold: 5,
			RTTThreshold:     300,
			LossThreshold:    0.3,
			Priority:         []string{"ebpf", "faketcp", "udp", "websocket"},
		},

		Metrics: MetricsConfig{
			Enabled:     true,
			Listen:      ":9100",
			Path:        "/metrics",
			HealthPath:  "/health",
			EnablePprof: false,
		},

		Tunnel: TunnelConfig{
			Enabled:    false,
			Mode:       "temp",
			DomainMode: "auto",
			CertMode:   "auto",
			LocalAddr:  "127.0.0.1",
			Protocol:   "http",
			LogLevel:   "info",
		},
	}
}

// Validate 验证配置
func (c *Config) Validate() error {
	if c.PSK == "" {
		return fmt.Errorf("psk 不能为空")
	}
	if c.TimeWindow < 1 || c.TimeWindow > 300 {
		return fmt.Errorf("time_window 需在 1-300 之间")
	}

	// 验证主监听端口
	mainPort, err := parsePort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen 端口格式错误: %w", err)
	}

	// 端口冲突检测
	ports := map[int]string{mainPort: "listen"}

	if c.FakeTCP.Enabled {
		ftcpPort, err := parsePort(c.FakeTCP.Listen)
		if err != nil {
			return fmt.Errorf("faketcp.listen 端口格式错误: %w", err)
		}
		if existing, exists := ports[ftcpPort]; exists {
			return fmt.Errorf("faketcp.listen 端口 (%d) 与 %s 冲突", ftcpPort, existing)
		}
		ports[ftcpPort] = "faketcp"
	}

	if c.WebSocket.Enabled {
		wsPort, err := parsePort(c.WebSocket.Listen)
		if err != nil {
			return fmt.Errorf("websocket.listen 端口格式错误: %w", err)
		}
		if existing, exists := ports[wsPort]; exists {
			return fmt.Errorf("websocket.listen 端口 (%d) 与 %s 冲突", wsPort, existing)
		}
		ports[wsPort] = "websocket"
	}

	if c.Metrics.Enabled {
		metricsPort, err := parsePort(c.Metrics.Listen)
		if err != nil {
			return fmt.Errorf("metrics.listen 端口格式错误: %w", err)
		}
		if existing, exists := ports[metricsPort]; exists {
			return fmt.Errorf("metrics.listen 端口 (%d) 与 %s 冲突", metricsPort, existing)
		}
	}

	// 验证隧道配置关联
	if c.Tunnel.Enabled {
		if c.Tunnel.LocalPort != 0 && c.Tunnel.LocalPort != mainPort {
			return fmt.Errorf("tunnel.local_port (%d) 必须与 listen 端口 (%d) 一致，或设为 0 自动同步",
				c.Tunnel.LocalPort, mainPort)
		}
	}

	// 验证 ARQ 配置
	if c.ARQ.Enabled {
		if c.ARQ.WindowSize < 16 || c.ARQ.WindowSize > 4096 {
			return fmt.Errorf("arq.window_size 需在 16-4096 之间")
		}
		if c.ARQ.MaxRetries < 1 || c.ARQ.MaxRetries > 50 {
			return fmt.Errorf("arq.max_retries 需在 1-50 之间")
		}
	}

	// 验证切换器优先级不包含 ARQ
	for _, mode := range c.Switcher.Priority {
		if strings.ToLower(mode) == "arq" {
			return fmt.Errorf("switcher.priority 不应包含 'arq'，ARQ 是 UDP 的增强层而非独立模式")
		}
	}

	return nil
}

// syncRelatedConfig 同步关联配置
func (c *Config) syncRelatedConfig() {
	// 同步隧道端口
	if c.Tunnel.Enabled {
		listenPort, _ := parsePort(c.Listen)
		if c.Tunnel.LocalPort == 0 {
			c.Tunnel.LocalPort = listenPort
		}
		if c.Tunnel.LocalAddr == "" {
			c.Tunnel.LocalAddr = "127.0.0.1"
		}
	}

	// 如果启用 eBPF TC FakeTCP，同步到 FakeTCP 配置
	if c.EBPF.Enabled && c.EBPF.TCFakeTCP {
		c.FakeTCP.UseEBPF = true
	}

	// 同步网卡配置
	if c.EBPF.Interface != "" && c.FakeTCP.Interface == "" {
		c.FakeTCP.Interface = c.EBPF.Interface
	}
}

// parsePort 解析端口号
func parsePort(addr string) (int, error) {
	if strings.HasPrefix(addr, ":") {
		return strconv.Atoi(addr[1:])
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return strconv.Atoi(addr)
	}
	return strconv.Atoi(portStr)
}

// GetListenPort 获取监听端口
func (c *Config) GetListenPort() int {
	port, _ := parsePort(c.Listen)
	return port
}

// ToTunnelConfig 转换为 tunnel 包的配置类型
func (c *TunnelConfig) ToTunnelConfig() interface{} {
	return c
}



