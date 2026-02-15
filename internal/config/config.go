// =============================================================================
// 文件: internal/config/config.go
// 描述: 配置管理 - 修复配置隐性关联、端口冲突检测、ARQ 优先级验证
//       增加 ACME 自动证书配置支持、DDNS 动态域名支持和 TLS 指纹伪装配置
//       新增：eBPF/UDP 互斥标记
// =============================================================================
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

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
	TLS       TLSConfig       `yaml:"tls"` // 新增：TLS 指纹伪装配置
}

// TLSConfig TLS 指纹伪装配置
type TLSConfig struct {
	// 基础配置
	Enabled    bool   `yaml:"enabled"`     // 是否启用 TLS 伪装
	ServerName string `yaml:"server_name"` // SNI 域名 (如 www.bing.com)

	// 指纹配置
	Fingerprint string `yaml:"fingerprint"` // 浏览器指纹: chrome, firefox, safari, ios, android, edge, qq, 360

	// ECH 配置 (Encrypted Client Hello)
	EnableECH   bool   `yaml:"enable_ech"`   // 是否启用 ECH
	ECHConfig   string `yaml:"ech_config"`   // ECH 配置 (Base64 编码)
	ECHProvider string `yaml:"ech_provider"` // ECH 配置提供商: cloudflare, custom

	// 服务端配置
	FallbackEnabled bool   `yaml:"fallback_enabled"` // 是否启用回落
	FallbackAddr    string `yaml:"fallback_addr"`    // 探测流量回落地址 (如 127.0.0.1:80)
	FallbackTimeout int    `yaml:"fallback_timeout"` // 回落超时 (秒)

	// 证书配置 (服务端)
	CertFile   string `yaml:"cert_file"`   // TLS 证书文件
	KeyFile    string `yaml:"key_file"`    // TLS 私钥文件
	AutoCert   bool   `yaml:"auto_cert"`   // 自动从 CertManager 获取证书
	VerifyCert bool   `yaml:"verify_cert"` // 客户端是否验证证书 (生产环境建议 true)

	// 高级配置
	ALPN              []string `yaml:"alpn"`                // ALPN 协议列表 (如 ["h2", "http/1.1"])
	MinVersion        string   `yaml:"min_version"`         // 最低 TLS 版本: tls10, tls11, tls12, tls13
	MaxVersion        string   `yaml:"max_version"`         // 最高 TLS 版本
	SessionTicket     bool     `yaml:"session_ticket"`      // 启用会话票据
	InsecureSkipAuth  bool     `yaml:"insecure_skip_auth"`  // 跳过 PSK 认证 (仅用于测试)
	RandomSNI         bool     `yaml:"random_sni"`          // 随机 SNI (从预定义列表选择)
	SNIList           []string `yaml:"sni_list"`            // 随机 SNI 列表
	PaddingEnabled    bool     `yaml:"padding_enabled"`     // 启用 TLS 记录填充
	PaddingMinSize    int      `yaml:"padding_min_size"`    // 最小填充大小
	PaddingMaxSize    int      `yaml:"padding_max_size"`    // 最大填充大小
	FragmentEnabled   bool     `yaml:"fragment_enabled"`    // 启用 ClientHello 分片
	FragmentSize      int      `yaml:"fragment_size"`       // 分片大小
	FragmentSleepMs   int      `yaml:"fragment_sleep_ms"`   // 分片间隔 (毫秒)
	MimicBrowserOrder bool     `yaml:"mimic_browser_order"` // 模拟浏览器扩展顺序
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
	Enabled       bool   `yaml:"enabled"`
	Interface     string `yaml:"interface"`
	XDPMode       string `yaml:"xdp_mode"`
	ProgramPath   string `yaml:"program_path"`
	MapSize       int    `yaml:"map_size"`
	EnableStats   bool   `yaml:"enable_stats"`
	EnableTC      bool   `yaml:"enable_tc"`
	TCFakeTCP     bool   `yaml:"tc_faketcp"`
	DisableListen bool   `yaml:"disable_listen"` // 新增：禁用用户态监听（eBPF 独占模式）
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
	CertMode string `yaml:"cert_mode"` // auto, selfsigned, acme, letsencrypt, zerossl, cforigin, custom
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CertDir  string `yaml:"cert_dir"` // 证书存储目录

	// ACME 配置 (Let's Encrypt / ZeroSSL)
	ACMEProvider      string   `yaml:"acme_provider"`       // letsencrypt, letsencrypt-staging, zerossl
	ACMEEmail         string   `yaml:"acme_email"`          // ACME 账户邮箱 (必填)
	ACMEDomains       []string `yaml:"acme_domains"`        // 要申请证书的域名列表
	ACMEChallengeType string   `yaml:"acme_challenge_type"` // http-01, tls-alpn-01
	ACMEHTTPPort      int      `yaml:"acme_http_port"`      // HTTP-01 挑战端口，默认 80
	ACMEUseTunnel     bool     `yaml:"acme_use_tunnel"`     // 使用 Cloudflare 隧道进行 ACME 验证

	// ZeroSSL EAB 配置 (External Account Binding)
	ACMEEABKeyID   string `yaml:"acme_eab_key_id"`
	ACMEEABHMACKey string `yaml:"acme_eab_hmac_key"`

	// Cloudflare 配置
	CFToken    string `yaml:"cf_token"`
	CFTunnelID string `yaml:"cf_tunnel_id"`

	// DuckDNS 配置（简化）
	DuckDNSToken  string `yaml:"duckdns_token"`
	DuckDNSDomain string `yaml:"duckdns_domain"`

	// DuckDNS 配置（结构体）
	DuckDNS DuckDNSConfig `yaml:"duckdns"`

	// FreeDNS 配置
	FreeDNS FreeDNSConfig `yaml:"freedns"`

	// DDNS 完整配置
	DDNS *DDNSConfig `yaml:"ddns"`

	// Let's Encrypt 配置 (旧版兼容)
	LetsEncrypt LetsEncryptConfig `yaml:"letsencrypt"`

	// 本地服务配置
	LocalAddr   string `yaml:"local_addr"`
	LocalPort   int    `yaml:"local_port"`
	Protocol    string `yaml:"protocol"` // http, https, tcp
	NoTLSVerify bool   `yaml:"no_tls_verify"`
	Metrics     string `yaml:"metrics"`
	LogLevel    string `yaml:"log_level"`

	// 高级配置
	AutoRestart     bool `yaml:"auto_restart"`
	MaxRestarts     int  `yaml:"max_restarts"`
	RestartDelaySec int  `yaml:"restart_delay_sec"`
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

// DDNSConfig DDNS 完整配置
type DDNSConfig struct {
	Enabled        bool     `yaml:"enabled"`
	Provider       string   `yaml:"provider"` // duckdns, freedns, noip
	UpdateInterval string   `yaml:"update_interval"`
	Token          string   `yaml:"token"`
	Domains        []string `yaml:"domains"`

	// DuckDNS
	DuckDNS struct {
		Token   string   `yaml:"token"`
		Domains []string `yaml:"domains"`
	} `yaml:"duckdns"`

	// FreeDNS
	FreeDNS struct {
		Token  string `yaml:"token"`
		Domain string `yaml:"domain"`
	} `yaml:"freedns"`

	// No-IP
	NoIP struct {
		Username string   `yaml:"username"`
		Password string   `yaml:"password"`
		Hostname []string `yaml:"hostname"`
	} `yaml:"noip"`
}

// LetsEncryptConfig Let's Encrypt 配置 (旧版兼容，推荐使用 ACME* 字段)
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
			Enabled:       false,
			XDPMode:       "generic",
			MapSize:       65536,
			EnableTC:      false,
			TCFakeTCP:     false,
			DisableListen: false, // 默认不禁用
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
			Enabled:           false,
			Mode:              "temp",
			DomainMode:        "auto",
			CertMode:          "auto",
			LocalAddr:         "127.0.0.1",
			Protocol:          "http",
			LogLevel:          "info",
			AutoRestart:       true,
			MaxRestarts:       5,
			RestartDelaySec:   5,
			ACMEProvider:      "letsencrypt",
			ACMEChallengeType: "http-01",
			ACMEHTTPPort:      80,
			ACMEUseTunnel:     true,
		},

		// 默认 TLS 配置
		TLS: TLSConfig{
			Enabled:           false,
			ServerName:        "www.microsoft.com",
			Fingerprint:       "chrome",
			EnableECH:         false,
			FallbackEnabled:   true,
			FallbackAddr:      "127.0.0.1:80",
			FallbackTimeout:   10,
			AutoCert:          true,
			VerifyCert:        false,
			ALPN:              []string{"h2", "http/1.1"},
			MinVersion:        "tls12",
			MaxVersion:        "tls13",
			SessionTicket:     true,
			PaddingEnabled:    false,
			PaddingMinSize:    16,
			PaddingMaxSize:    256,
			FragmentEnabled:   false,
			FragmentSize:      40,
			FragmentSleepMs:   10,
			MimicBrowserOrder: true,
			SNIList: []string{
				"www.microsoft.com",
				"www.bing.com",
				"www.apple.com",
				"www.cloudflare.com",
				"www.amazon.com",
				"www.google.com",
			},
		},
	}
}

// Validate 验证配置
func (c *Config) Validate() error {
	// 验证 PSK
	if c.PSK == "" {
		return fmt.Errorf("psk 不能为空")
	}

	// 验证时间窗口
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
		if c.ARQ.RTOMinMs < 10 || c.ARQ.RTOMinMs > 5000 {
			return fmt.Errorf("arq.rto_min_ms 需在 10-5000 之间")
		}
		if c.ARQ.RTOMaxMs < c.ARQ.RTOMinMs || c.ARQ.RTOMaxMs > 60000 {
			return fmt.Errorf("arq.rto_max_ms 需大于 rto_min_ms 且不超过 60000")
		}
	}

	// 验证切换器优先级不包含 ARQ
	for _, mode := range c.Switcher.Priority {
		if strings.ToLower(mode) == "arq" {
			return fmt.Errorf("switcher.priority 不应包含 'arq'，ARQ 是 UDP 的增强层而非独立模式")
		}
	}

	// 验证隧道配置
	if c.Tunnel.Enabled {
		if err := c.validateTunnelConfig(); err != nil {
			return fmt.Errorf("隧道配置错误: %w", err)
		}
	}

	// 验证 Hysteria2 配置
	if c.Hysteria2.Enabled {
		if err := c.validateHysteria2Config(); err != nil {
			return fmt.Errorf("hysteria2 配置错误: %w", err)
		}
	}

	// 验证 EBPF 配置
	if c.EBPF.Enabled {
		if err := c.validateEBPFConfig(); err != nil {
			return fmt.Errorf("ebpf 配置错误: %w", err)
		}
	}

	// 验证 WebSocket 配置
	if c.WebSocket.Enabled {
		if err := c.validateWebSocketConfig(); err != nil {
			return fmt.Errorf("websocket 配置错误: %w", err)
		}
	}

	// 验证 TLS 配置
	if c.TLS.Enabled {
		if err := c.validateTLSConfig(); err != nil {
			return fmt.Errorf("tls 配置错误: %w", err)
		}
	}

	return nil
}

// validateTLSConfig 验证 TLS 伪装配置
func (c *Config) validateTLSConfig() error {
	// 如果启用 TLS，ServerName 不能为空
	if c.TLS.ServerName == "" && !c.TLS.RandomSNI {
		return fmt.Errorf("tls.server_name 不能为空 (或启用 random_sni)")
	}

	// 验证指纹类型
	validFingerprints := map[string]bool{
		"chrome": true, "firefox": true, "safari": true, "ios": true,
		"android": true, "edge": true, "qq": true, "360": true,
		"random": true, "custom": true, "": true,
	}
	if !validFingerprints[strings.ToLower(c.TLS.Fingerprint)] {
		return fmt.Errorf("tls.fingerprint 无效: %s (支持: chrome, firefox, safari, ios, android, edge, qq, 360, random)", c.TLS.Fingerprint)
	}

	// 验证 TLS 版本
	validVersions := map[string]bool{
		"tls10": true, "tls11": true, "tls12": true, "tls13": true, "": true,
	}
	if !validVersions[strings.ToLower(c.TLS.MinVersion)] {
		return fmt.Errorf("tls.min_version 无效: %s", c.TLS.MinVersion)
	}
	if !validVersions[strings.ToLower(c.TLS.MaxVersion)] {
		return fmt.Errorf("tls.max_version 无效: %s", c.TLS.MaxVersion)
	}

	// 验证回落配置
	if c.TLS.FallbackEnabled {
		if c.TLS.FallbackAddr == "" {
			return fmt.Errorf("tls.fallback_addr 不能为空 (fallback 已启用)")
		}
		if _, _, err := net.SplitHostPort(c.TLS.FallbackAddr); err != nil {
			return fmt.Errorf("tls.fallback_addr 格式错误: %w", err)
		}
	}

	// 验证填充配置
	if c.TLS.PaddingEnabled {
		if c.TLS.PaddingMinSize < 0 || c.TLS.PaddingMinSize > 65535 {
			return fmt.Errorf("tls.padding_min_size 需在 0-65535 之间")
		}
		if c.TLS.PaddingMaxSize < c.TLS.PaddingMinSize || c.TLS.PaddingMaxSize > 65535 {
			return fmt.Errorf("tls.padding_max_size 需大于等于 padding_min_size 且不超过 65535")
		}
	}

	// 验证分片配置
	if c.TLS.FragmentEnabled {
		if c.TLS.FragmentSize < 1 || c.TLS.FragmentSize > 65535 {
			return fmt.Errorf("tls.fragment_size 需在 1-65535 之间")
		}
	}

	// 验证随机 SNI 列表
	if c.TLS.RandomSNI && len(c.TLS.SNIList) == 0 {
		return fmt.Errorf("tls.sni_list 不能为空 (random_sni 已启用)")
	}

	// 验证证书配置 (仅服务端)
	if !c.TLS.AutoCert {
		if c.TLS.CertFile != "" && c.TLS.KeyFile == "" {
			return fmt.Errorf("tls.key_file 不能为空 (已指定 cert_file)")
		}
		if c.TLS.KeyFile != "" && c.TLS.CertFile == "" {
			return fmt.Errorf("tls.cert_file 不能为空 (已指定 key_file)")
		}
	}

	return nil
}

// validateTunnelConfig 验证隧道配置
func (c *Config) validateTunnelConfig() error {
	// 验证模式
	switch c.Tunnel.Mode {
	case "temp", "fixed", "direct":
		// 有效模式
	case "":
		// 默认为 temp
		c.Tunnel.Mode = "temp"
	default:
		return fmt.Errorf("无效的隧道模式: %s (支持: temp, fixed, direct)", c.Tunnel.Mode)
	}

	// 固定隧道需要 token
	if c.Tunnel.Mode == "fixed" {
		if c.Tunnel.CFToken == "" {
			return fmt.Errorf("固定隧道模式需要配置 cf_token")
		}
	}

	// 验证协议
	switch c.Tunnel.Protocol {
	case "", "http", "https", "tcp":
		// 有效协议
		if c.Tunnel.Protocol == "" {
			c.Tunnel.Protocol = "http"
		}
	default:
		return fmt.Errorf("无效的隧道协议: %s (支持: http, https, tcp)", c.Tunnel.Protocol)
	}

	// 验证域名模式
	switch c.Tunnel.DomainMode {
	case "", "auto", "sslip", "nip", "duckdns", "freedns", "custom":
		// 有效模式
	default:
		return fmt.Errorf("无效的域名模式: %s", c.Tunnel.DomainMode)
	}

	// 验证证书模式
	switch c.Tunnel.CertMode {
	case "", "auto", "selfsigned", "acme", "letsencrypt", "zerossl", "cforigin", "custom":
		// 有效模式
		// 处理别名
		if c.Tunnel.CertMode == "letsencrypt" {
			c.Tunnel.CertMode = "acme"
			if c.Tunnel.ACMEProvider == "" {
				c.Tunnel.ACMEProvider = "letsencrypt"
			}
		}
		if c.Tunnel.CertMode == "zerossl" {
			c.Tunnel.CertMode = "acme"
			if c.Tunnel.ACMEProvider == "" {
				c.Tunnel.ACMEProvider = "zerossl"
			}
		}
	default:
		return fmt.Errorf("无效的证书模式: %s", c.Tunnel.CertMode)
	}

	// 如果是自定义域名模式，需要指定域名
	if c.Tunnel.DomainMode == "custom" && c.Tunnel.Domain == "" {
		return fmt.Errorf("自定义域名模式需要配置 domain")
	}

	// 如果是自定义证书模式，需要指定证书文件
	if c.Tunnel.CertMode == "custom" {
		if c.Tunnel.CertFile == "" || c.Tunnel.KeyFile == "" {
			return fmt.Errorf("自定义证书模式需要配置 cert_file 和 key_file")
		}
	}

	// 验证 ACME 配置
	if c.Tunnel.CertMode == "acme" {
		if err := c.validateACMEConfig(); err != nil {
			return fmt.Errorf("ACME 配置错误: %w", err)
		}
	}

	// 验证 DuckDNS 配置
	if c.Tunnel.DomainMode == "duckdns" {
		// 支持两种配置方式
		token := c.Tunnel.DuckDNSToken
		if token == "" {
			token = c.Tunnel.DuckDNS.Token
		}
		domains := c.Tunnel.DuckDNSDomain
		if domains == "" {
			domains = c.Tunnel.DuckDNS.Domains
		}

		if token == "" {
			return fmt.Errorf("DuckDNS 模式需要配置 duckdns_token 或 duckdns.token")
		}
		if domains == "" {
			return fmt.Errorf("DuckDNS 模式需要配置 duckdns_domain 或 duckdns.domains")
		}
	}

	// 验证 FreeDNS 配置
	if c.Tunnel.DomainMode == "freedns" {
		if c.Tunnel.FreeDNS.Token == "" {
			return fmt.Errorf("FreeDNS 模式需要配置 freedns.token")
		}
		if c.Tunnel.FreeDNS.Domain == "" {
			return fmt.Errorf("FreeDNS 模式需要配置 freedns.domain")
		}
	}

	// 验证 DDNS 配置
	if c.Tunnel.DDNS != nil && c.Tunnel.DDNS.Enabled {
		if err := c.validateDDNSConfig(); err != nil {
			return fmt.Errorf("DDNS 配置错误: %w", err)
		}
	}

	// 验证 Let's Encrypt 配置 (旧版兼容)
	if c.Tunnel.CertMode == "acme" && c.Tunnel.ACMEEmail == "" {
		// 尝试从旧版配置中获取
		if c.Tunnel.LetsEncrypt.Email != "" {
			c.Tunnel.ACMEEmail = c.Tunnel.LetsEncrypt.Email
			if c.Tunnel.LetsEncrypt.Staging {
				c.Tunnel.ACMEProvider = "letsencrypt-staging"
			}
		}
	}

	// 验证本地地址
	if c.Tunnel.LocalAddr != "" {
		if net.ParseIP(c.Tunnel.LocalAddr) == nil && c.Tunnel.LocalAddr != "localhost" {
			return fmt.Errorf("无效的本地地址: %s", c.Tunnel.LocalAddr)
		}
	}

	// 验证端口范围
	if c.Tunnel.LocalPort != 0 {
		if c.Tunnel.LocalPort < 1 || c.Tunnel.LocalPort > 65535 {
			return fmt.Errorf("无效的本地端口: %d", c.Tunnel.LocalPort)
		}
	}

	// 验证重启配置
	if c.Tunnel.MaxRestarts < 0 {
		return fmt.Errorf("max_restarts 不能为负数")
	}
	if c.Tunnel.RestartDelaySec < 0 {
		return fmt.Errorf("restart_delay_sec 不能为负数")
	}

	return nil
}

// validateACMEConfig 验证 ACME 配置
func (c *Config) validateACMEConfig() error {
	// 验证邮箱 (ACME 必需)
	if c.Tunnel.ACMEEmail == "" {
		return fmt.Errorf("ACME 模式需要配置 acme_email")
	}

	// 简单的邮箱格式验证
	if !strings.Contains(c.Tunnel.ACMEEmail, "@") {
		return fmt.Errorf("无效的邮箱地址: %s", c.Tunnel.ACMEEmail)
	}

	// 验证 ACME 提供商
	switch c.Tunnel.ACMEProvider {
	case "", "letsencrypt", "letsencrypt-staging", "zerossl":
		// 有效提供商
		if c.Tunnel.ACMEProvider == "" {
			c.Tunnel.ACMEProvider = "letsencrypt"
		}
	default:
		return fmt.Errorf("无效的 ACME 提供商: %s (支持: letsencrypt, letsencrypt-staging, zerossl)",
			c.Tunnel.ACMEProvider)
	}

	// 验证挑战类型
	switch c.Tunnel.ACMEChallengeType {
	case "", "http-01", "tls-alpn-01":
		// 有效挑战类型
		if c.Tunnel.ACMEChallengeType == "" {
			c.Tunnel.ACMEChallengeType = "http-01"
		}
	default:
		return fmt.Errorf("无效的 ACME 挑战类型: %s (支持: http-01, tls-alpn-01)",
			c.Tunnel.ACMEChallengeType)
	}

	// 验证 HTTP 端口
	if c.Tunnel.ACMEHTTPPort != 0 {
		if c.Tunnel.ACMEHTTPPort < 1 || c.Tunnel.ACMEHTTPPort > 65535 {
			return fmt.Errorf("无效的 ACME HTTP 端口: %d", c.Tunnel.ACMEHTTPPort)
		}
	}

	// ZeroSSL 需要 EAB 凭据
	if c.Tunnel.ACMEProvider == "zerossl" {
		if c.Tunnel.ACMEEABKeyID == "" || c.Tunnel.ACMEEABHMACKey == "" {
			return fmt.Errorf("ZeroSSL 需要配置 acme_eab_key_id 和 acme_eab_hmac_key")
		}
	}

	// 如果没有指定域名，尝试从 Domain 字段获取
	if len(c.Tunnel.ACMEDomains) == 0 && c.Tunnel.Domain != "" {
		c.Tunnel.ACMEDomains = []string{c.Tunnel.Domain}
	}

	return nil
}

// validateDDNSConfig 验证 DDNS 配置
func (c *Config) validateDDNSConfig() error {
	ddns := c.Tunnel.DDNS

	switch ddns.Provider {
	case "duckdns":
		token := ddns.DuckDNS.Token
		if token == "" {
			token = ddns.Token
		}
		if token == "" {
			return fmt.Errorf("DuckDNS 需要配置 token")
		}
		domains := ddns.DuckDNS.Domains
		if len(domains) == 0 {
			domains = ddns.Domains
		}
		if len(domains) == 0 {
			return fmt.Errorf("DuckDNS 需要配置 domains")
		}

	case "freedns":
		token := ddns.FreeDNS.Token
		if token == "" {
			token = ddns.Token
		}
		if token == "" {
			return fmt.Errorf("FreeDNS 需要配置 token")
		}

	case "noip":
		if ddns.NoIP.Username == "" || ddns.NoIP.Password == "" {
			return fmt.Errorf("No-IP 需要配置 username 和 password")
		}
		if len(ddns.NoIP.Hostname) == 0 {
			return fmt.Errorf("No-IP 需要配置 hostname")
		}

	case "":
		return fmt.Errorf("DDNS 需要配置 provider")

	default:
		return fmt.Errorf("不支持的 DDNS 提供商: %s (支持: duckdns, freedns, noip)", ddns.Provider)
	}

	return nil
}

// validateHysteria2Config 验证 Hysteria2 配置
func (c *Config) validateHysteria2Config() error {
	if c.Hysteria2.UpMbps < 1 || c.Hysteria2.UpMbps > 10000 {
		return fmt.Errorf("up_mbps 需在 1-10000 之间")
	}
	if c.Hysteria2.DownMbps < 1 || c.Hysteria2.DownMbps > 10000 {
		return fmt.Errorf("down_mbps 需在 1-10000 之间")
	}
	if c.Hysteria2.InitialWindow < 1 || c.Hysteria2.InitialWindow > 1024 {
		return fmt.Errorf("initial_window 需在 1-1024 之间")
	}
	if c.Hysteria2.MaxWindow < c.Hysteria2.InitialWindow || c.Hysteria2.MaxWindow > 4096 {
		return fmt.Errorf("max_window 需大于 initial_window 且不超过 4096")
	}
	if c.Hysteria2.LossThreshold < 0 || c.Hysteria2.LossThreshold > 1 {
		return fmt.Errorf("loss_threshold 需在 0-1 之间")
	}
	return nil
}

// validateEBPFConfig 验证 EBPF 配置
func (c *Config) validateEBPFConfig() error {
	switch c.EBPF.XDPMode {
	case "generic", "native", "offload":
		// 有效模式
	case "":
		c.EBPF.XDPMode = "generic"
	default:
		return fmt.Errorf("无效的 XDP 模式: %s (支持: generic, native, offload)", c.EBPF.XDPMode)
	}

	if c.EBPF.MapSize < 1024 || c.EBPF.MapSize > 1048576 {
		return fmt.Errorf("map_size 需在 1024-1048576 之间")
	}

	return nil
}

// validateWebSocketConfig 验证 WebSocket 配置
func (c *Config) validateWebSocketConfig() error {
	if c.WebSocket.Path == "" {
		c.WebSocket.Path = "/ws"
	}

	if !strings.HasPrefix(c.WebSocket.Path, "/") {
		return fmt.Errorf("websocket.path 必须以 / 开头")
	}

	if c.WebSocket.TLS {
		if c.WebSocket.CertFile == "" || c.WebSocket.KeyFile == "" {
			return fmt.Errorf("websocket TLS 模式需要配置 cert_file 和 key_file")
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

	// 同步默认值
	if c.Tunnel.MaxRestarts == 0 {
		c.Tunnel.MaxRestarts = 5
	}
	if c.Tunnel.RestartDelaySec == 0 {
		c.Tunnel.RestartDelaySec = 5
	}

	// 同步 ACME 默认值
	if c.Tunnel.CertMode == "acme" {
		if c.Tunnel.ACMEHTTPPort == 0 {
			c.Tunnel.ACMEHTTPPort = 80
		}
		if c.Tunnel.ACMEProvider == "" {
			c.Tunnel.ACMEProvider = "letsencrypt"
		}
		if c.Tunnel.ACMEChallengeType == "" {
			c.Tunnel.ACMEChallengeType = "http-01"
		}
	}

	// 同步 DuckDNS 配置 (简化字段 -> 结构体)
	if c.Tunnel.DuckDNSToken != "" && c.Tunnel.DuckDNS.Token == "" {
		c.Tunnel.DuckDNS.Token = c.Tunnel.DuckDNSToken
	}
	if c.Tunnel.DuckDNSDomain != "" && c.Tunnel.DuckDNS.Domains == "" {
		c.Tunnel.DuckDNS.Domains = c.Tunnel.DuckDNSDomain
	}

	// 同步 ACME 域名
	if c.Tunnel.CertMode == "acme" && len(c.Tunnel.ACMEDomains) == 0 && c.Tunnel.Domain != "" {
		c.Tunnel.ACMEDomains = []string{c.Tunnel.Domain}
	}

	// 同步 DDNS 配置（如果使用 domain_mode 但没有独立 DDNS 配置）
	if c.Tunnel.DDNS == nil && (c.Tunnel.DomainMode == "duckdns" || c.Tunnel.DomainMode == "freedns") {
		c.Tunnel.DDNS = &DDNSConfig{
			Enabled:        true,
			UpdateInterval: "5m",
		}
		switch c.Tunnel.DomainMode {
		case "duckdns":
			c.Tunnel.DDNS.Provider = "duckdns"
			c.Tunnel.DDNS.DuckDNS.Token = c.Tunnel.GetDuckDNSToken()
			c.Tunnel.DDNS.DuckDNS.Domains = []string{c.Tunnel.GetDuckDNSDomain()}
		case "freedns":
			c.Tunnel.DDNS.Provider = "freedns"
			c.Tunnel.DDNS.FreeDNS.Token = c.Tunnel.FreeDNS.Token
			c.Tunnel.DDNS.FreeDNS.Domain = c.Tunnel.FreeDNS.Domain
		}
	}

	// 同步 TLS 配置默认值
	if c.TLS.Enabled {
		if c.TLS.Fingerprint == "" {
			c.TLS.Fingerprint = "chrome"
		}
		if len(c.TLS.ALPN) == 0 {
			c.TLS.ALPN = []string{"h2", "http/1.1"}
		}
		if c.TLS.MinVersion == "" {
			c.TLS.MinVersion = "tls12"
		}
		if c.TLS.MaxVersion == "" {
			c.TLS.MaxVersion = "tls13"
		}
		if c.TLS.FallbackTimeout == 0 {
			c.TLS.FallbackTimeout = 10
		}
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

// GetListenHost 获取监听地址
func (c *Config) GetListenHost() string {
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return ""
	}
	return host
}

// ToTunnelConfig 转换为 tunnel 包的配置类型
func (c *TunnelConfig) ToTunnelConfig() interface{} {
	return c
}

// IsTempTunnel 是否为临时隧道模式
func (c *TunnelConfig) IsTempTunnel() bool {
	return c.Mode == "temp" || c.Mode == ""
}

// IsFixedTunnel 是否为固定隧道模式
func (c *TunnelConfig) IsFixedTunnel() bool {
	return c.Mode == "fixed"
}

// IsDirectTunnel 是否为直接 TCP 隧道模式
func (c *TunnelConfig) IsDirectTunnel() bool {
	return c.Mode == "direct"
}

// IsACMEEnabled 是否启用 ACME 证书
func (c *TunnelConfig) IsACMEEnabled() bool {
	return c.CertMode == "acme"
}

// IsDDNSEnabled 是否启用 DDNS
func (c *TunnelConfig) IsDDNSEnabled() bool {
	if c.DDNS != nil && c.DDNS.Enabled {
		return true
	}
	return c.DomainMode == "duckdns" || c.DomainMode == "freedns"
}

// GetLocalURL 获取本地服务 URL
func (c *TunnelConfig) GetLocalURL() string {
	addr := c.LocalAddr
	if addr == "" {
		addr = "127.0.0.1"
	}

	protocol := c.Protocol
	if protocol == "" {
		protocol = "http"
	}

	return fmt.Sprintf("%s://%s:%d", protocol, addr, c.LocalPort)
}

// GetACMEDomains 获取 ACME 域名列表
func (c *TunnelConfig) GetACMEDomains() []string {
	if len(c.ACMEDomains) > 0 {
		return c.ACMEDomains
	}
	if c.Domain != "" {
		return []string{c.Domain}
	}
	return nil
}

// GetDuckDNSToken 获取 DuckDNS Token
func (c *TunnelConfig) GetDuckDNSToken() string {
	if c.DuckDNSToken != "" {
		return c.DuckDNSToken
	}
	return c.DuckDNS.Token
}

// GetDuckDNSDomain 获取 DuckDNS 域名
func (c *TunnelConfig) GetDuckDNSDomain() string {
	if c.DuckDNSDomain != "" {
		return c.DuckDNSDomain
	}
	return c.DuckDNS.Domains
}

// GetDDNSProvider 获取 DDNS 提供商
func (c *TunnelConfig) GetDDNSProvider() string {
	if c.DDNS != nil {
		return c.DDNS.Provider
	}
	switch c.DomainMode {
	case "duckdns":
		return "duckdns"
	case "freedns":
		return "freedns"
	}
	return ""
}

// GetDDNSUpdateInterval 获取 DDNS 更新间隔
func (c *TunnelConfig) GetDDNSUpdateInterval() string {
	if c.DDNS != nil && c.DDNS.UpdateInterval != "" {
		return c.DDNS.UpdateInterval
	}
	return "5m"
}

// =============================================================================
// TLS 配置辅助方法
// =============================================================================

// GetRandomSNI 获取随机 SNI
func (c *TLSConfig) GetRandomSNI() string {
	if !c.RandomSNI || len(c.SNIList) == 0 {
		return c.ServerName
	}
	// 使用简单随机选择
	idx := int(time.Now().UnixNano()) % len(c.SNIList)
	return c.SNIList[idx]
}

// GetEffectiveSNI 获取有效的 SNI
func (c *TLSConfig) GetEffectiveSNI() string {
	if c.RandomSNI {
		return c.GetRandomSNI()
	}
	return c.ServerName
}

// =============================================================================
// 配置文件示例生成
// =============================================================================

// GenerateExampleConfig 生成示例配置
func GenerateExampleConfig() string {
	return `# Phantom Server 配置文件示例
# =============================================================================

# 基础配置
listen: ":54321"                    # 监听地址
psk: "your-secret-psk-here"         # 预共享密钥 (使用 --gen-psk 生成)
time_window: 30                     # 时间窗口 (秒)
log_level: "info"                   # 日志级别: debug, info, warn, error
mode: "auto"                        # 运行模式: auto, udp, faketcp, websocket, ebpf

# =============================================================================
# TLS 指纹伪装配置 (重要！用于绕过 DPI)
# =============================================================================
tls:
  enabled: false                    # 是否启用 TLS 伪装
  server_name: "www.microsoft.com"  # SNI 域名 (伪装目标)
  fingerprint: "chrome"             # 浏览器指纹: chrome, firefox, safari, ios, android, edge, qq, 360
  
  # ECH (Encrypted Client Hello) 配置
  enable_ech: false                 # 是否启用 ECH
  ech_provider: "cloudflare"        # ECH 配置来源: cloudflare, custom
  # ech_config: ""                  # 自定义 ECH 配置 (Base64)
  
  # 服务端回落配置 (防探测)
  fallback_enabled: true            # 是否启用回落
  fallback_addr: "127.0.0.1:80"     # 探测流量回落地址 (Nginx/Apache)
  fallback_timeout: 10              # 回落超时 (秒)
  
  # 证书配置 (服务端)
  auto_cert: true                   # 自动从 CertManager 获取证书
  # cert_file: "/path/to/cert.pem"  # 手动指定证书
  # key_file: "/path/to/key.pem"    # 手动指定私钥
  verify_cert: false                # 客户端是否验证证书
  
  # 高级配置
  alpn:                             # ALPN 协议
    - "h2"
    - "http/1.1"
  min_version: "tls12"              # 最低 TLS 版本
  max_version: "tls13"              # 最高 TLS 版本
  session_ticket: true              # 启用会话票据
  
  # 随机 SNI (增强抗检测)
  random_sni: false                 # 随机选择 SNI
  sni_list:                         # SNI 候选列表
    - "www.microsoft.com"
    - "www.bing.com"
    - "www.apple.com"
    - "www.cloudflare.com"
  
  # 流量混淆
  padding_enabled: false            # 启用 TLS 记录填充
  padding_min_size: 16              # 最小填充大小
  padding_max_size: 256             # 最大填充大小
  fragment_enabled: false           # 启用 ClientHello 分片
  fragment_size: 40                 # 分片大小
  fragment_sleep_ms: 10             # 分片间隔 (毫秒)
  mimic_browser_order: true         # 模拟浏览器扩展顺序

# ARQ 可靠传输层 (UDP 增强，非独立模式)
arq:
  enabled: true
  window_size: 256                  # 滑动窗口大小
  max_retries: 10                   # 最大重传次数
  rto_min_ms: 100                   # 最小重传超时 (毫秒)
  rto_max_ms: 10000                 # 最大重传超时 (毫秒)
  enable_sack: true                 # 启用选择性确认
  enable_timestamp: true            # 启用时间戳

# Hysteria2 拥塞控制
hysteria2:
  enabled: true
  up_mbps: 100                      # 上行带宽 (Mbps)
  down_mbps: 100                    # 下行带宽 (Mbps)
  initial_window: 32                # 初始拥塞窗口
  max_window: 512                   # 最大拥塞窗口
  loss_threshold: 0.1               # 丢包阈值

# FakeTCP 伪装
faketcp:
  enabled: false
  listen: ":54322"                  # FakeTCP 监听端口
  interface: ""                     # 网卡接口 (留空自动检测)
  use_ebpf: false                   # 使用 eBPF 加速

# WebSocket 传输
websocket:
  enabled: false
  listen: ":54323"                  # WebSocket 监听端口
  path: "/ws"                       # WebSocket 路径
  tls: false                        # 启用 TLS
  cert_file: ""                     # TLS 证书文件
  key_file: ""                      # TLS 密钥文件
  cdn: false                        # CDN 模式

# eBPF 加速
ebpf:
  enabled: false
  interface: ""                     # 网卡接口
  xdp_mode: "generic"               # XDP 模式: generic, native, offload
  map_size: 65536                   # eBPF Map 大小
  enable_tc: false                  # 启用 TC
  tc_faketcp: false                 # TC FakeTCP 模式
  disable_listen: false             # 禁用用户态监听 (eBPF 独占模式)

# 链路切换器
switcher:
  enabled: true
  check_interval_ms: 1000           # 检查间隔 (毫秒)
  fail_threshold: 3                 # 失败阈值
  recover_threshold: 5              # 恢复阈值
  rtt_threshold_ms: 300             # RTT 阈值 (毫秒)
  loss_threshold: 0.3               # 丢包率阈值
  priority:                         # 模式优先级 (不包含 arq)
    - ebpf
    - faketcp
    - udp
    - websocket

# Prometheus 监控
metrics:
  enabled: true
  listen: ":9100"                   # 监控端口
  path: "/metrics"                  # Prometheus 指标路径
  health_path: "/health"            # 健康检查路径
  enable_pprof: false               # 启用 pprof

# Cloudflare 隧道
tunnel:
  enabled: false
  mode: "temp"                      # 隧道模式: temp (临时), fixed (固定), direct (直接 TCP)
  local_addr: "127.0.0.1"           # 本地地址
  local_port: 0                     # 本地端口 (0 = 自动使用主监听端口)
  protocol: "http"                  # 协议: http, https, tcp
  domain_mode: "auto"               # 域名模式: auto, sslip, nip, duckdns, freedns, custom
  cert_mode: "auto"                 # 证书模式: auto, selfsigned, acme, letsencrypt, zerossl, cforigin, custom
`
}

// WriteExampleConfig 写入示例配置文件
func WriteExampleConfig(path string) error {
	return os.WriteFile(path, []byte(GenerateExampleConfig()), 0644)
}
