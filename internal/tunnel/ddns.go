// =============================================================================
// 文件: internal/tunnel/ddns.go
// 描述: DDNS 动态域名服务 - 支持 DuckDNS、FreeDNS、No-IP 等
// =============================================================================
package tunnel

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// DDNS 提供商常量
// =============================================================================

// DDNSProvider DDNS 提供商类型
type DDNSProvider string

const (
	DDNSProviderDuckDNS  DDNSProvider = "duckdns"
	DDNSProviderFreeDNS  DDNSProvider = "freedns"
	DDNSProviderNoIP     DDNSProvider = "noip"
	DDNSProviderDynDNS   DDNSProvider = "dyndns"
	DDNSProviderCloudflare DDNSProvider = "cloudflare"
)

// DDNS API 端点
const (
	DuckDNSAPIURL  = "https://www.duckdns.org/update"
	FreeDNSAPIURL  = "https://freedns.afraid.org/dynamic/update.php"
	NoIPAPIURL     = "https://dynupdate.no-ip.com/nic/update"
	DynDNSAPIURL   = "https://members.dyndns.org/nic/update"
)

// 公网 IP 检测服务
var publicIPServices = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
	"https://ipinfo.io/ip",
	"https://api.ip.sb/ip",
	"https://checkip.amazonaws.com",
}

// =============================================================================
// DDNS 配置
// =============================================================================

// DDNSConfig DDNS 配置
type DDNSConfig struct {
	Enabled  bool         `yaml:"enabled"`
	Provider DDNSProvider `yaml:"provider"`
	
	// 更新间隔
	UpdateInterval time.Duration `yaml:"update_interval"`
	
	// DuckDNS 配置
	DuckDNS DuckDNSConfig `yaml:"duckdns"`
	
	// FreeDNS 配置
	FreeDNS FreeDNSConfig `yaml:"freedns"`
	
	// No-IP 配置
	NoIP NoIPConfig `yaml:"noip"`
	
	// 通用配置
	Token   string   `yaml:"token"`   // 通用 token 字段
	Domains []string `yaml:"domains"` // 通用域名列表
	
	// 日志级别
	LogLevel int `yaml:"log_level"`
}

// DuckDNSConfig DuckDNS 配置
type DuckDNSConfig struct {
	Token   string   `yaml:"token"`
	Domains []string `yaml:"domains"` // 子域名列表（不含 .duckdns.org）
}

// FreeDNSConfig FreeDNS 配置
type FreeDNSConfig struct {
	Token  string `yaml:"token"`  // 更新 token（从 FreeDNS 获取）
	Domain string `yaml:"domain"` // 完整域名
}

// NoIPConfig No-IP 配置
type NoIPConfig struct {
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	Hostname []string `yaml:"hostname"`
}

// DefaultDDNSConfig 默认 DDNS 配置
func DefaultDDNSConfig() *DDNSConfig {
	return &DDNSConfig{
		Enabled:        false,
		UpdateInterval: 5 * time.Minute,
		LogLevel:       1,
	}
}

// =============================================================================
// DDNS 管理器
// =============================================================================

// DDNSManager DDNS 管理器
type DDNSManager struct {
	config *DDNSConfig
	
	// 状态
	currentIP   string
	lastUpdate  time.Time
	lastError   error
	updateCount uint64
	errorCount  uint64
	
	// HTTP 客户端
	httpClient *http.Client
	
	// 同步
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.RWMutex
	running  bool
	logLevel int
	
	// 回调
	onIPChanged   func(oldIP, newIP string)
	onUpdateError func(err error)
}

// NewDDNSManager 创建 DDNS 管理器
func NewDDNSManager(cfg *DDNSConfig) *DDNSManager {
	if cfg == nil {
		cfg = DefaultDDNSConfig()
	}
	
	return &DDNSManager{
		config:   cfg,
		logLevel: cfg.LogLevel,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// DDNSOption DDNS 管理器选项
type DDNSOption func(*DDNSManager)

// WithDDNSLogLevel 设置日志级别
func WithDDNSLogLevel(level int) DDNSOption {
	return func(m *DDNSManager) {
		m.logLevel = level
	}
}

// WithOnIPChanged 设置 IP 变化回调
func WithOnIPChanged(fn func(oldIP, newIP string)) DDNSOption {
	return func(m *DDNSManager) {
		m.onIPChanged = fn
	}
}

// WithOnUpdateError 设置更新错误回调
func WithOnUpdateError(fn func(err error)) DDNSOption {
	return func(m *DDNSManager) {
		m.onUpdateError = fn
	}
}

// Start 启动 DDNS 管理器
func (m *DDNSManager) Start(ctx context.Context) error {
	if !m.config.Enabled {
		m.log(1, "DDNS 已禁用")
		return nil
	}
	
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("DDNS 管理器已在运行")
	}
	m.running = true
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.mu.Unlock()
	
	m.log(1, "启动 DDNS 管理器 (提供商: %s)", m.config.Provider)
	
	// 立即执行一次更新
	if err := m.updateOnce(); err != nil {
		m.log(0, "首次 DDNS 更新失败: %v", err)
		// 不阻止启动，后续会重试
	}
	
	// 启动定期更新
	go m.updateLoop()
	
	return nil
}

// Stop 停止 DDNS 管理器
func (m *DDNSManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if !m.running {
		return
	}
	
	if m.cancel != nil {
		m.cancel()
	}
	m.running = false
	m.log(1, "DDNS 管理器已停止")
}

// updateLoop 定期更新循环
func (m *DDNSManager) updateLoop() {
	interval := m.config.UpdateInterval
	if interval < time.Minute {
		interval = 5 * time.Minute
	}
	
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if err := m.updateOnce(); err != nil {
				m.log(0, "DDNS 更新失败: %v", err)
				m.mu.Lock()
				m.lastError = err
				m.errorCount++
				m.mu.Unlock()
				
				if m.onUpdateError != nil {
					m.onUpdateError(err)
				}
			}
		}
	}
}

// updateOnce 执行一次更新
func (m *DDNSManager) updateOnce() error {
	// 获取公网 IP
	newIP, err := m.GetPublicIP()
	if err != nil {
		return fmt.Errorf("获取公网 IP 失败: %w", err)
	}
	
	m.mu.RLock()
	oldIP := m.currentIP
	m.mu.RUnlock()
	
	// 检查 IP 是否变化
	if newIP == oldIP && oldIP != "" {
		m.log(2, "IP 未变化: %s", newIP)
		return nil
	}
	
	m.log(1, "IP 变化: %s -> %s", oldIP, newIP)
	
	// 根据提供商更新
	var updateErr error
	switch m.config.Provider {
	case DDNSProviderDuckDNS:
		updateErr = m.updateDuckDNS(newIP)
	case DDNSProviderFreeDNS:
		updateErr = m.updateFreeDNS(newIP)
	case DDNSProviderNoIP:
		updateErr = m.updateNoIP(newIP)
	default:
		updateErr = fmt.Errorf("不支持的 DDNS 提供商: %s", m.config.Provider)
	}
	
	if updateErr != nil {
		return updateErr
	}
	
	// 更新状态
	m.mu.Lock()
	m.currentIP = newIP
	m.lastUpdate = time.Now()
	m.updateCount++
	m.lastError = nil
	m.mu.Unlock()
	
	// 触发回调
	if m.onIPChanged != nil && oldIP != "" {
		m.onIPChanged(oldIP, newIP)
	}
	
	return nil
}

// =============================================================================
// 公网 IP 检测
// =============================================================================

// GetPublicIP 获取公网 IP
func (m *DDNSManager) GetPublicIP() (string, error) {
	return GetPublicIP(m.httpClient)
}

// GetPublicIP 获取公网 IP（独立函数）
func GetPublicIP(client *http.Client) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	
	var lastErr error
	for _, svc := range publicIPServices {
		ip, err := fetchIPFromService(client, svc)
		if err == nil && ip != "" {
			return ip, nil
		}
		lastErr = err
	}
	
	if lastErr != nil {
		return "", fmt.Errorf("所有 IP 检测服务都失败: %w", lastErr)
	}
	return "", fmt.Errorf("无法获取公网 IP")
}

// fetchIPFromService 从单个服务获取 IP
func fetchIPFromService(client *http.Client, serviceURL string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", serviceURL, nil)
	if err != nil {
		return "", err
	}
	
	req.Header.Set("User-Agent", "Phantom-DDNS/1.0")
	
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	
	ip := strings.TrimSpace(string(body))
	
	// 简单验证 IP 格式
	if !isValidIP(ip) {
		return "", fmt.Errorf("无效的 IP 格式: %s", ip)
	}
	
	return ip, nil
}

// isValidIP 验证 IP 格式
func isValidIP(ip string) bool {
	if ip == "" {
		return false
	}
	
	// 简单检查：包含点号且不包含空格
	hasDot := false
	for _, c := range ip {
		if c == '.' {
			hasDot = true
		}
		if c == ' ' || c == '\n' || c == '\r' {
			return false
		}
	}
	
	// IPv4 或 IPv6
	return hasDot || strings.Contains(ip, ":")
}

// =============================================================================
// DuckDNS 更新
// =============================================================================

// updateDuckDNS 更新 DuckDNS
func (m *DDNSManager) updateDuckDNS(ip string) error {
	// 获取配置
	token := m.config.DuckDNS.Token
	if token == "" {
		token = m.config.Token
	}
	
	domains := m.config.DuckDNS.Domains
	if len(domains) == 0 {
		domains = m.config.Domains
	}
	
	if token == "" {
		return fmt.Errorf("DuckDNS token 未配置")
	}
	if len(domains) == 0 {
		return fmt.Errorf("DuckDNS domains 未配置")
	}
	
	// 构建请求 URL
	// https://www.duckdns.org/update?domains=xxx&token=xxx&ip=xxx
	params := url.Values{}
	params.Set("domains", strings.Join(domains, ","))
	params.Set("token", token)
	params.Set("ip", ip)
	
	reqURL := fmt.Sprintf("%s?%s", DuckDNSAPIURL, params.Encode())
	
	m.log(2, "DuckDNS 请求: %s", DuckDNSAPIURL)
	
	// 发送请求
	resp, err := m.httpRequest("GET", reqURL, nil)
	if err != nil {
		return fmt.Errorf("DuckDNS 请求失败: %w", err)
	}
	
	// 检查响应
	resp = strings.TrimSpace(resp)
	if resp != "OK" && !strings.HasPrefix(resp, "OK") {
		return fmt.Errorf("DuckDNS 更新失败: %s", resp)
	}
	
	m.log(1, "DuckDNS 更新成功: %v -> %s", domains, ip)
	return nil
}

// UpdateDuckDNS 更新 DuckDNS（独立函数）
func UpdateDuckDNS(token string, domains []string, ip string) error {
	if token == "" {
		return fmt.Errorf("DuckDNS token 不能为空")
	}
	if len(domains) == 0 {
		return fmt.Errorf("DuckDNS domains 不能为空")
	}
	
	params := url.Values{}
	params.Set("domains", strings.Join(domains, ","))
	params.Set("token", token)
	if ip != "" {
		params.Set("ip", ip)
	}
	
	reqURL := fmt.Sprintf("%s?%s", DuckDNSAPIURL, params.Encode())
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(reqURL)
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}
	
	result := strings.TrimSpace(string(body))
	if result != "OK" && !strings.HasPrefix(result, "OK") {
		return fmt.Errorf("DuckDNS 返回错误: %s", result)
	}
	
	return nil
}

// =============================================================================
// FreeDNS 更新
// =============================================================================

// updateFreeDNS 更新 FreeDNS
func (m *DDNSManager) updateFreeDNS(ip string) error {
	token := m.config.FreeDNS.Token
	if token == "" {
		token = m.config.Token
	}
	
	if token == "" {
		return fmt.Errorf("FreeDNS token 未配置")
	}
	
	// FreeDNS 更新 URL 格式：
	// https://freedns.afraid.org/dynamic/update.php?<token>
	// 或带 IP：https://freedns.afraid.org/dynamic/update.php?<token>&address=<ip>
	reqURL := fmt.Sprintf("%s?%s", FreeDNSAPIURL, token)
	if ip != "" {
		reqURL = fmt.Sprintf("%s&address=%s", reqURL, ip)
	}
	
	m.log(2, "FreeDNS 请求: %s", FreeDNSAPIURL)
	
	resp, err := m.httpRequest("GET", reqURL, nil)
	if err != nil {
		return fmt.Errorf("FreeDNS 请求失败: %w", err)
	}
	
	// FreeDNS 返回格式: "Updated <domain> to <ip>"
	resp = strings.TrimSpace(resp)
	if strings.Contains(strings.ToLower(resp), "error") {
		return fmt.Errorf("FreeDNS 更新失败: %s", resp)
	}
	
	m.log(1, "FreeDNS 更新成功: %s", resp)
	return nil
}

// UpdateFreeDNS 更新 FreeDNS（独立函数）
func UpdateFreeDNS(token string, ip string) error {
	if token == "" {
		return fmt.Errorf("FreeDNS token 不能为空")
	}
	
	reqURL := fmt.Sprintf("%s?%s", FreeDNSAPIURL, token)
	if ip != "" {
		reqURL = fmt.Sprintf("%s&address=%s", reqURL, ip)
	}
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(reqURL)
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}
	
	result := strings.TrimSpace(string(body))
	if strings.Contains(strings.ToLower(result), "error") {
		return fmt.Errorf("FreeDNS 返回错误: %s", result)
	}
	
	return nil
}

// =============================================================================
// No-IP 更新
// =============================================================================

// updateNoIP 更新 No-IP
func (m *DDNSManager) updateNoIP(ip string) error {
	cfg := m.config.NoIP
	
	if cfg.Username == "" || cfg.Password == "" {
		return fmt.Errorf("No-IP 用户名或密码未配置")
	}
	if len(cfg.Hostname) == 0 {
		return fmt.Errorf("No-IP hostname 未配置")
	}
	
	// No-IP API 格式：
	// https://username:password@dynupdate.no-ip.com/nic/update?hostname=xxx&myip=xxx
	params := url.Values{}
	params.Set("hostname", strings.Join(cfg.Hostname, ","))
	if ip != "" {
		params.Set("myip", ip)
	}
	
	reqURL := fmt.Sprintf("%s?%s", NoIPAPIURL, params.Encode())
	
	// 创建带认证的请求
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}
	req.SetBasicAuth(cfg.Username, cfg.Password)
	req.Header.Set("User-Agent", "Phantom-DDNS/1.0 admin@example.com")
	
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("No-IP 请求失败: %w", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}
	
	result := strings.TrimSpace(string(body))
	
	// No-IP 返回码:
	// good <ip> - 成功
	// nochg <ip> - IP 未变化
	// nohost - 主机名不存在
	// badauth - 认证失败
	// badagent - User-Agent 被禁
	// !donator - 付费功能
	// abuse - 滥用
	// 911 - 服务器错误
	
	if strings.HasPrefix(result, "good") || strings.HasPrefix(result, "nochg") {
		m.log(1, "No-IP 更新成功: %s", result)
		return nil
	}
	
	return fmt.Errorf("No-IP 更新失败: %s", result)
}

// =============================================================================
// HTTP 辅助方法
// =============================================================================

// httpRequest 发送 HTTP 请求
func (m *DDNSManager) httpRequest(method, reqURL string, headers map[string]string) (string, error) {
	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return "", err
	}
	
	req.Header.Set("User-Agent", "Phantom-DDNS/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return "", err
	}
	
	return string(body), nil
}

// =============================================================================
// 状态查询
// =============================================================================

// GetCurrentIP 获取当前缓存的 IP
func (m *DDNSManager) GetCurrentIP() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentIP
}

// GetLastUpdate 获取最后更新时间
func (m *DDNSManager) GetLastUpdate() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastUpdate
}

// GetLastError 获取最后错误
func (m *DDNSManager) GetLastError() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastError
}

// GetStats 获取统计信息
func (m *DDNSManager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	stats := map[string]interface{}{
		"enabled":      m.config.Enabled,
		"provider":     string(m.config.Provider),
		"running":      m.running,
		"current_ip":   m.currentIP,
		"update_count": m.updateCount,
		"error_count":  m.errorCount,
	}
	
	if !m.lastUpdate.IsZero() {
		stats["last_update"] = m.lastUpdate.Format(time.RFC3339)
		stats["last_update_ago"] = time.Since(m.lastUpdate).String()
	}
	
	if m.lastError != nil {
		stats["last_error"] = m.lastError.Error()
	}
	
	return stats
}

// IsRunning 检查是否运行中
func (m *DDNSManager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// ForceUpdate 强制更新
func (m *DDNSManager) ForceUpdate() error {
	return m.updateOnce()
}

// =============================================================================
// 日志
// =============================================================================

func (m *DDNSManager) log(level int, format string, args ...interface{}) {
	if level > m.logLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [DDNS] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

// =============================================================================
// 辅助函数 - 获取完整域名
// =============================================================================

// GetDuckDNSDomain 获取完整的 DuckDNS 域名
func GetDuckDNSDomain(subdomain string) string {
	subdomain = strings.TrimSuffix(subdomain, ".duckdns.org")
	return subdomain + ".duckdns.org"
}

// GetDuckDNSSubdomain 从完整域名提取子域名
func GetDuckDNSSubdomain(domain string) string {
	return strings.TrimSuffix(domain, ".duckdns.org")
}
