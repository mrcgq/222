// =============================================================================
// 文件: cmd/phantom-server/main.go
// 描述: 主程序入口 - 集成 Prometheus 指标和 Cloudflare 隧道
// =============================================================================
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/mrcgq/211/internal/config"
	"github.com/mrcgq/211/internal/crypto"
	"github.com/mrcgq/211/internal/handler"
	"github.com/mrcgq/211/internal/metrics"
	"github.com/mrcgq/211/internal/switcher"
	"github.com/mrcgq/211/internal/tunnel"
)

var (
	Version   = "4.0.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
	startTime = time.Now()
)

func main() {
	configPath := flag.String("c", "config.yaml", "配置文件路径")
	showVersion := flag.Bool("v", false, "显示版本")
	genPSK := flag.Bool("gen-psk", false, "生成新的 PSK")
	mode := flag.String("mode", "auto", "运行模式: auto/udp/faketcp/websocket/ebpf")

	tunnelMode := flag.String("tunnel", "", "隧道模式: temp/fixed/direct/off")
	tunnelDomain := flag.String("domain", "", "域名模式: auto/sslip/nip/duckdns/custom")
	tunnelCert := flag.String("cert", "", "证书模式: auto/selfsigned/letsencrypt")
	quickTunnel := flag.Bool("quick", false, "快速启动临时隧道")

	flag.Parse()

	if *showVersion {
		printVersion()
		return
	}

	if *genPSK {
		psk, _ := crypto.GeneratePSK()
		fmt.Println(psk)
		return
	}

	// 加载配置
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置错误: %v\n", err)
		os.Exit(1)
	}

	// 覆盖模式
	if *mode != "auto" {
		cfg.Mode = *mode
	}

	// 处理快速隧道
	if *quickTunnel {
		cfg.Tunnel.Enabled = true
		cfg.Tunnel.Mode = "temp"
		cfg.Tunnel.DomainMode = "auto"
	}

	// 覆盖隧道配置
	if *tunnelMode != "" {
		cfg.Tunnel.Enabled = *tunnelMode != "off"
		if *tunnelMode != "off" {
			cfg.Tunnel.Mode = *tunnelMode
		}
	}
	if *tunnelDomain != "" {
		cfg.Tunnel.DomainMode = *tunnelDomain
	}
	if *tunnelCert != "" {
		_ = tunnelCert
	}

	// 创建加密器
	cry, err := crypto.New(cfg.PSK, cfg.TimeWindow)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加密模块错误: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建 Metrics 服务器（提前创建以获取 registry）
	var metricsServer *metrics.MetricsServer
	var phantomMetrics *metrics.PhantomMetrics

	if cfg.Metrics.Enabled {
		metricsServer = metrics.NewMetricsServer(
			cfg.Metrics.Listen,
			cfg.Metrics.Path,
			cfg.Metrics.HealthPath,
			cfg.Metrics.EnablePprof,
		)

		// 创建实时埋点指标
		phantomMetrics = metrics.NewPhantomMetrics(metricsServer.GetRegistry())
	}

	// 创建统一处理器
	unifiedHandler := handler.NewUnifiedHandler(cry, cfg)

	// 如果有 phantomMetrics，设置到 handler
	if phantomMetrics != nil {
		unifiedHandler.SetMetrics(phantomMetrics)
	}

	// 创建智能链路切换器
	sw := switcher.New(cfg, cry, unifiedHandler)

	// 如果有 phantomMetrics，设置到 switcher
	if phantomMetrics != nil {
		sw.SetMetrics(phantomMetrics)
	}

	// 注册 Prometheus 收集器
	if metricsServer != nil {
		// 注册 Switcher 收集器
		switcherCollector := metrics.NewSwitcherCollector(
			&switcherStatsAdapter{sw: sw},
		)
		metricsServer.MustRegisterCollector(switcherCollector)

		// 注册 Handler 收集器
		handlerCollector := metrics.NewHandlerCollector(
			&handlerStatsAdapter{h: unifiedHandler},
		)
		metricsServer.MustRegisterCollector(handlerCollector)

		// 设置健康检查
		metricsServer.SetHealthCheck(func() metrics.HealthStatus {
			return createHealthStatus(sw, unifiedHandler)
		})

		if err := metricsServer.Start(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Metrics 启动失败: %v\n", err)
		}
	}

	// 启动服务
	if err := sw.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "启动失败: %v\n", err)
		os.Exit(1)
	}

	// 启动隧道
	var tunnelMgr *TunnelManager
	if cfg.Tunnel.Enabled {
		tunnelMgr = NewTunnelManager(&cfg.Tunnel, cfg.GetListenPort())
		if err := tunnelMgr.Start(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "隧道启动失败: %v (继续运行)\n", err)
		}
	}

	printBanner(cfg, sw, tunnelMgr, metricsServer)

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n正在关闭...")
	cancel()

	if metricsServer != nil {
		metricsServer.Stop()
	}
	if tunnelMgr != nil {
		tunnelMgr.Stop()
	}
	sw.Stop()
}

// =============================================================================
// TunnelManager - Cloudflare 隧道管理器
// =============================================================================

// TunnelManager 隧道管理器
type TunnelManager struct {
	config    *config.TunnelConfig
	localPort int

	// 子组件
	downloader  *tunnel.BinaryDownloader
	privManager *tunnel.PrivilegeManager
	runner      *tunnel.CloudflaredRunner

	// 状态
	running   bool
	tunnelURL string
	domain    string
	startTime time.Time

	// 同步
	mu     sync.RWMutex
	cancel context.CancelFunc
}

// NewTunnelManager 创建隧道管理器
func NewTunnelManager(cfg *config.TunnelConfig, listenPort int) *TunnelManager {
	// 使用配置的端口，如果未配置则使用主监听端口
	localPort := cfg.LocalPort
	if localPort == 0 {
		localPort = listenPort
	}

	return &TunnelManager{
		config:    cfg,
		localPort: localPort,
	}
}

// Start 启动隧道
func (tm *TunnelManager) Start(ctx context.Context) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if !tm.config.Enabled {
		return nil
	}

	tm.startTime = time.Now()

	// 创建可取消的上下文
	runCtx, cancel := context.WithCancel(ctx)
	tm.cancel = cancel

	// 1. 初始化下载器
	tm.downloader = tunnel.NewBinaryDownloader("",
		tunnel.WithLogLevel(1),
		tunnel.WithProgressCallback(func(downloaded, total int64) {
			if total > 0 {
				percent := float64(downloaded) / float64(total) * 100
				fmt.Printf("\r下载 cloudflared: %.1f%%", percent)
			}
		}),
	)

	// 2. 确保 cloudflared 可用
	binaryPath, err := tm.downloader.EnsureCloudflared()
	if err != nil {
		cancel()
		return fmt.Errorf("获取 cloudflared 失败: %w", err)
	}

	fmt.Printf("\n") // 换行（下载进度后）

	// 3. 初始化权限管理器
	privCfg := tunnel.DefaultPrivilegeConfig()
	tm.privManager, err = tunnel.NewPrivilegeManager(privCfg)
	if err != nil {
		// 权限管理器初始化失败不阻止启动
		fmt.Printf("[WARN] 权限管理器初始化失败: %v\n", err)
	}

	// 4. 确定隧道模式
	mode := tm.determineTunnelMode()

	// 5. 创建运行器
	runnerCfg := &tunnel.RunnerConfig{
		BinaryPath:  binaryPath,
		Mode:        mode,
		LocalAddr:   tm.config.LocalAddr,
		LocalPort:   tm.localPort,
		Protocol:    tm.config.Protocol,
		CFToken:     tm.config.CFToken,
		CFTunnelID:  tm.config.CFTunnelID,
		PrivManager: tm.privManager,
		AutoRestart: true,
		LogLevel:    1,

		OnURLReady: func(url string) {
			tm.mu.Lock()
			tm.tunnelURL = url
			tm.domain = extractDomainFromURL(url)
			tm.mu.Unlock()
			fmt.Printf("[INFO] 隧道 URL 就绪: %s\n", url)
		},
		OnError: func(err error) {
			fmt.Printf("[ERROR] 隧道错误: %v\n", err)
		},
		OnStateChange: func(running bool) {
			tm.mu.Lock()
			tm.running = running
			tm.mu.Unlock()
		},
	}

	tm.runner, err = tunnel.NewCloudflaredRunner(runnerCfg)
	if err != nil {
		cancel()
		return fmt.Errorf("创建 cloudflared 运行器失败: %w", err)
	}

	// 6. 启动运行器
	if err := tm.runner.Start(runCtx); err != nil {
		cancel()
		return fmt.Errorf("启动 cloudflared 失败: %w", err)
	}

	tm.running = true

	// 7. 对于临时隧道，等待 URL 就绪
	if mode == tunnel.ModeTempTunnel {
		go func() {
			url, err := tm.runner.WaitForURL(30 * time.Second)
			if err != nil {
				fmt.Printf("[WARN] 等待隧道 URL 失败: %v\n", err)
			} else {
				fmt.Printf("[INFO] 临时隧道已建立: %s\n", url)
			}
		}()
	}

	return nil
}

// determineTunnelMode 确定隧道模式
func (tm *TunnelManager) determineTunnelMode() tunnel.TunnelMode {
	switch tm.config.Mode {
	case "temp":
		return tunnel.ModeTempTunnel
	case "fixed":
		return tunnel.ModeFixedTunnel
	case "direct":
		return tunnel.ModeDirectTCP
	default:
		// 如果有 token，使用固定模式；否则使用临时模式
		if tm.config.CFToken != "" {
			return tunnel.ModeFixedTunnel
		}
		return tunnel.ModeTempTunnel
	}
}

// Stop 停止隧道
func (tm *TunnelManager) Stop() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.cancel != nil {
		tm.cancel()
	}

	if tm.runner != nil {
		if err := tm.runner.Stop(); err != nil {
			fmt.Printf("[WARN] 停止 cloudflared 失败: %v\n", err)
		}
	}

	tm.running = false
	tm.tunnelURL = ""
	tm.domain = ""
}

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

// GetStatus 获取状态
func (tm *TunnelManager) GetStatus() map[string]interface{} {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	status := map[string]interface{}{
		"running": tm.running,
		"mode":    tm.config.Mode,
	}

	if tm.running {
		status["uptime"] = time.Since(tm.startTime).String()
	}

	if tm.tunnelURL != "" {
		status["url"] = tm.tunnelURL
		status["domain"] = tm.domain
	}

	if tm.runner != nil {
		status["pid"] = tm.runner.GetPID()
	}

	return status
}

// extractDomainFromURL 从 URL 中提取域名
func extractDomainFromURL(url string) string {
	// 移除协议前缀
	for _, prefix := range []string{"https://", "http://"} {
		if len(url) > len(prefix) && url[:len(prefix)] == prefix {
			url = url[len(prefix):]
			break
		}
	}

	// 移除路径和端口
	for _, sep := range []string{"/", ":"} {
		if idx := indexOf(url, sep); idx != -1 {
			url = url[:idx]
		}
	}

	return url
}

// indexOf 查找字符串位置
func indexOf(s, substr string) int {
	for i := 0; i < len(s); i++ {
		if i+len(substr) <= len(s) && s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// =============================================================================
// 适配器：将 Switcher 和 Handler 适配到 Prometheus 收集器接口
// =============================================================================

// switcherStatsAdapter 适配 Switcher 到 SwitcherStats 接口
type switcherStatsAdapter struct {
	sw *switcher.Switcher
}

func (a *switcherStatsAdapter) GetCurrentMode() string {
	return string(a.sw.GetStats().CurrentMode)
}

func (a *switcherStatsAdapter) GetCurrentState() string {
	return a.sw.GetStats().CurrentState.String()
}

func (a *switcherStatsAdapter) GetTotalSwitches() uint64 {
	return a.sw.GetStats().TotalSwitches
}

func (a *switcherStatsAdapter) GetSuccessSwitches() uint64 {
	return a.sw.GetStats().SuccessSwitches
}

func (a *switcherStatsAdapter) GetFailedSwitches() uint64 {
	return a.sw.GetStats().FailedSwitches
}

func (a *switcherStatsAdapter) GetUptimeSeconds() float64 {
	return a.sw.GetStats().Uptime.Seconds()
}

func (a *switcherStatsAdapter) GetCurrentModeTimeSeconds() float64 {
	return a.sw.GetStats().CurrentModeTime.Seconds()
}

func (a *switcherStatsAdapter) IsARQEnabled() bool {
	return a.sw.GetStats().ARQEnabled
}

func (a *switcherStatsAdapter) GetARQActiveConns() int {
	return int(a.sw.GetStats().ARQActiveConns)
}

func (a *switcherStatsAdapter) GetModeStats() map[string]metrics.ModeStatData {
	result := make(map[string]metrics.ModeStatData)
	for mode, ms := range a.sw.GetStats().ModeStats {
		data := metrics.ModeStatData{
			State:          ms.State.String(),
			SwitchInCount:  ms.SwitchInCount,
			SwitchOutCount: ms.SwitchOutCount,
			FailureCount:   ms.FailureCount,
			TotalTimeSec:   ms.TotalTime.Seconds(),
		}
		if ms.Quality != nil {
			data.RTTMs = float64(ms.Quality.RTT.Milliseconds())
			data.LossRate = ms.Quality.LossRate
			data.TotalPackets = ms.Quality.TotalPackets
		}
		result[string(mode)] = data
	}
	return result
}

// handlerStatsAdapter 适配 Handler 到 HandlerStats 接口
type handlerStatsAdapter struct {
	h *handler.UnifiedHandler
}

func (a *handlerStatsAdapter) GetActiveConnections() int64 {
	return int64(a.h.GetActiveConns())
}

func (a *handlerStatsAdapter) GetTotalConnections() uint64 {
	stats := a.h.GetStats()
	if v, ok := stats["total_connections"].(uint64); ok {
		return v
	}
	return 0
}

func (a *handlerStatsAdapter) GetTotalPacketsIn() uint64 {
	stats := a.h.GetStats()
	if v, ok := stats["packets_in"].(uint64); ok {
		return v
	}
	return 0
}

func (a *handlerStatsAdapter) GetTotalPacketsOut() uint64 {
	stats := a.h.GetStats()
	if v, ok := stats["packets_out"].(uint64); ok {
		return v
	}
	return 0
}

func (a *handlerStatsAdapter) GetTotalBytesIn() uint64 {
	stats := a.h.GetStats()
	if v, ok := stats["bytes_in"].(uint64); ok {
		return v
	}
	return 0
}

func (a *handlerStatsAdapter) GetTotalBytesOut() uint64 {
	stats := a.h.GetStats()
	if v, ok := stats["bytes_out"].(uint64); ok {
		return v
	}
	return 0
}

func (a *handlerStatsAdapter) GetAuthSuccessCount() uint64 {
	stats := a.h.GetStats()
	if v, ok := stats["auth_success"].(uint64); ok {
		return v
	}
	return 0
}

func (a *handlerStatsAdapter) GetAuthFailureCount() uint64 {
	stats := a.h.GetStats()
	if v, ok := stats["auth_failure"].(uint64); ok {
		return v
	}
	return 0
}

func (a *handlerStatsAdapter) GetDecryptErrors() uint64 {
	stats := a.h.GetStats()
	if v, ok := stats["decrypt_errors"].(uint64); ok {
		return v
	}
	return 0
}

func (a *handlerStatsAdapter) GetReplayAttacks() uint64 {
	stats := a.h.GetStats()
	if v, ok := stats["replay_attacks"].(uint64); ok {
		return v
	}
	return 0
}

// =============================================================================
// 其他函数
// =============================================================================

// createHealthStatus 创建健康状态
func createHealthStatus(sw *switcher.Switcher, h *handler.UnifiedHandler) metrics.HealthStatus {
	status := metrics.HealthStatus{
		Status:     "healthy",
		Timestamp:  time.Now(),
		Version:    Version,
		Uptime:     time.Since(startTime),
		Components: make(map[string]metrics.ComponentHealth),
	}

	stats := sw.GetStats()

	// 传输层状态
	if stats.CurrentState == switcher.StateRunning {
		status.Components["transport"] = metrics.ComponentHealth{
			Status:  "healthy",
			Message: fmt.Sprintf("mode: %s", stats.CurrentMode),
		}
	} else {
		status.Status = "degraded"
		status.Components["transport"] = metrics.ComponentHealth{
			Status:  "degraded",
			Message: fmt.Sprintf("state: %s", stats.CurrentState),
		}
	}

	// 连接状态
	activeConns := h.GetActiveConns()
	status.Components["connections"] = metrics.ComponentHealth{
		Status:  "healthy",
		Message: fmt.Sprintf("active: %d", activeConns),
	}

	// ARQ 状态
	if stats.ARQEnabled {
		status.Components["arq"] = metrics.ComponentHealth{
			Status:  "healthy",
			Message: fmt.Sprintf("active_conns: %d", stats.ARQActiveConns),
		}
	}

	// 拥塞控制状态
	if sw.HasHysteria2() {
		status.Components["congestion"] = metrics.ComponentHealth{
			Status:  "healthy",
			Message: "hysteria2 active",
		}
	}

	return status
}

func printVersion() {
	fmt.Printf("Phantom Server v%s (Ultimate Edition)\n", Version)
	fmt.Printf("  Build: %s\n", BuildTime)
	fmt.Printf("  Commit: %s\n", GitCommit)
	fmt.Printf("  Go: %s\n", runtime.Version())
	fmt.Printf("  OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()
	fmt.Println("支持模式:")
	fmt.Println("  - auto      : 自动检测最优模式")
	fmt.Println("  - udp       : 原生 UDP + ARQ 增强 (低延迟)")
	fmt.Println("  - faketcp   : FakeTCP 伪装 (绕过 QoS)")
	fmt.Println("  - websocket : WebSocket/CDN (高隐蔽)")
	fmt.Println("  - ebpf      : eBPF 内核加速 (极致性能)")
	fmt.Println()
	fmt.Println("隧道模式:")
	fmt.Println("  - temp      : Cloudflare 临时隧道 (无需配置)")
	fmt.Println("  - fixed     : Cloudflare 固定隧道 (需要 token)")
	fmt.Println("  - direct    : 直接 TCP 隧道")
	fmt.Println()
	fmt.Println("监控:")
	fmt.Println("  - /metrics  : Prometheus 格式指标")
	fmt.Println("  - /health   : JSON 健康状态")
}

func printBanner(cfg *config.Config, sw *switcher.Switcher, tm *TunnelManager, ms *metrics.MetricsServer) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║         Phantom Server v4.0 - Ultimate Edition                   ║")
	fmt.Println("║         eBPF + Hysteria2 + FakeTCP + WebSocket/CDN               ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  主模式: %-55s ║\n", sw.CurrentMode())
	fmt.Printf("║  监听端口: %-53s ║\n", formatListenPorts(cfg))
	fmt.Printf("║  时间窗口: %-53s ║\n", fmt.Sprintf("%d 秒", cfg.TimeWindow))

	if tm != nil && tm.IsRunning() {
		fmt.Println("╠══════════════════════════════════════════════════════════════════╣")
		fmt.Println("║  Cloudflare 隧道:                                                ║")
		url := tm.GetTunnelURL()
		if url == "" {
			url = "(正在建立...)"
		}
		fmt.Printf("║    URL: %-58s ║\n", truncateString(url, 58))
		domain := tm.GetDomain()
		if domain != "" {
			fmt.Printf("║    域名: %-57s ║\n", truncateString(domain, 57))
		}
		fmt.Printf("║    模式: %-57s ║\n", cfg.Tunnel.Mode)
	}

	if ms != nil {
		fmt.Println("╠══════════════════════════════════════════════════════════════════╣")
		fmt.Printf("║  Prometheus: http://localhost%s%-35s ║\n", cfg.Metrics.Listen, cfg.Metrics.Path)
		fmt.Printf("║  健康检查:   http://localhost%s%-33s ║\n", cfg.Metrics.Listen, cfg.Metrics.HealthPath)
	}

	fmt.Println("╠══════════════════════════════════════════════════════════════════╣")
	fmt.Println("║  已启用功能:                                                     ║")
	if sw.HasEBPF() {
		fmt.Println("║    ✓ eBPF/XDP 内核加速                                           ║")
	}
	if sw.HasFakeTCP() {
		fmt.Println("║    ✓ FakeTCP 伪装 (绕过 UDP QoS)                                 ║")
	}
	if sw.HasHysteria2() {
		fmt.Println("║    ✓ Hysteria2 拥塞控制 (暴力抗丢包)                             ║")
	}
	if sw.HasARQ() {
		fmt.Println("║    ✓ ARQ 可靠传输 (UDP 增强层)                                   ║")
	}
	if sw.HasWebSocket() {
		fmt.Println("║    ✓ WebSocket/CDN 回退 (终极隐蔽)                               ║")
	}
	if tm != nil && tm.IsRunning() {
		fmt.Println("║    ✓ Cloudflare 隧道 (全球加速)                                  ║")
	}
	fmt.Println("║    ✓ TSKD 0-RTT 认证                                             ║")
	fmt.Println("║    ✓ ChaCha20-Poly1305 加密                                      ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════════╣")
	fmt.Println("║  按 Ctrl+C 停止                                                  ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func formatListenPorts(cfg *config.Config) string {
	ports := cfg.Listen
	if cfg.FakeTCP.Enabled {
		ports += fmt.Sprintf(", %s (FakeTCP)", cfg.FakeTCP.Listen)
	}
	if cfg.WebSocket.Enabled {
		ports += fmt.Sprintf(", %s (WS)", cfg.WebSocket.Listen)
	}
	return ports
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
