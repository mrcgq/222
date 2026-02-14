



// =============================================================================
// 文件: cmd/phantom-server/main.go
// 描述: 主程序入口 - 集成 Prometheus 指标
// =============================================================================
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
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

	// 创建统一处理器（注入指标）
	unifiedHandler := handler.NewUnifiedHandler(cry, cfg, phantomMetrics)

	// 创建智能链路切换器（注入指标）
	sw := switcher.New(cfg, cry, unifiedHandler, phantomMetrics)

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
	var tunnelMgr *tunnel.TunnelManager
	if cfg.Tunnel.Enabled {
		tunnelMgr = tunnel.NewTunnelManager(&cfg.Tunnel)
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
	return a.sw.GetStats().ARQActiveConns
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
// 其他函数（保持不变）
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
	fmt.Println("监控:")
	fmt.Println("  - /metrics  : Prometheus 格式指标")
	fmt.Println("  - /health   : JSON 健康状态")
}

func printBanner(cfg *config.Config, sw *switcher.Switcher, tm *tunnel.TunnelManager, ms *metrics.MetricsServer) {
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
		fmt.Printf("║    URL: %-58s ║\n", url)
		domain := tm.GetDomain()
		if domain != "" {
			fmt.Printf("║    域名: %-57s ║\n", domain)
		}
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








