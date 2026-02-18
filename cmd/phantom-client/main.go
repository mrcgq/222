


// cmd/phantom-client/main.go
// Phantom v4.0 Windows 客户端入口
// 系统装配器与环境初始化中心

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/mrcgq/211/internal/handler"
	"github.com/mrcgq/211/internal/socks5"
)

// ============================================
// 版本信息
// ============================================

var (
	Version   = "4.0.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// ============================================
// 应用结构
// ============================================

// Application 应用程序
type Application struct {
	config      *ClientConfig
	socksServer *socks5.Server
	handler     *handler.PhantomClientHandler

	ctx    context.Context
	cancel context.CancelFunc
}

// ClientConfig 客户端配置
type ClientConfig struct {
	// 服务端
	ServerAddr string `json:"server"`
	ServerPort uint16 `json:"port"`
	PSK        string `json:"psk"`

	// 本地
	SocksAddr string `json:"socks"`

	// 性能
	UploadMbps   int `json:"up"`
	DownloadMbps int `json:"down"`

	// 传输
	TransportMode  string `json:"transport"`
	TLSFingerprint string `json:"fingerprint"`

	// 高级
	TimeWindow time.Duration `json:"time_window"`
	LogLevel   string        `json:"log_level"`
}

// ============================================
// 主函数
// ============================================

func main() {
	// 解析配置
	cfg := parseFlags()

	// 打印横幅
	printBanner(cfg)

	// 创建应用
	app, err := NewApplication(cfg)
	if err != nil {
		fmt.Printf("[ERROR] 初始化失败: %v\n", err)
		os.Exit(1)
	}

	// 运行
	if err := app.Run(); err != nil {
		fmt.Printf("[ERROR] 运行失败: %v\n", err)
		os.Exit(1)
	}
}

// parseFlags 解析命令行参数
func parseFlags() *ClientConfig {
	cfg := &ClientConfig{}

	// 基础参数
	flag.StringVar(&cfg.ServerAddr, "server", "", "VPS 服务器地址 (必需)")
	port := flag.Int("port", 54321, "VPS 服务器端口")
	flag.StringVar(&cfg.PSK, "psk", "", "预共享密钥 (必需)")
	flag.StringVar(&cfg.SocksAddr, "socks", "127.0.0.1:1080", "本地 SOCKS5 地址")

	// 性能参数
	flag.IntVar(&cfg.UploadMbps, "up", 100, "上行带宽 (Mbps)")
	flag.IntVar(&cfg.DownloadMbps, "down", 100, "下行带宽 (Mbps)")

	// 传输参数
	flag.StringVar(&cfg.TransportMode, "transport", "udp", "传输模式: udp, faketcp, wss")
	flag.StringVar(&cfg.TLSFingerprint, "fingerprint", "chrome", "TLS 指纹")

	// 高级参数
	timeWindow := flag.Int("time-window", 30, "时间窗口 (秒)")
	flag.StringVar(&cfg.LogLevel, "log", "info", "日志级别")

	// 配置文件
	configFile := flag.String("config", "", "配置文件路径")

	// 其他
	showVersion := flag.Bool("version", false, "显示版本")

	flag.Parse()

	// 版本信息
	if *showVersion {
		fmt.Printf("Phantom Client v%s\n", Version)
		fmt.Printf("Build: %s\n", BuildTime)
		fmt.Printf("Go: %s\n", runtime.Version())
		fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// 加载配置文件
	if *configFile != "" {
		loadConfig(*configFile, cfg)
	}

	// 应用参数
	cfg.ServerPort = uint16(*port)
	cfg.TimeWindow = time.Duration(*timeWindow) * time.Second

	// 验证
	if cfg.ServerAddr == "" {
		fmt.Println("[ERROR] 必须指定 -server")
		flag.Usage()
		os.Exit(1)
	}
	if cfg.PSK == "" {
		fmt.Println("[ERROR] 必须指定 -psk")
		flag.Usage()
		os.Exit(1)
	}

	return cfg
}

// loadConfig 加载配置文件
func loadConfig(path string, cfg *ClientConfig) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("[WARN] 无法读取配置文件: %v\n", err)
		return
	}
	json.Unmarshal(data, cfg)
}

// printBanner 打印横幅
func printBanner(cfg *ClientConfig) {
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║           Phantom Protocol v4.0 Ultimate Edition          ║")
	fmt.Println("║                    Windows Client Engine                  ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════╣")
	fmt.Printf("║  服务器: %-48s ║\n", fmt.Sprintf("%s:%d", cfg.ServerAddr, cfg.ServerPort))
	fmt.Printf("║  传输层: %-48s ║\n", cfg.TransportMode)
	fmt.Printf("║  带宽:   上行 %3d Mbps / 下行 %3d Mbps                     ║\n", cfg.UploadMbps, cfg.DownloadMbps)
	fmt.Printf("║  代理:   %-48s ║\n", cfg.SocksAddr)
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// ============================================
// 应用生命周期
// ============================================

// NewApplication 创建应用
func NewApplication(cfg *ClientConfig) (*Application, error) {
	ctx, cancel := context.WithCancel(context.Background())

	app := &Application{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
	}

	// 1. 初始化协议处理器
	handlerCfg := &handler.Config{
		ServerAddr:     cfg.ServerAddr,
		ServerPort:     cfg.ServerPort,
		PSK:            cfg.PSK,
		TimeWindow:     cfg.TimeWindow,
		UploadMbps:     cfg.UploadMbps,
		DownloadMbps:   cfg.DownloadMbps,
		TransportMode:  cfg.TransportMode,
		TLSFingerprint: cfg.TLSFingerprint,
	}

	h, err := handler.NewClientHandler(handlerCfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("handler init failed: %w", err)
	}
	app.handler = h

	// 2. 初始化 SOCKS5 服务器
	app.socksServer = socks5.New(cfg.SocksAddr, h)

	return app, nil
}

// Run 运行应用
func (app *Application) Run() error {
	fmt.Println("[INFO] 正在启动...")

	// 启动统计
	go app.statsLoop()

	// 启动 SOCKS5
	go func() {
		if err := app.socksServer.Listen(); err != nil {
			fmt.Printf("[ERROR] SOCKS5 错误: %v\n", err)
			app.cancel()
		}
	}()

	fmt.Printf("[INFO] SOCKS5 代理就绪: %s\n", app.config.SocksAddr)
	fmt.Println("[INFO] 按 Ctrl+C 退出")
	fmt.Println()

	// 等待退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		fmt.Printf("\n[INFO] 收到信号 %v\n", sig)
	case <-app.ctx.Done():
	}

	// 关闭
	return app.shutdown()
}

// statsLoop 统计循环
func (app *Application) statsLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-app.ctx.Done():
			return
		case <-ticker.C:
			stats := app.handler.GetStats()
			active, total := app.socksServer.Stats()
			fmt.Printf("[STATS] 连接: %d/%d | 发送: %s | 接收: %s\n",
				active, total,
				formatBytes(stats.BytesSent),
				formatBytes(stats.BytesReceived))
		}
	}
}

// shutdown 关闭
func (app *Application) shutdown() error {
	fmt.Println("[INFO] 正在关闭...")

	app.cancel()

	if app.socksServer != nil {
		app.socksServer.Close()
	}
	if app.handler != nil {
		app.handler.Close()
	}

	fmt.Println("[INFO] 已停止")
	return nil
}

// formatBytes 格式化字节
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
