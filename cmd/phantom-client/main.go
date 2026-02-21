
// cmd/phantom-client/main.go
// Phantom v4.0 Windows 客户端入口
// 系统装配器与环境初始化中心

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

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
	ServerAddr string `yaml:"server" json:"server"`
	ServerPort uint16 `yaml:"port" json:"port"`
	PSK        string `yaml:"psk" json:"psk"`

	// 本地
	SocksAddr string `yaml:"socks" json:"socks"`

	// 性能
	UploadMbps   int `yaml:"up" json:"up"`
	DownloadMbps int `yaml:"down" json:"down"`

	// 传输
	TransportMode  string `yaml:"transport" json:"transport"`
	TLSFingerprint string `yaml:"fingerprint" json:"fingerprint"`

	// 高级
	TimeWindow time.Duration `yaml:"time_window" json:"time_window"`
	LogLevel   string        `yaml:"log_level" json:"log_level"`
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
	cfg := &ClientConfig{
		// 设置默认值
		ServerPort:    54321,
		SocksAddr:     "127.0.0.1:1080",
		UploadMbps:    100,
		DownloadMbps:  100,
		TransportMode: "udp",
		TimeWindow:    30 * time.Second,
		LogLevel:      "info",
	}

	// 基础参数
	server := flag.String("server", "", "VPS 服务器地址")
	port := flag.Int("port", 0, "VPS 服务器端口")
	psk := flag.String("psk", "", "预共享密钥")
	socksAddr := flag.String("socks", "", "本地 SOCKS5 地址")

	// 性能参数
	up := flag.Int("up", 0, "上行带宽 (Mbps)")
	down := flag.Int("down", 0, "下行带宽 (Mbps)")

	// 传输参数
	transport := flag.String("transport", "", "传输模式: udp, faketcp, wss")
	fingerprint := flag.String("fingerprint", "", "TLS 指纹")

	// 高级参数
	timeWindow := flag.Int("time-window", 0, "时间窗口 (秒)")
	logLevel := flag.String("log", "", "日志级别")

	// 配置文件
	configFile := flag.String("config", "", "配置文件路径 (YAML)")

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

	// 修复：先加载配置文件，再用命令行参数覆盖
	if *configFile != "" {
		if err := loadConfigFile(*configFile, cfg); err != nil {
			fmt.Printf("[WARN] 加载配置文件失败: %v\n", err)
		}
	}

	// 命令行参数覆盖配置文件
	if *server != "" {
		cfg.ServerAddr = *server
	}
	if *port != 0 {
		cfg.ServerPort = uint16(*port)
	}
	if *psk != "" {
		cfg.PSK = *psk
	}
	if *socksAddr != "" {
		cfg.SocksAddr = *socksAddr
	}
	if *up != 0 {
		cfg.UploadMbps = *up
	}
	if *down != 0 {
		cfg.DownloadMbps = *down
	}
	if *transport != "" {
		cfg.TransportMode = *transport
	}
	if *fingerprint != "" {
		cfg.TLSFingerprint = *fingerprint
	}
	if *timeWindow != 0 {
		cfg.TimeWindow = time.Duration(*timeWindow) * time.Second
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}

	// 清理 PSK 中的空白字符
	cfg.PSK = strings.TrimSpace(cfg.PSK)

	// 修复：最后进行验证
	if cfg.ServerAddr == "" {
		fmt.Println("[ERROR] 必须指定服务器地址 (-server 或配置文件中的 server)")
		flag.Usage()
		os.Exit(1)
	}
	if cfg.PSK == "" {
		fmt.Println("[ERROR] 必须指定预共享密钥 (-psk 或配置文件中的 psk)")
		flag.Usage()
		os.Exit(1)
	}

	return cfg
}

// loadConfigFile 加载 YAML 配置文件
func loadConfigFile(path string, cfg *ClientConfig) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 使用 YAML 解析器
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("解析 YAML 失败: %w", err)
	}

	fmt.Printf("[INFO] 已加载配置文件: %s\n", path)
	return nil
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
			// 获取处理器统计
			hStats := app.handler.GetStats()
			// 获取 SOCKS5 统计
			sActive, sTotal := app.socksServer.Stats()

			fmt.Printf("[STATS] 活跃连接: %d/%d | 发送: %s | 接收: %s\n",
				sActive, sTotal,
				formatBytes(hStats.BytesSent),
				formatBytes(hStats.BytesReceived))
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

