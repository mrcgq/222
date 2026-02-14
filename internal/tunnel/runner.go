// =============================================================================
// 文件: internal/tunnel/runner.go
// 描述: Cloudflare Tunnel 进程管理 - 封装 cloudflared 子进程的启动、监控和停止
// =============================================================================
package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// 常量定义
// =============================================================================

const (
	// URL 解析超时时间
	URLParseTimeout = 30 * time.Second

	// 进程健康检查间隔
	HealthCheckInterval = 10 * time.Second

	// 进程重启延迟
	RestartDelay = 5 * time.Second

	// 最大重启次数
	MaxRestartAttempts = 5

	// 重启计数器重置时间（成功运行这么长时间后重置重启计数）
	RestartCounterResetTime = 5 * time.Minute
)

// TunnelMode 隧道模式
type TunnelMode string

const (
	ModeTempTunnel  TunnelMode = "temp"
	ModeFixedTunnel TunnelMode = "fixed"
	ModeDirectTCP   TunnelMode = "direct"
)

// =============================================================================
// CloudflaredRunner - cloudflared 进程管理器
// =============================================================================

// CloudflaredRunner 管理 cloudflared 子进程
type CloudflaredRunner struct {
	// 配置
	binaryPath string
	mode       TunnelMode
	localAddr  string
	localPort  int
	protocol   string

	// 固定隧道配置
	cfToken    string
	cfTunnelID string

	// 权限管理
	privManager *PrivilegeManager

	// 进程状态
	cmd        *exec.Cmd
	cancelFunc context.CancelFunc
	running    atomic.Bool
	tunnelURL  atomic.Value // string
	domain     atomic.Value // string

	// 输出管道
	stdout io.ReadCloser
	stderr io.ReadCloser

	// 回调函数
	onURLReady    func(url string)
	onError       func(err error)
	onStateChange func(running bool)

	// 重启控制
	restartCount   int
	lastRestartAt  time.Time
	autoRestart    bool
	restartEnabled atomic.Bool

	// 日志
	logLevel  int
	logPrefix string

	// 同步
	mu       sync.RWMutex
	wg       sync.WaitGroup
	doneChan chan struct{}
}

// RunnerConfig 运行器配置
type RunnerConfig struct {
	BinaryPath  string
	Mode        TunnelMode
	LocalAddr   string
	LocalPort   int
	Protocol    string // http, https, tcp
	CFToken     string
	CFTunnelID  string
	PrivManager *PrivilegeManager
	AutoRestart bool
	LogLevel    int

	// 回调
	OnURLReady    func(url string)
	OnError       func(err error)
	OnStateChange func(running bool)
}

// NewCloudflaredRunner 创建新的 cloudflared 运行器
func NewCloudflaredRunner(cfg *RunnerConfig) (*CloudflaredRunner, error) {
	if cfg.BinaryPath == "" {
		return nil, fmt.Errorf("binaryPath 不能为空")
	}

	if cfg.LocalPort <= 0 || cfg.LocalPort > 65535 {
		return nil, fmt.Errorf("无效的端口号: %d", cfg.LocalPort)
	}

	if cfg.Mode == ModeFixedTunnel {
		if cfg.CFToken == "" {
			return nil, fmt.Errorf("固定隧道模式需要 cf_token")
		}
	}

	localAddr := cfg.LocalAddr
	if localAddr == "" {
		localAddr = "127.0.0.1"
	}

	protocol := cfg.Protocol
	if protocol == "" {
		protocol = "http"
	}

	runner := &CloudflaredRunner{
		binaryPath:  cfg.BinaryPath,
		mode:        cfg.Mode,
		localAddr:   localAddr,
		localPort:   cfg.LocalPort,
		protocol:    protocol,
		cfToken:     cfg.CFToken,
		cfTunnelID:  cfg.CFTunnelID,
		privManager: cfg.PrivManager,
		autoRestart: cfg.AutoRestart,
		logLevel:    cfg.LogLevel,
		logPrefix:   "[CloudflaredRunner]",
		doneChan:    make(chan struct{}),

		onURLReady:    cfg.OnURLReady,
		onError:       cfg.OnError,
		onStateChange: cfg.OnStateChange,
	}

	runner.tunnelURL.Store("")
	runner.domain.Store("")
	runner.restartEnabled.Store(cfg.AutoRestart)

	return runner, nil
}

// Start 启动 cloudflared 进程
func (r *CloudflaredRunner) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running.Load() {
		return fmt.Errorf("cloudflared 已在运行中")
	}

	// 创建可取消的上下文
	runCtx, cancel := context.WithCancel(ctx)
	r.cancelFunc = cancel

	// 重置状态
	r.doneChan = make(chan struct{})

	// 根据模式启动
	var err error
	switch r.mode {
	case ModeTempTunnel:
		err = r.startTempTunnel(runCtx)
	case ModeFixedTunnel:
		err = r.startFixedTunnel(runCtx)
	case ModeDirectTCP:
		err = r.startDirectTCP(runCtx)
	default:
		err = fmt.Errorf("未知的隧道模式: %s", r.mode)
	}

	if err != nil {
		cancel()
		return err
	}

	r.running.Store(true)
	r.notifyStateChange(true)

	// 启动输出监控
	r.wg.Add(1)
	go r.monitorOutput(runCtx)

	// 启动进程监控
	r.wg.Add(1)
	go r.monitorProcess(runCtx)

	return nil
}

// startTempTunnel 启动临时隧道
func (r *CloudflaredRunner) startTempTunnel(ctx context.Context) error {
	// 构建本地 URL
	localURL := fmt.Sprintf("%s://%s:%d", r.protocol, r.localAddr, r.localPort)

	r.log(1, "启动临时隧道: %s -> cloudflare", localURL)

	// 构建命令参数
	args := []string{
		"tunnel",
		"--url", localURL,
		"--no-autoupdate",
	}

	return r.startProcess(ctx, args)
}

// startFixedTunnel 启动固定隧道
func (r *CloudflaredRunner) startFixedTunnel(ctx context.Context) error {
	r.log(1, "启动固定隧道: tunnel_id=%s", r.cfTunnelID)

	// 构建命令参数
	args := []string{
		"tunnel",
		"run",
		"--token", r.cfToken,
	}

	// 如果指定了 tunnel ID，添加到参数
	if r.cfTunnelID != "" {
		args = append(args, r.cfTunnelID)
	}

	return r.startProcess(ctx, args)
}

// startDirectTCP 启动直接 TCP 模式
func (r *CloudflaredRunner) startDirectTCP(ctx context.Context) error {
	localAddr := fmt.Sprintf("%s:%d", r.localAddr, r.localPort)

	r.log(1, "启动 TCP 隧道: %s -> cloudflare", localAddr)

	args := []string{
		"tunnel",
		"--url", fmt.Sprintf("tcp://%s", localAddr),
		"--no-autoupdate",
	}

	return r.startProcess(ctx, args)
}

// startProcess 启动进程
func (r *CloudflaredRunner) startProcess(ctx context.Context, args []string) error {
	cmd := exec.CommandContext(ctx, r.binaryPath, args...)

	// 配置权限降级
	if r.privManager != nil && r.privManager.IsEnabled() {
		if err := r.privManager.ConfigureCommand(cmd); err != nil {
			r.log(0, "配置权限降级失败: %v", err)
			// 继续执行，不中断
		}
	}

	// 获取 stdout 和 stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("获取 stdout 失败: %w", err)
	}
	r.stdout = stdout

	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdout.Close()
		return fmt.Errorf("获取 stderr 失败: %w", err)
	}
	r.stderr = stderr

	// 设置环境变量（禁用自动更新检查）
	cmd.Env = append(os.Environ(),
		"TUNNEL_METRICS=",
		"NO_AUTOUPDATE=true",
	)

	// 启动进程
	if err := cmd.Start(); err != nil {
		stdout.Close()
		stderr.Close()
		return fmt.Errorf("启动 cloudflared 失败: %w", err)
	}

	r.cmd = cmd
	r.log(1, "cloudflared 进程已启动: PID=%d", cmd.Process.Pid)

	return nil
}

// monitorOutput 监控进程输出
func (r *CloudflaredRunner) monitorOutput(ctx context.Context) {
	defer r.wg.Done()

	// URL 匹配正则表达式
	// 匹配格式如: https://xxx-xxx-xxx.trycloudflare.com
	urlRegex := regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`)
	// 备用匹配：任何 trycloudflare.com 域名
	altRegex := regexp.MustCompile(`([a-zA-Z0-9-]+\.trycloudflare\.com)`)

	urlFound := make(chan string, 1)
	var urlOnce sync.Once

	// 处理单行输出
	processLine := func(line string, source string) {
		r.log(2, "[%s] %s", source, line)

		// 只在临时隧道模式下解析 URL
		if r.mode == ModeTempTunnel {
			// 尝试匹配完整 URL
			if match := urlRegex.FindString(line); match != "" {
				urlOnce.Do(func() {
					urlFound <- match
				})
				return
			}

			// 备用匹配
			if strings.Contains(line, "trycloudflare.com") {
				if matches := altRegex.FindStringSubmatch(line); len(matches) > 1 {
					url := "https://" + matches[1]
					urlOnce.Do(func() {
						urlFound <- url
					})
				}
			}
		}

		// 检测错误信息
		if strings.Contains(strings.ToLower(line), "error") ||
			strings.Contains(strings.ToLower(line), "failed") {
			r.notifyError(fmt.Errorf("cloudflared: %s", line))
		}
	}

	// 启动 stdout 读取
	go func() {
		if r.stdout == nil {
			return
		}
		scanner := bufio.NewScanner(r.stdout)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 增大缓冲区
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
				processLine(scanner.Text(), "stdout")
			}
		}
	}()

	// 启动 stderr 读取
	go func() {
		if r.stderr == nil {
			return
		}
		scanner := bufio.NewScanner(r.stderr)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
				processLine(scanner.Text(), "stderr")
			}
		}
	}()

	// 等待 URL（仅临时隧道模式）
	if r.mode == ModeTempTunnel {
		select {
		case url := <-urlFound:
			r.tunnelURL.Store(url)
			r.domain.Store(extractDomain(url))
			r.log(1, "隧道 URL 已就绪: %s", url)
			r.notifyURLReady(url)

		case <-time.After(URLParseTimeout):
			r.log(0, "等待隧道 URL 超时 (%v)", URLParseTimeout)
			r.notifyError(fmt.Errorf("等待隧道 URL 超时"))

		case <-ctx.Done():
			return
		}
	}

	// 继续等待上下文取消
	<-ctx.Done()
}

// monitorProcess 监控进程状态
func (r *CloudflaredRunner) monitorProcess(ctx context.Context) {
	defer r.wg.Done()
	defer close(r.doneChan)

	if r.cmd == nil || r.cmd.Process == nil {
		return
	}

	// 等待进程退出
	err := r.cmd.Wait()

	r.running.Store(false)
	r.notifyStateChange(false)

	if err != nil {
		r.log(1, "cloudflared 进程退出: %v", err)
	} else {
		r.log(1, "cloudflared 进程正常退出")
	}

	// 检查是否需要重启
	select {
	case <-ctx.Done():
		// 上下文已取消，不重启
		return
	default:
		if r.restartEnabled.Load() {
			r.handleRestart(ctx)
		}
	}
}

// handleRestart 处理进程重启
func (r *CloudflaredRunner) handleRestart(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 检查是否应该重置重启计数器
	if time.Since(r.lastRestartAt) > RestartCounterResetTime {
		r.restartCount = 0
	}

	// 检查重启次数
	if r.restartCount >= MaxRestartAttempts {
		r.log(0, "达到最大重启次数 (%d)，停止重启", MaxRestartAttempts)
		r.notifyError(fmt.Errorf("cloudflared 多次重启失败"))
		return
	}

	r.restartCount++
	r.lastRestartAt = time.Now()

	r.log(1, "准备重启 cloudflared (%d/%d)，延迟 %v",
		r.restartCount, MaxRestartAttempts, RestartDelay)

	// 延迟重启
	select {
	case <-time.After(RestartDelay):
	case <-ctx.Done():
		return
	}

	// 重新启动
	r.mu.Unlock() // 释放锁以避免死锁
	if err := r.Start(ctx); err != nil {
		r.log(0, "重启失败: %v", err)
		r.notifyError(err)
	}
	r.mu.Lock() // 重新获取锁
}

// Stop 停止 cloudflared 进程
func (r *CloudflaredRunner) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 禁用自动重启
	r.restartEnabled.Store(false)

	if !r.running.Load() {
		return nil
	}

	r.log(1, "正在停止 cloudflared...")

	// 取消上下文
	if r.cancelFunc != nil {
		r.cancelFunc()
	}

	// 发送 SIGTERM
	if r.cmd != nil && r.cmd.Process != nil {
		if err := r.cmd.Process.Signal(os.Interrupt); err != nil {
			r.log(2, "发送 SIGTERM 失败: %v，尝试 SIGKILL", err)
			r.cmd.Process.Kill()
		}
	}

	// 等待进程退出（带超时）
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		r.log(1, "cloudflared 已停止")
	case <-time.After(10 * time.Second):
		r.log(0, "等待进程退出超时，强制终止")
		if r.cmd != nil && r.cmd.Process != nil {
			r.cmd.Process.Kill()
		}
	}

	// 关闭管道
	if r.stdout != nil {
		r.stdout.Close()
	}
	if r.stderr != nil {
		r.stderr.Close()
	}

	r.running.Store(false)
	r.tunnelURL.Store("")
	r.domain.Store("")

	return nil
}

// IsRunning 检查是否运行中
func (r *CloudflaredRunner) IsRunning() bool {
	return r.running.Load()
}

// GetTunnelURL 获取隧道 URL
func (r *CloudflaredRunner) GetTunnelURL() string {
	if v := r.tunnelURL.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// GetDomain 获取域名
func (r *CloudflaredRunner) GetDomain() string {
	if v := r.domain.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// GetPID 获取进程 PID
func (r *CloudflaredRunner) GetPID() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.cmd != nil && r.cmd.Process != nil {
		return r.cmd.Process.Pid
	}
	return 0
}

// WaitForURL 等待 URL 就绪
func (r *CloudflaredRunner) WaitForURL(timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if url := r.GetTunnelURL(); url != "" {
			return url, nil
		}

		select {
		case <-r.doneChan:
			return "", fmt.Errorf("进程已退出")
		case <-time.After(500 * time.Millisecond):
			continue
		}
	}

	return "", fmt.Errorf("等待 URL 超时")
}

// SetAutoRestart 设置自动重启
func (r *CloudflaredRunner) SetAutoRestart(enabled bool) {
	r.restartEnabled.Store(enabled)
}

// =============================================================================
// 回调通知
// =============================================================================

func (r *CloudflaredRunner) notifyURLReady(url string) {
	if r.onURLReady != nil {
		go r.onURLReady(url)
	}
}

func (r *CloudflaredRunner) notifyError(err error) {
	if r.onError != nil {
		go r.onError(err)
	}
}

func (r *CloudflaredRunner) notifyStateChange(running bool) {
	if r.onStateChange != nil {
		go r.onStateChange(running)
	}
}

// =============================================================================
// 日志
// =============================================================================

func (r *CloudflaredRunner) log(level int, format string, args ...interface{}) {
	if level > r.logLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s %s %s\n",
		prefix,
		time.Now().Format("15:04:05"),
		r.logPrefix,
		fmt.Sprintf(format, args...))
}

// =============================================================================
// 辅助函数
// =============================================================================

// extractDomain 从 URL 中提取域名
func extractDomain(url string) string {
	// 移除协议前缀
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	// 移除路径
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	// 移除端口
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	return url
}

// =============================================================================
// RunnerStatus 运行器状态
// =============================================================================

// RunnerStatus 运行器状态信息
type RunnerStatus struct {
	Running      bool          `json:"running"`
	Mode         TunnelMode    `json:"mode"`
	TunnelURL    string        `json:"tunnel_url,omitempty"`
	Domain       string        `json:"domain,omitempty"`
	PID          int           `json:"pid,omitempty"`
	RestartCount int           `json:"restart_count"`
	Uptime       time.Duration `json:"uptime,omitempty"`
}

// GetStatus 获取运行器状态
func (r *CloudflaredRunner) GetStatus() RunnerStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return RunnerStatus{
		Running:      r.running.Load(),
		Mode:         r.mode,
		TunnelURL:    r.GetTunnelURL(),
		Domain:       r.GetDomain(),
		PID:          r.GetPID(),
		RestartCount: r.restartCount,
	}
}
