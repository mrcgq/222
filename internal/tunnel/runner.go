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
	"syscall"
	"time"
)

// =============================================================================
// 常量定义
// =============================================================================

const (
	URLParseTimeout         = 30 * time.Second
	HealthCheckInterval     = 10 * time.Second
	RestartDelay            = 5 * time.Second
	MaxRestartAttempts      = 5
	RestartCounterResetTime = 5 * time.Minute
	GracefulStopTimeout     = 10 * time.Second
)

type TunnelMode string

const (
	ModeTempTunnel  TunnelMode = "temp"
	ModeFixedTunnel TunnelMode = "fixed"
	ModeDirectTCP   TunnelMode = "direct"
)

// =============================================================================
// CloudflaredRunner - cloudflared 进程管理器
// =============================================================================

type CloudflaredRunner struct {
	binaryPath string
	mode       TunnelMode
	localAddr  string
	localPort  int
	protocol   string

	cfToken    string
	cfTunnelID string

	privManager *PrivilegeManager

	cmd        *exec.Cmd
	cancelFunc context.CancelFunc
	running    atomic.Bool
	tunnelURL  atomic.Value
	domain     atomic.Value

	stdout io.ReadCloser
	stderr io.ReadCloser

	onURLReady    func(url string)
	onError       func(err error)
	onStateChange func(running bool)

	restartCount   int
	lastRestartAt  time.Time
	autoRestart    bool
	restartEnabled atomic.Bool

	logLevel  int
	logPrefix string

	mu       sync.RWMutex
	wg       sync.WaitGroup
	doneChan chan struct{}
}

type RunnerConfig struct {
	BinaryPath  string
	Mode        TunnelMode
	LocalAddr   string
	LocalPort   int
	Protocol    string
	CFToken     string
	CFTunnelID  string
	PrivManager *PrivilegeManager
	AutoRestart bool
	LogLevel    int

	OnURLReady    func(url string)
	OnError       func(err error)
	OnStateChange func(running bool)
}

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

func (r *CloudflaredRunner) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running.Load() {
		return fmt.Errorf("cloudflared 已在运行中")
	}

	// 修复：确保二进制文件有执行权限
	if err := os.Chmod(r.binaryPath, 0755); err != nil {
		r.log(1, "设置执行权限失败: %v (继续尝试启动)", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	r.cancelFunc = cancel

	r.doneChan = make(chan struct{})

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

	r.wg.Add(1)
	go r.monitorOutput(runCtx)

	r.wg.Add(1)
	go r.monitorProcess(runCtx)

	return nil
}

func (r *CloudflaredRunner) startTempTunnel(ctx context.Context) error {
	localURL := fmt.Sprintf("%s://%s:%d", r.protocol, r.localAddr, r.localPort)

	r.log(1, "启动临时隧道: %s -> cloudflare", localURL)

	args := []string{
		"tunnel",
		"--url", localURL,
		"--no-autoupdate",
	}

	return r.startProcess(ctx, args)
}

func (r *CloudflaredRunner) startFixedTunnel(ctx context.Context) error {
	r.log(1, "启动固定隧道: tunnel_id=%s", r.cfTunnelID)

	args := []string{
		"tunnel",
		"run",
		"--token", r.cfToken,
	}

	if r.cfTunnelID != "" {
		args = append(args, r.cfTunnelID)
	}

	return r.startProcess(ctx, args)
}

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

func (r *CloudflaredRunner) startProcess(ctx context.Context, args []string) error {
	cmd := exec.CommandContext(ctx, r.binaryPath, args...)

	if r.privManager != nil && r.privManager.IsEnabled() {
		if err := r.privManager.ConfigureCommand(cmd); err != nil {
			r.log(0, "配置权限降级失败: %v", err)
		}
	}

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

	cmd.Env = append(os.Environ(),
		"TUNNEL_METRICS=",
		"NO_AUTOUPDATE=true",
	)

	// 修复：设置进程组，便于完整清理子进程
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if err := cmd.Start(); err != nil {
		stdout.Close()
		stderr.Close()
		return fmt.Errorf("启动 cloudflared 失败: %w", err)
	}

	r.cmd = cmd
	r.log(1, "cloudflared 进程已启动: PID=%d", cmd.Process.Pid)

	return nil
}

func (r *CloudflaredRunner) monitorOutput(ctx context.Context) {
	defer r.wg.Done()

	urlRegex := regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`)
	altRegex := regexp.MustCompile(`([a-zA-Z0-9-]+\.trycloudflare\.com)`)

	urlFound := make(chan string, 1)
	var urlOnce sync.Once

	processLine := func(line string, source string) {
		r.log(2, "[%s] %s", source, line)

		if r.mode == ModeTempTunnel {
			if match := urlRegex.FindString(line); match != "" {
				urlOnce.Do(func() {
					urlFound <- match
				})
				return
			}

			if strings.Contains(line, "trycloudflare.com") {
				if matches := altRegex.FindStringSubmatch(line); len(matches) > 1 {
					url := "https://" + matches[1]
					urlOnce.Do(func() {
						urlFound <- url
					})
				}
			}
		}

		if strings.Contains(strings.ToLower(line), "error") ||
			strings.Contains(strings.ToLower(line), "failed") {
			r.notifyError(fmt.Errorf("cloudflared: %s", line))
		}
	}

	go func() {
		if r.stdout == nil {
			return
		}
		scanner := bufio.NewScanner(r.stdout)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
				processLine(scanner.Text(), "stdout")
			}
		}
	}()

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

	<-ctx.Done()
}

func (r *CloudflaredRunner) monitorProcess(ctx context.Context) {
	defer r.wg.Done()
	defer close(r.doneChan)

	if r.cmd == nil || r.cmd.Process == nil {
		return
	}

	err := r.cmd.Wait()

	r.running.Store(false)
	r.notifyStateChange(false)

	if err != nil {
		r.log(1, "cloudflared 进程退出: %v", err)
	} else {
		r.log(1, "cloudflared 进程正常退出")
	}

	select {
	case <-ctx.Done():
		return
	default:
		if r.restartEnabled.Load() {
			r.handleRestart(ctx)
		}
	}
}

func (r *CloudflaredRunner) handleRestart(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if time.Since(r.lastRestartAt) > RestartCounterResetTime {
		r.restartCount = 0
	}

	if r.restartCount >= MaxRestartAttempts {
		r.log(0, "达到最大重启次数 (%d)，停止重启", MaxRestartAttempts)
		r.notifyError(fmt.Errorf("cloudflared 多次重启失败"))
		return
	}

	r.restartCount++
	r.lastRestartAt = time.Now()

	r.log(1, "准备重启 cloudflared (%d/%d)，延迟 %v",
		r.restartCount, MaxRestartAttempts, RestartDelay)

	select {
	case <-time.After(RestartDelay):
	case <-ctx.Done():
		return
	}

	r.mu.Unlock()
	if err := r.Start(ctx); err != nil {
		r.log(0, "重启失败: %v", err)
		r.notifyError(err)
	}
	r.mu.Lock()
}

// Stop 停止 cloudflared 进程
// 修复：使用进程组确保完整清理子进程
func (r *CloudflaredRunner) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.restartEnabled.Store(false)

	if !r.running.Load() {
		return nil
	}

	r.log(1, "正在停止 cloudflared...")

	if r.cancelFunc != nil {
		r.cancelFunc()
	}

	// 修复：通过进程组发送信号，确保子进程也被终止
	if r.cmd != nil && r.cmd.Process != nil {
		pid := r.cmd.Process.Pid
		
		// 先尝试优雅终止（SIGTERM 到进程组）
		if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
			r.log(2, "发送 SIGTERM 到进程组失败: %v", err)
			// 回退到单进程
			r.cmd.Process.Signal(syscall.SIGTERM)
		}
	}

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		r.log(1, "cloudflared 已停止")
	case <-time.After(GracefulStopTimeout):
		r.log(0, "等待进程退出超时，强制终止")
		if r.cmd != nil && r.cmd.Process != nil {
			pid := r.cmd.Process.Pid
			// 强制终止进程组
			syscall.Kill(-pid, syscall.SIGKILL)
			r.cmd.Process.Kill()
		}
	}

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

func (r *CloudflaredRunner) IsRunning() bool {
	return r.running.Load()
}

func (r *CloudflaredRunner) GetTunnelURL() string {
	if v := r.tunnelURL.Load(); v != nil {
		return v.(string)
	}
	return ""
}

func (r *CloudflaredRunner) GetDomain() string {
	if v := r.domain.Load(); v != nil {
		return v.(string)
	}
	return ""
}

func (r *CloudflaredRunner) GetPID() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.cmd != nil && r.cmd.Process != nil {
		return r.cmd.Process.Pid
	}
	return 0
}

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

func extractDomain(url string) string {
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	return url
}

// =============================================================================
// RunnerStatus 运行器状态
// =============================================================================

type RunnerStatus struct {
	Running      bool          `json:"running"`
	Mode         TunnelMode    `json:"mode"`
	TunnelURL    string        `json:"tunnel_url,omitempty"`
	Domain       string        `json:"domain,omitempty"`
	PID          int           `json:"pid,omitempty"`
	RestartCount int           `json:"restart_count"`
	Uptime       time.Duration `json:"uptime,omitempty"`
}

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
