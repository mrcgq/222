// =============================================================================
// 文件: internal/tunnel/downloader.go
// 描述: 外部依赖下载器 - 仅 cloudflared（已移除 acme.sh）
// =============================================================================
package tunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// =============================================================================
// 版本信息
// =============================================================================

// BinaryInfo 二进制信息
type BinaryInfo struct {
	Name       string
	Version    string
	URL        string
	SHA256     string
	InstallDir string
}

// CloudflaredVersions cloudflared 版本信息
// 版本锁定，确保可重复构建
var CloudflaredVersions = map[string]BinaryInfo{
	"linux-amd64": {
		Name:       "cloudflared",
		Version:    "2024.1.5",
		URL:        "https://github.com/cloudflare/cloudflared/releases/download/2024.1.5/cloudflared-linux-amd64",
		SHA256:     "", // 留空表示跳过校验
		InstallDir: "/usr/local/bin",
	},
	"linux-arm64": {
		Name:       "cloudflared",
		Version:    "2024.1.5",
		URL:        "https://github.com/cloudflare/cloudflared/releases/download/2024.1.5/cloudflared-linux-arm64",
		SHA256:     "",
		InstallDir: "/usr/local/bin",
	},
	"linux-arm": {
		Name:       "cloudflared",
		Version:    "2024.1.5",
		URL:        "https://github.com/cloudflare/cloudflared/releases/download/2024.1.5/cloudflared-linux-arm",
		SHA256:     "",
		InstallDir: "/usr/local/bin",
	},
	"darwin-amd64": {
		Name:       "cloudflared",
		Version:    "2024.1.5",
		URL:        "https://github.com/cloudflare/cloudflared/releases/download/2024.1.5/cloudflared-darwin-amd64.tgz",
		SHA256:     "",
		InstallDir: "/usr/local/bin",
	},
	"darwin-arm64": {
		Name:       "cloudflared",
		Version:    "2024.1.5",
		URL:        "https://github.com/cloudflare/cloudflared/releases/download/2024.1.5/cloudflared-darwin-arm64.tgz",
		SHA256:     "",
		InstallDir: "/usr/local/bin",
	},
	"windows-amd64": {
		Name:       "cloudflared.exe",
		Version:    "2024.1.5",
		URL:        "https://github.com/cloudflare/cloudflared/releases/download/2024.1.5/cloudflared-windows-amd64.exe",
		SHA256:     "",
		InstallDir: "",
	},
	"windows-386": {
		Name:       "cloudflared.exe",
		Version:    "2024.1.5",
		URL:        "https://github.com/cloudflare/cloudflared/releases/download/2024.1.5/cloudflared-windows-386.exe",
		SHA256:     "",
		InstallDir: "",
	},
}

// =============================================================================
// 下载器
// =============================================================================

// BinaryDownloader 二进制下载器
type BinaryDownloader struct {
	cacheDir   string
	httpClient *http.Client
	logLevel   int

	// 下载进度回调
	progressCallback func(downloaded, total int64)
}

// DownloaderOption 下载器选项
type DownloaderOption func(*BinaryDownloader)

// WithCacheDir 设置缓存目录
func WithCacheDir(dir string) DownloaderOption {
	return func(d *BinaryDownloader) {
		d.cacheDir = dir
	}
}

// WithProgressCallback 设置进度回调
func WithProgressCallback(cb func(downloaded, total int64)) DownloaderOption {
	return func(d *BinaryDownloader) {
		d.progressCallback = cb
	}
}

// WithLogLevel 设置日志级别
func WithLogLevel(level int) DownloaderOption {
	return func(d *BinaryDownloader) {
		d.logLevel = level
	}
}

// NewBinaryDownloader 创建下载器
func NewBinaryDownloader(cacheDir string, opts ...DownloaderOption) *BinaryDownloader {
	if cacheDir == "" {
		// 优先使用用户目录
		homeDir, err := os.UserHomeDir()
		if err == nil {
			cacheDir = filepath.Join(homeDir, ".phantom", "bin")
		} else {
			cacheDir = filepath.Join(os.TempDir(), "phantom-binaries")
		}
	}
	os.MkdirAll(cacheDir, 0755)

	d := &BinaryDownloader{
		cacheDir: cacheDir,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				DisableCompression:  false,
				DisableKeepAlives:   false,
				MaxIdleConnsPerHost: 5,
			},
		},
		logLevel: 1,
	}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

// EnsureCloudflared 确保 cloudflared 已安装
func (d *BinaryDownloader) EnsureCloudflared() (string, error) {
	// 1. 检查系统 PATH
	if path, err := exec.LookPath("cloudflared"); err == nil {
		if d.verifyCloudflared(path) {
			version, _ := d.getCloudflaredVersion(path)
			d.log(2, "发现系统 cloudflared: %s (版本: %s)", path, version)
			return path, nil
		}
	}

	// 2. 检查标准安装位置
	standardPaths := d.getStandardPaths()
	for _, p := range standardPaths {
		if d.verifyCloudflared(p) {
			d.log(2, "发现已安装的 cloudflared: %s", p)
			return p, nil
		}
	}

	// 3. 检查缓存
	arch := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	info, ok := CloudflaredVersions[arch]
	if !ok {
		return "", fmt.Errorf("不支持的平台: %s", arch)
	}

	cachedPath := d.getCachedPath(info)
	if d.isValidBinary(cachedPath, info.SHA256) {
		d.log(1, "使用缓存的 cloudflared: %s", cachedPath)
		return cachedPath, nil
	}

	// 4. 下载
	d.log(1, "下载 cloudflared %s for %s...", info.Version, arch)
	if err := d.downloadCloudflared(info, cachedPath); err != nil {
		return "", fmt.Errorf("下载 cloudflared 失败: %w", err)
	}

	// 5. 验证下载的文件
	if !d.verifyCloudflared(cachedPath) {
		os.Remove(cachedPath)
		return "", fmt.Errorf("下载的 cloudflared 无法执行")
	}

	d.log(1, "cloudflared 已下载并验证: %s", cachedPath)
	return cachedPath, nil
}

// getStandardPaths 获取标准安装路径
func (d *BinaryDownloader) getStandardPaths() []string {
	paths := []string{}

	switch runtime.GOOS {
	case "linux", "darwin":
		paths = append(paths,
			"/usr/local/bin/cloudflared",
			"/usr/bin/cloudflared",
		)
		if home, err := os.UserHomeDir(); err == nil {
			paths = append(paths, filepath.Join(home, ".local/bin/cloudflared"))
		}
	case "windows":
		if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
			paths = append(paths, filepath.Join(programFiles, "cloudflared", "cloudflared.exe"))
		}
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			paths = append(paths, filepath.Join(localAppData, "cloudflared", "cloudflared.exe"))
		}
	}

	return paths
}

// getCachedPath 获取缓存路径
func (d *BinaryDownloader) getCachedPath(info BinaryInfo) string {
	name := fmt.Sprintf("cloudflared-%s-%s", info.Version, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(d.cacheDir, name)
}

// verifyCloudflared 验证 cloudflared 是否可用
func (d *BinaryDownloader) verifyCloudflared(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 {
		return false
	}

	// 检查是否可执行
	if runtime.GOOS != "windows" {
		if info.Mode()&0111 == 0 {
			return false
		}
	}

	// 尝试执行 --version
	cmd := exec.Command(path, "--version")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// 验证输出包含 cloudflared
	return strings.Contains(strings.ToLower(string(output)), "cloudflared")
}

// downloadCloudflared 下载 cloudflared
func (d *BinaryDownloader) downloadCloudflared(info BinaryInfo, destPath string) error {
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 创建临时文件
	tmpPath := destPath + ".tmp"
	defer os.Remove(tmpPath)

	// 发起请求
	d.log(2, "请求: %s", info.URL)
	resp, err := d.httpClient.Get(info.URL)
	if err != nil {
		return fmt.Errorf("HTTP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP 状态码: %d", resp.StatusCode)
	}

	// 创建输出文件
	out, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}

	// 计算哈希并写入
	hash := sha256.New()
	var writer io.Writer = out

	// 如果有进度回调，包装 writer
	if d.progressCallback != nil {
		writer = &progressWriter{
			writer:   out,
			total:    resp.ContentLength,
			callback: d.progressCallback,
		}
	}

	writer = io.MultiWriter(writer, hash)

	_, err = io.Copy(writer, resp.Body)
	out.Close()
	if err != nil {
		return fmt.Errorf("写入失败: %w", err)
	}

	// 验证哈希（如果配置了）
	if info.SHA256 != "" {
		actualHash := hex.EncodeToString(hash.Sum(nil))
		if !strings.EqualFold(actualHash, info.SHA256) {
			return fmt.Errorf("SHA256 校验失败: 期望 %s, 实际 %s", info.SHA256, actualHash)
		}
		d.log(2, "SHA256 校验通过")
	}

	// 处理压缩文件（macOS）
	if strings.HasSuffix(info.URL, ".tgz") || strings.HasSuffix(info.URL, ".tar.gz") {
		if err := d.extractTgz(tmpPath, destPath); err != nil {
			return fmt.Errorf("解压失败: %w", err)
		}
	} else {
		// 直接重命名
		if err := os.Rename(tmpPath, destPath); err != nil {
			return fmt.Errorf("重命名失败: %w", err)
		}
	}

	// 设置可执行权限
	if runtime.GOOS != "windows" {
		if err := os.Chmod(destPath, 0755); err != nil {
			return fmt.Errorf("设置权限失败: %w", err)
		}
	}

	return nil
}

// extractTgz 解压 tgz 文件
func (d *BinaryDownloader) extractTgz(tgzPath, destPath string) error {
	destDir := filepath.Dir(destPath)

	// 使用系统 tar 命令解压
	cmd := exec.Command("tar", "-xzf", tgzPath, "-C", destDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tar 解压失败: %w\n%s", err, string(output))
	}

	// 查找解压出的文件
	extractedPath := filepath.Join(destDir, "cloudflared")
	if _, err := os.Stat(extractedPath); err == nil {
		return os.Rename(extractedPath, destPath)
	}

	return fmt.Errorf("未找到解压的 cloudflared 文件")
}

// isValidBinary 检查二进制是否有效
func (d *BinaryDownloader) isValidBinary(path, expectedHash string) bool {
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 {
		return false
	}

	// 检查是否可执行
	if runtime.GOOS != "windows" {
		if info.Mode()&0111 == 0 {
			return false
		}
	}

	// 如果配置了哈希，验证哈希
	if expectedHash != "" {
		file, err := os.Open(path)
		if err != nil {
			return false
		}
		defer file.Close()

		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			return false
		}

		actualHash := hex.EncodeToString(hash.Sum(nil))
		if !strings.EqualFold(actualHash, expectedHash) {
			d.log(2, "哈希不匹配: %s vs %s", actualHash, expectedHash)
			return false
		}
	}

	return true
}

// getCloudflaredVersion 获取 cloudflared 版本
func (d *BinaryDownloader) getCloudflaredVersion(path string) (string, error) {
	cmd := exec.Command(path, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// 解析版本号
	version := strings.TrimSpace(string(output))
	// cloudflared version 2024.1.5 (built 2024-01-15T12:00:00Z)
	parts := strings.Fields(version)
	if len(parts) >= 3 {
		return parts[2], nil
	}

	return version, nil
}

// GetCacheDir 获取缓存目录
func (d *BinaryDownloader) GetCacheDir() string {
	return d.cacheDir
}

// CleanCache 清理缓存
func (d *BinaryDownloader) CleanCache() error {
	return os.RemoveAll(d.cacheDir)
}

// log 日志输出
func (d *BinaryDownloader) log(level int, format string, args ...interface{}) {
	if level > d.logLevel {
		return
	}
	prefix := map[int]string{0: "[ERROR]", 1: "[INFO]", 2: "[DEBUG]"}[level]
	fmt.Printf("%s %s [Downloader] %s\n", prefix, time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

// =============================================================================
// 辅助类型
// =============================================================================

// progressWriter 进度写入器
type progressWriter struct {
	writer     io.Writer
	total      int64
	downloaded int64
	callback   func(downloaded, total int64)
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.writer.Write(p)
	pw.downloaded += int64(n)
	if pw.callback != nil {
		pw.callback(pw.downloaded, pw.total)
	}
	return n, err
}

// =============================================================================
// 预构建检查
// =============================================================================

// VerifyCloudflaredIntegrity 验证 cloudflared 完整性
func VerifyCloudflaredIntegrity(path string) error {
	// 1. 检查文件存在
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("文件不存在: %w", err)
	}

	// 2. 检查大小（cloudflared 通常 > 20MB）
	if info.Size() < 20*1024*1024 {
		return fmt.Errorf("文件大小异常: %d bytes", info.Size())
	}

	// 3. 尝试执行 --version
	cmd := exec.Command(path, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("执行失败: %w", err)
	}

	// 4. 验证输出格式
	if !strings.Contains(string(output), "cloudflared version") {
		return fmt.Errorf("版本输出格式异常: %s", string(output))
	}

	return nil
}

// GetLatestCloudflaredVersion 获取最新 cloudflared 版本（从 GitHub API）
func GetLatestCloudflaredVersion() (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/cloudflare/cloudflared/releases/latest")
	if err != nil {
		return "", fmt.Errorf("获取版本信息失败: %w", err)
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("解析响应失败: %w", err)
	}

	return release.TagName, nil
}

// UpdateCloudflaredVersions 更新版本信息（用于自动更新场景）
func UpdateCloudflaredVersions(version string) {
	for arch := range CloudflaredVersions {
		info := CloudflaredVersions[arch]
		info.Version = version

		// 更新下载 URL
		var filename string
		switch arch {
		case "linux-amd64":
			filename = "cloudflared-linux-amd64"
		case "linux-arm64":
			filename = "cloudflared-linux-arm64"
		case "linux-arm":
			filename = "cloudflared-linux-arm"
		case "darwin-amd64":
			filename = "cloudflared-darwin-amd64.tgz"
		case "darwin-arm64":
			filename = "cloudflared-darwin-arm64.tgz"
		case "windows-amd64":
			filename = "cloudflared-windows-amd64.exe"
		case "windows-386":
			filename = "cloudflared-windows-386.exe"
		default:
			continue
		}

		info.URL = fmt.Sprintf("https://github.com/cloudflare/cloudflared/releases/download/%s/%s", version, filename)
		info.SHA256 = "" // 清空哈希，跳过校验
		CloudflaredVersions[arch] = info
	}
}
