


// =============================================================================
// 文件: internal/tunnel/downloader.go
// 描述: 外部依赖下载器 - 仅 cloudflared（已移除 acme.sh）
// =============================================================================
package tunnel

import (
	"crypto/sha256"
	"encoding/hex"
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
		SHA256:     "a]6b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3", // 示例哈希，部署时替换
		InstallDir: "/usr/local/bin",
	},
	"linux-arm64": {
		Name:       "cloudflared",
		Version:    "2024.1.5",
		URL:        "https://github.com/cloudflare/cloudflared/releases/download/2024.1.5/cloudflared-linux-arm64",
		SHA256:     "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3", // 示例哈希，部署时替换
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
		cacheDir = filepath.Join(os.TempDir(), "phantom-binaries")
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
		version, _ := d.getCloudflaredVersion(path)
		d.log(2, "发现系统 cloudflared: %s (版本: %s)", path, version)
		return path, nil
	}

	// 2. 检查标准安装位置
	standardPaths := []string{
		"/usr/local/bin/cloudflared",
		"/usr/bin/cloudflared",
		filepath.Join(os.Getenv("HOME"), ".local/bin/cloudflared"),
	}

	for _, p := range standardPaths {
		if _, err := os.Stat(p); err == nil {
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

	cachedPath := filepath.Join(d.cacheDir, fmt.Sprintf("cloudflared-%s-%s", info.Version, runtime.GOARCH))
	if runtime.GOOS == "windows" {
		cachedPath += ".exe"
	}

	if d.isValidBinary(cachedPath, info.SHA256) {
		d.log(1, "使用缓存的 cloudflared: %s", cachedPath)
		return cachedPath, nil
	}

	// 4. 下载
	d.log(1, "下载 cloudflared %s for %s...", info.Version, arch)
	if err := d.downloadCloudflared(info, cachedPath); err != nil {
		return "", fmt.Errorf("下载 cloudflared 失败: %w", err)
	}

	d.log(1, "cloudflared 已下载: %s", cachedPath)
	return cachedPath, nil
}

// downloadCloudflared 下载 cloudflared
func (d *BinaryDownloader) downloadCloudflared(info BinaryInfo, destPath string) error {
	// 创建临时文件
	tmpPath := destPath + ".tmp"
	defer os.Remove(tmpPath)

	// 发起请求
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
	if strings.HasSuffix(info.URL, ".tgz") {
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
	// 使用系统 tar 命令解压
	destDir := filepath.Dir(destPath)
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
	resp, err := http.Get("https://api.github.com/repos/cloudflare/cloudflared/releases/latest")
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

// 需要导入 encoding/json
import "encoding/json"




