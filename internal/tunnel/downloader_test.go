

// =============================================================================
// 文件: internal/tunnel/downloader_test.go
// 描述: 二进制下载器单元测试
// =============================================================================
package tunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBinaryDownloader_NewDownloader(t *testing.T) {
	tmpDir := t.TempDir()

	d := NewBinaryDownloader(tmpDir)

	if d.cacheDir != tmpDir {
		t.Errorf("缓存目录不匹配: 期望 %s, 实际 %s", tmpDir, d.cacheDir)
	}

	if d.httpClient == nil {
		t.Error("HTTP 客户端为空")
	}

	if d.logLevel != 1 {
		t.Errorf("默认日志级别应该是 1, 实际 %d", d.logLevel)
	}
}

func TestBinaryDownloader_DefaultCacheDir(t *testing.T) {
	d := NewBinaryDownloader("")

	if d.cacheDir == "" {
		t.Error("默认缓存目录不应为空")
	}

	// 验证目录被创建
	if _, err := os.Stat(d.cacheDir); os.IsNotExist(err) {
		t.Error("缓存目录未创建")
	}
}

func TestBinaryDownloader_Options(t *testing.T) {
	tmpDir := t.TempDir()
	progressCalled := false

	d := NewBinaryDownloader("",
		WithCacheDir(tmpDir),
		WithLogLevel(2),
		WithProgressCallback(func(downloaded, total int64) {
			progressCalled = true
		}),
	)

	if d.cacheDir != tmpDir {
		t.Errorf("WithCacheDir 选项未生效")
	}

	if d.logLevel != 2 {
		t.Errorf("WithLogLevel 选项未生效")
	}

	if d.progressCallback == nil {
		t.Error("WithProgressCallback 选项未生效")
	}

	// 调用回调验证
	d.progressCallback(100, 200)
	if !progressCalled {
		t.Error("进度回调未被调用")
	}
}

func TestBinaryDownloader_IsValidBinary(t *testing.T) {
	tmpDir := t.TempDir()
	d := NewBinaryDownloader(tmpDir)

	// 测试不存在的文件
	if d.isValidBinary("/nonexistent/file", "") {
		t.Error("不存在的文件不应该被认为有效")
	}

	// 创建空文件
	emptyFile := filepath.Join(tmpDir, "empty")
	os.WriteFile(emptyFile, []byte{}, 0755)
	if d.isValidBinary(emptyFile, "") {
		t.Error("空文件不应该被认为有效")
	}

	// 创建有内容的文件
	content := []byte("test binary content")
	validFile := filepath.Join(tmpDir, "valid")
	os.WriteFile(validFile, content, 0755)

	if !d.isValidBinary(validFile, "") {
		t.Error("有效文件应该被认为有效（无哈希校验）")
	}

	// 测试哈希校验
	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])

	if !d.isValidBinary(validFile, hashStr) {
		t.Error("哈希正确的文件应该被认为有效")
	}

	if d.isValidBinary(validFile, "invalid_hash") {
		t.Error("哈希错误的文件不应该被认为有效")
	}
}

func TestBinaryDownloader_IsValidBinaryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 不支持 Unix 权限")
	}

	tmpDir := t.TempDir()
	d := NewBinaryDownloader(tmpDir)

	// 创建不可执行的文件
	nonExecFile := filepath.Join(tmpDir, "nonexec")
	os.WriteFile(nonExecFile, []byte("content"), 0644) // 无执行权限

	if d.isValidBinary(nonExecFile, "") {
		t.Error("无执行权限的文件不应该被认为有效")
	}

	// 添加执行权限
	os.Chmod(nonExecFile, 0755)
	if !d.isValidBinary(nonExecFile, "") {
		t.Error("有执行权限的文件应该被认为有效")
	}
}

func TestBinaryDownloader_Download(t *testing.T) {
	// 创建测试服务器
	testContent := []byte("mock binary content for testing")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(testContent)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	d := NewBinaryDownloader(tmpDir)

	destPath := filepath.Join(tmpDir, "downloaded")

	// 测试下载
	err := d.downloadAndVerify(server.URL, destPath, "")
	if err != nil {
		t.Fatalf("下载失败: %v", err)
	}

	// 验证文件内容
	content, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("读取文件失败: %v", err)
	}

	if string(content) != string(testContent) {
		t.Error("下载内容不匹配")
	}
}

func TestBinaryDownloader_DownloadWithHash(t *testing.T) {
	testContent := []byte("content with hash verification")
	hash := sha256.Sum256(testContent)
	hashStr := hex.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(testContent)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	d := NewBinaryDownloader(tmpDir)

	// 正确的哈希
	destPath1 := filepath.Join(tmpDir, "correct_hash")
	err := d.downloadAndVerify(server.URL, destPath1, hashStr)
	if err != nil {
		t.Fatalf("正确哈希下载失败: %v", err)
	}

	// 错误的哈希
	destPath2 := filepath.Join(tmpDir, "wrong_hash")
	err = d.downloadAndVerify(server.URL, destPath2, "wrong_hash_value")
	if err == nil {
		t.Fatal("错误哈希应该返回错误")
	}
}

func TestBinaryDownloader_DownloadProgress(t *testing.T) {
	testContent := make([]byte, 1024*100) // 100KB
	for i := range testContent {
		testContent[i] = byte(i % 256)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "102400")
		w.Write(testContent)
	}))
	defer server.Close()

	tmpDir := t.TempDir()

	var progressUpdates []int64
	d := NewBinaryDownloader(tmpDir,
		WithProgressCallback(func(downloaded, total int64) {
			progressUpdates = append(progressUpdates, downloaded)
		}),
	)

	destPath := filepath.Join(tmpDir, "progress_test")
	err := d.downloadAndVerify(server.URL, destPath, "")
	if err != nil {
		t.Fatalf("下载失败: %v", err)
	}

	if len(progressUpdates) == 0 {
		t.Error("进度回调未被调用")
	}

	// 验证进度递增
	for i := 1; i < len(progressUpdates); i++ {
		if progressUpdates[i] < progressUpdates[i-1] {
			t.Error("进度应该递增")
		}
	}
}

func TestBinaryDownloader_DownloadHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	d := NewBinaryDownloader(tmpDir)

	destPath := filepath.Join(tmpDir, "error_test")
	err := d.downloadAndVerify(server.URL, destPath, "")
	if err == nil {
		t.Fatal("HTTP 404 应该返回错误")
	}
}

func TestBinaryDownloader_CleanCache(t *testing.T) {
	tmpDir := t.TempDir()
	d := NewBinaryDownloader(tmpDir)

	// 创建一些缓存文件
	os.WriteFile(filepath.Join(tmpDir, "file1"), []byte("content1"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "file2"), []byte("content2"), 0644)

	// 清理缓存
	if err := d.CleanCache(); err != nil {
		t.Fatalf("清理缓存失败: %v", err)
	}

	// 验证目录被删除
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		t.Error("缓存目录应该被删除")
	}
}

func TestBinaryDownloader_GetCacheDir(t *testing.T) {
	tmpDir := t.TempDir()
	d := NewBinaryDownloader(tmpDir)

	if d.GetCacheDir() != tmpDir {
		t.Error("GetCacheDir 返回错误的目录")
	}
}

func TestCloudflaredVersions(t *testing.T) {
	// 验证版本配置存在
	requiredArches := []string{"linux-amd64", "linux-arm64"}

	for _, arch := range requiredArches {
		info, ok := CloudflaredVersions[arch]
		if !ok {
			t.Errorf("缺少架构配置: %s", arch)
			continue
		}

		if info.Name == "" {
			t.Errorf("架构 %s 缺少 Name", arch)
		}
		if info.Version == "" {
			t.Errorf("架构 %s 缺少 Version", arch)
		}
		if info.URL == "" {
			t.Errorf("架构 %s 缺少 URL", arch)
		}
	}
}

func TestVerifyCloudflaredIntegrity(t *testing.T) {
	tmpDir := t.TempDir()

	// 测试不存在的文件
	err := VerifyCloudflaredIntegrity("/nonexistent/cloudflared")
	if err == nil {
		t.Error("不存在的文件应该返回错误")
	}

	// 测试太小的文件
	smallFile := filepath.Join(tmpDir, "small")
	os.WriteFile(smallFile, []byte("small"), 0755)
	err = VerifyCloudflaredIntegrity(smallFile)
	if err == nil {
		t.Error("太小的文件应该返回错误")
	}
}

func TestProgressWriter(t *testing.T) {
	var lastDownloaded, lastTotal int64

	pw := &progressWriter{
		writer: os.Discard,
		total:  1000,
		callback: func(downloaded, total int64) {
			lastDownloaded = downloaded
			lastTotal = total
		},
	}

	// 写入数据
	n, err := pw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if n != 5 {
		t.Errorf("写入字节数错误: %d", n)
	}

	if lastDownloaded != 5 {
		t.Errorf("下载进度错误: %d", lastDownloaded)
	}
	if lastTotal != 1000 {
		t.Errorf("总大小错误: %d", lastTotal)
	}

	// 再次写入
	pw.Write([]byte("world"))
	if lastDownloaded != 10 {
		t.Errorf("累计下载进度错误: %d", lastDownloaded)
	}
}

// =============================================================================
// 集成测试（需要网络）
// =============================================================================

func TestBinaryDownloader_EnsureCloudflared_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过集成测试")
	}

	tmpDir := t.TempDir()
	d := NewBinaryDownloader(tmpDir)

	// 这个测试会真正下载 cloudflared（如果本地没有）
	path, err := d.EnsureCloudflared()
	if err != nil {
		// 如果是网络问题，跳过
		t.Skipf("下载失败（可能是网络问题）: %v", err)
	}

	if path == "" {
		t.Error("路径不应为空")
	}

	// 验证文件存在
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("文件不存在: %s", path)
	}
}





