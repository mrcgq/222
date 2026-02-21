//go:build linux

// =============================================================================
// 文件: internal/transport/ebpf_restart_manager.go
// 描述: eBPF 平滑重启管理器
// =============================================================================
package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// RestartState 重启状态
type RestartState struct {
	Version       string            `json:"version"`
	Timestamp     time.Time         `json:"timestamp"`
	PID           int               `json:"pid"`
	Interface     string            `json:"interface"`
	ListenPorts   []uint16          `json:"listen_ports"`
	SessionCount  int64             `json:"session_count"`
	Configuration map[string]string `json:"configuration"`
}

// GracefulRestartManager 平滑重启管理器
type GracefulRestartManager struct {
	loader    *EBPFLoader
	statePath string
	mu        sync.Mutex

	// 状态
	prepared bool
	restored bool

	// 回调
	onPrepare func() error
	onRestore func() error
}

// NewGracefulRestartManager 创建管理器
func NewGracefulRestartManager(loader *EBPFLoader) *GracefulRestartManager {
	return &GracefulRestartManager{
		loader:    loader,
		statePath: filepath.Join(loader.GetPinPath(), "restart_state.json"),
	}
}

// SetCallbacks 设置回调
func (m *GracefulRestartManager) SetCallbacks(onPrepare, onRestore func() error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onPrepare = onPrepare
	m.onRestore = onRestore
}

// PrepareRestart 准备重启
func (m *GracefulRestartManager) PrepareRestart(listenPorts []uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 获取当前状态
	stats, _ := m.loader.GetStats()
	sessionCount := int64(0)
	if stats != nil {
		sessionCount = int64(stats.SessionsCreated)
	}

	state := RestartState{
		Version:      "1.0",
		Timestamp:    time.Now(),
		PID:          os.Getpid(),
		Interface:    m.loader.GetInterface(),
		ListenPorts:  listenPorts,
		SessionCount: sessionCount,
	}

	// 保存状态
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化状态失败: %w", err)
	}

	if err := os.WriteFile(m.statePath, data, 0644); err != nil {
		return fmt.Errorf("保存状态失败: %w", err)
	}

	// 调用回调
	if m.onPrepare != nil {
		if err := m.onPrepare(); err != nil {
			return fmt.Errorf("准备回调失败: %w", err)
		}
	}

	// 准备 loader - 确保 maps 已 pin
	if err := m.loader.PrepareGracefulRestart(); err != nil {
		return fmt.Errorf("准备 loader 失败: %w", err)
	}

	m.prepared = true
	return nil
}

// TryRestore 尝试恢复
func (m *GracefulRestartManager) TryRestore() (*RestartState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查状态文件
	data, err := os.ReadFile(m.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // 没有重启状态
		}
		return nil, fmt.Errorf("读取状态失败: %w", err)
	}

	var state RestartState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("解析状态失败: %w", err)
	}

	// 检查状态是否过期 (5分钟)
	if time.Since(state.Timestamp) > 5*time.Minute {
		os.Remove(m.statePath)
		return nil, fmt.Errorf("重启状态已过期")
	}

	// 检查旧进程是否仍在运行
	if processExists(state.PID) && state.PID != os.Getpid() {
		return nil, fmt.Errorf("旧进程 %d 仍在运行", state.PID)
	}

	// 尝试恢复 loader - 从 pinned maps 恢复
	if err := m.loader.RecoverFromRestart(); err != nil {
		return nil, fmt.Errorf("恢复 loader 失败: %w", err)
	}

	// 调用回调
	if m.onRestore != nil {
		if err := m.onRestore(); err != nil {
			return nil, fmt.Errorf("恢复回调失败: %w", err)
		}
	}

	// 清理状态文件
	os.Remove(m.statePath)

	m.restored = true
	return &state, nil
}

// IsRestored 是否已恢复
func (m *GracefulRestartManager) IsRestored() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restored
}

// SetupSignalHandler 设置信号处理
func (m *GracefulRestartManager) SetupSignalHandler(ctx context.Context, listenPorts []uint16) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGUSR2) // 使用 SIGUSR2 触发平滑重启

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case sig := <-sigChan:
				if sig == syscall.SIGUSR2 {
					fmt.Println("收到 SIGUSR2，准备平滑重启...")
					if err := m.PrepareRestart(listenPorts); err != nil {
						fmt.Printf("准备重启失败: %v\n", err)
					} else {
						fmt.Println("准备完成，可以重启进程")
					}
				}
			}
		}
	}()
}

// Cleanup 清理
func (m *GracefulRestartManager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	os.Remove(m.statePath)
}
