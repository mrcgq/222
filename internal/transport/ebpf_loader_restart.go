//go:build linux

// =============================================================================
// 文件: internal/transport/ebpf_loader_restart.go
// 描述: EBPFLoader 的平滑重启相关方法
// =============================================================================
package transport

import (
	"fmt"
	"os"
)

// prepareGracefulRestart 准备平滑重启
func (l *EBPFLoader) prepareGracefulRestart() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.loaded {
		return fmt.Errorf("eBPF 程序未加载")
	}

	// 标记为准备重启状态
	l.pinned = true

	// 确保 map 已 pin 到 bpffs
	if l.config.EnablePinning {
		if err := l.pinMaps(); err != nil {
			return fmt.Errorf("pin maps 失败: %w", err)
		}
	}

	return nil
}

// recoverFromRestart 从重启恢复
func (l *EBPFLoader) recoverFromRestart() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// 尝试从 pin 路径恢复 maps
	if l.config.EnablePinning {
		if err := l.loadPinnedMaps(); err != nil {
			return fmt.Errorf("加载 pinned maps 失败: %w", err)
		}
	}

	l.loaded = true
	l.pinned = true

	return nil
}

// pinMaps 将 maps pin 到 bpffs
func (l *EBPFLoader) pinMaps() error {
	pinPath := l.GetPinPath()

	// 确保目录存在
	if err := os.MkdirAll(pinPath, 0755); err != nil {
		return fmt.Errorf("创建 pin 目录失败: %w", err)
	}

	// Pin 各个 map
	if l.objects != nil {
		maps := l.objects.PhantomMaps

		if maps.Sessions != nil {
			if err := maps.Sessions.Pin(pinPath + "/sessions"); err != nil {
				return fmt.Errorf("pin sessions map 失败: %w", err)
			}
		}

		if maps.Stats != nil {
			if err := maps.Stats.Pin(pinPath + "/stats"); err != nil {
				return fmt.Errorf("pin stats map 失败: %w", err)
			}
		}

		if maps.ListenPorts != nil {
			if err := maps.ListenPorts.Pin(pinPath + "/listen_ports"); err != nil {
				return fmt.Errorf("pin listen_ports map 失败: %w", err)
			}
		}

		if maps.Config != nil {
			if err := maps.Config.Pin(pinPath + "/config"); err != nil {
				return fmt.Errorf("pin config map 失败: %w", err)
			}
		}
	}

	return nil
}

// loadPinnedMaps 从 bpffs 加载 pinned maps
func (l *EBPFLoader) loadPinnedMaps() error {
	// 此处需要根据实际情况实现
	// 通常使用 ebpf.LoadPinnedMap() 加载
	return nil
}

// processExists 检查进程是否存在
func processExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// 在 Unix 系统上，FindProcess 总是成功的
	// 需要发送信号 0 来检查进程是否真的存在
	err = process.Signal(os.Signal(nil))
	return err == nil
}
