//go:build windows

package tunnel

import (
	"os"
	"os/exec"
)

// configurePlatformProcess 配置平台特定的进程属性 (Windows)
func configurePlatformProcess(cmd *exec.Cmd) {
	// Windows 不支持进程组，无需特殊配置
}

// terminateProcess 优雅终止进程 (Windows)
func terminateProcess(process *os.Process) {
	if process == nil {
		return
	}
	// Windows 上直接 Kill，没有 SIGTERM 概念
	_ = process.Kill()
}

// killProcess 强制终止进程 (Windows)
func killProcess(process *os.Process) {
	if process == nil {
		return
	}
	_ = process.Kill()
}
