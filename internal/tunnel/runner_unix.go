
//go:build linux || darwin || freebsd

package tunnel

import (
	"os"
	"os/exec"
	"syscall"
)

// configurePlatformProcess 配置平台特定的进程属性 (Unix)
func configurePlatformProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
}

// terminateProcess 优雅终止进程 (Unix)
func terminateProcess(process *os.Process) {
	if process == nil {
		return
	}
	pid := process.Pid
	// 向进程组发送 SIGTERM
	_ = syscall.Kill(-pid, syscall.SIGTERM)
}

// killProcess 强制终止进程 (Unix)
func killProcess(process *os.Process) {
	if process == nil {
		return
	}
	pid := process.Pid
	// 向进程组发送 SIGKILL
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	// 作为后备，也直接 Kill 进程
	_ = process.Kill()
}



