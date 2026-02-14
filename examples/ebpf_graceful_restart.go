


// =============================================================================
// 文件: examples/ebpf_graceful_restart.go
// 描述: 平滑重启示例
// =============================================================================
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"phantom/internal/transport"
)

func main() {
	// 创建配置
	config := transport.DefaultEBPFLoaderConfig()
	config.EnablePinning = true
	config.PinMode = transport.PinModeReuse
	config.GracefulRestart = true
	config.StateTimeout = 5 * time.Minute
	config.Interface = "eth0"

	// 创建 loader
	loader := transport.NewEBPFLoader(config)

	// 创建重启管理器
	restartMgr := transport.NewGracefulRestartManager(loader)

	// 设置回调
	restartMgr.SetCallbacks(
		func() error {
			fmt.Println("准备重启: 保存应用状态...")
			return nil
		},
		func() error {
			fmt.Println("恢复中: 恢复应用状态...")
			return nil
		},
	)

	// 尝试从重启中恢复
	state, err := restartMgr.TryRestore()
	if err != nil {
		fmt.Printf("恢复失败: %v，进行全新启动\n", err)
	}

	if state != nil {
		fmt.Printf("成功恢复! 之前的会话数: %d\n", state.SessionCount)
	} else {
		// 全新启动
		if err := loader.Load(); err != nil {
			fmt.Printf("加载失败: %v\n", err)
			os.Exit(1)
		}

		if err := loader.Attach(); err != nil {
			fmt.Printf("附加失败: %v\n", err)
			os.Exit(1)
		}
	}

	// 配置端口
	listenPorts := []uint16{8080, 8443}
	for _, port := range listenPorts {
		loader.ConfigurePort(port, true)
	}

	// 设置信号处理
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	restartMgr.SetupSignalHandler(ctx, listenPorts)

	// 处理退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("服务运行中...")
	fmt.Println("发送 SIGUSR2 准备平滑重启")
	fmt.Println("发送 SIGINT/SIGTERM 退出")

	// 状态监控
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats, _ := loader.GetStats()
				if stats != nil {
					fmt.Printf("状态: 活跃会话=%d, 收包=%d, 发包=%d\n",
						stats.ActiveSessions, stats.PacketsRx, stats.PacketsTx)
				}
			}
		}
	}()

	// 等待信号
	sig := <-sigChan
	fmt.Printf("\n收到信号: %v\n", sig)

	// 清理
	cancel()
	
	if !config.GracefulRestart {
		loader.Close()
	}

	fmt.Println("退出完成")
}



