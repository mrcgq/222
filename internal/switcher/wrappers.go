
// =============================================================================
// 文件: internal/switcher/wrappers.go (追加内容)
// 描述: FakeTCP eBPF 模式的传输层包装器
// =============================================================================
package switcher

import (
	"net"

	"github.com/mrcgq/211/internal/transport"
)

// FakeTCPEBPFWrapper FakeTCP eBPF 模式包装器
// 当使用 eBPF TC 加速时，FakeTCP 流量实际上会被内核转换后
// 直接投递给 UDP 服务器，所以这个包装器只是一个逻辑占位符
type FakeTCPEBPFWrapper struct {
	tcManager *transport.EBPFTCManager
	udpServer *transport.UDPServer
}

// NewFakeTCPEBPFWrapper 创建 FakeTCP eBPF 包装器
func NewFakeTCPEBPFWrapper(tcManager *transport.EBPFTCManager, udpServer *transport.UDPServer) *FakeTCPEBPFWrapper {
	return &FakeTCPEBPFWrapper{
		tcManager: tcManager,
		udpServer: udpServer,
	}
}

// Send 发送数据 (实际通过 UDP 发送，内核会转换为 TCP)
func (w *FakeTCPEBPFWrapper) Send(data []byte, addr *net.UDPAddr) error {
	// 数据通过 UDP 发送，内核 TC egress 程序会将其转换为 TCP
	return w.udpServer.SendTo(data, addr)
}

// IsRunning 检查是否运行中
func (w *FakeTCPEBPFWrapper) IsRunning() bool {
	return w.tcManager != nil && w.tcManager.IsLoaded()
}

// GetStats 获取统计
func (w *FakeTCPEBPFWrapper) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["mode"] = "ebpf_tc"
	stats["loaded"] = w.tcManager.IsLoaded()
	stats["udp_port"] = w.tcManager.GetUDPPort()
	stats["tcp_port"] = w.tcManager.GetTCPPort()
	
	if tcStats, err := w.tcManager.GetStats(); err == nil {
		for k, v := range tcStats {
			stats[k] = v
		}
	}
	
	return stats
}

// Close 关闭
func (w *FakeTCPEBPFWrapper) Close() error {
	if w.tcManager != nil {
		return w.tcManager.Unload()
	}
	return nil
}



