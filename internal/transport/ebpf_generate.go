

//go:build linux && ignore

// =============================================================================
// 文件: internal/transport/ebpf_generate.go
// 描述: 使用 bpf2go 自动生成 eBPF 绑定代码
// 用法: go generate ./internal/transport/...
// =============================================================================

package transport

// 生成 XDP 程序绑定
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel,bpfeb -type session_key -type session_value -type global_config -type stats_counter -type port_config -type packet_event Phantom ../../ebpf/xdp_phantom.c -- -I../../ebpf/lib

// 生成 TC 程序绑定
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel,bpfeb -type session_key -type session_value PhantomTC ../../ebpf/tc_phantom.c -- -I../../ebpf/lib

// 生成 FakeTCP TC 程序绑定
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel,bpfeb FakeTCPTC ../../ebpf/tc_faketcp.c -- -I../../ebpf/lib


