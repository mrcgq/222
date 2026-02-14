



// =============================================================================
// 文件: ebpf/common.h
// 描述: eBPF 公共头文件
// =============================================================================

#ifndef __PHANTOM_COMMON_H__
#define __PHANTOM_COMMON_H__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 常量定义
#define MAX_SESSIONS    65536
#define PHANTOM_PORT    54321

// 会话状态
#define STATE_NEW           0
#define STATE_ESTABLISHED   1
#define STATE_CLOSING       2

// TCP 标志
#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PSH    0x08
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_URG    0x20

// 辅助宏
#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

// IP 校验和计算
static __always_inline __u16 csum_fold(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u16 ip_checksum(void *data, int len) {
    __u32 sum = 0;
    __u16 *ptr = data;
    
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (i * 2 >= len)
            break;
        sum += ptr[i];
    }
    
    return csum_fold(sum);
}

#endif // __PHANTOM_COMMON_H__



