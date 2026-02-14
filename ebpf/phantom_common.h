// =============================================================================
// 文件: ebpf/phantom_common.h
// 描述: eBPF 公共头文件 - 类型定义和辅助函数 (IPv4/IPv6 双栈支持)
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
#include <linux/in6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// =============================================================================
// 常量定义
// =============================================================================

#define MAX_SESSIONS        65536
#define MAX_PORTS           16
#define PHANTOM_MAGIC       0x5048414E  // "PHAN"
#define SESSION_TIMEOUT_NS  (300ULL * 1000000000ULL)  // 5 分钟

// 会话状态
#define STATE_NEW           0
#define STATE_HANDSHAKE     1
#define STATE_ESTABLISHED   2
#define STATE_CLOSING       3
#define STATE_CLOSED        4

// 动作
#define ACTION_PASS         0
#define ACTION_DROP         1
#define ACTION_REDIRECT     2
#define ACTION_ENCRYPT      3
#define ACTION_DECRYPT      4

// 协议类型
#define PROTO_PHANTOM       0x50  // 'P'
#define PROTO_HEARTBEAT     0x48  // 'H'
#define PROTO_DATA          0x44  // 'D'

// 地址族
#define AF_INET_BPF         2     // IPv4
#define AF_INET6_BPF        10    // IPv6

// IPv6 扩展头类型
#define IPPROTO_HOPOPTS     0     // Hop-by-hop options
#define IPPROTO_ROUTING     43    // Routing header
#define IPPROTO_FRAGMENT    44    // Fragment header
#define IPPROTO_DSTOPTS     60    // Destination options
#define IPPROTO_NONE        59    // No next header

// IPv6 扩展头解析最大深度
#define IPV6_EXT_MAX_DEPTH  8

// =============================================================================
// IPv6 地址结构
// =============================================================================

// 统一的 IP 地址存储 (支持 IPv4 和 IPv6)
// 注意: 此结构体用于网络数据和 map 键，保持 packed
struct ip_addr {
    union {
        __u32 v4;               // IPv4 地址
        __u32 v6[4];            // IPv6 地址 (128 位)
        __u8  v6_bytes[16];     // IPv6 字节形式
        struct {
            __u64 hi;           // IPv6 高 64 位
            __u64 lo;           // IPv6 低 64 位
        } v6_parts;
    };
} __attribute__((packed));

// =============================================================================
// 会话键 - 支持 IPv4/IPv6 双栈
// 注意: 用作 BPF map 键，保持 packed 确保精确布局
// =============================================================================

struct session_key {
    struct ip_addr src_ip;      // 源 IP (v4 或 v6)
    struct ip_addr dst_ip;      // 目的 IP (v4 或 v6)
    __u16 src_port;             // 源端口
    __u16 dst_port;             // 目的端口
    __u8  family;               // 地址族: AF_INET_BPF 或 AF_INET6_BPF
    __u8  protocol;             // 协议: IPPROTO_UDP, IPPROTO_TCP
    __u8  reserved[2];          // 对齐填充
} __attribute__((packed));

// =============================================================================
// 会话值 - 移除 packed，确保原子操作的对齐要求
// =============================================================================

struct session_value {
    // 8 字节对齐的成员放前面，确保原子操作安全
    __u64 created_ns;           // 创建时间
    __u64 last_seen_ns;         // 最后活动时间
    __u64 bytes_in;             // 入向字节数
    __u64 bytes_out;            // 出向字节数
    __u64 packets_in;           // 入向包数
    __u64 packets_out;          // 出向包数
    
    // IP 地址 (16 字节)
    struct ip_addr peer_ip;     // 对端 IP
    
    // 4 字节成员
    __u32 seq_local;            // 本地序号
    __u32 seq_remote;           // 远端序号
    
    // 2 字节成员
    __u16 peer_port;            // 对端端口
    
    // 1 字节成员 + 填充
    __u8  state;                // 会话状态
    __u8  flags;                // 标志位
    __u8  family;               // 地址族
    __u8  reserved[3];          // 对齐到 8 字节边界
} __attribute__((aligned(8)));

// =============================================================================
// 端口配置
// =============================================================================

struct port_config {
    __u16 port;
    __u8  enabled;
    __u8  flags;
} __attribute__((packed));

// =============================================================================
// 全局配置
// =============================================================================

struct global_config {
    __u32 magic;
    __u16 listen_port;
    __u8  mode;                 // 0=pass, 1=accelerate, 2=full
    __u8  log_level;
    __u32 session_timeout;
    __u32 max_sessions;
    __u8  enable_stats;
    __u8  enable_conntrack;
    __u8  enable_ipv6;          // 是否启用 IPv6 支持
    __u8  reserved;
} __attribute__((packed));

// =============================================================================
// 统计计数器 - 移除 packed，确保原子操作的对齐要求
// =============================================================================

struct stats_counter {
    __u64 packets_rx;
    __u64 packets_tx;
    __u64 bytes_rx;
    __u64 bytes_tx;
    __u64 packets_dropped;
    __u64 packets_passed;
    __u64 packets_redirected;
    __u64 sessions_created;
    __u64 sessions_expired;
    __u64 errors;
    __u64 checksum_errors;
    __u64 invalid_packets;
    // IPv6 特定统计
    __u64 ipv6_packets_rx;
    __u64 ipv6_packets_tx;
    __u64 ipv6_sessions_created;
} __attribute__((aligned(8)));

// =============================================================================
// 事件结构 (用于 perf buffer)
// =============================================================================

struct packet_event {
    __u64 timestamp;
    struct ip_addr src_ip;
    struct ip_addr dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 len;
    __u8  protocol;
    __u8  action;
    __u8  state;
    __u8  flags;
    __u8  family;               // 地址族
    __u8  reserved;
} __attribute__((packed));

// =============================================================================
// IPv6 扩展头解析结果
// =============================================================================

struct ipv6_parse_result {
    __u8  next_hdr;             // 最终的协议号
    __u8  valid;                // 解析是否成功
    __u16 payload_offset;       // payload 相对于 IPv6 头的偏移
    __u16 payload_len;          // payload 长度
    __u8  fragment;             // 是否为分片包
    __u8  reserved;
};

// =============================================================================
// 辅助宏
// =============================================================================

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

#define ARRAY_SIZE(x)   (sizeof(x) / sizeof((x)[0]))

// 边界检查宏
#define CHECK_BOUNDS(ptr, end, size) \
    if ((void *)((ptr) + 1) > (end)) return XDP_PASS; \
    if ((void *)(ptr) + (size) > (end)) return XDP_PASS;

#define CHECK_BOUNDS_TC(ptr, end, size) \
    if ((void *)((ptr) + 1) > (end)) return TC_ACT_OK; \
    if ((void *)(ptr) + (size) > (end)) return TC_ACT_OK;

// =============================================================================
// IPv6 地址操作辅助函数
// =============================================================================

// 比较两个 IPv6 地址是否相等
static __always_inline int ipv6_addr_equal(const struct ip_addr *a, 
                                           const struct ip_addr *b) {
    return (a->v6[0] == b->v6[0] &&
            a->v6[1] == b->v6[1] &&
            a->v6[2] == b->v6[2] &&
            a->v6[3] == b->v6[3]);
}

// 比较两个 IP 地址 (支持双栈)
static __always_inline int ip_addr_equal(const struct ip_addr *a,
                                         const struct ip_addr *b,
                                         __u8 family) {
    if (family == AF_INET_BPF) {
        return a->v4 == b->v4;
    } else {
        return ipv6_addr_equal(a, b);
    }
}

// 复制 IPv6 地址
static __always_inline void ipv6_addr_copy(struct ip_addr *dst,
                                           const struct in6_addr *src) {
    dst->v6[0] = src->in6_u.u6_addr32[0];
    dst->v6[1] = src->in6_u.u6_addr32[1];
    dst->v6[2] = src->in6_u.u6_addr32[2];
    dst->v6[3] = src->in6_u.u6_addr32[3];
}

// 从原始内存复制 IPv6 地址
static __always_inline void ipv6_addr_copy_raw(struct ip_addr *dst,
                                               const __u32 *src) {
    dst->v6[0] = src[0];
    dst->v6[1] = src[1];
    dst->v6[2] = src[2];
    dst->v6[3] = src[3];
}

// 复制 IPv4 地址
static __always_inline void ipv4_addr_copy(struct ip_addr *dst, __u32 src) {
    dst->v4 = src;
    // 清零 IPv6 部分以保持一致性
    dst->v6[1] = 0;
    dst->v6[2] = 0;
    dst->v6[3] = 0;
}

// 清零 IP 地址
static __always_inline void ip_addr_clear(struct ip_addr *addr) {
    addr->v6[0] = 0;
    addr->v6[1] = 0;
    addr->v6[2] = 0;
    addr->v6[3] = 0;
}

// 检查是否为 IPv4 映射的 IPv6 地址 (::ffff:x.x.x.x)
static __always_inline int is_ipv4_mapped_ipv6(const struct ip_addr *addr) {
    return (addr->v6[0] == 0 &&
            addr->v6[1] == 0 &&
            addr->v6[2] == bpf_htonl(0x0000FFFF));
}

// 从 IPv4 映射地址提取 IPv4
static __always_inline __u32 extract_ipv4_from_mapped(const struct ip_addr *addr) {
    return addr->v6[3];
}

// =============================================================================
// 校验和计算
// =============================================================================

static __always_inline __u16 csum_fold(__u32 csum) {
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u32 csum_add(__u32 csum, __u32 addend) {
    csum += addend;
    return csum + (csum < addend);
}

static __always_inline __u32 csum_sub(__u32 csum, __u32 addend) {
    return csum_add(csum, ~addend);
}

static __always_inline void csum_replace2(__u16 *sum, __u16 old, __u16 new) {
    __u32 csum = ~((__u32)*sum) & 0xFFFF;
    csum = csum_sub(csum, old);
    csum = csum_add(csum, new);
    *sum = ~csum_fold(csum);
}

static __always_inline void csum_replace4(__u16 *sum, __u32 old, __u32 new) {
    __u32 csum = ~((__u32)*sum) & 0xFFFF;
    csum = csum_sub(csum, old >> 16);
    csum = csum_sub(csum, old & 0xFFFF);
    csum = csum_add(csum, new >> 16);
    csum = csum_add(csum, new & 0xFFFF);
    *sum = ~csum_fold(csum);
}

// IPv4 校验和
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

// IPv6 伪头校验和 (用于 UDP/TCP)
static __always_inline __u32 ipv6_pseudo_csum(const struct ip_addr *src,
                                              const struct ip_addr *dst,
                                              __u16 len,
                                              __u8 proto) {
    __u32 sum = 0;
    
    // 源地址
    sum = csum_add(sum, src->v6[0] >> 16);
    sum = csum_add(sum, src->v6[0] & 0xFFFF);
    sum = csum_add(sum, src->v6[1] >> 16);
    sum = csum_add(sum, src->v6[1] & 0xFFFF);
    sum = csum_add(sum, src->v6[2] >> 16);
    sum = csum_add(sum, src->v6[2] & 0xFFFF);
    sum = csum_add(sum, src->v6[3] >> 16);
    sum = csum_add(sum, src->v6[3] & 0xFFFF);
    
    // 目的地址
    sum = csum_add(sum, dst->v6[0] >> 16);
    sum = csum_add(sum, dst->v6[0] & 0xFFFF);
    sum = csum_add(sum, dst->v6[1] >> 16);
    sum = csum_add(sum, dst->v6[1] & 0xFFFF);
    sum = csum_add(sum, dst->v6[2] >> 16);
    sum = csum_add(sum, dst->v6[2] & 0xFFFF);
    sum = csum_add(sum, dst->v6[3] >> 16);
    sum = csum_add(sum, dst->v6[3] & 0xFFFF);
    
    // 长度和协议
    sum = csum_add(sum, bpf_htons(len));
    sum = csum_add(sum, bpf_htons(proto));
    
    return sum;
}

// =============================================================================
// 数据包解析辅助函数
// =============================================================================

// 解析以太网头
static __always_inline struct ethhdr *parse_ethhdr(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return NULL;
    return eth;
}

// 解析 IPv4 头
static __always_inline struct iphdr *parse_iphdr(void *data, void *data_end) {
    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end)
        return NULL;
    if (ip->ihl < 5)
        return NULL;
    if ((void *)ip + (ip->ihl * 4) > data_end)
        return NULL;
    return ip;
}

// 解析 IPv6 头
static __always_inline struct ipv6hdr *parse_ipv6hdr(void *data, void *data_end) {
    struct ipv6hdr *ip6 = data;
    if ((void *)(ip6 + 1) > data_end)
        return NULL;
    // 检查版本号
    if ((ip6->version) != 6)
        return NULL;
    return ip6;
}

// IPv6 扩展头解析
// 返回: 0 = 成功, -1 = 失败
static __always_inline int parse_ipv6_ext_headers(
    void *data,
    void *data_end,
    struct ipv6hdr *ip6,
    struct ipv6_parse_result *result
) {
    __u8 next_hdr = ip6->nexthdr;
    void *ptr = (void *)(ip6 + 1);
    __u16 offset = sizeof(struct ipv6hdr);
    
    result->fragment = 0;
    result->valid = 0;
    
    // 限制扩展头解析深度以避免验证器循环检查问题
    #pragma unroll
    for (int i = 0; i < IPV6_EXT_MAX_DEPTH; i++) {
        // 检查是否到达最终协议
        switch (next_hdr) {
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_ICMPV6:
            // 找到传输层协议
            result->next_hdr = next_hdr;
            result->payload_offset = offset;
            result->payload_len = bpf_ntohs(ip6->payload_len) - 
                                 (offset - sizeof(struct ipv6hdr));
            result->valid = 1;
            return 0;
            
        case IPPROTO_NONE:
            // 无后续头部
            result->next_hdr = next_hdr;
            result->payload_offset = offset;
            result->payload_len = 0;
            result->valid = 1;
            return 0;
            
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS: {
            // 可变长度扩展头
            if (ptr + 2 > data_end)
                return -1;
            
            __u8 *hdr = ptr;
            __u8 ext_next = hdr[0];
            __u8 ext_len = hdr[1];  // 以 8 字节为单位，不包括第一个 8 字节
            __u16 total_len = (ext_len + 1) * 8;
            
            if (ptr + total_len > data_end)
                return -1;
            
            next_hdr = ext_next;
            ptr += total_len;
            offset += total_len;
            break;
        }
        
        case IPPROTO_FRAGMENT: {
            // 分片头 (固定 8 字节)
            if (ptr + 8 > data_end)
                return -1;
            
            __u8 *frag_hdr = ptr;
            next_hdr = frag_hdr[0];
            result->fragment = 1;
            
            ptr += 8;
            offset += 8;
            break;
        }
        
        default:
            // 未知扩展头，假设已到达传输层
            result->next_hdr = next_hdr;
            result->payload_offset = offset;
            result->payload_len = bpf_ntohs(ip6->payload_len) - 
                                 (offset - sizeof(struct ipv6hdr));
            result->valid = 1;
            return 0;
        }
    }
    
    // 超过最大深度
    return -1;
}

// 解析 UDP 头
static __always_inline struct udphdr *parse_udphdr(void *data, void *data_end) {
    struct udphdr *udp = data;
    if ((void *)(udp + 1) > data_end)
        return NULL;
    return udp;
}

// 解析 TCP 头
static __always_inline struct tcphdr *parse_tcphdr(void *data, void *data_end) {
    struct tcphdr *tcp = data;
    if ((void *)(tcp + 1) > data_end)
        return NULL;
    if (tcp->doff < 5)
        return NULL;
    if ((void *)tcp + (tcp->doff * 4) > data_end)
        return NULL;
    return tcp;
}

// =============================================================================
// 会话键操作函数
// =============================================================================

// 创建 IPv4 会话键
static __always_inline void make_session_key_v4(
    struct session_key *key,
    __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u8 protocol
) {
    __builtin_memset(key, 0, sizeof(*key));
    key->src_ip.v4 = src_ip;
    key->dst_ip.v4 = dst_ip;
    key->src_port = src_port;
    key->dst_port = dst_port;
    key->family = AF_INET_BPF;
    key->protocol = protocol;
}

// 创建 IPv6 会话键
static __always_inline void make_session_key_v6(
    struct session_key *key,
    const struct in6_addr *src_ip,
    const struct in6_addr *dst_ip,
    __u16 src_port, __u16 dst_port,
    __u8 protocol
) {
    __builtin_memset(key, 0, sizeof(*key));
    ipv6_addr_copy(&key->src_ip, src_ip);
    ipv6_addr_copy(&key->dst_ip, dst_ip);
    key->src_port = src_port;
    key->dst_port = dst_port;
    key->family = AF_INET6_BPF;
    key->protocol = protocol;
}

// 从 ip_addr 创建 IPv6 会话键
static __always_inline void make_session_key_v6_raw(
    struct session_key *key,
    const struct ip_addr *src_ip,
    const struct ip_addr *dst_ip,
    __u16 src_port, __u16 dst_port,
    __u8 protocol
) {
    __builtin_memset(key, 0, sizeof(*key));
    key->src_ip = *src_ip;
    key->dst_ip = *dst_ip;
    key->src_port = src_port;
    key->dst_port = dst_port;
    key->family = AF_INET6_BPF;
    key->protocol = protocol;
}

// 通用会话键创建 (兼容旧代码)
static __always_inline void make_session_key(
    struct session_key *key,
    __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port
) {
    make_session_key_v4(key, src_ip, dst_ip, src_port, dst_port, IPPROTO_UDP);
}

// 创建反向会话键
static __always_inline void make_reverse_key(
    struct session_key *rev,
    const struct session_key *key
) {
    rev->src_ip = key->dst_ip;
    rev->dst_ip = key->src_ip;
    rev->src_port = key->dst_port;
    rev->dst_port = key->src_port;
    rev->family = key->family;
    rev->protocol = key->protocol;
    rev->reserved[0] = 0;
    rev->reserved[1] = 0;
}

// =============================================================================
// 日志辅助宏
// =============================================================================

#ifdef DEBUG
#define LOG_DEBUG(fmt, ...) \
    bpf_printk("phantom: " fmt, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...)
#endif

#define LOG_INFO(fmt, ...) \
    bpf_printk("phantom: " fmt, ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...) \
    bpf_printk("phantom ERROR: " fmt, ##__VA_ARGS__)

#endif // __PHANTOM_COMMON_H__
