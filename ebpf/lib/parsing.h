// =============================================================================
// 文件: ebpf/lib/parsing.h
// 描述: 协议解析引擎 - 从原始字节流中安全、高效地提取协议头
// =============================================================================

#ifndef __PARSING_H__
#define __PARSING_H__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// =============================================================================
// 常量定义
// =============================================================================

// 地址族
#define AF_INET_BPF         2
#define AF_INET6_BPF        10

// IPv6 扩展头类型
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS     0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING     43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT    44
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS     60
#endif
#ifndef IPPROTO_NONE
#define IPPROTO_NONE        59
#endif
#ifndef IPPROTO_MH
#define IPPROTO_MH          135
#endif

// 解析限制
#define IPV6_EXT_MAX_DEPTH  8
#define PARSE_OK            0
#define PARSE_ERR           -1
#define PARSE_TRUNCATED     -2
#define PARSE_INVALID       -3

// =============================================================================
// 解析结果结构体
// =============================================================================

/**
 * 以太网解析结果
 */
struct eth_parse_result {
    struct ethhdr *eth;         // 以太网头指针
    __u16 proto;                // 下一层协议 (主机字节序)
    __u16 offset;               // 以太网头后的偏移量
    __u8  valid;                // 解析是否成功
    __u8  reserved[3];
};

/**
 * IP 层解析结果 (统一 IPv4/IPv6)
 */
struct ip_parse_result {
    union {
        struct iphdr *v4;       // IPv4 头指针
        struct ipv6hdr *v6;     // IPv6 头指针
    } hdr;
    __u8  family;               // 地址族: AF_INET_BPF 或 AF_INET6_BPF
    __u8  protocol;             // 传输层协议 (IPPROTO_UDP, IPPROTO_TCP 等)
    __u8  valid;                // 解析是否成功
    __u8  is_fragment;          // 是否为分片包
    __u16 payload_offset;       // 传输层头相对于数据包起始的偏移
    __u16 payload_len;          // 传输层 payload 长度
    __u16 total_len;            // IP 包总长度
    __u16 reserved;
    // 源/目的地址 (统一存储)
    union {
        __u32 v4;
        __u32 v6[4];
    } src_addr;
    union {
        __u32 v4;
        __u32 v6[4];
    } dst_addr;
};

/**
 * UDP 解析结果
 */
struct udp_parse_result {
    struct udphdr *udp;         // UDP 头指针
    void *payload;              // Payload 起始位置
    __u16 src_port;             // 源端口 (主机字节序)
    __u16 dst_port;             // 目的端口 (主机字节序)
    __u16 payload_len;          // Payload 长度
    __u16 payload_offset;       // Payload 相对于数据包起始的偏移
    __u8  valid;                // 解析是否成功
    __u8  reserved[3];
};

/**
 * TCP 解析结果
 */
struct tcp_parse_result {
    struct tcphdr *tcp;         // TCP 头指针
    void *payload;              // Payload 起始位置
    __u16 src_port;             // 源端口 (主机字节序)
    __u16 dst_port;             // 目的端口 (主机字节序)
    __u16 payload_len;          // Payload 长度
    __u16 payload_offset;       // Payload 相对于数据包起始的偏移
    __u8  valid;                // 解析是否成功
    __u8  hdr_len;              // TCP 头长度 (包含选项)
    __u8  flags;                // TCP 标志位
    __u8  reserved;
    __u32 seq;                  // 序列号
    __u32 ack;                  // 确认号
};

/**
 * 完整数据包解析上下文
 */
struct parse_context {
    void *data;                 // 数据包起始
    void *data_end;             // 数据包结束
    struct eth_parse_result eth;
    struct ip_parse_result ip;
    union {
        struct udp_parse_result udp;
        struct tcp_parse_result tcp;
    } l4;
    __u8 l4_proto;              // L4 协议类型
    __u8 fully_parsed;          // 是否完全解析成功
    __u8 reserved[2];
};

// =============================================================================
// 内联辅助宏
// =============================================================================

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

// 安全边界检查
#define BOUNDS_CHECK(ptr, size, end) \
    ((void *)((ptr) + (size)) <= (end))

#define BOUNDS_CHECK_HDR(ptr, end) \
    ((void *)((ptr) + 1) <= (end))

// =============================================================================
// 以太网解析
// =============================================================================

/**
 * parse_eth - 解析以太网头
 * @data: 数据包起始指针
 * @data_end: 数据包结束指针
 * @result: 解析结果输出
 *
 * 返回: 成功返回 PARSE_OK，失败返回负值错误码
 *
 * 该函数提取以太网头，识别下一层协议类型，并计算偏移量。
 * 支持 802.1Q VLAN 标签的跳过处理。
 */
static __always_inline int parse_eth(
    void *data,
    void *data_end,
    struct eth_parse_result *result
) {
    struct ethhdr *eth = data;
    __u16 offset = sizeof(struct ethhdr);
    __u16 proto;

    // 初始化结果
    result->eth = NULL;
    result->proto = 0;
    result->offset = 0;
    result->valid = 0;

    // 边界检查
    if (unlikely(!BOUNDS_CHECK_HDR(eth, data_end))) {
        return PARSE_TRUNCATED;
    }

    proto = bpf_ntohs(eth->h_proto);

    // 处理 VLAN 标签 (802.1Q)
    // 最多处理两层 VLAN (QinQ)
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto != ETH_P_8021Q && proto != ETH_P_8021AD) {
            break;
        }

        // VLAN 头: 2 字节 TCI + 2 字节下一层协议
        if (!BOUNDS_CHECK(data, offset + 4, data_end)) {
            return PARSE_TRUNCATED;
        }

        // 跳过 TCI，读取下一层协议
        __u16 *vlan_proto = data + offset + 2;
        if (!BOUNDS_CHECK_HDR(vlan_proto, data_end)) {
            return PARSE_TRUNCATED;
        }
        proto = bpf_ntohs(*vlan_proto);
        offset += 4;
    }

    result->eth = eth;
    result->proto = proto;
    result->offset = offset;
    result->valid = 1;

    return PARSE_OK;
}

/**
 * parse_eth_simple - 简化版以太网解析 (无 VLAN 支持)
 * @data: 数据包起始指针
 * @data_end: 数据包结束指针
 * @result: 解析结果输出
 *
 * 返回: 成功返回 PARSE_OK，失败返回负值错误码
 */
static __always_inline int parse_eth_simple(
    void *data,
    void *data_end,
    struct eth_parse_result *result
) {
    struct ethhdr *eth = data;

    result->eth = NULL;
    result->proto = 0;
    result->offset = 0;
    result->valid = 0;

    if (unlikely(!BOUNDS_CHECK_HDR(eth, data_end))) {
        return PARSE_TRUNCATED;
    }

    result->eth = eth;
    result->proto = bpf_ntohs(eth->h_proto);
    result->offset = sizeof(struct ethhdr);
    result->valid = 1;

    return PARSE_OK;
}

// =============================================================================
// IPv4 解析
// =============================================================================

/**
 * parse_ipv4 - 解析 IPv4 头
 * @data: IP 头起始指针
 * @data_end: 数据包结束指针
 * @base_offset: IP 头相对于数据包起始的偏移
 * @result: 解析结果输出
 *
 * 返回: 成功返回 PARSE_OK，失败返回负值错误码
 */
static __always_inline int parse_ipv4(
    void *data,
    void *data_end,
    __u16 base_offset,
    struct ip_parse_result *result
) {
    struct iphdr *ip = data;
    __u16 ip_hdr_len;

    // 初始化结果
    result->valid = 0;
    result->family = AF_INET_BPF;

    // 基本边界检查
    if (unlikely(!BOUNDS_CHECK_HDR(ip, data_end))) {
        return PARSE_TRUNCATED;
    }

    // 验证版本
    if (unlikely(ip->version != 4)) {
        return PARSE_INVALID;
    }

    // 验证 IHL (最小 5，即 20 字节)
    if (unlikely(ip->ihl < 5)) {
        return PARSE_INVALID;
    }

    ip_hdr_len = ip->ihl * 4;

    // 检查完整的 IP 头是否在包内
    if (unlikely(!BOUNDS_CHECK(data, ip_hdr_len, data_end))) {
        return PARSE_TRUNCATED;
    }

    // 填充结果
    result->hdr.v4 = ip;
    result->protocol = ip->protocol;
    result->payload_offset = base_offset + ip_hdr_len;
    result->total_len = bpf_ntohs(ip->tot_len);
    
    // 计算 payload 长度
    if (result->total_len >= ip_hdr_len) {
        result->payload_len = result->total_len - ip_hdr_len;
    } else {
        return PARSE_INVALID;
    }

    // 检查分片
    __u16 frag_off = bpf_ntohs(ip->frag_off);
    result->is_fragment = (frag_off & 0x1FFF) != 0 || (frag_off & 0x2000);

    // 复制地址
    result->src_addr.v4 = ip->saddr;
    result->dst_addr.v4 = ip->daddr;

    result->valid = 1;
    return PARSE_OK;
}

// =============================================================================
// IPv6 扩展头解析
// =============================================================================

/**
 * is_ipv6_ext_header - 检查是否为 IPv6 扩展头
 * @nexthdr: 下一个头部类型
 *
 * 返回: 是扩展头返回 1，否则返回 0
 */
static __always_inline int is_ipv6_ext_header(__u8 nexthdr) {
    switch (nexthdr) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_FRAGMENT:
    case IPPROTO_DSTOPTS:
    case IPPROTO_MH:
        return 1;
    default:
        return 0;
    }
}

/**
 * parse_ipv6_ext_headers_internal - 解析 IPv6 扩展头链
 * @data: 数据包起始
 * @data_end: 数据包结束
 * @ip6: IPv6 头指针
 * @result: 解析结果输出
 *
 * 返回: 成功返回 PARSE_OK，失败返回负值错误码
 *
 * 循环解析 IPv6 扩展头直至找到传输层协议 (UDP/TCP/ICMP6 等)
 */
static __always_inline int parse_ipv6_ext_headers_internal(
    void *data,
    void *data_end,
    struct ipv6hdr *ip6,
    struct ip_parse_result *result
) {
    __u8 nexthdr = ip6->nexthdr;
    void *ptr = (void *)(ip6 + 1);
    __u16 offset = sizeof(struct ipv6hdr);

    result->is_fragment = 0;

    // 循环解析扩展头，限制最大深度防止验证器问题
    #pragma unroll
    for (int i = 0; i < IPV6_EXT_MAX_DEPTH; i++) {
        // 检查是否到达最终协议
        switch (nexthdr) {
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_ICMPV6:
        case IPPROTO_SCTP:
        case IPPROTO_DCCP:
            // 找到传输层协议
            result->protocol = nexthdr;
            result->payload_offset += offset;
            result->payload_len = bpf_ntohs(ip6->payload_len) - 
                                 (offset - sizeof(struct ipv6hdr));
            return PARSE_OK;

        case IPPROTO_NONE:
            // 无后续头部
            result->protocol = nexthdr;
            result->payload_offset += offset;
            result->payload_len = 0;
            return PARSE_OK;

        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
        case IPPROTO_MH: {
            // 可变长度扩展头
            // 格式: [next_hdr:8][len:8][data...]
            // len 表示扩展头长度 (以 8 字节为单位，不包括第一个 8 字节)
            if (!BOUNDS_CHECK(ptr, 2, data_end)) {
                return PARSE_TRUNCATED;
            }

            __u8 *hdr = ptr;
            __u8 ext_next = hdr[0];
            __u8 ext_len = hdr[1];
            __u16 total_len = ((__u16)ext_len + 1) * 8;

            if (!BOUNDS_CHECK(ptr, total_len, data_end)) {
                return PARSE_TRUNCATED;
            }

            nexthdr = ext_next;
            ptr += total_len;
            offset += total_len;
            break;
        }

        case IPPROTO_FRAGMENT: {
            // 分片头 (固定 8 字节)
            // 格式: [next_hdr:8][reserved:8][frag_off:13][res:2][M:1][id:32]
            if (!BOUNDS_CHECK(ptr, 8, data_end)) {
                return PARSE_TRUNCATED;
            }

            __u8 *frag_hdr = ptr;
            nexthdr = frag_hdr[0];
            
            // 检查分片偏移和 M 标志
            __u16 frag_info = ((__u16)frag_hdr[2] << 8) | frag_hdr[3];
            if ((frag_info & 0xFFF8) != 0 || (frag_info & 0x1)) {
                result->is_fragment = 1;
            }

            ptr += 8;
            offset += 8;
            break;
        }

        default:
            // 未知类型，假设已到达传输层
            result->protocol = nexthdr;
            result->payload_offset += offset;
            result->payload_len = bpf_ntohs(ip6->payload_len) - 
                                 (offset - sizeof(struct ipv6hdr));
            return PARSE_OK;
        }
    }

    // 超过最大深度，返回当前状态
    result->protocol = nexthdr;
    result->payload_offset += offset;
    return PARSE_ERR;
}

/**
 * parse_ipv6 - 解析 IPv6 头 (包括扩展头)
 * @data: IPv6 头起始指针
 * @data_end: 数据包结束指针
 * @base_offset: IPv6 头相对于数据包起始的偏移
 * @result: 解析结果输出
 *
 * 返回: 成功返回 PARSE_OK，失败返回负值错误码
 */
static __always_inline int parse_ipv6(
    void *data,
    void *data_end,
    __u16 base_offset,
    struct ip_parse_result *result
) {
    struct ipv6hdr *ip6 = data;

    // 初始化结果
    result->valid = 0;
    result->family = AF_INET6_BPF;

    // 基本边界检查
    if (unlikely(!BOUNDS_CHECK_HDR(ip6, data_end))) {
        return PARSE_TRUNCATED;
    }

    // 验证版本
    if (unlikely(ip6->version != 6)) {
        return PARSE_INVALID;
    }

    // 填充基本信息
    result->hdr.v6 = ip6;
    result->total_len = sizeof(struct ipv6hdr) + bpf_ntohs(ip6->payload_len);
    result->payload_offset = base_offset;

    // 复制地址
    __builtin_memcpy(result->src_addr.v6, &ip6->saddr, 16);
    __builtin_memcpy(result->dst_addr.v6, &ip6->daddr, 16);

    // 解析扩展头
    int ret = parse_ipv6_ext_headers_internal(
        (void *)ip6 - base_offset,  // 传入数据包起始
        data_end,
        ip6,
        result
    );

    if (ret != PARSE_OK) {
        return ret;
    }

    result->valid = 1;
    return PARSE_OK;
}

// =============================================================================
// 统一 IP 解析
// =============================================================================

/**
 * parse_ip - 统一 IP 层解析 (自动识别 IPv4/IPv6)
 * @data: 数据包起始指针
 * @data_end: 数据包结束指针
 * @eth_proto: 以太网层协议类型 (主机字节序)
 * @base_offset: IP 头相对于数据包起始的偏移
 * @result: 解析结果输出
 *
 * 返回: 成功返回 PARSE_OK，失败返回负值错误码
 *
 * 该函数根据以太网协议类型自动选择 IPv4 或 IPv6 解析器。
 */
static __always_inline int parse_ip(
    void *data,
    void *data_end,
    __u16 eth_proto,
    __u16 base_offset,
    struct ip_parse_result *result
) {
    void *ip_hdr = data + base_offset;

    // 根据以太网协议类型选择解析器
    if (eth_proto == ETH_P_IP) {
        return parse_ipv4(ip_hdr, data_end, base_offset, result);
    } else if (eth_proto == ETH_P_IPV6) {
        return parse_ipv6(ip_hdr, data_end, base_offset, result);
    }

    // 不支持的协议
    result->valid = 0;
    return PARSE_INVALID;
}

/**
 * parse_ip_auto - 自动检测并解析 IP 头
 * @data: IP 头起始指针
 * @data_end: 数据包结束指针
 * @base_offset: IP 头相对于数据包起始的偏移
 * @result: 解析结果输出
 *
 * 返回: 成功返回 PARSE_OK，失败返回负值错误码
 *
 * 通过检查 IP 版本字段自动选择解析器。
 */
static __always_inline int parse_ip_auto(
    void *data,
    void *data_end,
    __u16 base_offset,
    struct ip_parse_result *result
) {
    void *ip_hdr = data + base_offset;

    // 边界检查 (至少需要 1 字节来检查版本)
    if (!BOUNDS_CHECK(ip_hdr, 1, data_end)) {
        result->valid = 0;
        return PARSE_TRUNCATED;
    }

    __u8 version = (*((__u8 *)ip_hdr)) >> 4;

    if (version == 4) {
        return parse_ipv4(ip_hdr, data_end, base_offset, result);
    } else if (version == 6) {
        return parse_ipv6(ip_hdr, data_end, base_offset, result);
    }

    result->valid = 0;
    return PARSE_INVALID;
}

// =============================================================================
// UDP 解析
// =============================================================================

/**
 * parse_udp - 解析 UDP 头
 * @data: 数据包起始指针
 * @data_end: 数据包结束指针
 * @offset: UDP 头相对于数据包起始的偏移
 * @result: 解析结果输出
 *
 * 返回: 成功返回 PARSE_OK，失败返回负值错误码
 *
 * 该函数验证 UDP 头部完整性，并定位 Payload 的起始位置。
 */
static __always_inline int parse_udp(
    void *data,
    void *data_end,
    __u16 offset,
    struct udp_parse_result *result
) {
    struct udphdr *udp = data + offset;

    // 初始化结果
    result->udp = NULL;
    result->payload = NULL;
    result->src_port = 0;
    result->dst_port = 0;
    result->payload_len = 0;
    result->payload_offset = 0;
    result->valid = 0;

    // 边界检查
    if (unlikely(!BOUNDS_CHECK_HDR(udp, data_end))) {
        return PARSE_TRUNCATED;
    }

    // 获取 UDP 长度
    __u16 udp_len = bpf_ntohs(udp->len);

    // 验证 UDP 长度 (最小为 UDP 头大小)
    if (unlikely(udp_len < sizeof(struct udphdr))) {
        return PARSE_INVALID;
    }

    // 计算 Payload 长度和偏移
    __u16 payload_len = udp_len - sizeof(struct udphdr);
    __u16 payload_offset = offset + sizeof(struct udphdr);
    void *payload = data + payload_offset;

    // 验证完整的 UDP 数据在包内
    if (unlikely(!BOUNDS_CHECK(data + offset, udp_len, data_end))) {
        return PARSE_TRUNCATED;
    }

    // 填充结果
    result->udp = udp;
    result->payload = payload;
    result->src_port = bpf_ntohs(udp->source);
    result->dst_port = bpf_ntohs(udp->dest);
    result->payload_len = payload_len;
    result->payload_offset = payload_offset;
    result->valid = 1;

    return PARSE_OK;
}

/**
 * parse_udp_from_ip - 基于 IP 解析结果解析 UDP
 * @data: 数据包起始指针
 * @data_end: 数据包结束指针
 * @ip_result: IP 层解析结果
 * @result: UDP 解析结果输出
 *
 * 返回: 成功返回 PARSE_OK，失败返回负值错误码
 */
static __always_inline int parse_udp_from_ip(
    void *data,
    void *data_end,
    struct ip_parse_result *ip_result,
    struct udp_parse_result *result
) {
    // 验证 IP 解析成功且协议为 UDP
    if (!ip_result->valid) {
        result->valid = 0;
        return PARSE_ERR;
    }

    if (ip_result->protocol != IPPROTO_UDP) {
        result->valid = 0;
        return PARSE_INVALID;
    }

    return parse_udp(data, data_end, ip_result->payload_offset, result);
}

// =============================================================================
// TCP 解析
// =============================================================================

/**
 * parse_tcp - 解析 TCP 头
 * @data: 数据包起始指针
 * @data_end: 数据包结束指针
 * @offset: TCP 头相对于数据包起始的偏移
 * @result: 解析结果输出
 *
 * 返回: 成功返回 PARSE_OK，失败返回负值错误码
 */
static __always_inline int parse_tcp(
    void *data,
    void *data_end,
    __u16 offset,
    struct tcp_parse_result *result
) {
    struct tcphdr *tcp = data + offset;

    // 初始化结果
    result->tcp = NULL;
    result->payload = NULL;
    result->src_port = 0;
    result->dst_port = 0;
    result->payload_len = 0;
    result->payload_offset = 0;
    result->valid = 0;
    result->hdr_len = 0;
    result->flags = 0;

    // 边界检查 (至少需要基本 TCP 头)
    if (unlikely(!BOUNDS_CHECK_HDR(tcp, data_end))) {
        return PARSE_TRUNCATED;
    }

    // 验证数据偏移 (最小 5，即 20 字节)
    if (unlikely(tcp->doff < 5)) {
        return PARSE_INVALID;
    }

    __u8 tcp_hdr_len = tcp->doff * 4;

    // 检查完整的 TCP 头 (包含选项) 是否在包内
    if (unlikely(!BOUNDS_CHECK(data + offset, tcp_hdr_len, data_end))) {
        return PARSE_TRUNCATED;
    }

    // 计算 Payload 偏移
    __u16 payload_offset = offset + tcp_hdr_len;
    void *payload = data + payload_offset;

    // 填充结果
    result->tcp = tcp;
    result->payload = payload;
    result->src_port = bpf_ntohs(tcp->source);
    result->dst_port = bpf_ntohs(tcp->dest);
    result->payload_offset = payload_offset;
    result->hdr_len = tcp_hdr_len;
    result->seq = bpf_ntohl(tcp->seq);
    result->ack = bpf_ntohl(tcp->ack_seq);

    // 提取 TCP 标志位
    result->flags = 0;
    if (tcp->fin) result->flags |= 0x01;
    if (tcp->syn) result->flags |= 0x02;
    if (tcp->rst) result->flags |= 0x04;
    if (tcp->psh) result->flags |= 0x08;
    if (tcp->ack) result->flags |= 0x10;
    if (tcp->urg) result->flags |= 0x20;

    result->valid = 1;
    return PARSE_OK;
}

/**
 * parse_tcp_from_ip - 基于 IP 解析结果解析 TCP
 * @data: 数据包起始指针
 * @data_end: 数据包结束指针
 * @ip_result: IP 层解析结果
 * @ip_payload_len: IP 层 payload 长度 (用于计算 TCP payload)
 * @result: TCP 解析结果输出
 *
 * 返回: 成功返回 PARSE_OK，失败返回负值错误码
 */
static __always_inline int parse_tcp_from_ip(
    void *data,
    void *data_end,
    struct ip_parse_result *ip_result,
    struct tcp_parse_result *result
) {
    // 验证 IP 解析成功且协议为 TCP
    if (!ip_result->valid) {
        result->valid = 0;
        return PARSE_ERR;
    }

    if (ip_result->protocol != IPPROTO_TCP) {
        result->valid = 0;
        return PARSE_INVALID;
    }

    int ret = parse_tcp(data, data_end, ip_result->payload_offset, result);
    if (ret != PARSE_OK) {
        return ret;
    }

    // 计算 payload 长度
    if (ip_result->payload_len >= result->hdr_len) {
        result->payload_len = ip_result->payload_len - result->hdr_len;
    } else {
        result->payload_len = 0;
    }

    return PARSE_OK;
}

// =============================================================================
// 完整数据包解析
// =============================================================================

/**
 * parse_packet_full - 完整解析数据包 (以太网 -> IP -> L4)
 * @data: 数据包起始指针
 * @data_end: 数据包结束指针
 * @ctx: 解析上下文输出
 *
 * 返回: 成功返回 PARSE_OK，失败返回负值错误码
 *
 * 该函数执行完整的数据包解析，从以太网头到传输层。
 */
static __always_inline int parse_packet_full(
    void *data,
    void *data_end,
    struct parse_context *ctx
) {
    int ret;

    // 初始化上下文
    ctx->data = data;
    ctx->data_end = data_end;
    ctx->fully_parsed = 0;
    ctx->l4_proto = 0;

    // 解析以太网头
    ret = parse_eth(data, data_end, &ctx->eth);
    if (ret != PARSE_OK || !ctx->eth.valid) {
        return ret;
    }

    // 检查是否为 IP 协议
    if (ctx->eth.proto != ETH_P_IP && ctx->eth.proto != ETH_P_IPV6) {
        return PARSE_OK;  // 非 IP 协议，停止解析但返回成功
    }

    // 解析 IP 层
    ret = parse_ip(data, data_end, ctx->eth.proto, ctx->eth.offset, &ctx->ip);
    if (ret != PARSE_OK || !ctx->ip.valid) {
        return ret;
    }

    // 记录 L4 协议
    ctx->l4_proto = ctx->ip.protocol;

    // 根据 L4 协议解析传输层
    switch (ctx->ip.protocol) {
    case IPPROTO_UDP:
        ret = parse_udp_from_ip(data, data_end, &ctx->ip, &ctx->l4.udp);
        if (ret == PARSE_OK && ctx->l4.udp.valid) {
            ctx->fully_parsed = 1;
        }
        break;

    case IPPROTO_TCP:
        ret = parse_tcp_from_ip(data, data_end, &ctx->ip, &ctx->l4.tcp);
        if (ret == PARSE_OK && ctx->l4.tcp.valid) {
            ctx->fully_parsed = 1;
        }
        break;

    default:
        // 其他协议暂不解析 L4
        ctx->fully_parsed = 0;
        ret = PARSE_OK;
        break;
    }

    return ret;
}

// =============================================================================
// 便捷解析函数
// =============================================================================

/**
 * parse_udp_packet - 快速解析 UDP 数据包
 * @data: 数据包起始指针
 * @data_end: 数据包结束指针
 * @eth_result: 以太网解析结果输出
 * @ip_result: IP 解析结果输出
 * @udp_result: UDP 解析结果输出
 *
 * 返回: 成功返回 PARSE_OK，失败返回负值错误码
 *
 * 便捷函数，一次性完成以太网->IP->UDP 解析。
 */
static __always_inline int parse_udp_packet(
    void *data,
    void *data_end,
    struct eth_parse_result *eth_result,
    struct ip_parse_result *ip_result,
    struct udp_parse_result *udp_result
) {
    int ret;

    // 解析以太网
    ret = parse_eth(data, data_end, eth_result);
    if (ret != PARSE_OK || !eth_result->valid) {
        return ret;
    }

    // 检查 IP 协议
    if (eth_result->proto != ETH_P_IP && eth_result->proto != ETH_P_IPV6) {
        ip_result->valid = 0;
        udp_result->valid = 0;
        return PARSE_INVALID;
    }

    // 解析 IP
    ret = parse_ip(data, data_end, eth_result->proto, eth_result->offset, ip_result);
    if (ret != PARSE_OK || !ip_result->valid) {
        udp_result->valid = 0;
        return ret;
    }

    // 检查 UDP 协议
    if (ip_result->protocol != IPPROTO_UDP) {
        udp_result->valid = 0;
        return PARSE_INVALID;
    }

    // 解析 UDP
    return parse_udp_from_ip(data, data_end, ip_result, udp_result);
}

/**
 * get_transport_ports - 快速获取传输层端口
 * @data: 数据包起始指针
 * @data_end: 数据包结束指针
 * @offset: 传输层头偏移
 * @protocol: 传输层协议
 * @src_port: 源端口输出 (主机字节序)
 * @dst_port: 目的端口输出 (主机字节序)
 *
 * 返回: 成功返回 PARSE_OK，失败返回负值错误码
 */
static __always_inline int get_transport_ports(
    void *data,
    void *data_end,
    __u16 offset,
    __u8 protocol,
    __u16 *src_port,
    __u16 *dst_port
) {
    // UDP 和 TCP 的端口位置相同 (头部前 4 字节)
    if (protocol != IPPROTO_UDP && protocol != IPPROTO_TCP) {
        return PARSE_INVALID;
    }

    __u16 *ports = data + offset;
    if (!BOUNDS_CHECK(ports, 4, data_end)) {
        return PARSE_TRUNCATED;
    }

    *src_port = bpf_ntohs(ports[0]);
    *dst_port = bpf_ntohs(ports[1]);

    return PARSE_OK;
}

#endif // __PARSING_H__
