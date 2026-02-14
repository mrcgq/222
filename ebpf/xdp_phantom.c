


// =============================================================================
// 文件: ebpf/xdp_phantom.c
// 描述: XDP 加速程序 - 高性能数据包处理 (IPv4/IPv6 双栈支持)
// =============================================================================

#include "phantom_common.h"

// =============================================================================
// eBPF Maps
// =============================================================================

// 会话表 - 支持 IPv4/IPv6 双栈
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_SESSIONS);
    __type(key, struct session_key);
    __type(value, struct session_value);
} sessions SEC(".maps");

// 监听端口表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PORTS);
    __type(key, __u16);
    __type(value, struct port_config);
} listen_ports SEC(".maps");

// 全局配置
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_config);
} config SEC(".maps");

// Per-CPU 统计计数器
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_counter);
} stats SEC(".maps");

// 事件缓冲区 (perf buffer)
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// TX 端口 (用于重定向)
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} tx_ports SEC(".maps");

// =============================================================================
// 统计更新辅助函数
// =============================================================================

static __always_inline void update_stats_rx(struct stats_counter *s, __u32 bytes) {
    __sync_fetch_and_add(&s->packets_rx, 1);
    __sync_fetch_and_add(&s->bytes_rx, bytes);
}

static __always_inline void update_stats_tx(struct stats_counter *s, __u32 bytes) {
    __sync_fetch_and_add(&s->packets_tx, 1);
    __sync_fetch_and_add(&s->bytes_tx, bytes);
}

static __always_inline void update_stats_drop(struct stats_counter *s) {
    __sync_fetch_and_add(&s->packets_dropped, 1);
}

static __always_inline void update_stats_pass(struct stats_counter *s) {
    __sync_fetch_and_add(&s->packets_passed, 1);
}

static __always_inline void update_stats_error(struct stats_counter *s) {
    __sync_fetch_and_add(&s->errors, 1);
}

static __always_inline void update_stats_ipv6_rx(struct stats_counter *s, __u32 bytes) {
    __sync_fetch_and_add(&s->ipv6_packets_rx, 1);
    __sync_fetch_and_add(&s->packets_rx, 1);
    __sync_fetch_and_add(&s->bytes_rx, bytes);
}

// =============================================================================
// 会话管理
// =============================================================================

static __always_inline struct session_value *lookup_session(
    struct session_key *key
) {
    return bpf_map_lookup_elem(&sessions, key);
}

// 创建 IPv4 会话
static __always_inline int create_session_v4(
    struct session_key *key,
    __u32 peer_ip,
    __u16 peer_port
) {
    __u64 now = bpf_ktime_get_ns();
    
    struct session_value val = {};
    val.peer_ip.v4 = peer_ip;
    val.peer_port = peer_port;
    val.state = STATE_NEW;
    val.flags = 0;
    val.family = AF_INET_BPF;
    val.created_ns = now;
    val.last_seen_ns = now;
    
    return bpf_map_update_elem(&sessions, key, &val, BPF_ANY);
}

// 创建 IPv6 会话
static __always_inline int create_session_v6(
    struct session_key *key,
    const struct ip_addr *peer_ip,
    __u16 peer_port
) {
    __u64 now = bpf_ktime_get_ns();
    
    struct session_value val = {};
    val.peer_ip = *peer_ip;
    val.peer_port = peer_port;
    val.state = STATE_NEW;
    val.flags = 0;
    val.family = AF_INET6_BPF;
    val.created_ns = now;
    val.last_seen_ns = now;
    
    return bpf_map_update_elem(&sessions, key, &val, BPF_ANY);
}

// 兼容旧代码的会话创建
static __always_inline int create_session(
    struct session_key *key,
    __u32 peer_ip,
    __u16 peer_port
) {
    return create_session_v4(key, peer_ip, peer_port);
}

static __always_inline void update_session(
    struct session_value *session,
    __u32 bytes,
    int is_rx
) {
    session->last_seen_ns = bpf_ktime_get_ns();
    
    if (is_rx) {
        __sync_fetch_and_add(&session->bytes_in, bytes);
        __sync_fetch_and_add(&session->packets_in, 1);
    } else {
        __sync_fetch_and_add(&session->bytes_out, bytes);
        __sync_fetch_and_add(&session->packets_out, 1);
    }
}

// =============================================================================
// 端口检查
// =============================================================================

static __always_inline int is_listen_port(__u16 port) {
    struct port_config *cfg = bpf_map_lookup_elem(&listen_ports, &port);
    if (cfg && cfg->enabled)
        return 1;
    
    __u32 key = 0;
    struct global_config *gcfg = bpf_map_lookup_elem(&config, &key);
    if (gcfg && gcfg->listen_port == port)
        return 1;
    
    return 0;
}

// 检查是否启用 IPv6
static __always_inline int is_ipv6_enabled(void) {
    __u32 key = 0;
    struct global_config *gcfg = bpf_map_lookup_elem(&config, &key);
    if (gcfg)
        return gcfg->enable_ipv6;
    return 1;  // 默认启用
}

// =============================================================================
// 发送事件到用户态
// =============================================================================

static __always_inline void send_event_v4(
    void *ctx,
    __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u16 len, __u8 protocol,
    __u8 action, __u8 state
) {
    struct packet_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.src_ip.v4 = src_ip;
    event.dst_ip.v4 = dst_ip;
    event.src_port = src_port;
    event.dst_port = dst_port;
    event.len = len;
    event.protocol = protocol;
    event.action = action;
    event.state = state;
    event.family = AF_INET_BPF;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

static __always_inline void send_event_v6(
    void *ctx,
    const struct ip_addr *src_ip,
    const struct ip_addr *dst_ip,
    __u16 src_port, __u16 dst_port,
    __u16 len, __u8 protocol,
    __u8 action, __u8 state
) {
    struct packet_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.src_ip = *src_ip;
    event.dst_ip = *dst_ip;
    event.src_port = src_port;
    event.dst_port = dst_port;
    event.len = len;
    event.protocol = protocol;
    event.action = action;
    event.state = state;
    event.family = AF_INET6_BPF;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

// =============================================================================
// IPv4 UDP 处理
// =============================================================================

static __always_inline int process_udp_v4(
    struct xdp_md *ctx,
    struct stats_counter *stats_ptr,
    struct iphdr *ip,
    void *data_end
) {
    __u32 ip_hdr_len = ip->ihl * 4;
    struct udphdr *udp = parse_udphdr((void *)ip + ip_hdr_len, data_end);
    if (!udp) {
        update_stats_error(stats_ptr);
        return XDP_PASS;
    }
    
    __u16 dst_port = bpf_ntohs(udp->dest);
    __u16 src_port = bpf_ntohs(udp->source);
    
    // 检查是否是监听端口
    if (!is_listen_port(dst_port)) {
        // 检查反向会话
        struct session_key rev_key;
        make_session_key_v4(&rev_key, ip->daddr, ip->saddr, 
                           dst_port, src_port, IPPROTO_UDP);
        struct session_value *rev_session = lookup_session(&rev_key);
        if (!rev_session) {
            update_stats_pass(stats_ptr);
            return XDP_PASS;
        }
        update_session(rev_session, bpf_ntohs(udp->len), 0);
    }
    
    // 计算 payload
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(struct udphdr)) {
        update_stats_error(stats_ptr);
        return XDP_DROP;
    }
    
    __u16 payload_len = udp_len - sizeof(struct udphdr);
    void *payload = (void *)(udp + 1);
    
    if ((void *)payload + payload_len > data_end) {
        update_stats_error(stats_ptr);
        return XDP_PASS;
    }
    
    update_stats_rx(stats_ptr, udp_len);
    
    // 会话处理
    struct session_key key;
    make_session_key_v4(&key, ip->saddr, ip->daddr, 
                       src_port, dst_port, IPPROTO_UDP);
    
    struct session_value *session = lookup_session(&key);
    if (!session) {
        int ret = create_session_v4(&key, ip->saddr, src_port);
        if (ret < 0) {
            update_stats_error(stats_ptr);
            return XDP_PASS;
        }
        
        __sync_fetch_and_add(&stats_ptr->sessions_created, 1);
        
        session = lookup_session(&key);
        if (!session) {
            update_stats_error(stats_ptr);
            return XDP_PASS;
        }
        
        session->state = STATE_NEW;
    }
    
    update_session(session, payload_len, 1);
    
    if (session->state == STATE_NEW) {
        session->state = STATE_ESTABLISHED;
    }
    
    update_stats_pass(stats_ptr);
    return XDP_PASS;
}

// =============================================================================
// IPv6 UDP 处理
// =============================================================================

static __always_inline int process_udp_v6(
    struct xdp_md *ctx,
    struct stats_counter *stats_ptr,
    struct ipv6hdr *ip6,
    void *data_end
) {
    // 解析 IPv6 扩展头
    struct ipv6_parse_result parse_result = {};
    if (parse_ipv6_ext_headers((void *)ip6, data_end, ip6, &parse_result) < 0) {
        update_stats_error(stats_ptr);
        return XDP_PASS;
    }
    
    if (!parse_result.valid) {
        update_stats_error(stats_ptr);
        return XDP_PASS;
    }
    
    // 只处理 UDP
    if (parse_result.next_hdr != IPPROTO_UDP) {
        return XDP_PASS;
    }
    
    // 不处理分片包
    if (parse_result.fragment) {
        update_stats_pass(stats_ptr);
        return XDP_PASS;
    }
    
    // 解析 UDP 头
    void *udp_ptr = (void *)ip6 + parse_result.payload_offset;
    struct udphdr *udp = parse_udphdr(udp_ptr, data_end);
    if (!udp) {
        update_stats_error(stats_ptr);
        return XDP_PASS;
    }
    
    __u16 dst_port = bpf_ntohs(udp->dest);
    __u16 src_port = bpf_ntohs(udp->source);
    
    // 构建 IPv6 地址结构
    struct ip_addr src_addr = {};
    struct ip_addr dst_addr = {};
    ipv6_addr_copy_raw(&src_addr, (__u32 *)&ip6->saddr);
    ipv6_addr_copy_raw(&dst_addr, (__u32 *)&ip6->daddr);
    
    // 检查是否是监听端口
    if (!is_listen_port(dst_port)) {
        // 检查反向会话
        struct session_key rev_key;
        make_session_key_v6_raw(&rev_key, &dst_addr, &src_addr,
                               dst_port, src_port, IPPROTO_UDP);
        struct session_value *rev_session = lookup_session(&rev_key);
        if (!rev_session) {
            update_stats_pass(stats_ptr);
            return XDP_PASS;
        }
        update_session(rev_session, bpf_ntohs(udp->len), 0);
    }
    
    // 计算 payload
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(struct udphdr)) {
        update_stats_error(stats_ptr);
        return XDP_DROP;
    }
    
    __u16 payload_len = udp_len - sizeof(struct udphdr);
    void *payload = (void *)(udp + 1);
    
    if ((void *)payload + payload_len > data_end) {
        update_stats_error(stats_ptr);
        return XDP_PASS;
    }
    
    update_stats_ipv6_rx(stats_ptr, udp_len);
    
    // 会话处理
    struct session_key key;
    make_session_key_v6_raw(&key, &src_addr, &dst_addr,
                           src_port, dst_port, IPPROTO_UDP);
    
    struct session_value *session = lookup_session(&key);
    if (!session) {
        int ret = create_session_v6(&key, &src_addr, src_port);
        if (ret < 0) {
            update_stats_error(stats_ptr);
            return XDP_PASS;
        }
        
        __sync_fetch_and_add(&stats_ptr->sessions_created, 1);
        __sync_fetch_and_add(&stats_ptr->ipv6_sessions_created, 1);
        
        session = lookup_session(&key);
        if (!session) {
            update_stats_error(stats_ptr);
            return XDP_PASS;
        }
        
        session->state = STATE_NEW;
    }
    
    update_session(session, payload_len, 1);
    
    if (session->state == STATE_NEW) {
        session->state = STATE_ESTABLISHED;
    }
    
    update_stats_pass(stats_ptr);
    return XDP_PASS;
}

// =============================================================================
// XDP 主入口 - 支持 IPv4/IPv6 双栈
// =============================================================================

SEC("xdp")
int xdp_phantom_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 获取统计计数器
    __u32 stats_key = 0;
    struct stats_counter *stats_ptr = bpf_map_lookup_elem(&stats, &stats_key);
    if (!stats_ptr)
        return XDP_PASS;
    
    // 解析以太网头
    struct ethhdr *eth = parse_ethhdr(data, data_end);
    if (!eth) {
        update_stats_error(stats_ptr);
        return XDP_PASS;
    }
    
    __u16 eth_proto = eth->h_proto;
    
    // IPv4 处理
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = parse_iphdr(eth + 1, data_end);
        if (!ip) {
            update_stats_error(stats_ptr);
            return XDP_PASS;
        }
        
        if (ip->protocol != IPPROTO_UDP)
            return XDP_PASS;
        
        return process_udp_v4(ctx, stats_ptr, ip, data_end);
    }
    
    // IPv6 处理
    if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        // 检查是否启用 IPv6
        if (!is_ipv6_enabled())
            return XDP_PASS;
        
        struct ipv6hdr *ip6 = parse_ipv6hdr(eth + 1, data_end);
        if (!ip6) {
            update_stats_error(stats_ptr);
            return XDP_PASS;
        }
        
        return process_udp_v6(ctx, stats_ptr, ip6, data_end);
    }
    
    // 其他协议直接放行
    return XDP_PASS;
}

// =============================================================================
// XDP 快速路径 - 支持 IPv4/IPv6 双栈
// =============================================================================

SEC("xdp")
int xdp_phantom_fast(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    __u32 stats_key = 0;
    struct stats_counter *stats_ptr = bpf_map_lookup_elem(&stats, &stats_key);
    if (!stats_ptr)
        return XDP_PASS;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    __u16 eth_proto = eth->h_proto;
    
    // IPv4 快速路径
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        
        if (ip->protocol != IPPROTO_UDP)
            return XDP_PASS;
        
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        
        struct session_key key;
        make_session_key_v4(&key, ip->saddr, ip->daddr,
                           bpf_ntohs(udp->source), bpf_ntohs(udp->dest),
                           IPPROTO_UDP);
        
        struct session_value *session = lookup_session(&key);
        if (session && session->state == STATE_ESTABLISHED) {
            update_session(session, bpf_ntohs(udp->len), 1);
            update_stats_rx(stats_ptr, bpf_ntohs(udp->len));
            update_stats_pass(stats_ptr);
            return XDP_PASS;
        }
    }
    
    // IPv6 快速路径
    if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        if (!is_ipv6_enabled())
            return XDP_PASS;
        
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        
        // 简化：只处理无扩展头的情况
        if (ip6->nexthdr != IPPROTO_UDP)
            return XDP_PASS;
        
        struct udphdr *udp = (void *)(ip6 + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        
        struct ip_addr src_addr = {};
        struct ip_addr dst_addr = {};
        ipv6_addr_copy_raw(&src_addr, (__u32 *)&ip6->saddr);
        ipv6_addr_copy_raw(&dst_addr, (__u32 *)&ip6->daddr);
        
        struct session_key key;
        make_session_key_v6_raw(&key, &src_addr, &dst_addr,
                               bpf_ntohs(udp->source), bpf_ntohs(udp->dest),
                               IPPROTO_UDP);
        
        struct session_value *session = lookup_session(&key);
        if (session && session->state == STATE_ESTABLISHED) {
            update_session(session, bpf_ntohs(udp->len), 1);
            update_stats_ipv6_rx(stats_ptr, bpf_ntohs(udp->len));
            update_stats_pass(stats_ptr);
            return XDP_PASS;
        }
    }
    
    return XDP_PASS;
}

// =============================================================================
// XDP 过滤器 - 支持 IPv4/IPv6 双栈
// =============================================================================

SEC("xdp")
int xdp_phantom_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    __u32 stats_key = 0;
    struct stats_counter *stats_ptr = bpf_map_lookup_elem(&stats, &stats_key);
    if (!stats_ptr)
        return XDP_PASS;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    __u16 eth_proto = eth->h_proto;
    
    // IPv4 过滤
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        
        if (ip->version != 4) {
            update_stats_drop(stats_ptr);
            return XDP_DROP;
        }
        
        if (ip->ihl < 5) {
            update_stats_drop(stats_ptr);
            return XDP_DROP;
        }
        
        return XDP_PASS;
    }
    
    // IPv6 过滤
    if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        
        if (ip6->version != 6) {
            update_stats_drop(stats_ptr);
            return XDP_DROP;
        }
        
        // 检查 hop limit (类似 TTL)
        if (ip6->hop_limit == 0) {
            update_stats_drop(stats_ptr);
            return XDP_DROP;
        }
        
        return XDP_PASS;
    }
    
    return XDP_PASS;
}

// =============================================================================
// 许可证
// =============================================================================

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;



