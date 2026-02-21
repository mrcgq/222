// =============================================================================
// 文件: ebpf/xdp_phantom.c
// 描述: XDP 加速程序 - 首包过滤与防重放盾牌 (IPv4/IPv6 双栈支持)
// 核心功能: 
//   1. 黑名单过滤 - 在网卡层直接 DROP 恶意 IP
//   2. 速率限制 - 防止单 IP 洪水攻击
//   3. 会话跟踪 - 为 Go 端提供连接状态
// =============================================================================

#include "phantom_common.h"

// =============================================================================
// 黑名单相关常量
// =============================================================================

#define BLACKLIST_MAX_ENTRIES   100000   // 最大黑名单条目
#define RATELIMIT_MAX_ENTRIES   50000    // 速率限制表条目
#define RATELIMIT_WINDOW_NS     1000000000ULL  // 1 秒窗口 (纳秒)
#define RATELIMIT_MAX_PPS       1000     // 单 IP 每秒最大包数
#define RATELIMIT_MAX_BPS       10485760 // 单 IP 每秒最大字节数 (10MB)

// 黑名单标志
#define BLOCK_FLAG_NONE         0
#define BLOCK_FLAG_MANUAL       1   // 手动封禁
#define BLOCK_FLAG_REPLAY       2   // 重放攻击
#define BLOCK_FLAG_AUTH_FAIL    3   // 认证失败
#define BLOCK_FLAG_RATELIMIT    4   // 速率超限
#define BLOCK_FLAG_MALFORMED    5   // 畸形包

// =============================================================================
// 黑名单数据结构 - 已在 phantom_common.h 中定义
// =============================================================================
// struct blacklist_entry_v4  - 定义在 phantom_common.h
// struct blacklist_entry_v6  - 定义在 phantom_common.h
// struct ratelimit_entry     - 定义在 phantom_common.h

// =============================================================================
// eBPF Maps - 黑名单与速率限制
// =============================================================================

// IPv4 黑名单
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, BLACKLIST_MAX_ENTRIES);
    __type(key, __u32);                      // IPv4 地址
    __type(value, struct blacklist_entry_v4);
} blacklist_v4 SEC(".maps");

// IPv6 黑名单
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, BLACKLIST_MAX_ENTRIES / 4);
    __type(key, struct ip_addr);             // IPv6 地址 (128 位)
    __type(value, struct blacklist_entry_v6);
} blacklist_v6 SEC(".maps");

// IPv4 速率限制
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATELIMIT_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct ratelimit_entry);
} ratelimit_v4 SEC(".maps");

// IPv6 速率限制
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATELIMIT_MAX_ENTRIES / 4);
    __type(key, struct ip_addr);
    __type(value, struct ratelimit_entry);
} ratelimit_v6 SEC(".maps");

// =============================================================================
// eBPF Maps - 会话与配置
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

// 事件缓冲区 (perf buffer) - 用于向 Go 端报告事件
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
// 事件类型 (用于 perf buffer)
// =============================================================================

#define EVENT_TYPE_BLOCKED      1
#define EVENT_TYPE_RATELIMITED  2
#define EVENT_TYPE_NEW_SESSION  3
#define EVENT_TYPE_SUSPICIOUS   4

struct block_event {
    __u32 event_type;
    __u32 src_ip_v4;        // IPv4 地址 (如果是 IPv6 则为 0)
    struct ip_addr src_ip_v6; // IPv6 地址
    __u8  ip_version;       // 4 或 6
    __u8  block_reason;
    __u16 src_port;
    __u16 dst_port;
    __u16 pad;
    __u64 timestamp_ns;
};

// =============================================================================
// 统计更新辅助函数
// =============================================================================

static __always_inline void update_stats_rx(struct stats_counter *s, __u32 bytes) {
    __sync_fetch_and_add(&s->packets_rx, 1);
    __sync_fetch_and_add(&s->bytes_rx, bytes);
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

static __always_inline void update_stats_blacklist_hit(struct stats_counter *s) {
    __sync_fetch_and_add(&s->blacklist_hits, 1);
}

static __always_inline void update_stats_ratelimit_hit(struct stats_counter *s) {
    __sync_fetch_and_add(&s->ratelimit_hits, 1);
}

// =============================================================================
// 黑名单检查 - IPv4
// =============================================================================

static __always_inline int check_blacklist_v4(
    __u32 src_ip,
    __u32 pkt_len,
    struct stats_counter *stats_ptr
) {
    struct blacklist_entry_v4 *entry = bpf_map_lookup_elem(&blacklist_v4, &src_ip);
    if (!entry)
        return 0;  // 不在黑名单中
    
    if (entry->block_flag == BLOCK_FLAG_NONE)
        return 0;  // 已解除封禁
    
    // 更新拦截统计
    __sync_fetch_and_add(&entry->blocked_packets, 1);
    __sync_fetch_and_add(&entry->blocked_bytes, pkt_len);
    entry->last_seen = bpf_ktime_get_ns() / 1000000000ULL;
    
    update_stats_blacklist_hit(stats_ptr);
    update_stats_drop(stats_ptr);
    
    return 1;  // 在黑名单中，应该 DROP
}

// =============================================================================
// 黑名单检查 - IPv6
// =============================================================================

static __always_inline int check_blacklist_v6(
    const struct ip_addr *src_ip,
    __u32 pkt_len,
    struct stats_counter *stats_ptr
) {
    struct blacklist_entry_v6 *entry = bpf_map_lookup_elem(&blacklist_v6, src_ip);
    if (!entry)
        return 0;
    
    if (entry->block_flag == BLOCK_FLAG_NONE)
        return 0;
    
    __sync_fetch_and_add(&entry->blocked_packets, 1);
    __sync_fetch_and_add(&entry->blocked_bytes, pkt_len);
    entry->last_seen = bpf_ktime_get_ns() / 1000000000ULL;
    
    update_stats_blacklist_hit(stats_ptr);
    update_stats_drop(stats_ptr);
    
    return 1;
}

// =============================================================================
// 速率限制检查 - IPv4
// =============================================================================

static __always_inline int check_ratelimit_v4(
    __u32 src_ip,
    __u32 pkt_len,
    struct stats_counter *stats_ptr
) {
    __u64 now = bpf_ktime_get_ns();
    
    struct ratelimit_entry *entry = bpf_map_lookup_elem(&ratelimit_v4, &src_ip);
    if (!entry) {
        // 首次访问，创建条目
        struct ratelimit_entry new_entry = {
            .window_start_ns = now,
            .packet_count = 1,
            .byte_count = pkt_len,
            .warned = 0,
        };
        bpf_map_update_elem(&ratelimit_v4, &src_ip, &new_entry, BPF_ANY);
        return 0;
    }
    
    // 检查是否需要重置窗口
    if (now - entry->window_start_ns > RATELIMIT_WINDOW_NS) {
        entry->window_start_ns = now;
        entry->packet_count = 1;
        entry->byte_count = pkt_len;
        entry->warned = 0;
        return 0;
    }
    
    // 累加计数
    __sync_fetch_and_add(&entry->packet_count, 1);
    __sync_fetch_and_add(&entry->byte_count, pkt_len);
    
    // 检查是否超限
    if (entry->packet_count > RATELIMIT_MAX_PPS || 
        entry->byte_count > RATELIMIT_MAX_BPS) {
        
        update_stats_ratelimit_hit(stats_ptr);
        
        // 如果严重超限，自动加入黑名单
        if (entry->packet_count > RATELIMIT_MAX_PPS * 5) {
            struct blacklist_entry_v4 block_entry = {
                .block_flag = BLOCK_FLAG_RATELIMIT,
                .severity = 5,
                .fail_count = 1,
                .first_seen = now / 1000000000ULL,
                .last_seen = now / 1000000000ULL,
                .blocked_packets = 0,
                .blocked_bytes = 0,
            };
            bpf_map_update_elem(&blacklist_v4, &src_ip, &block_entry, BPF_ANY);
        }
        
        return 1;  // 超限，应该 DROP
    }
    
    return 0;
}

// =============================================================================
// 速率限制检查 - IPv6
// =============================================================================

static __always_inline int check_ratelimit_v6(
    const struct ip_addr *src_ip,
    __u32 pkt_len,
    struct stats_counter *stats_ptr
) {
    __u64 now = bpf_ktime_get_ns();
    
    struct ratelimit_entry *entry = bpf_map_lookup_elem(&ratelimit_v6, src_ip);
    if (!entry) {
        struct ratelimit_entry new_entry = {
            .window_start_ns = now,
            .packet_count = 1,
            .byte_count = pkt_len,
            .warned = 0,
        };
        bpf_map_update_elem(&ratelimit_v6, src_ip, &new_entry, BPF_ANY);
        return 0;
    }
    
    if (now - entry->window_start_ns > RATELIMIT_WINDOW_NS) {
        entry->window_start_ns = now;
        entry->packet_count = 1;
        entry->byte_count = pkt_len;
        entry->warned = 0;
        return 0;
    }
    
    __sync_fetch_and_add(&entry->packet_count, 1);
    __sync_fetch_and_add(&entry->byte_count, pkt_len);
    
    if (entry->packet_count > RATELIMIT_MAX_PPS || 
        entry->byte_count > RATELIMIT_MAX_BPS) {
        
        update_stats_ratelimit_hit(stats_ptr);
        
        if (entry->packet_count > RATELIMIT_MAX_PPS * 5) {
            struct blacklist_entry_v6 block_entry = {
                .block_flag = BLOCK_FLAG_RATELIMIT,
                .severity = 5,
                .fail_count = 1,
                .first_seen = now / 1000000000ULL,
                .last_seen = now / 1000000000ULL,
                .blocked_packets = 0,
                .blocked_bytes = 0,
            };
            bpf_map_update_elem(&blacklist_v6, src_ip, &block_entry, BPF_ANY);
        }
        
        return 1;
    }
    
    return 0;
}

// =============================================================================
// 会话管理
// =============================================================================

static __always_inline struct session_value *lookup_session(
    struct session_key *key
) {
    return bpf_map_lookup_elem(&sessions, key);
}

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

static __always_inline int is_ipv6_enabled(void) {
    __u32 key = 0;
    struct global_config *gcfg = bpf_map_lookup_elem(&config, &key);
    if (gcfg)
        return gcfg->enable_ipv6;
    return 1;
}

// 获取速率限制配置
static __always_inline __u32 get_ratelimit_pps(void) {
    __u32 key = 0;
    struct global_config *gcfg = bpf_map_lookup_elem(&config, &key);
    if (gcfg && gcfg->ratelimit_pps > 0)
        return gcfg->ratelimit_pps;
    return RATELIMIT_MAX_PPS;
}

// =============================================================================
// IPv4 UDP 处理（带黑名单和速率限制）
// =============================================================================

static __always_inline int process_udp_v4(
    struct xdp_md *ctx,
    struct stats_counter *stats_ptr,
    struct iphdr *ip,
    void *data_end
) {
    __u32 src_ip = ip->saddr;
    __u32 total_len = bpf_ntohs(ip->tot_len);
    
    // ========== 第一道防线：黑名单检查 ==========
    if (check_blacklist_v4(src_ip, total_len, stats_ptr)) {
        return XDP_DROP;  // 在内核态直接丢弃恶意 IP
    }
    
    // ========== 第二道防线：速率限制 ==========
    if (check_ratelimit_v4(src_ip, total_len, stats_ptr)) {
        return XDP_DROP;  // 速率超限，丢弃
    }
    
    // ========== 正常处理流程 ==========
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
    
    // 交给 Go 的 UDP Server 处理
    update_stats_pass(stats_ptr);
    return XDP_PASS;
}

// =============================================================================
// IPv6 UDP 处理（带黑名单和速率限制）
// =============================================================================

static __always_inline int process_udp_v6(
    struct xdp_md *ctx,
    struct stats_counter *stats_ptr,
    struct ipv6hdr *ip6,
    void *data_end
) {
    // 构建 IPv6 地址结构
    struct ip_addr src_addr = {};
    ipv6_addr_copy_raw(&src_addr, (__u32 *)&ip6->saddr);
    
    __u32 payload_len = bpf_ntohs(ip6->payload_len);
    
    // ========== 第一道防线：黑名单检查 ==========
    if (check_blacklist_v6(&src_addr, payload_len, stats_ptr)) {
        return XDP_DROP;
    }
    
    // ========== 第二道防线：速率限制 ==========
    if (check_ratelimit_v6(&src_addr, payload_len, stats_ptr)) {
        return XDP_DROP;
    }
    
    // ========== 正常处理流程 ==========
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
    
    struct ip_addr dst_addr = {};
    ipv6_addr_copy_raw(&dst_addr, (__u32 *)&ip6->daddr);
    
    // 检查是否是监听端口
    if (!is_listen_port(dst_port)) {
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
    
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(struct udphdr)) {
        update_stats_error(stats_ptr);
        return XDP_DROP;
    }
    
    __u16 udp_payload_len = udp_len - sizeof(struct udphdr);
    void *payload = (void *)(udp + 1);
    
    if ((void *)payload + udp_payload_len > data_end) {
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
    
    update_session(session, udp_payload_len, 1);
    
    if (session->state == STATE_NEW) {
        session->state = STATE_ESTABLISHED;
    }
    
    update_stats_pass(stats_ptr);
    return XDP_PASS;
}

// =============================================================================
// XDP 主入口 - 首包过滤与防重放盾牌
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
// XDP 快速路径 - 已建立会话的快速处理（带黑名单检查）
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
        
        // 快速黑名单检查
        if (check_blacklist_v4(ip->saddr, bpf_ntohs(ip->tot_len), stats_ptr))
            return XDP_DROP;
        
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
        
        // 快速黑名单检查
        struct ip_addr src_addr = {};
        ipv6_addr_copy_raw(&src_addr, (__u32 *)&ip6->saddr);
        if (check_blacklist_v6(&src_addr, bpf_ntohs(ip6->payload_len), stats_ptr))
            return XDP_DROP;
        
        // 简化：只处理无扩展头的情况
        if (ip6->nexthdr != IPPROTO_UDP)
            return XDP_PASS;
        
        struct udphdr *udp = (void *)(ip6 + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        
        struct ip_addr dst_addr = {};
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
// XDP 过滤器 - 基础包过滤（带黑名单）
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
        
        // 黑名单检查
        if (check_blacklist_v4(ip->saddr, bpf_ntohs(ip->tot_len), stats_ptr))
            return XDP_DROP;
        
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
        
        // 黑名单检查
        struct ip_addr src_addr = {};
        ipv6_addr_copy_raw(&src_addr, (__u32 *)&ip6->saddr);
        if (check_blacklist_v6(&src_addr, bpf_ntohs(ip6->payload_len), stats_ptr))
            return XDP_DROP;
        
        if (ip6->version != 6) {
            update_stats_drop(stats_ptr);
            return XDP_DROP;
        }
        
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
__u32 _version SEC("version") = 2;
