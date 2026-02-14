
// =============================================================================
// 文件: ebpf/tc_phantom.c
// 描述: TC (Traffic Control) 程序 - 出口处理 (IPv4/IPv6 双栈支持)
// =============================================================================

#include "phantom_common.h"

// =============================================================================
// 引用 XDP 程序的 Maps
// =============================================================================

extern struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_SESSIONS);
    __type(key, struct session_key);
    __type(value, struct session_value);
} sessions SEC(".maps");

extern struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_counter);
} stats SEC(".maps");

extern struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_config);
} config SEC(".maps");

// =============================================================================
// 辅助函数
// =============================================================================

// 检查是否启用 IPv6
static __always_inline int is_ipv6_enabled_tc(void) {
    __u32 key = 0;
    struct global_config *gcfg = bpf_map_lookup_elem(&config, &key);
    if (gcfg)
        return gcfg->enable_ipv6;
    return 1;
}

// =============================================================================
// IPv4 出口处理
// =============================================================================

static __always_inline int tc_process_egress_v4(
    struct __sk_buff *skb,
    struct stats_counter *stats_ptr,
    struct iphdr *ip,
    void *data_end
) {
    __u32 ip_hdr_len = ip->ihl * 4;
    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    
    __u16 src_port = bpf_ntohs(udp->source);
    __u16 dst_port = bpf_ntohs(udp->dest);
    
    // 出口使用反向键查找会话
    struct session_key key;
    make_session_key_v4(&key, ip->daddr, ip->saddr,
                       dst_port, src_port, IPPROTO_UDP);
    
    struct session_value *session = bpf_map_lookup_elem(&sessions, &key);
    if (session) {
        // 更新出口统计
        __u16 payload_len = bpf_ntohs(udp->len) - sizeof(struct udphdr);
        __sync_fetch_and_add(&session->bytes_out, payload_len);
        __sync_fetch_and_add(&session->packets_out, 1);
        session->last_seen_ns = bpf_ktime_get_ns();
        
        // 更新全局统计
        __sync_fetch_and_add(&stats_ptr->packets_tx, 1);
        __sync_fetch_and_add(&stats_ptr->bytes_tx, bpf_ntohs(udp->len));
    }
    
    return TC_ACT_OK;
}

// =============================================================================
// IPv6 出口处理
// =============================================================================

static __always_inline int tc_process_egress_v6(
    struct __sk_buff *skb,
    struct stats_counter *stats_ptr,
    struct ipv6hdr *ip6,
    void *data_end
) {
    // 解析 IPv6 扩展头
    struct ipv6_parse_result parse_result = {};
    if (parse_ipv6_ext_headers((void *)ip6, data_end, ip6, &parse_result) < 0)
        return TC_ACT_OK;
    
    if (!parse_result.valid)
        return TC_ACT_OK;
    
    // 只处理 UDP
    if (parse_result.next_hdr != IPPROTO_UDP)
        return TC_ACT_OK;
    
    // 不处理分片包
    if (parse_result.fragment)
        return TC_ACT_OK;
    
    // 解析 UDP 头
    void *udp_ptr = (void *)ip6 + parse_result.payload_offset;
    struct udphdr *udp = udp_ptr;
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    
    __u16 src_port = bpf_ntohs(udp->source);
    __u16 dst_port = bpf_ntohs(udp->dest);
    
    // 构建 IPv6 地址
    struct ip_addr src_addr = {};
    struct ip_addr dst_addr = {};
    ipv6_addr_copy_raw(&src_addr, (__u32 *)&ip6->saddr);
    ipv6_addr_copy_raw(&dst_addr, (__u32 *)&ip6->daddr);
    
    // 出口使用反向键查找会话
    struct session_key key;
    make_session_key_v6_raw(&key, &dst_addr, &src_addr,
                           dst_port, src_port, IPPROTO_UDP);
    
    struct session_value *session = bpf_map_lookup_elem(&sessions, &key);
    if (session) {
        // 更新出口统计
        __u16 payload_len = bpf_ntohs(udp->len) - sizeof(struct udphdr);
        __sync_fetch_and_add(&session->bytes_out, payload_len);
        __sync_fetch_and_add(&session->packets_out, 1);
        session->last_seen_ns = bpf_ktime_get_ns();
        
        // 更新全局统计
        __sync_fetch_and_add(&stats_ptr->packets_tx, 1);
        __sync_fetch_and_add(&stats_ptr->bytes_tx, bpf_ntohs(udp->len));
        __sync_fetch_and_add(&stats_ptr->ipv6_packets_tx, 1);
    }
    
    return TC_ACT_OK;
}

// =============================================================================
// TC Egress - 出口处理 (IPv4/IPv6 双栈)
// =============================================================================

SEC("tc")
int tc_phantom_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    __u32 stats_key = 0;
    struct stats_counter *stats_ptr = bpf_map_lookup_elem(&stats, &stats_key);
    if (!stats_ptr)
        return TC_ACT_OK;
    
    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    __u16 eth_proto = eth->h_proto;
    
    // IPv4 处理
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;
        
        if (ip->protocol != IPPROTO_UDP)
            return TC_ACT_OK;
        
        return tc_process_egress_v4(skb, stats_ptr, ip, data_end);
    }
    
    // IPv6 处理
    if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        if (!is_ipv6_enabled_tc())
            return TC_ACT_OK;
        
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;
        
        return tc_process_egress_v6(skb, stats_ptr, ip6, data_end);
    }
    
    return TC_ACT_OK;
}

// =============================================================================
// IPv4 入口处理
// =============================================================================

static __always_inline int tc_process_ingress_v4(
    struct __sk_buff *skb,
    struct stats_counter *stats_ptr,
    struct iphdr *ip,
    void *data_end
) {
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    
    __sync_fetch_and_add(&stats_ptr->packets_rx, 1);
    __sync_fetch_and_add(&stats_ptr->bytes_rx, bpf_ntohs(udp->len));
    
    return TC_ACT_OK;
}

// =============================================================================
// IPv6 入口处理
// =============================================================================

static __always_inline int tc_process_ingress_v6(
    struct __sk_buff *skb,
    struct stats_counter *stats_ptr,
    struct ipv6hdr *ip6,
    void *data_end
) {
    // 解析扩展头
    struct ipv6_parse_result parse_result = {};
    if (parse_ipv6_ext_headers((void *)ip6, data_end, ip6, &parse_result) < 0)
        return TC_ACT_OK;
    
    if (!parse_result.valid || parse_result.next_hdr != IPPROTO_UDP)
        return TC_ACT_OK;
    
    if (parse_result.fragment)
        return TC_ACT_OK;
    
    void *udp_ptr = (void *)ip6 + parse_result.payload_offset;
    struct udphdr *udp = udp_ptr;
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    
    __sync_fetch_and_add(&stats_ptr->packets_rx, 1);
    __sync_fetch_and_add(&stats_ptr->bytes_rx, bpf_ntohs(udp->len));
    __sync_fetch_and_add(&stats_ptr->ipv6_packets_rx, 1);
    
    return TC_ACT_OK;
}

// =============================================================================
// TC Ingress - 入口处理 (IPv4/IPv6 双栈)
// =============================================================================

SEC("tc")
int tc_phantom_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    __u32 stats_key = 0;
    struct stats_counter *stats_ptr = bpf_map_lookup_elem(&stats, &stats_key);
    if (!stats_ptr)
        return TC_ACT_OK;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    __u16 eth_proto = eth->h_proto;
    
    // IPv4 处理
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;
        
        if (ip->protocol != IPPROTO_UDP)
            return TC_ACT_OK;
        
        return tc_process_ingress_v4(skb, stats_ptr, ip, data_end);
    }
    
    // IPv6 处理
    if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        if (!is_ipv6_enabled_tc())
            return TC_ACT_OK;
        
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;
        
        return tc_process_ingress_v6(skb, stats_ptr, ip6, data_end);
    }
    
    return TC_ACT_OK;
}

// =============================================================================
// 许可证
// =============================================================================

char _license[] SEC("license") = "GPL";




