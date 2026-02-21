
// =============================================================================
// 文件: ebpf/tc_faketcp.c
// 描述: TC FakeTCP 程序 - 在内核完成 UDP<->TCP 转换
// 版本: 3.0 - 修复 skb 空间调整，确保 Payload 不被截断
// =============================================================================

#include "phantom_common.h"

// =============================================================================
// 配置索引常量
// =============================================================================
#define CFG_UDP_PORT        0   // Go 监听的真实 UDP 端口
#define CFG_TCP_PORT        1   // FakeTCP 对外暴露的 TCP 端口
#define CFG_ENABLED         2   // 是否启用
#define CFG_DEBUG           3   // 调试开关

// 默认端口
#define DEFAULT_UDP_PORT    54321
#define DEFAULT_TCP_PORT    54322

// 头部大小差异
#define TCP_HDR_MIN_SIZE    20  // TCP 最小头部
#define UDP_HDR_SIZE        8   // UDP 头部
#define HDR_SIZE_DIFF       (TCP_HDR_MIN_SIZE - UDP_HDR_SIZE)  // 12 字节

// =============================================================================
// FakeTCP 会话状态
// =============================================================================
struct faketcp_state {
    __u32 seq_num;          // 本地序列号
    __u32 ack_num;          // 确认号
    __u32 peer_seq;         // 对端序列号
    __u8  state;            // 连接状态: 0=NEW, 1=ESTABLISHED, 2=CLOSING
    __u8  flags;            // 标志位
    __u8  _pad[2];          // 填充
    __u64 last_seen;        // 最后活动时间
    __u64 bytes_tx;         // 发送字节数
    __u64 bytes_rx;         // 接收字节数
} __attribute__((aligned(8)));

// 会话键 (IPv4)
struct ft_session_key {
    __u32 local_ip;
    __u32 remote_ip;
    __u16 local_port;
    __u16 remote_port;
} __attribute__((packed));

// =============================================================================
// BPF Maps
// =============================================================================

// 会话 Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ft_session_key);
    __type(value, struct faketcp_state);
} faketcp_sessions SEC(".maps");

// 配置 Map (存储端口配置)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} faketcp_config SEC(".maps");

// 统计 Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_counter);
} faketcp_stats SEC(".maps");

// =============================================================================
// 辅助函数
// =============================================================================

// 从配置 Map 读取端口
static __always_inline __u16 get_config_port(__u32 key, __u16 default_port) {
    __u32 *val = bpf_map_lookup_elem(&faketcp_config, &key);
    if (val && *val > 0 && *val < 65536) {
        return (__u16)*val;
    }
    return default_port;
}

// 计算 IP 校验和
static __always_inline __u16 calc_ip_csum(struct iphdr *ip) {
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)ip;
    
    ip->check = 0;
    
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        sum += ptr[i];
    }
    
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    
    return ~sum;
}

// 计算 TCP 伪头校验和
static __always_inline __u32 tcp_pseudo_csum(struct iphdr *ip, __u16 tcp_len) {
    __u32 sum = 0;
    
    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += ip->saddr & 0xFFFF;
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += ip->daddr & 0xFFFF;
    sum += bpf_htons(IPPROTO_TCP);
    sum += bpf_htons(tcp_len);
    
    return sum;
}

// 计算 TCP 校验和
static __always_inline __u16 calc_tcp_csum(struct iphdr *ip, struct tcphdr *tcp, 
                                           void *data_end, __u16 tcp_len) {
    __u32 sum = tcp_pseudo_csum(ip, tcp_len);
    
    tcp->check = 0;
    __u16 *ptr = (__u16 *)tcp;
    __u16 words = tcp_len / 2;
    
    #pragma unroll
    for (int i = 0; i < 512; i++) {
        if (i >= words)
            break;
        if ((void *)(ptr + 1) > data_end)
            break;
        sum += *ptr++;
    }
    
    if (tcp_len & 1) {
        __u8 *last = (__u8 *)ptr;
        if ((void *)(last + 1) <= data_end) {
            sum += (*last) << 8;
        }
    }
    
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    
    return ~sum;
}

// 更新统计
static __always_inline void update_stats(__u64 bytes, int is_rx) {
    __u32 key = 0;
    struct stats_counter *stats = bpf_map_lookup_elem(&faketcp_stats, &key);
    if (stats) {
        if (is_rx) {
            __sync_fetch_and_add(&stats->packets_rx, 1);
            __sync_fetch_and_add(&stats->bytes_rx, bytes);
        } else {
            __sync_fetch_and_add(&stats->packets_tx, 1);
            __sync_fetch_and_add(&stats->bytes_tx, bytes);
        }
    }
}

// =============================================================================
// TC Egress: UDP -> FakeTCP (出站：将 UDP 伪装成 TCP)
// 关键修复：使用 bpf_skb_adjust_room 扩展 12 字节空间
// =============================================================================
SEC("tc")
int tc_faketcp_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // 解析 IP 头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    // 解析 UDP 头
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    // 获取配置端口
    __u16 udp_port = get_config_port(CFG_UDP_PORT, DEFAULT_UDP_PORT);
    __u16 tcp_port = get_config_port(CFG_TCP_PORT, DEFAULT_TCP_PORT);

    // 检查是否是需要转换的端口
    if (udp->source != bpf_htons(udp_port))
        return TC_ACT_OK;

    // =========================================================================
    // 保存转换前的关键数据（扩容后指针会失效）
    // =========================================================================
    __u16 orig_sport = udp->source;
    __u16 orig_dport = udp->dest;
    __u16 udp_len = bpf_ntohs(udp->len);
    
    if (udp_len < sizeof(struct udphdr))
        return TC_ACT_OK;
    
    __u16 payload_len = udp_len - sizeof(struct udphdr);
    
    // 保存会话键所需数据
    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;

    // =========================================================================
    // 关键修复：扩展 skb 空间 (UDP 8 字节 -> TCP 20 字节，需要增加 12 字节)
    // =========================================================================
    int ret = bpf_skb_adjust_room(skb, HDR_SIZE_DIFF, BPF_ADJ_ROOM_NET, 0);
    if (ret) {
        // 扩容失败，放弃转换
        return TC_ACT_OK;
    }

    // =========================================================================
    // 关键：扩容后所有指针失效，必须重新获取！
    // =========================================================================
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;
    
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_SHOT;
    
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_SHOT;

    // =========================================================================
    // 查找或创建会话
    // =========================================================================
    struct ft_session_key skey = {
        .local_ip = saddr,
        .remote_ip = daddr,
        .local_port = orig_sport,
        .remote_port = orig_dport,
    };

    struct faketcp_state *state = bpf_map_lookup_elem(&faketcp_sessions, &skey);
    if (!state) {
        struct faketcp_state new_state = {
            .seq_num = bpf_get_prandom_u32(),
            .ack_num = 0,
            .peer_seq = 0,
            .state = 1,
            .flags = 0,
            .last_seen = bpf_ktime_get_ns(),
            .bytes_tx = 0,
            .bytes_rx = 0,
        };
        bpf_map_update_elem(&faketcp_sessions, &skey, &new_state, BPF_ANY);
        state = bpf_map_lookup_elem(&faketcp_sessions, &skey);
        if (!state)
            return TC_ACT_SHOT;
    }

    // =========================================================================
    // 修改 IP 头部
    // =========================================================================
    ip->protocol = IPPROTO_TCP;
    // 更新总长度 (增加了 12 字节)
    ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + HDR_SIZE_DIFF);

    // =========================================================================
    // 构造 TCP 头部 (现在有足够空间，不会覆盖 Payload)
    // =========================================================================
    tcp->source = bpf_htons(tcp_port);  // 源端口改为 FakeTCP 端口
    tcp->dest = orig_dport;              // 目标端口保持不变
    tcp->seq = bpf_htonl(state->seq_num);
    tcp->ack_seq = bpf_htonl(state->ack_num);
    tcp->doff = 5;      // 20 字节头部 (5 * 4)
    tcp->res1 = 0;
    tcp->fin = 0;
    tcp->syn = 0;
    tcp->rst = 0;
    tcp->psh = (payload_len > 0) ? 1 : 0;
    tcp->ack = 1;
    tcp->urg = 0;
    tcp->res2 = 0;
    tcp->window = bpf_htons(65535);
    tcp->urg_ptr = 0;
    tcp->check = 0;

    // 更新会话状态
    state->seq_num += payload_len;
    state->last_seen = bpf_ktime_get_ns();
    state->bytes_tx += payload_len;

    // =========================================================================
    // 重新计算校验和
    // =========================================================================
    ip->check = calc_ip_csum(ip);
    
    __u16 tcp_total_len = TCP_HDR_MIN_SIZE + payload_len;
    tcp->check = calc_tcp_csum(ip, tcp, data_end, tcp_total_len);

    // 更新统计
    update_stats(payload_len, 0);

    return TC_ACT_OK;
}

// =============================================================================
// TC Ingress: FakeTCP -> UDP (入站：将 TCP 还原为 UDP)
// 关键修复：使用 bpf_skb_adjust_room 缩减空间，确保 Payload 正确对齐
// =============================================================================
SEC("tc")
int tc_faketcp_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // 解析 IP 头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // 解析 TCP 头
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // 获取配置端口
    __u16 udp_port = get_config_port(CFG_UDP_PORT, DEFAULT_UDP_PORT);
    __u16 tcp_port = get_config_port(CFG_TCP_PORT, DEFAULT_TCP_PORT);

    // 检查是否是 FakeTCP 端口
    if (tcp->dest != bpf_htons(tcp_port))
        return TC_ACT_OK;

    // =========================================================================
    // 保存转换前的关键数据（缩减后指针会失效）
    // =========================================================================
    __u16 orig_sport = tcp->source;
    __u16 orig_dport = tcp->dest;
    __u16 tcp_hdr_len = tcp->doff * 4;
    __u32 tcp_seq = bpf_ntohl(tcp->seq);
    
    // 计算 Payload 长度
    __u16 ip_len = bpf_ntohs(ip->tot_len);
    __u16 ip_hdr_len = ip->ihl * 4;
    
    if (ip_len < ip_hdr_len + tcp_hdr_len)
        return TC_ACT_OK;
    
    __u16 payload_len = ip_len - ip_hdr_len - tcp_hdr_len;
    
    // 保存会话键所需数据
    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;

    // =========================================================================
    // 更新会话状态
    // =========================================================================
    struct ft_session_key skey = {
        .local_ip = daddr,
        .remote_ip = saddr,
        .local_port = bpf_htons(udp_port),
        .remote_port = orig_sport,
    };

    struct faketcp_state *state = bpf_map_lookup_elem(&faketcp_sessions, &skey);
    if (state) {
        state->peer_seq = tcp_seq;
        state->ack_num = tcp_seq + payload_len;
        if (payload_len == 0) {
            state->ack_num = tcp_seq + 1;
        }
        state->last_seen = bpf_ktime_get_ns();
        state->bytes_rx += payload_len;
    }

    // =========================================================================
    // 关键修复：缩减 skb 空间 (TCP 20+ 字节 -> UDP 8 字节)
    // 计算需要缩减的字节数（负数表示缩减）
    // =========================================================================
    int shrink_size = UDP_HDR_SIZE - tcp_hdr_len;  // 8 - 20 = -12 (或更多)
    
    int ret = bpf_skb_adjust_room(skb, shrink_size, BPF_ADJ_ROOM_NET, 0);
    if (ret) {
        // 缩减失败，放弃转换
        return TC_ACT_OK;
    }

    // =========================================================================
    // 关键：缩减后所有指针失效，必须重新获取！
    // =========================================================================
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;
    
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_SHOT;
    
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_SHOT;

    // =========================================================================
    // 修改 IP 头部
    // =========================================================================
    ip->protocol = IPPROTO_UDP;
    // 更新总长度 (减少了 tcp_hdr_len - 8 字节)
    __u16 new_ip_len = ip_hdr_len + UDP_HDR_SIZE + payload_len;
    ip->tot_len = bpf_htons(new_ip_len);

    // =========================================================================
    // 构造 UDP 头部
    // =========================================================================
    udp->source = orig_sport;
    udp->dest = bpf_htons(udp_port);  // 关键：改为 Go 监听的真实 UDP 端口
    udp->len = bpf_htons(UDP_HDR_SIZE + payload_len);
    udp->check = 0;  // UDP 校验和可选

    // =========================================================================
    // 重新计算 IP 校验和
    // =========================================================================
    ip->check = calc_ip_csum(ip);

    // 更新统计
    update_stats(payload_len, 1);

    return TC_ACT_OK;
}

// =============================================================================
// 许可证
// =============================================================================
char _license[] SEC("license") = "GPL";









