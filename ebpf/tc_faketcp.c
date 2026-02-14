
// =============================================================================
// 文件: ebpf/tc_faketcp.c
// 描述: TC FakeTCP 程序 - 在 egress 路径上将 UDP 伪装成 TCP
// =============================================================================

#include "common.h"

#define PHANTOM_UDP_PORT 54321
#define PHANTOM_TCP_PORT 54322

// FakeTCP 会话状态
struct faketcp_state {
    __u32 seq_num;
    __u32 ack_num;
    __u32 peer_seq;
    __u8  state;
    __u8  padding[3];
    __u64 last_seen;
};

// 会话键
struct ft_session_key {
    __u32 local_ip;
    __u32 remote_ip;
    __u16 local_port;
    __u16 remote_port;
};

// 会话 Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ft_session_key);
    __type(value, struct faketcp_state);
} faketcp_sessions SEC(".maps");

// 配置 Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} faketcp_config SEC(".maps");

// 计算 TCP 校验和
static __always_inline __u16 calc_tcp_csum(struct iphdr *ip, struct tcphdr *tcp, void *data_end) {
    __u32 sum = 0;

    // 伪头部
    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += ip->saddr & 0xFFFF;
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += ip->daddr & 0xFFFF;
    sum += bpf_htons(IPPROTO_TCP);
    
    __u16 len = bpf_ntohs(ip->tot_len) - (ip->ihl * 4);
    sum += bpf_htons(len);

    // TCP 头 + 数据
    tcp->check = 0;
    __u16 *ptr = (__u16 *)tcp;
    
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if ((void *)(ptr + 1) > data_end)
            break;
        sum += *ptr++;
    }

    // 折叠
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

// TC egress: UDP -> FakeTCP
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

    // 只处理 UDP
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    // 解析 UDP 头
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    // 检查是否是目标端口
    __u32 cfg_key = 0;
    __u32 *target_port = bpf_map_lookup_elem(&faketcp_config, &cfg_key);
    __u16 port = target_port ? *target_port : PHANTOM_UDP_PORT;

    if (bpf_ntohs(udp->source) != port && bpf_ntohs(udp->dest) != port)
        return TC_ACT_OK;

    // 获取 UDP payload 长度
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(struct udphdr))
        return TC_ACT_OK;

    __u16 payload_len = udp_len - sizeof(struct udphdr);

    // 查找会话
    struct ft_session_key skey = {
        .local_ip = ip->saddr,
        .remote_ip = ip->daddr,
        .local_port = udp->source,
        .remote_port = udp->dest,
    };

    struct faketcp_state *state = bpf_map_lookup_elem(&faketcp_sessions, &skey);
    if (!state) {
        struct faketcp_state new_state = {
            .seq_num = bpf_get_prandom_u32(),
            .ack_num = 0,
            .peer_seq = 0,
            .state = 1,
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&faketcp_sessions, &skey, &new_state, BPF_ANY);
        state = bpf_map_lookup_elem(&faketcp_sessions, &skey);
        if (!state)
            return TC_ACT_OK;
    }

    // 修改 IP 协议字段
    ip->protocol = IPPROTO_TCP;

    // 将 UDP 头改写为 TCP 头
    struct tcphdr *tcp = (struct tcphdr *)udp;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // 保存端口
    __u16 sport = udp->source;
    __u16 dport = udp->dest;

    // 构造 TCP 头
    tcp->source = sport;
    tcp->dest = dport;
    tcp->seq = bpf_htonl(state->seq_num);
    tcp->ack_seq = bpf_htonl(state->ack_num);
    tcp->doff = 5;
    tcp->res1 = 0;
    tcp->fin = 0;
    tcp->syn = 0;
    tcp->rst = 0;
    tcp->psh = 1;
    tcp->ack = 1;
    tcp->urg = 0;
    tcp->res2 = 0;
    tcp->window = bpf_htons(65535);
    tcp->urg_ptr = 0;

    // 更新序列号
    state->seq_num += payload_len;
    state->last_seen = bpf_ktime_get_ns();

    // 重新计算校验和
    ip->check = 0;
    tcp->check = calc_tcp_csum(ip, tcp, data_end);

    return TC_ACT_OK;
}

// TC ingress: FakeTCP -> UDP
SEC("tc")
int tc_faketcp_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // 只处理 TCP
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // 检查是否是目标端口
    __u32 cfg_key = 1;
    __u32 *target_port = bpf_map_lookup_elem(&faketcp_config, &cfg_key);
    __u16 port = target_port ? *target_port : PHANTOM_TCP_PORT;

    if (bpf_ntohs(tcp->dest) != port)
        return TC_ACT_OK;

    // 查找会话并更新 ACK
    struct ft_session_key skey = {
        .local_ip = ip->daddr,
        .remote_ip = ip->saddr,
        .local_port = tcp->dest,
        .remote_port = tcp->source,
    };

    struct faketcp_state *state = bpf_map_lookup_elem(&faketcp_sessions, &skey);
    if (state) {
        state->peer_seq = bpf_ntohl(tcp->seq);
        state->ack_num = state->peer_seq + 1;
        state->last_seen = bpf_ktime_get_ns();
    }

    // 将 TCP 头改回 UDP 头
    ip->protocol = IPPROTO_UDP;

    struct udphdr *udp = (struct udphdr *)tcp;
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    __u16 sport = tcp->source;
    __u16 dport = tcp->dest;
    __u16 tcp_len = bpf_ntohs(ip->tot_len) - (ip->ihl * 4);
    __u16 tcp_hdr_len = tcp->doff * 4;
    __u16 payload_len = tcp_len - tcp_hdr_len;

    udp->source = sport;
    udp->dest = dport;
    udp->len = bpf_htons(sizeof(struct udphdr) + payload_len);
    udp->check = 0;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";




