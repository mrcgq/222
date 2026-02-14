



// =============================================================================
// 文件: ebpf/lib/session.h
// 描述: 会话管理库 - 封装 sessions 和 listen_ports Map 操作
// =============================================================================

#ifndef __PHANTOM_SESSION_H__
#define __PHANTOM_SESSION_H__

#include "../phantom_common.h"

// =============================================================================
// Map 声明 (外部定义)
// =============================================================================

// 会话表 - 使用 LRU_HASH 自动淘汰旧会话
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct session_key);
    __type(value, struct session_value);
    __uint(max_entries, MAX_SESSIONS);
} sessions SEC(".maps");

// 监听端口白名单 - 快速端口查找
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, struct port_config);
    __uint(max_entries, MAX_PORTS);
} listen_ports SEC(".maps");

// =============================================================================
// 会话查找函数
// =============================================================================

/**
 * lookup_session - 在会话表中查找会话
 * @key: 会话键 (源/目的 IP、端口、协议、地址族)
 *
 * 返回: 会话值指针，未找到返回 NULL
 *
 * 注意: 此函数必须与用户态 Go 代码写入 Map 的结构完全对齐
 * Go 端使用 EBPFSessionKey 和 EBPFSessionValue 结构
 */
static __always_inline struct session_value *
lookup_session(const struct session_key *key)
{
    if (unlikely(!key))
        return NULL;
    
    return bpf_map_lookup_elem(&sessions, key);
}

/**
 * lookup_session_v4 - IPv4 会话快速查找
 * @src_ip:   源 IPv4 地址 (网络字节序)
 * @dst_ip:   目的 IPv4 地址 (网络字节序)
 * @src_port: 源端口 (网络字节序)
 * @dst_port: 目的端口 (网络字节序)
 * @protocol: 协议号 (IPPROTO_UDP/IPPROTO_TCP)
 *
 * 返回: 会话值指针，未找到返回 NULL
 */
static __always_inline struct session_value *
lookup_session_v4(__u32 src_ip, __u32 dst_ip,
                  __u16 src_port, __u16 dst_port,
                  __u8 protocol)
{
    struct session_key key;
    
    make_session_key_v4(&key, src_ip, dst_ip, src_port, dst_port, protocol);
    
    return bpf_map_lookup_elem(&sessions, &key);
}

/**
 * lookup_session_v6 - IPv6 会话快速查找
 * @src_ip:   源 IPv6 地址
 * @dst_ip:   目的 IPv6 地址
 * @src_port: 源端口 (网络字节序)
 * @dst_port: 目的端口 (网络字节序)
 * @protocol: 协议号 (IPPROTO_UDP/IPPROTO_TCP)
 *
 * 返回: 会话值指针，未找到返回 NULL
 */
static __always_inline struct session_value *
lookup_session_v6(const struct in6_addr *src_ip,
                  const struct in6_addr *dst_ip,
                  __u16 src_port, __u16 dst_port,
                  __u8 protocol)
{
    struct session_key key;
    
    make_session_key_v6(&key, src_ip, dst_ip, src_port, dst_port, protocol);
    
    return bpf_map_lookup_elem(&sessions, &key);
}

/**
 * lookup_session_bidir - 双向会话查找
 * @key:     会话键
 * @rev_key: 用于存储反向键的缓冲区 (可选，可为 NULL)
 *
 * 先查找正向会话，未找到则查找反向会话
 *
 * 返回: 会话值指针，未找到返回 NULL
 */
static __always_inline struct session_value *
lookup_session_bidir(const struct session_key *key,
                     struct session_key *rev_key)
{
    struct session_value *value;
    struct session_key local_rev;
    
    if (unlikely(!key))
        return NULL;
    
    // 正向查找
    value = bpf_map_lookup_elem(&sessions, key);
    if (value)
        return value;
    
    // 反向查找
    if (rev_key) {
        make_reverse_key(rev_key, key);
        return bpf_map_lookup_elem(&sessions, rev_key);
    } else {
        make_reverse_key(&local_rev, key);
        return bpf_map_lookup_elem(&sessions, &local_rev);
    }
}

// =============================================================================
// 会话创建/更新函数
// =============================================================================

/**
 * create_session - 创建新会话
 * @key:   会话键
 * @value: 会话初始值
 * @flags: BPF_NOEXIST (仅创建) 或 BPF_ANY (创建或更新)
 *
 * 返回: 0 成功，负数失败
 */
static __always_inline int
create_session(const struct session_key *key,
               const struct session_value *value,
               __u64 flags)
{
    if (unlikely(!key || !value))
        return -1;
    
    return bpf_map_update_elem(&sessions, key, value, flags);
}

/**
 * update_session - 更新会话
 * @key:   会话键
 * @value: 新的会话值
 *
 * 返回: 0 成功，负数失败
 */
static __always_inline int
update_session(const struct session_key *key,
               const struct session_value *value)
{
    return create_session(key, value, BPF_ANY);
}

/**
 * init_session_value - 初始化会话值
 * @value:    要初始化的会话值
 * @peer_ip:  对端 IP 地址
 * @peer_port: 对端端口
 * @family:   地址族 (AF_INET_BPF 或 AF_INET6_BPF)
 * @state:    初始状态
 */
static __always_inline void
init_session_value(struct session_value *value,
                   const struct ip_addr *peer_ip,
                   __u16 peer_port,
                   __u8 family,
                   __u8 state)
{
    __u64 now = bpf_ktime_get_ns();
    
    __builtin_memset(value, 0, sizeof(*value));
    
    if (peer_ip) {
        value->peer_ip = *peer_ip;
    }
    value->peer_port = peer_port;
    value->family = family;
    value->state = state;
    value->created_ns = now;
    value->last_seen_ns = now;
}

/**
 * update_session_activity - 更新会话活动时间和统计
 * @value:     会话值
 * @bytes:     数据字节数
 * @is_inbound: 是否为入向流量
 */
static __always_inline void
update_session_activity(struct session_value *value,
                        __u32 bytes,
                        int is_inbound)
{
    value->last_seen_ns = bpf_ktime_get_ns();
    
    if (is_inbound) {
        __sync_fetch_and_add(&value->bytes_in, bytes);
        __sync_fetch_and_add(&value->packets_in, 1);
    } else {
        __sync_fetch_and_add(&value->bytes_out, bytes);
        __sync_fetch_and_add(&value->packets_out, 1);
    }
}

/**
 * delete_session - 删除会话
 * @key: 会话键
 *
 * 返回: 0 成功，负数失败
 */
static __always_inline int
delete_session(const struct session_key *key)
{
    if (unlikely(!key))
        return -1;
    
    return bpf_map_delete_elem(&sessions, key);
}

/**
 * is_session_expired - 检查会话是否过期
 * @value:      会话值
 * @timeout_ns: 超时时间 (纳秒)
 *
 * 返回: 1 已过期，0 未过期
 */
static __always_inline int
is_session_expired(const struct session_value *value, __u64 timeout_ns)
{
    __u64 now = bpf_ktime_get_ns();
    
    if (unlikely(!value))
        return 1;
    
    return (now - value->last_seen_ns) > timeout_ns;
}

/**
 * is_session_established - 检查会话是否已建立
 * @value: 会话值
 *
 * 返回: 1 已建立，0 未建立
 */
static __always_inline int
is_session_established(const struct session_value *value)
{
    if (unlikely(!value))
        return 0;
    
    return value->state == STATE_ESTABLISHED;
}

// =============================================================================
// 端口检查函数
// =============================================================================

/**
 * check_port - 检查端口是否在白名单中
 * @port: 端口号 (主机字节序)
 *
 * 返回: 1 端口已启用，0 端口未启用或不存在
 */
static __always_inline int
check_port(__u16 port)
{
    struct port_config *config;
    
    config = bpf_map_lookup_elem(&listen_ports, &port);
    if (!config)
        return 0;
    
    return config->enabled != 0;
}

/**
 * check_port_net - 检查端口是否在白名单中 (网络字节序)
 * @port_net: 端口号 (网络字节序)
 *
 * 返回: 1 端口已启用，0 端口未启用或不存在
 */
static __always_inline int
check_port_net(__u16 port_net)
{
    __u16 port = bpf_ntohs(port_net);
    return check_port(port);
}

/**
 * get_port_config - 获取端口配置
 * @port: 端口号 (主机字节序)
 *
 * 返回: 端口配置指针，未找到返回 NULL
 */
static __always_inline struct port_config *
get_port_config(__u16 port)
{
    return bpf_map_lookup_elem(&listen_ports, &port);
}

/**
 * is_listen_port - 检查是否为监听端口 (便捷别名)
 * @port: 端口号 (主机字节序)
 *
 * 返回: 1 是监听端口，0 不是
 */
static __always_inline int
is_listen_port(__u16 port)
{
    return check_port(port);
}

/**
 * is_phantom_traffic - 检查是否为 Phantom 流量
 * @src_port: 源端口 (网络字节序)
 * @dst_port: 目的端口 (网络字节序)
 *
 * 检查源端口或目的端口是否为 Phantom 监听端口
 *
 * 返回: 1 是 Phantom 流量，0 不是
 */
static __always_inline int
is_phantom_traffic(__u16 src_port_net, __u16 dst_port_net)
{
    __u16 src_port = bpf_ntohs(src_port_net);
    __u16 dst_port = bpf_ntohs(dst_port_net);
    
    return check_port(dst_port) || check_port(src_port);
}

// =============================================================================
// 会话键规范化函数 (确保唯一性)
// =============================================================================

/**
 * normalize_session_key - 规范化会话键
 * @key: 会话键 (将被修改)
 *
 * 规范化会话键以确保双向流量使用相同的键
 * 规则: 较小的 IP:Port 对放在 src，较大的放在 dst
 *
 * 返回: 1 已交换，0 未交换
 *
 * 注意: 这个函数用于需要双向会话共享同一 Map 条目的场景
 */
static __always_inline int
normalize_session_key(struct session_key *key)
{
    int swap = 0;
    
    if (key->family == AF_INET_BPF) {
        // IPv4: 比较 IP 地址
        if (key->src_ip.v4 > key->dst_ip.v4) {
            swap = 1;
        } else if (key->src_ip.v4 == key->dst_ip.v4) {
            // IP 相同时比较端口
            if (key->src_port > key->dst_port) {
                swap = 1;
            }
        }
    } else {
        // IPv6: 依次比较 32 位块
        for (int i = 0; i < 4; i++) {
            if (key->src_ip.v6[i] > key->dst_ip.v6[i]) {
                swap = 1;
                break;
            } else if (key->src_ip.v6[i] < key->dst_ip.v6[i]) {
                break;
            }
        }
        // 如果 IP 完全相同，比较端口
        if (!swap && ipv6_addr_equal(&key->src_ip, &key->dst_ip)) {
            if (key->src_port > key->dst_port) {
                swap = 1;
            }
        }
    }
    
    if (swap) {
        // 交换源和目的
        struct ip_addr tmp_ip = key->src_ip;
        __u16 tmp_port = key->src_port;
        
        key->src_ip = key->dst_ip;
        key->dst_ip = tmp_ip;
        key->src_port = key->dst_port;
        key->dst_port = tmp_port;
    }
    
    return swap;
}

// =============================================================================
// 调试辅助函数
// =============================================================================

#ifdef DEBUG
/**
 * log_session_key - 打印会话键信息 (仅调试模式)
 * @prefix: 日志前缀
 * @key:    会话键
 */
static __always_inline void
log_session_key(const char *prefix, const struct session_key *key)
{
    if (!key)
        return;
    
    if (key->family == AF_INET_BPF) {
        bpf_printk("%s: v4 %pI4:%d -> %pI4:%d proto=%d",
                   prefix,
                   &key->src_ip.v4, bpf_ntohs(key->src_port),
                   &key->dst_ip.v4, bpf_ntohs(key->dst_port),
                   key->protocol);
    } else {
        bpf_printk("%s: v6 [%pI6]:%d -> [%pI6]:%d proto=%d",
                   prefix,
                   &key->src_ip.v6, bpf_ntohs(key->src_port),
                   &key->dst_ip.v6, bpf_ntohs(key->dst_port),
                   key->protocol);
    }
}

/**
 * log_session_value - 打印会话值信息 (仅调试模式)
 * @prefix: 日志前缀
 * @value:  会话值
 */
static __always_inline void
log_session_value(const char *prefix, const struct session_value *value)
{
    if (!value)
        return;
    
    bpf_printk("%s: state=%d bytes_in=%llu bytes_out=%llu",
               prefix, value->state, value->bytes_in, value->bytes_out);
}
#else
#define log_session_key(prefix, key)
#define log_session_value(prefix, value)
#endif

#endif // __PHANTOM_SESSION_H__





