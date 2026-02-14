











// =============================================================================
// 文件: ebpf/lib/stats.h
// 描述: 原子统计库 - Per-CPU Map 高性能统计操作 (IPv4/IPv6 双栈支持)
// =============================================================================

#ifndef __PHANTOM_STATS_H__
#define __PHANTOM_STATS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// =============================================================================
// 前向声明 - 依赖 phantom_common.h 中的类型定义
// =============================================================================

// 注意: 此头文件需要在 phantom_common.h 之后包含，
// 或者确保 struct stats_counter 已定义

// =============================================================================
// 统计更新标志
// =============================================================================

#define STATS_FLAG_IPV6         (1 << 0)    // IPv6 流量
#define STATS_FLAG_SESSION      (1 << 1)    // 会话相关
#define STATS_FLAG_ERROR        (1 << 2)    // 错误统计
#define STATS_FLAG_CHECKSUM     (1 << 3)    // 校验和错误

// =============================================================================
// 内部辅助宏
// =============================================================================

// 原子递增宏
#define ATOMIC_INC(ptr)         __sync_fetch_and_add((ptr), 1)
#define ATOMIC_ADD(ptr, val)    __sync_fetch_and_add((ptr), (val))

// 安全的统计指针获取
#define GET_STATS_PTR(map, key_ptr)  \
    (struct stats_counter *)bpf_map_lookup_elem(&(map), (key_ptr))

// =============================================================================
// RX 统计更新函数
// =============================================================================

/**
 * update_rx_stats - 更新接收统计 (通用版本)
 * @stats: 统计计数器指针
 * @bytes: 接收字节数
 *
 * 原子更新接收包数和字节数
 */
static __always_inline void update_rx_stats(
    struct stats_counter *stats,
    __u64 bytes
) {
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->packets_rx);
    ATOMIC_ADD(&stats->bytes_rx, bytes);
}

/**
 * update_rx_stats_v4 - 更新 IPv4 接收统计
 * @stats: 统计计数器指针
 * @bytes: 接收字节数
 */
static __always_inline void update_rx_stats_v4(
    struct stats_counter *stats,
    __u64 bytes
) {
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->packets_rx);
    ATOMIC_ADD(&stats->bytes_rx, bytes);
}

/**
 * update_rx_stats_v6 - 更新 IPv6 接收统计
 * @stats: 统计计数器指针
 * @bytes: 接收字节数
 *
 * 同时更新通用 RX 统计和 IPv6 特定统计
 */
static __always_inline void update_rx_stats_v6(
    struct stats_counter *stats,
    __u64 bytes
) {
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->packets_rx);
    ATOMIC_ADD(&stats->bytes_rx, bytes);
    ATOMIC_INC(&stats->ipv6_packets_rx);
}

/**
 * update_rx_stats_by_family - 根据地址族更新接收统计
 * @stats: 统计计数器指针
 * @bytes: 接收字节数
 * @family: 地址族 (AF_INET_BPF 或 AF_INET6_BPF)
 */
static __always_inline void update_rx_stats_by_family(
    struct stats_counter *stats,
    __u64 bytes,
    __u8 family
) {
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->packets_rx);
    ATOMIC_ADD(&stats->bytes_rx, bytes);
    
    if (family == AF_INET6_BPF) {
        ATOMIC_INC(&stats->ipv6_packets_rx);
    }
}

// =============================================================================
// TX 统计更新函数
// =============================================================================

/**
 * update_tx_stats - 更新发送统计 (通用版本)
 * @stats: 统计计数器指针
 * @bytes: 发送字节数
 */
static __always_inline void update_tx_stats(
    struct stats_counter *stats,
    __u64 bytes
) {
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->packets_tx);
    ATOMIC_ADD(&stats->bytes_tx, bytes);
}

/**
 * update_tx_stats_v4 - 更新 IPv4 发送统计
 * @stats: 统计计数器指针
 * @bytes: 发送字节数
 */
static __always_inline void update_tx_stats_v4(
    struct stats_counter *stats,
    __u64 bytes
) {
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->packets_tx);
    ATOMIC_ADD(&stats->bytes_tx, bytes);
}

/**
 * update_tx_stats_v6 - 更新 IPv6 发送统计
 * @stats: 统计计数器指针
 * @bytes: 发送字节数
 */
static __always_inline void update_tx_stats_v6(
    struct stats_counter *stats,
    __u64 bytes
) {
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->packets_tx);
    ATOMIC_ADD(&stats->bytes_tx, bytes);
    ATOMIC_INC(&stats->ipv6_packets_tx);
}

/**
 * update_tx_stats_by_family - 根据地址族更新发送统计
 * @stats: 统计计数器指针
 * @bytes: 发送字节数
 * @family: 地址族
 */
static __always_inline void update_tx_stats_by_family(
    struct stats_counter *stats,
    __u64 bytes,
    __u8 family
) {
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->packets_tx);
    ATOMIC_ADD(&stats->bytes_tx, bytes);
    
    if (family == AF_INET6_BPF) {
        ATOMIC_INC(&stats->ipv6_packets_tx);
    }
}

// =============================================================================
// DROP/PASS 统计函数
// =============================================================================

/**
 * count_drop - 统计被丢弃的数据包
 * @stats: 统计计数器指针
 *
 * 原子递增丢弃计数
 */
static __always_inline void count_drop(struct stats_counter *stats)
{
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->packets_dropped);
}

/**
 * count_drop_with_bytes - 统计被丢弃的数据包和字节
 * @stats: 统计计数器指针
 * @bytes: 丢弃的字节数 (用于详细统计)
 */
static __always_inline void count_drop_with_bytes(
    struct stats_counter *stats,
    __u64 bytes
) {
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->packets_dropped);
    // 注意: 当前 stats_counter 没有 bytes_dropped 字段
    // 如需要可扩展结构体
}

/**
 * count_pass - 统计被放行的数据包
 * @stats: 统计计数器指针
 */
static __always_inline void count_pass(struct stats_counter *stats)
{
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->packets_passed);
}

/**
 * count_pass_with_bytes - 统计被放行的数据包和字节
 * @stats: 统计计数器指针
 * @bytes: 放行的字节数
 */
static __always_inline void count_pass_with_bytes(
    struct stats_counter *stats,
    __u64 bytes
) {
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->packets_passed);
    // 放行的字节通常已计入 rx/tx 统计
}

/**
 * count_redirect - 统计被重定向的数据包
 * @stats: 统计计数器指针
 */
static __always_inline void count_redirect(struct stats_counter *stats)
{
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->packets_redirected);
}

// =============================================================================
// 错误统计函数
// =============================================================================

/**
 * count_error - 统计通用错误
 * @stats: 统计计数器指针
 */
static __always_inline void count_error(struct stats_counter *stats)
{
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->errors);
}

/**
 * count_checksum_error - 统计校验和错误
 * @stats: 统计计数器指针
 */
static __always_inline void count_checksum_error(struct stats_counter *stats)
{
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->checksum_errors);
}

/**
 * count_invalid_packet - 统计无效数据包
 * @stats: 统计计数器指针
 */
static __always_inline void count_invalid_packet(struct stats_counter *stats)
{
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->invalid_packets);
}

// =============================================================================
// 会话统计函数
// =============================================================================

/**
 * count_session_created - 统计新建会话
 * @stats: 统计计数器指针
 */
static __always_inline void count_session_created(struct stats_counter *stats)
{
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->sessions_created);
}

/**
 * count_session_created_v6 - 统计新建 IPv6 会话
 * @stats: 统计计数器指针
 */
static __always_inline void count_session_created_v6(struct stats_counter *stats)
{
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->sessions_created);
    ATOMIC_INC(&stats->ipv6_sessions_created);
}

/**
 * count_session_created_by_family - 根据地址族统计新建会话
 * @stats: 统计计数器指针
 * @family: 地址族
 */
static __always_inline void count_session_created_by_family(
    struct stats_counter *stats,
    __u8 family
) {
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->sessions_created);
    
    if (family == AF_INET6_BPF) {
        ATOMIC_INC(&stats->ipv6_sessions_created);
    }
}

/**
 * count_session_expired - 统计过期会话
 * @stats: 统计计数器指针
 */
static __always_inline void count_session_expired(struct stats_counter *stats)
{
    if (!stats)
        return;
    
    ATOMIC_INC(&stats->sessions_expired);
}

// =============================================================================
// 会话流量统计函数
// =============================================================================

/**
 * update_session_rx_stats - 更新会话接收统计
 * @session: 会话值指针
 * @bytes: 接收字节数
 */
static __always_inline void update_session_rx_stats(
    struct session_value *session,
    __u64 bytes
) {
    if (!session)
        return;
    
    ATOMIC_INC(&session->packets_in);
    ATOMIC_ADD(&session->bytes_in, bytes);
    session->last_seen_ns = bpf_ktime_get_ns();
}

/**
 * update_session_tx_stats - 更新会话发送统计
 * @session: 会话值指针
 * @bytes: 发送字节数
 */
static __always_inline void update_session_tx_stats(
    struct session_value *session,
    __u64 bytes
) {
    if (!session)
        return;
    
    ATOMIC_INC(&session->packets_out);
    ATOMIC_ADD(&session->bytes_out, bytes);
    session->last_seen_ns = bpf_ktime_get_ns();
}

// =============================================================================
// 批量统计更新函数
// =============================================================================

/**
 * struct stats_update - 批量统计更新结构
 */
struct stats_update {
    __u64 packets_rx;
    __u64 packets_tx;
    __u64 bytes_rx;
    __u64 bytes_tx;
    __u64 drops;
    __u64 passes;
    __u8  family;
    __u8  reserved[7];
};

/**
 * apply_stats_update - 应用批量统计更新
 * @stats: 统计计数器指针
 * @update: 更新结构指针
 */
static __always_inline void apply_stats_update(
    struct stats_counter *stats,
    const struct stats_update *update
) {
    if (!stats || !update)
        return;
    
    if (update->packets_rx)
        ATOMIC_ADD(&stats->packets_rx, update->packets_rx);
    if (update->packets_tx)
        ATOMIC_ADD(&stats->packets_tx, update->packets_tx);
    if (update->bytes_rx)
        ATOMIC_ADD(&stats->bytes_rx, update->bytes_rx);
    if (update->bytes_tx)
        ATOMIC_ADD(&stats->bytes_tx, update->bytes_tx);
    if (update->drops)
        ATOMIC_ADD(&stats->packets_dropped, update->drops);
    if (update->passes)
        ATOMIC_ADD(&stats->packets_passed, update->passes);
    
    // IPv6 特定统计
    if (update->family == AF_INET6_BPF) {
        if (update->packets_rx)
            ATOMIC_ADD(&stats->ipv6_packets_rx, update->packets_rx);
        if (update->packets_tx)
            ATOMIC_ADD(&stats->ipv6_packets_tx, update->packets_tx);
    }
}

// =============================================================================
// 统计获取辅助函数 (用于 Map 查询)
// =============================================================================

/**
 * get_stats_ptr - 从 Map 获取统计指针
 * @map: 统计 Map 引用
 *
 * 返回 Per-CPU 统计指针，失败返回 NULL
 */
#define get_stats_ptr(map)                              \
    ({                                                  \
        __u32 _key = 0;                                 \
        (struct stats_counter *)bpf_map_lookup_elem(&(map), &_key); \
    })

/**
 * with_stats - 条件执行统计更新的宏
 * @map: 统计 Map
 * @code: 要执行的代码块 (可使用 _stats 变量)
 */
#define with_stats(map, code)                           \
    do {                                                \
        struct stats_counter *_stats = get_stats_ptr(map); \
        if (_stats) {                                   \
            code;                                       \
        }                                               \
    } while (0)

// =============================================================================
// 组合统计更新宏 (简化常见模式)
// =============================================================================

/**
 * STATS_RX - 更新 RX 统计的快捷宏
 */
#define STATS_RX(stats, bytes, family)                  \
    do {                                                \
        if (stats) {                                    \
            update_rx_stats_by_family((stats), (bytes), (family)); \
        }                                               \
    } while (0)

/**
 * STATS_TX - 更新 TX 统计的快捷宏
 */
#define STATS_TX(stats, bytes, family)                  \
    do {                                                \
        if (stats) {                                    \
            update_tx_stats_by_family((stats), (bytes), (family)); \
        }                                               \
    } while (0)

/**
 * STATS_DROP - 统计丢弃的快捷宏
 */
#define STATS_DROP(stats)                               \
    do {                                                \
        if (stats) {                                    \
            count_drop(stats);                          \
        }                                               \
    } while (0)

/**
 * STATS_PASS - 统计放行的快捷宏
 */
#define STATS_PASS(stats)                               \
    do {                                                \
        if (stats) {                                    \
            count_pass(stats);                          \
        }                                               \
    } while (0)

/**
 * STATS_ERROR - 统计错误的快捷宏
 */
#define STATS_ERROR(stats)                              \
    do {                                                \
        if (stats) {                                    \
            count_error(stats);                         \
        }                                               \
    } while (0)

/**
 * STATS_SESSION_NEW - 统计新会话的快捷宏
 */
#define STATS_SESSION_NEW(stats, family)                \
    do {                                                \
        if (stats) {                                    \
            count_session_created_by_family((stats), (family)); \
        }                                               \
    } while (0)

#endif // __PHANTOM_STATS_H__
