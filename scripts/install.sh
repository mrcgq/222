#!/usr/bin/env bash
# =============================================================================
# Phantom Server 一键安装脚本 v5.5
# 修复：eBPF 内核资产下载 + 旧钩子清理 + 监听冲突
# =============================================================================

[[ ! -t 0 ]] && exec 0</dev/tty

INSTALL_DIR="/opt/phantom"
CONFIG_DIR="/etc/phantom"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
SERVICE_FILE="/etc/systemd/system/phantom.service"
EBPF_DIR="${INSTALL_DIR}/ebpf"

DOWNLOAD_URLS=(
    "https://github.com/mrcgq/222/releases/latest/download"
    "https://ghproxy.com/https://github.com/mrcgq/222/releases/latest/download"
)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
step()  { echo -e "${BLUE}${BOLD}==>${NC} $1"; }

print_logo() {
    clear
    echo -e "${CYAN}"
    echo '  ____  _                 _                  '
    echo ' |  _ \| |__   __ _ _ __ | |_ ___  _ __ ___  '
    echo ' | |_) |  _ \ / _` |  _ \| __/ _ \|  _ ` _ \ '
    echo ' |  __/| | | | (_| | | | | || (_) | | | | | |'
    echo ' |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|'
    echo -e "${NC}"
    echo ""
}

check_root() {
    [[ $EUID -ne 0 ]] && { error "请使用 root 运行"; exit 1; }
}

get_arch() {
    case "$(uname -m)" in
        x86_64) echo "amd64" ;; aarch64) echo "arm64" ;; *) echo "amd64" ;;
    esac
}

get_iface() {
    ip route 2>/dev/null | grep default | awk '{print $5}' | head -1 || echo "eth0"
}

# Base64 PSK 生成
generate_psk() {
    openssl rand -base64 32 2>/dev/null | tr -d '\n' || head -c 32 /dev/urandom | base64 | tr -d '\n'
}

validate_psk() {
    local psk="$1"
    local decoded_len=$(echo -n "$psk" | base64 -d 2>/dev/null | wc -c)
    [[ "$decoded_len" -eq 32 ]]
}

# =============================================================================
# eBPF 环境检测与清理
# =============================================================================

check_ebpf_support() {
    local supported="full"
    
    # 内核版本检查 (需要 5.4+)
    local kv_major=$(uname -r | cut -d. -f1)
    local kv_minor=$(uname -r | cut -d. -f2)
    if [[ $kv_major -lt 5 ]] || [[ $kv_major -eq 5 && $kv_minor -lt 4 ]]; then
        supported="none"
    fi
    
    # 虚拟化检查
    local virt=$(systemd-detect-virt 2>/dev/null || echo "none")
    case "$virt" in
        openvz|lxc|docker) supported="none" ;;
    esac
    
    # BTF 支持检查
    [[ ! -f "/sys/kernel/btf/vmlinux" ]] && supported="partial"
    
    # BPF JIT 启用
    local jit=$(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null || echo "0")
    if [[ "$jit" != "1" ]]; then
        echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null
        # 持久化
        grep -q "bpf_jit_enable" /etc/sysctl.conf 2>/dev/null || \
            echo "net.core.bpf_jit_enable = 1" >> /etc/sysctl.conf
    fi
    
    echo "$supported"
}

# 清理旧的 eBPF 钩子 (关键修复)
cleanup_ebpf_hooks() {
    local iface=$(get_iface)
    
    echo -n "  清理旧 eBPF 钩子... "
    
    # 1. 清理 XDP 钩子
    if command -v ip &>/dev/null; then
        ip link set dev "$iface" xdp off 2>/dev/null
        ip link set dev "$iface" xdpgeneric off 2>/dev/null
        ip link set dev "$iface" xdpdrv off 2>/dev/null
        ip link set dev "$iface" xdpoffload off 2>/dev/null
    fi
    
    # 2. 清理 TC 钩子
    if command -v tc &>/dev/null; then
        tc qdisc del dev "$iface" clsact 2>/dev/null
        tc filter del dev "$iface" ingress 2>/dev/null
        tc filter del dev "$iface" egress 2>/dev/null
    fi
    
    # 3. 清理 BPF 文件系统中的 pinned maps
    if [[ -d "/sys/fs/bpf/phantom" ]]; then
        rm -rf /sys/fs/bpf/phantom 2>/dev/null
    fi
    
    # 4. 使用 bpftool 清理 (如果可用)
    if command -v bpftool &>/dev/null; then
        # 列出并卸载与 phantom 相关的程序
        bpftool prog list 2>/dev/null | grep -E "xdp_phantom|tc_phantom" | \
            awk '{print $1}' | tr -d ':' | while read id; do
                bpftool prog detach id "$id" 2>/dev/null
            done
        
        # 清理 orphaned maps
        bpftool map list 2>/dev/null | grep -E "phantom" | \
            awk '{print $1}' | tr -d ':' | while read id; do
                bpftool map delete id "$id" 2>/dev/null
            done
    fi
    
    echo -e "${GREEN}完成${NC}"
}

# 安装 eBPF 依赖工具
install_ebpf_tools() {
    # 检查并安装必要工具
    if ! command -v bpftool &>/dev/null; then
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq linux-tools-common linux-tools-$(uname -r) 2>/dev/null
        elif command -v yum &>/dev/null; then
            yum install -y -q bpftool 2>/dev/null
        fi
    fi
}

# =============================================================================
# 下载功能
# =============================================================================

download_file() {
    local filename="$1" output="$2"
    for base_url in "${DOWNLOAD_URLS[@]}"; do
        echo -n "    尝试 $(echo $base_url | cut -d'/' -f3)... "
        if curl -fsSL --connect-timeout 10 -o "$output" "${base_url}/${filename}" 2>/dev/null && [[ -s "$output" ]]; then
            echo -e "${GREEN}成功${NC}"
            return 0
        fi
        echo -e "${RED}失败${NC}"
    done
    return 1
}

# 下载 eBPF 内核字节码 (关键新增)
download_ebpf_programs() {
    echo "  下载 eBPF 内核程序..."
    
    mkdir -p "$EBPF_DIR"
    
    local arch=$(get_arch)
    local files=("xdp_phantom.o" "tc_phantom.o")
    local success=true
    
    for file in "${files[@]}"; do
        # 尝试下载架构特定版本
        if download_file "ebpf/${arch}/${file}" "${EBPF_DIR}/${file}"; then
            continue
        fi
        
        # 尝试下载通用版本
        if download_file "ebpf/${file}" "${EBPF_DIR}/${file}"; then
            continue
        fi
        
        # 尝试直接下载
        if download_file "${file}" "${EBPF_DIR}/${file}"; then
            continue
        fi
        
        warn "无法下载 ${file} (将使用用户态回退)"
        success=false
    done
    
    # 设置权限
    chmod 644 "${EBPF_DIR}"/*.o 2>/dev/null
    
    if $success && [[ -f "${EBPF_DIR}/xdp_phantom.o" ]]; then
        info "eBPF 内核程序已就绪"
        return 0
    else
        warn "eBPF 程序不完整，将使用用户态模式"
        return 1
    fi
}

yaml_set() {
    local key="$1" value="$2"
    [[ -f "$CONFIG_FILE" ]] && sed -i "s|^${key}:.*|${key}: ${value}|" "$CONFIG_FILE"
}

yaml_set_section() {
    local sec="$1" key="$2" value="$3"
    [[ ! -f "$CONFIG_FILE" ]] && return
    awk -v s="$sec" -v k="$key" -v v="$value" '
    BEGIN{in_s=0} {
        if($0~"^"s":"){in_s=1;print;next}
        if(in_s && /^[a-z_]+:/){in_s=0}
        if(in_s && $0~"^  "k":"){sub(/:.*/,": "v)}
        print
    }' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}

# =============================================================================
# 服务管理
# =============================================================================

# 安全停止服务并清理
safe_stop_service() {
    echo -n "  停止服务... "
    
    # 停止服务
    systemctl stop phantom 2>/dev/null
    
    # 等待进程完全退出
    local max_wait=10
    local waited=0
    while pgrep -f "phantom-server" &>/dev/null && [[ $waited -lt $max_wait ]]; do
        sleep 1
        ((waited++))
    done
    
    # 强制终止残留进程
    pkill -9 -f "phantom-server" 2>/dev/null
    
    echo -e "${GREEN}完成${NC}"
}

# 启动前完整清理
pre_start_cleanup() {
    step "执行启动前清理"
    
    safe_stop_service
    cleanup_ebpf_hooks
    
    # 等待资源释放
    sleep 2
}

# =============================================================================
# 主安装流程
# =============================================================================
guided_install() {
    print_logo
    echo -e "${BOLD}欢迎使用 Phantom Server 安装向导${NC}"
    echo ""
    read -rp "开始安装 [Y/n]: " confirm
    [[ "$confirm" =~ ^[Nn]$ ]] && exit 0
    
    # 第 1 步：基础配置
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 1 步：基础配置"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    read -rp "  监听端口 [54321]: " input_port
    local PORT=${input_port:-54321}
    info "端口: ${PORT}"
    
    local PSK=$(generate_psk)
    if validate_psk "$PSK"; then
        info "PSK 已生成: ${CYAN}${PSK}${NC}"
    else
        error "PSK 生成失败"; exit 1
    fi
    
    # 第 2 步：环境检测
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 2 步：环境检测"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    local ebpf_support=$(check_ebpf_support)
    local ebpf_enabled="false"
    local xdp_mode="generic"
    local ebpf_programs_ok=false
    
    case "$ebpf_support" in
        full)
            xdp_mode="native"
            info "eBPF 环境: ${GREEN}完全支持${NC} (native 模式)"
            ;;
        partial)
            xdp_mode="generic"
            info "eBPF 环境: ${YELLOW}部分支持${NC} (generic 模式)"
            ;;
        none)
            warn "eBPF 环境: ${RED}不支持${NC} (将使用 FakeTCP)"
            ;;
    esac
    
    # 安装 eBPF 工具
    if [[ "$ebpf_support" != "none" ]]; then
        install_ebpf_tools
    fi
    
    # 第 3 步：连接方式
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 3 步：选择连接方式"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${CYAN}1${NC}. IP 直连 ${GREEN}(最简单)${NC}"
    echo -e "  ${CYAN}2${NC}. Cloudflare 隧道 ${GREEN}(推荐)${NC}"
    echo -e "  ${CYAN}3${NC}. 自己的域名"
    echo ""
    read -rp "选择 [1-3，默认 1]: " conn_choice
    
    local USE_TUNNEL="false"
    local TUNNEL_MODE="temp"
    local CF_TOKEN=""
    local DOMAIN=""
    
    case ${conn_choice:-1} in
        2)
            USE_TUNNEL="true"
            echo ""
            read -rp "临时隧道(a) 或 固定隧道(b) [a]: " tm
            if [[ "$tm" =~ ^[Bb]$ ]]; then
                TUNNEL_MODE="fixed"
                read -rp "CF Token: " CF_TOKEN
                [[ -z "$CF_TOKEN" ]] && TUNNEL_MODE="temp"
            fi
            info "隧道: ${TUNNEL_MODE}"
            ;;
        3)
            read -rp "域名: " DOMAIN
            ;;
    esac
    
    # 第 4 步：下载
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 4 步：下载程序"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$EBPF_DIR"
    local arch=$(get_arch)
    info "系统: linux/${arch}"
    
    # 下载主程序
    echo "  下载主程序..."
    if [[ -f "./phantom-server" ]]; then
        cp "./phantom-server" "$INSTALL_DIR/phantom-server"
        chmod +x "$INSTALL_DIR/phantom-server"
        info "使用本地文件"
    elif [[ ! -x "$INSTALL_DIR/phantom-server" ]]; then
        if ! download_file "phantom-server-linux-${arch}" "$INSTALL_DIR/phantom-server"; then
            download_file "phantom-server" "$INSTALL_DIR/phantom-server" || { error "下载失败"; exit 1; }
        fi
        chmod +x "$INSTALL_DIR/phantom-server"
    else
        info "使用已安装版本"
    fi
    
    # 下载 eBPF 程序 (关键新增)
    if [[ "$ebpf_support" != "none" ]]; then
        if download_ebpf_programs; then
            ebpf_enabled="true"
            ebpf_programs_ok=true
        else
            ebpf_enabled="false"
            warn "eBPF 程序下载失败，将使用用户态模式"
        fi
    fi
    
    # 第 5 步：生成配置
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 5 步：生成配置"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    local iface=$(get_iface)
    
    cat > "$CONFIG_FILE" << EOF
# Phantom Server 配置 v5.5
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
listen: ":${PORT}"
psk: "${PSK}"
mode: "auto"
log_level: "info"
time_window: 30

tunnel:
  enabled: ${USE_TUNNEL}
  mode: "${TUNNEL_MODE}"
  cf_token: "${CF_TOKEN}"
  local_port: ${PORT}

domain:
  name: "${DOMAIN}"

# eBPF 加速 (内核层，与 UDP 共存)
ebpf:
  enabled: ${ebpf_enabled}
  interface: "${iface}"
  xdp_mode: "${xdp_mode}"
  program_path: "${EBPF_DIR}"
  map_size: 65536
  enable_stats: true
  enable_tc: true

# FakeTCP - 独立端口
faketcp:
  enabled: true
  listen: ":$((PORT+1))"
  interface: "${iface}"
  use_ebpf: false

# WebSocket - 独立端口
websocket:
  enabled: true
  listen: ":$((PORT+2))"
  path: "/ws"

# Hysteria2 拥塞控制
hysteria2:
  enabled: true
  up_mbps: 100
  down_mbps: 100

# ARQ 可靠传输 (UDP 增强层)
arq:
  enabled: true
  window_size: 256
  max_retries: 10
  rto_min_ms: 100
  rto_max_ms: 10000
  enable_sack: true

# 智能切换器
switcher:
  enabled: true
  check_interval_ms: 1000
  rtt_threshold_ms: 300
  loss_threshold: 0.3
  fail_threshold: 3
  recover_threshold: 5
  priority:
    - "ebpf"
    - "faketcp"
    - "udp"
    - "websocket"

# TLS 伪装
tls:
  enabled: false
  server_name: "${DOMAIN:-www.microsoft.com}"
  fingerprint: "chrome"

# 监控指标
metrics:
  enabled: true
  listen: ":9100"
  path: "/metrics"
  health_path: "/health"
EOF
    
    info "配置已生成"
    
    # 第 6 步：Systemd
    echo ""
    step "第 6 步：配置服务"
    
    cat > "$SERVICE_FILE" << 'SERVICEFILE'
[Unit]
Description=Phantom Server
Documentation=https://github.com/mrcgq/222
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/phantom
ExecStartPre=/bin/bash -c 'ip link set $(ip route | grep default | awk "{print \$5}" | head -1) xdp off 2>/dev/null || true'
ExecStartPre=/bin/bash -c 'rm -rf /sys/fs/bpf/phantom 2>/dev/null || true'
SERVICEFILE

    cat >> "$SERVICE_FILE" << EOF
ExecStart=${INSTALL_DIR}/phantom-server -c ${CONFIG_FILE}
ExecStopPost=/bin/bash -c 'ip link set ${iface} xdp off 2>/dev/null || true'
ExecStopPost=/bin/bash -c 'rm -rf /sys/fs/bpf/phantom 2>/dev/null || true'
Restart=always
RestartSec=5
LimitNOFILE=1048576
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_BPF CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_IPC_LOCK
Environment=GOGC=100
Environment=GOMEMLIMIT=512MiB

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable phantom 2>/dev/null
    info "服务已配置"
    
    # 第 7 步：启动
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 7 步：启动服务"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # 执行启动前清理 (关键)
    pre_start_cleanup
    
    echo -n "  启动服务... "
    systemctl start phantom
    sleep 3
    
    if systemctl is-active --quiet phantom; then
        echo -e "${GREEN}成功${NC}"
        
        # 检查实际运行状态
        sleep 2
        local actual_mode=$(journalctl -u phantom -n 20 --no-pager 2>/dev/null | grep -oP '初始模式: \K\w+' | tail -1)
        local ebpf_status=$(journalctl -u phantom -n 20 --no-pager 2>/dev/null | grep -q "eBPF 内核加速已就绪" && echo "active" || echo "inactive")
        
        local TUNNEL_URL=""
        if [[ "$USE_TUNNEL" == "true" ]]; then
            sleep 5
            TUNNEL_URL=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
        fi
        
        local SERVER_IP=$(curl -s4 --connect-timeout 5 ip.sb 2>/dev/null || echo "你的IP")
        
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}${BOLD}           🎉 安装完成！${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        [[ -n "$TUNNEL_URL" ]] && echo -e "  🌐 隧道: ${CYAN}${TUNNEL_URL}${NC}"
        echo -e "  📍 IP:   ${CYAN}${SERVER_IP}${NC}"
        echo -e "  🔌 端口: ${CYAN}${PORT}${NC}"
        echo -e "  🔑 PSK:  ${CYAN}${PSK}${NC}"
        
        # 显示真实 eBPF 状态
        if [[ "$ebpf_status" == "active" ]]; then
            echo -e "  ⚡ eBPF: ${GREEN}已启用 (${xdp_mode} 模式)${NC}"
        elif [[ "$ebpf_enabled" == "true" ]]; then
            echo -e "  ⚡ eBPF: ${YELLOW}已配置，等待激活${NC}"
        else
            echo -e "  ⚡ eBPF: ${RED}不可用${NC}"
        fi
        
        echo -e "  🚀 模式: ${CYAN}${actual_mode:-auto}${NC}"
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    else
        error "启动失败"
        echo ""
        echo "最近日志:"
        journalctl -u phantom -n 20 --no-pager
        exit 1
    fi
}

# =============================================================================
# 管理菜单
# =============================================================================
show_menu() {
    while true; do
        print_logo
        local status=$(systemctl is-active phantom 2>/dev/null || echo "未安装")
        case "$status" in
            active) echo -e "状态: ${GREEN}● 运行中${NC}" ;;
            *) echo -e "状态: ${RED}✗ 未运行${NC}" ;;
        esac
        
        # 显示当前模式
        if [[ "$status" == "active" ]]; then
            local mode=$(journalctl -u phantom -n 50 --no-pager 2>/dev/null | grep -oP '当前模式: \K\w+' | tail -1)
            [[ -n "$mode" ]] && echo -e "模式: ${CYAN}${mode}${NC}"
        fi
        
        echo ""
        echo "  1. 重新安装   2. 卸载"
        echo "  3. 启动       4. 停止      5. 重启"
        echo "  6. 日志       7. 修改端口  8. 重置PSK"
        echo "  9. 隧道      10. 查看配置"
        echo " 11. 清理eBPF  12. 状态检查"
        echo "  0. 退出"
        echo ""
        read -rp "选择: " c
        
        case $c in
            1) guided_install; read -rp "Enter..." _ ;;
            2) 
                pre_start_cleanup
                rm -rf "$INSTALL_DIR" "$CONFIG_DIR" "$SERVICE_FILE"
                systemctl daemon-reload
                info "已卸载"
                read -rp "Enter..." _ 
                ;;
            3) 
                pre_start_cleanup
                systemctl start phantom
                sleep 2
                systemctl status phantom --no-pager
                read -rp "Enter..." _ 
                ;;
            4) 
                safe_stop_service
                cleanup_ebpf_hooks
                read -rp "Enter..." _ 
                ;;
            5) 
                pre_start_cleanup
                systemctl start phantom
                sleep 2
                systemctl status phantom --no-pager
                read -rp "Enter..." _ 
                ;;
            6) journalctl -u phantom -f -n 50 ;;
            7) 
                read -rp "新端口: " p
                yaml_set "listen" "\":${p}\""
                yaml_set_section "faketcp" "listen" "\":$((p+1))\""
                yaml_set_section "websocket" "listen" "\":$((p+2))\""
                pre_start_cleanup
                systemctl start phantom
                read -rp "Enter..." _ 
                ;;
            8) 
                local np=$(generate_psk)
                yaml_set "psk" "\"${np}\""
                systemctl restart phantom
                info "新PSK: $np"
                read -rp "Enter..." _ 
                ;;
            9) 
                yaml_set_section "tunnel" "enabled" "true"
                systemctl restart phantom
                sleep 5
                journalctl -u phantom -n 50 | grep trycloudflare
                read -rp "Enter..." _ 
                ;;
            10) cat "$CONFIG_FILE"; read -rp "Enter..." _ ;;
            11)
                echo "手动清理 eBPF 钩子..."
                cleanup_ebpf_hooks
                info "清理完成"
                read -rp "Enter..." _
                ;;
            12)
                echo ""
                echo "=== 服务状态 ==="
                systemctl status phantom --no-pager 2>/dev/null || echo "服务未安装"
                echo ""
                echo "=== eBPF 状态 ==="
                if command -v bpftool &>/dev/null; then
                    echo "XDP 程序:"
                    bpftool prog list 2>/dev/null | grep -E "xdp|phantom" || echo "  无"
                    echo "TC 程序:"
                    bpftool prog list 2>/dev/null | grep -E "tc|phantom" || echo "  无"
                else
                    echo "bpftool 未安装"
                fi
                echo ""
                echo "=== 网卡 XDP 状态 ==="
                local iface=$(get_iface)
                ip link show "$iface" 2>/dev/null | grep -E "xdp|prog"
                echo ""
                echo "=== 端口监听 ==="
                ss -ulnp | grep -E "$(grep -oP 'listen: ":\K\d+' $CONFIG_FILE 2>/dev/null | head -1)" 2>/dev/null || echo "  无"
                echo ""
                read -rp "Enter..." _
                ;;
            0) exit 0 ;;
        esac
    done
}

# =============================================================================
# 入口
# =============================================================================
check_root

# 确保 BPF 文件系统已挂载
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
fi

if [[ -f "$CONFIG_FILE" ]]; then
    show_menu
else
    guided_install
    read -rp "Enter继续..." _
    show_menu
fi
