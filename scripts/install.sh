#!/usr/bin/env bash
# =============================================================================
# Phantom Server 一键安装脚本 v5.4
# 修复：eBPF 监听冲突 + Base64 PSK + 环境预检测
# =============================================================================

[[ ! -t 0 ]] && exec 0</dev/tty

INSTALL_DIR="/opt/phantom"
CONFIG_DIR="/etc/phantom"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
SERVICE_FILE="/etc/systemd/system/phantom.service"

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

# eBPF 环境检测
check_ebpf_support() {
    local supported="full"
    
    # 内核版本检查
    local kv=$(uname -r | cut -d. -f1)
    [[ $kv -lt 5 ]] && supported="none"
    
    # 虚拟化检查
    local virt=$(systemd-detect-virt 2>/dev/null || echo "none")
    case "$virt" in
        openvz|lxc|docker) supported="none" ;;
    esac
    
    # BPF JIT
    local jit=$(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null || echo "0")
    [[ "$jit" != "1" ]] && echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null
    
    echo "$supported"
}

download_file() {
    local filename="$1" output="$2"
    for base_url in "${DOWNLOAD_URLS[@]}"; do
        echo -n "  尝试 $(echo $base_url | cut -d'/' -f3)... "
        if curl -fsSL --connect-timeout 10 -o "$output" "${base_url}/${filename}" 2>/dev/null && [[ -s "$output" ]]; then
            echo -e "${GREEN}成功${NC}"; return 0
        fi
        echo -e "${RED}失败${NC}"
    done
    return 1
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

# ─────────────────────────────────────────────────────────────────────────────
# 主安装流程
# ─────────────────────────────────────────────────────────────────────────────
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
    
    case "$ebpf_support" in
        full)
            ebpf_enabled="true"
            xdp_mode="native"
            info "eBPF: ${GREEN}完全支持${NC} (native 模式)"
            ;;
        partial)
            ebpf_enabled="true"
            xdp_mode="generic"
            info "eBPF: ${YELLOW}部分支持${NC} (generic 模式)"
            ;;
        none)
            ebpf_enabled="false"
            warn "eBPF: ${RED}不支持${NC} (将使用 FakeTCP)"
            ;;
    esac
    
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
    
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
    local arch=$(get_arch)
    info "系统: linux/${arch}"
    
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
    
    # 第 5 步：生成配置
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 5 步：生成配置"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    local iface=$(get_iface)
    
    cat > "$CONFIG_FILE" << EOF
# Phantom Server 配置
listen: ":${PORT}"
psk: "${PSK}"
mode: "auto"
log_level: "info"

tunnel:
  enabled: ${USE_TUNNEL}
  mode: "${TUNNEL_MODE}"
  token: "${CF_TOKEN}"
  local_port: ${PORT}

domain:
  name: "${DOMAIN}"

# 【修复】eBPF - 根据环境自动配置
ebpf:
  enabled: ${ebpf_enabled}
  interface: "${iface}"
  xdp_mode: "${xdp_mode}"
  enable_tc: true

# FakeTCP - 独立端口，不会与 eBPF/UDP 冲突
faketcp:
  enabled: true
  listen: ":$((PORT+1))"
  interface: "${iface}"
  use_ebpf: false

websocket:
  enabled: true
  listen: ":$((PORT+2))"
  path: "/ws"

hysteria2:
  enabled: true
  up_mbps: 100
  down_mbps: 100

arq:
  enabled: true
  window_size: 256

switcher:
  enabled: true
  rtt_threshold_ms: 300
  loss_threshold: 0.3
  priority:
    - "ebpf"
    - "faketcp"
    - "udp"
    - "websocket"

tls:
  enabled: false
  server_name: "${DOMAIN:-www.microsoft.com}"

metrics:
  enabled: true
  listen: ":9100"
EOF
    
    info "配置已生成"
    
    # 第 6 步：Systemd
    echo ""
    step "第 6 步：配置服务"
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Phantom Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/phantom-server -c ${CONFIG_FILE}
Restart=always
RestartSec=5
LimitNOFILE=1048576
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_BPF CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_IPC_LOCK

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable phantom 2>/dev/null
    info "服务已配置"
    
    # 第 7 步：启动
    echo ""
    step "第 7 步：启动服务"
    
    systemctl stop phantom 2>/dev/null
    sleep 1
    systemctl start phantom
    sleep 3
    
    if systemctl is-active --quiet phantom; then
        info "服务启动成功！"
        
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
        [[ "$ebpf_enabled" == "true" ]] && echo -e "  ⚡ eBPF: ${GREEN}已启用 (${xdp_mode})${NC}"
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    else
        error "启动失败"
        journalctl -u phantom -n 10 --no-pager
        exit 1
    fi
}

# 管理菜单（简化版）
show_menu() {
    while true; do
        print_logo
        local status=$(systemctl is-active phantom 2>/dev/null || echo "未安装")
        case "$status" in
            active) echo -e "状态: ${GREEN}● 运行中${NC}" ;;
            *) echo -e "状态: ${RED}✗ 未运行${NC}" ;;
        esac
        
        echo ""
        echo "  1. 重新安装   2. 卸载"
        echo "  3. 启动       4. 停止      5. 重启"
        echo "  6. 日志       7. 修改端口  8. 重置PSK"
        echo "  9. 隧道      10. 查看配置"
        echo "  0. 退出"
        echo ""
        read -rp "选择: " c
        
        case $c in
            1) guided_install; read -rp "Enter..." _ ;;
            2) systemctl stop phantom; rm -rf "$INSTALL_DIR" "$CONFIG_DIR" "$SERVICE_FILE"; systemctl daemon-reload; info "已卸载"; read -rp "Enter..." _ ;;
            3) systemctl start phantom; read -rp "Enter..." _ ;;
            4) systemctl stop phantom; read -rp "Enter..." _ ;;
            5) systemctl restart phantom; read -rp "Enter..." _ ;;
            6) journalctl -u phantom -f -n 50 ;;
            7) read -rp "新端口: " p; yaml_set "listen" "\":${p}\""; systemctl restart phantom; read -rp "Enter..." _ ;;
            8) local np=$(generate_psk); yaml_set "psk" "\"${np}\""; systemctl restart phantom; info "新PSK: $np"; read -rp "Enter..." _ ;;
            9) yaml_set_section "tunnel" "enabled" "true"; systemctl restart phantom; sleep 5; journalctl -u phantom -n 50 | grep trycloudflare; read -rp "Enter..." _ ;;
            10) cat "$CONFIG_FILE"; read -rp "Enter..." _ ;;
            0) exit 0 ;;
        esac
    done
}

# 入口
check_root
if [[ -f "$CONFIG_FILE" ]]; then
    show_menu
else
    guided_install
    read -rp "Enter继续..." _
    show_menu
fi
