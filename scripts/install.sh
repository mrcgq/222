#!/usr/bin/env bash
# Phantom Server v5.2 - 修复 PSK 问题

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

# 【核心修复】生成正确的 32 字节 PSK
generate_psk() {
    # openssl rand -hex 16 生成 32 个十六进制字符
    openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | xxd -p
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
    echo "本向导将引导你完成安装，大部分情况下直接回车即可。"
    echo ""
    read -rp "准备好了吗？开始安装 [Y/n]: " confirm
    [[ "$confirm" =~ ^[Nn]$ ]] && exit 0
    
    # ═══════════════════════════════════════════════════════════════════════
    # 第 1 步：基础配置
    # ═══════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 1 步：基础配置"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    echo -e "${CYAN}[?]${NC} 监听端口"
    read -rp "  直接回车使用 54321: " input_port
    local PORT=${input_port:-54321}
    info "端口: ${PORT}"
    
    # 【关键】生成 32 字节 PSK
    local PSK=$(generate_psk)
    info "PSK 密钥已自动生成 (32字节): ${CYAN}${PSK}${NC}"
    echo "  (请保存此密钥，客户端连接时需要)"
    
    # 验证 PSK 长度
    if [[ ${#PSK} -ne 32 ]]; then
        error "PSK 生成异常，长度为 ${#PSK}，需要 32"
        PSK=$(printf '%032d' 0 | head -c 32)
        warn "使用备用 PSK: ${PSK}"
    fi
    
    # ═══════════════════════════════════════════════════════════════════════
    # 第 2 步：连接方式
    # ═══════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 2 步：选择连接方式"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "你希望如何访问服务器？"
    echo ""
    echo -e "  ${CYAN}1${NC}. 使用服务器 IP 直连 ${GREEN}(最简单)${NC}"
    echo -e "  ${CYAN}2${NC}. 使用 Cloudflare 隧道 ${GREEN}(推荐，免费隐藏IP)${NC}"
    echo -e "  ${CYAN}3${NC}. 使用自己的域名"
    echo ""
    read -rp "请选择 [1-3，默认 1]: " conn_choice
    conn_choice=${conn_choice:-1}
    
    local USE_TUNNEL="false"
    local TUNNEL_MODE="temp"
    local CF_TOKEN=""
    local DOMAIN=""
    
    case $conn_choice in
        2)
            USE_TUNNEL="true"
            echo ""
            echo "Cloudflare 隧道模式："
            echo -e "  ${CYAN}a${NC}. 临时隧道 - 无需配置，域名每次重启会变"
            echo -e "  ${CYAN}b${NC}. 固定隧道 - 需要 CF 账号，域名永久固定"
            echo ""
            read -rp "选择 [a/b，默认 a]: " tunnel_choice
            
            if [[ "$tunnel_choice" =~ ^[Bb]$ ]]; then
                TUNNEL_MODE="fixed"
                echo ""
                echo "获取 Token: https://one.dash.cloudflare.com → Tunnels → Create"
                read -rp "粘贴 Token: " CF_TOKEN
                [[ -z "$CF_TOKEN" ]] && { warn "未输入Token，使用临时隧道"; TUNNEL_MODE="temp"; }
            fi
            info "隧道模式: ${TUNNEL_MODE}"
            ;;
        3)
            echo ""
            read -rp "输入域名 (如 vpn.example.com): " DOMAIN
            [[ -n "$DOMAIN" ]] && info "域名: ${DOMAIN}"
            ;;
    esac
    
    # ═══════════════════════════════════════════════════════════════════════
    # 第 3 步：下载程序
    # ═══════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 3 步：下载程序文件"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
    local arch=$(get_arch)
    info "检测系统: linux/${arch}"
    
    if [[ -f "./phantom-server" ]]; then
        cp "./phantom-server" "$INSTALL_DIR/phantom-server"
        chmod +x "$INSTALL_DIR/phantom-server"
        info "使用本地文件"
    elif [[ -x "$INSTALL_DIR/phantom-server" ]]; then
        echo ""
        read -rp "发现已安装版本，重新下载？ [y/N]: " redown
        if [[ "$redown" =~ ^[Yy]$ ]]; then
            rm -f "$INSTALL_DIR/phantom-server"
        else
            info "使用现有版本"
        fi
    fi
    
    if [[ ! -x "$INSTALL_DIR/phantom-server" ]]; then
        echo "正在下载..."
        if ! download_file "phantom-server-linux-${arch}" "$INSTALL_DIR/phantom-server"; then
            download_file "phantom-server" "$INSTALL_DIR/phantom-server" || {
                error "下载失败，请手动下载到 $INSTALL_DIR/phantom-server"
                exit 1
            }
        fi
        chmod +x "$INSTALL_DIR/phantom-server"
    fi
    info "程序准备完成"
    
    # ═══════════════════════════════════════════════════════════════════════
    # 第 4 步：生成配置（每次都重新生成，确保 PSK 正确）
    # ═══════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 4 步：生成配置文件"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    local iface=$(get_iface)
    
    # 【关键】始终重新生成配置文件，确保新 PSK 生效
    cat > "$CONFIG_FILE" << EOF
# Phantom Server 配置
# 生成: $(date '+%Y-%m-%d %H:%M:%S')
# PSK: 32 字节十六进制字符串

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

faketcp:
  enabled: true
  listen: ":$((PORT+1))"
  interface: "${iface}"

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
  rto_min_ms: 100
  rto_max_ms: 3000

switcher:
  enabled: true
  rtt_threshold_ms: 300
  loss_threshold: 0.3
  priority:
    - "ebpf"
    - "faketcp"
    - "udp"
    - "websocket"

ebpf:
  enabled: true
  interface: "${iface}"
  xdp_mode: "generic"

tls:
  enabled: false
  server_name: "${DOMAIN:-www.microsoft.com}"
  fingerprint: "chrome"

metrics:
  enabled: true
  listen: ":9100"
EOF
    
    info "配置文件已生成 (PSK: ${#PSK} 字节)"
    
    # 验证配置文件中的 PSK
    local saved_psk=$(grep "^psk:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
    if [[ ${#saved_psk} -ne 32 ]]; then
        error "配置文件中 PSK 长度异常: ${#saved_psk}"
        exit 1
    fi
    
    # ═══════════════════════════════════════════════════════════════════════
    # 第 5 步：系统服务
    # ═══════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 5 步：配置系统服务"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
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
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_BPF CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable phantom 2>/dev/null
    info "系统服务已配置"
    
    # ═══════════════════════════════════════════════════════════════════════
    # 第 6 步：启动
    # ═══════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 6 步：启动服务"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    systemctl stop phantom 2>/dev/null
    sleep 1
    systemctl start phantom
    sleep 3
    
    if systemctl is-active --quiet phantom; then
        info "服务启动成功！"
        
        local TUNNEL_URL=""
        if [[ "$USE_TUNNEL" == "true" ]]; then
            echo "正在获取隧道地址..."
            sleep 5
            TUNNEL_URL=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
        fi
        
        local SERVER_IP=$(curl -s4 --connect-timeout 5 ip.sb 2>/dev/null || echo "你的服务器IP")
        
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}${BOLD}           🎉 安装完成！${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${BOLD}【连接信息】${NC}"
        [[ -n "$TUNNEL_URL" ]] && echo -e "  🌐 隧道: ${CYAN}${BOLD}${TUNNEL_URL}${NC}"
        echo -e "  📍 IP:   ${CYAN}${SERVER_IP}${NC}"
        echo -e "  🔌 端口: ${CYAN}${PORT}${NC}"
        echo -e "  🔑 PSK:  ${CYAN}${BOLD}${PSK}${NC}"
        echo ""
        echo -e "${BOLD}【常用命令】${NC}"
        echo "  状态: systemctl status phantom"
        echo "  日志: journalctl -u phantom -f"
        echo "  重启: systemctl restart phantom"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
    else
        error "服务启动失败"
        echo ""
        echo "错误日志："
        journalctl -u phantom -n 10 --no-pager
        echo ""
        
        # 调试信息
        echo "调试: 检查 PSK 长度..."
        local cfg_psk=$(grep "^psk:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
        echo "  配置文件中 PSK: ${cfg_psk}"
        echo "  长度: ${#cfg_psk} 字节"
        
        exit 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# 管理菜单
# ─────────────────────────────────────────────────────────────────────────────
show_menu() {
    while true; do
        print_logo
        
        local status=$(systemctl is-active phantom 2>/dev/null || echo "未安装")
        case "$status" in
            active)   echo -e "状态: ${GREEN}● 运行中${NC}" ;;
            inactive) echo -e "状态: ${YELLOW}○ 已停止${NC}" ;;
            *)        echo -e "状态: ${RED}✗ 未安装${NC}" ;;
        esac
        
        if [[ -f "$CONFIG_FILE" ]]; then
            local port=$(grep "^listen:" "$CONFIG_FILE" | grep -oP '\d+')
            local psk=$(grep "^psk:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
            echo -e "端口: ${CYAN}${port}${NC}  PSK: ${CYAN}${psk}${NC} (${#psk}字节)"
            
            if grep -q "enabled: true" <(grep -A1 "^tunnel:" "$CONFIG_FILE"); then
                local url=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
                [[ -n "$url" ]] && echo -e "隧道: ${CYAN}${url}${NC}"
            fi
        fi
        
        echo ""
        echo -e "${BOLD}════════════ 菜单 ════════════${NC}"
        echo ""
        echo "  1. 重新安装"
        echo "  2. 卸载"
        echo ""
        echo "  3. 启动   4. 停止   5. 重启"
        echo "  6. 日志"
        echo ""
        echo "  7. 修改端口"
        echo "  8. 重置PSK"
        echo "  9. 隧道设置"
        echo "  10. 查看配置"
        echo ""
        echo "  0. 退出"
        echo ""
        read -rp "选择: " choice
        
        case $choice in
            1) guided_install; read -rp "Enter继续..." _ ;;
            2)
                read -rp "确认卸载? [y/N]: " c
                [[ "$c" =~ ^[Yy]$ ]] && {
                    systemctl stop phantom; systemctl disable phantom
                    rm -rf "$INSTALL_DIR" "$CONFIG_DIR" "$SERVICE_FILE"
                    systemctl daemon-reload
                    info "已卸载"
                }
                read -rp "Enter继续..." _
                ;;
            3) systemctl start phantom && info "已启动" || error "失败"; read -rp "Enter..." _ ;;
            4) systemctl stop phantom && info "已停止" || error "失败"; read -rp "Enter..." _ ;;
            5) systemctl restart phantom && info "已重启" || error "失败"; read -rp "Enter..." _ ;;
            6) echo "Ctrl+C 退出"; journalctl -u phantom -f -n 50 ;;
            7)
                read -rp "新端口: " p
                [[ "$p" =~ ^[0-9]+$ ]] && {
                    yaml_set "listen" "\":${p}\""
                    yaml_set_section "tunnel" "local_port" "$p"
                    yaml_set_section "faketcp" "listen" "\":$((p+1))\""
                    yaml_set_section "websocket" "listen" "\":$((p+2))\""
                    systemctl restart phantom && info "已修改"
                }
                read -rp "Enter..." _
                ;;
            8)
                local new_psk=$(generate_psk)
                yaml_set "psk" "\"${new_psk}\""
                systemctl restart phantom
                info "新PSK: ${CYAN}${new_psk}${NC} (${#new_psk}字节)"
                read -rp "Enter..." _
                ;;
            9)
                echo ""
                echo "  1. 临时隧道  2. 固定隧道  3. 禁用  4. 查看地址"
                read -rp "选择: " t
                case $t in
                    1) yaml_set_section "tunnel" "enabled" "true"; yaml_set_section "tunnel" "mode" "\"temp\""; systemctl restart phantom; sleep 5
                       url=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
                       [[ -n "$url" ]] && info "隧道: ${url}" || warn "等待中..." ;;
                    2) read -rp "Token: " tk; [[ -n "$tk" ]] && {
                       yaml_set_section "tunnel" "enabled" "true"; yaml_set_section "tunnel" "mode" "\"fixed\""; yaml_set_section "tunnel" "token" "\"${tk}\""
                       systemctl restart phantom; info "已配置"; } ;;
                    3) yaml_set_section "tunnel" "enabled" "false"; systemctl restart phantom; info "已禁用" ;;
                    4) url=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
                       [[ -n "$url" ]] && info "隧道: ${url}" || warn "未找到" ;;
                esac
                read -rp "Enter..." _
                ;;
            10) cat "$CONFIG_FILE" 2>/dev/null; read -rp "Enter..." _ ;;
            0) exit 0 ;;
        esac
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# 入口
# ─────────────────────────────────────────────────────────────────────────────
check_root

if [[ -f "$CONFIG_FILE" ]] && systemctl is-enabled phantom &>/dev/null 2>&1; then
    show_menu
else
    guided_install
    echo ""
    read -rp "按 Enter 继续..." _
    show_menu
fi
