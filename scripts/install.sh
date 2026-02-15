#!/usr/bin/env bash
# =============================================================================
# Phantom Server 一键安装脚本 v5.0
# 设计理念：新手友好，一路回车就能用
# =============================================================================

# 确保交互可用
[[ ! -t 0 ]] && exec 0</dev/tty

# ─────────────────────────────────────────────────────────────────────────────
# 基础设置
# ─────────────────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/phantom"
CONFIG_DIR="/etc/phantom"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
SERVICE_FILE="/etc/systemd/system/phantom.service"

# 下载源（多个备用）
DOWNLOAD_URLS=(
    "https://github.com/mrcgq/222/releases/latest/download"
    "https://ghproxy.com/https://github.com/mrcgq/222/releases/latest/download"
    "https://mirror.ghproxy.com/https://github.com/mrcgq/222/releases/latest/download"
)

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─────────────────────────────────────────────────────────────────────────────
# 辅助函数
# ─────────────────────────────────────────────────────────────────────────────
print_logo() {
    clear
    echo -e "${CYAN}"
    echo '  ____  _                 _                  '
    echo ' |  _ \| |__   __ _ _ __ | |_ ___  _ __ ___  '
    echo ' | |_) | '"'"'_ \ / _` | '"'"'_ \| __/ _ \| '"'"'_ ` _ \ '
    echo ' |  __/| | | | (_| | | | | || (_) | | | | | |'
    echo ' |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|'
    echo -e "${NC}"
    echo ""
}

info()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; }
step()    { echo -e "${BLUE}${BOLD}==>${NC} $1"; }
ask()     { echo -e "${CYAN}[?]${NC} $1"; }

press_enter() {
    echo ""
    read -rp "按 Enter 继续..." _
}

confirm() {
    local prompt="$1"
    local default="${2:-y}"
    
    if [[ "$default" == "y" ]]; then
        read -rp "$prompt [Y/n]: " choice
        [[ -z "$choice" || "$choice" =~ ^[Yy]$ ]]
    else
        read -rp "$prompt [y/N]: " choice
        [[ "$choice" =~ ^[Yy]$ ]]
    fi
}

# 检测系统
get_arch() {
    case "$(uname -m)" in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        armv7l)  echo "arm" ;;
        *)       echo "amd64" ;;
    esac
}

get_iface() {
    ip route 2>/dev/null | grep default | awk '{print $5}' | head -1 || echo "eth0"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "请使用 root 权限运行此脚本"
        echo "  sudo bash $0"
        exit 1
    fi
}

check_system() {
    if [[ ! -f /etc/os-release ]]; then
        error "不支持的操作系统"
        exit 1
    fi
    
    # 检查必要工具
    for cmd in curl systemctl; do
        if ! command -v $cmd &>/dev/null; then
            error "缺少必要工具: $cmd"
            exit 1
        fi
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# 下载函数（多源备用）
# ─────────────────────────────────────────────────────────────────────────────
download_file() {
    local filename="$1"
    local output="$2"
    local success=false
    
    for base_url in "${DOWNLOAD_URLS[@]}"; do
        local url="${base_url}/${filename}"
        echo -n "  尝试: $(echo $base_url | cut -d'/' -f3) ... "
        
        if curl -fsSL --connect-timeout 10 -o "$output" "$url" 2>/dev/null; then
            if [[ -s "$output" ]]; then
                echo -e "${GREEN}成功${NC}"
                success=true
                break
            fi
        fi
        echo -e "${RED}失败${NC}"
    done
    
    $success
}

# ─────────────────────────────────────────────────────────────────────────────
# YAML 操作
# ─────────────────────────────────────────────────────────────────────────────
yaml_set() {
    local key="$1" value="$2"
    if grep -q "^${key}:" "$CONFIG_FILE" 2>/dev/null; then
        sed -i "s|^${key}:.*|${key}: ${value}|" "$CONFIG_FILE"
    fi
}

yaml_set_section() {
    local sec="$1" key="$2" value="$3"
    [[ ! -f "$CONFIG_FILE" ]] && return
    awk -v s="$sec" -v k="$key" -v v="$value" '
    BEGIN{in_s=0}
    {
        if($0~"^"s":"){in_s=1;print;next}
        if(in_s && /^[a-z_]+:/){in_s=0}
        if(in_s && $0~"^  "k":"){sub(/:.*/,": "v)}
        print
    }' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}

# ─────────────────────────────────────────────────────────────────────────────
# 核心安装流程（引导式）
# ─────────────────────────────────────────────────────────────────────────────
guided_install() {
    print_logo
    echo -e "${BOLD}欢迎使用 Phantom Server 安装向导${NC}"
    echo ""
    echo "本向导将引导你完成安装，大部分情况下直接回车即可。"
    echo ""
    
    if ! confirm "准备好了吗？开始安装"; then
        echo "安装已取消"
        exit 0
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 第一步：基础配置
    # ─────────────────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 1 步：基础配置"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # 端口
    local default_port=54321
    ask "监听端口"
    read -rp "  直接回车使用 ${default_port}: " input_port
    local PORT=${input_port:-$default_port}
    info "端口: ${PORT}"
    
    # PSK
    local PSK=$(openssl rand -base64 16 2>/dev/null | tr -d '=+/' | head -c 16)
    info "PSK 密钥已自动生成: ${CYAN}${PSK}${NC}"
    echo "  (请保存此密钥，客户端连接时需要)"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 第二步：连接方式
    # ─────────────────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 2 步：选择连接方式"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "你希望如何访问服务器？"
    echo ""
    echo "  ${CYAN}1${NC}. 使用服务器 IP 直连 ${GREEN}(最简单)${NC}"
    echo "  ${CYAN}2${NC}. 使用 Cloudflare 隧道 ${GREEN}(推荐，免费隐藏IP)${NC}"
    echo "  ${CYAN}3${NC}. 使用自己的域名"
    echo ""
    read -rp "请选择 [1-3，默认 1]: " conn_choice
    conn_choice=${conn_choice:-1}
    
    local USE_TUNNEL=false
    local USE_DOMAIN=false
    local DOMAIN=""
    local CF_TOKEN=""
    local TUNNEL_MODE=""
    
    case $conn_choice in
        2)
            USE_TUNNEL=true
            echo ""
            echo "Cloudflare 隧道有两种模式："
            echo ""
            echo "  ${CYAN}a${NC}. 临时隧道 - 无需配置，但域名每次重启会变"
            echo "  ${CYAN}b${NC}. 固定隧道 - 需要 CF 账号，域名永久固定"
            echo ""
            read -rp "选择模式 [a/b，默认 a]: " tunnel_choice
            tunnel_choice=${tunnel_choice:-a}
            
            if [[ "$tunnel_choice" == "b" ]]; then
                TUNNEL_MODE="fixed"
                echo ""
                echo "请先在 Cloudflare 控制台创建隧道并获取 Token："
                echo "  1. 访问 https://one.dash.cloudflare.com"
                echo "  2. 进入 Networks → Tunnels → Create"
                echo "  3. 复制生成的 Token"
                echo ""
                read -rp "粘贴 Token: " CF_TOKEN
                if [[ -z "$CF_TOKEN" ]]; then
                    warn "未输入 Token，将使用临时隧道"
                    TUNNEL_MODE="temp"
                fi
            else
                TUNNEL_MODE="temp"
            fi
            info "隧道模式: ${TUNNEL_MODE}"
            ;;
        3)
            USE_DOMAIN=true
            echo ""
            read -rp "请输入你的域名 (如 vpn.example.com): " DOMAIN
            if [[ -z "$DOMAIN" ]]; then
                warn "未输入域名，将使用 IP 直连"
                USE_DOMAIN=false
            else
                info "域名: ${DOMAIN}"
                
                echo ""
                echo "是否需要自动申请 SSL 证书？"
                echo "  ${CYAN}1${NC}. 是，使用 Let's Encrypt 免费证书 ${GREEN}(推荐)${NC}"
                echo "  ${CYAN}2${NC}. 否，我有自己的证书"
                echo "  ${CYAN}3${NC}. 否，不使用 HTTPS"
                echo ""
                read -rp "选择 [1-3，默认 1]: " cert_choice
                cert_choice=${cert_choice:-1}
            fi
            ;;
    esac
    
    # ─────────────────────────────────────────────────────────────────────────
    # 第三步：下载安装
    # ─────────────────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 3 步：下载程序文件"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
    
    local arch=$(get_arch)
    local binary_name="phantom-server-linux-${arch}"
    
    info "检测系统: linux/${arch}"
    echo ""
    echo "正在下载程序..."
    
    # 检查本地文件
    if [[ -f "./phantom-server" ]]; then
        info "发现本地文件，使用本地版本"
        cp "./phantom-server" "$INSTALL_DIR/phantom-server"
        chmod +x "$INSTALL_DIR/phantom-server"
    elif [[ -f "$INSTALL_DIR/phantom-server" ]]; then
        if confirm "  发现已安装版本，是否重新下载？" "n"; then
            rm -f "$INSTALL_DIR/phantom-server"
        else
            info "使用现有版本"
        fi
    fi
    
    # 需要下载
    if [[ ! -x "$INSTALL_DIR/phantom-server" ]]; then
        if ! download_file "$binary_name" "$INSTALL_DIR/phantom-server"; then
            # 尝试不带架构的文件名
            if ! download_file "phantom-server" "$INSTALL_DIR/phantom-server"; then
                echo ""
                error "自动下载失败"
                echo ""
                echo "请手动下载并安装："
                echo "  1. 访问 https://github.com/mrcgq/222/releases"
                echo "  2. 下载对应系统的文件"
                echo "  3. 上传到服务器 /opt/phantom/phantom-server"
                echo "  4. 执行: chmod +x /opt/phantom/phantom-server"
                echo "  5. 重新运行此脚本"
                echo ""
                exit 1
            fi
        fi
        chmod +x "$INSTALL_DIR/phantom-server"
    fi
    
    info "程序下载完成"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 第四步：生成配置
    # ─────────────────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 4 步：生成配置文件"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    local iface=$(get_iface)
    
    cat > "$CONFIG_FILE" << EOF
# Phantom Server 配置文件
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

listen: ":${PORT}"
psk: "${PSK}"
mode: "auto"
log_level: "info"

# 隧道配置
tunnel:
  enabled: ${USE_TUNNEL}
  mode: "${TUNNEL_MODE:-temp}"
  token: "${CF_TOKEN}"
  local_port: ${PORT}

# 域名配置
domain:
  name: "${DOMAIN}"
  cert_mode: "${cert_choice:-none}"

# 传输协议
faketcp:
  enabled: true
  listen: ":$((PORT+1))"
  interface: "${iface}"

websocket:
  enabled: true
  listen: ":$((PORT+2))"
  path: "/ws"

# 性能优化
hysteria2:
  enabled: true
  up_mbps: 100
  down_mbps: 100

arq:
  enabled: true
  window_size: 256

# eBPF 加速
ebpf:
  enabled: true
  interface: "${iface}"
  xdp_mode: "generic"

# 监控
metrics:
  enabled: true
  listen: ":9100"
EOF
    
    info "配置文件已生成"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 第五步：配置系统服务
    # ─────────────────────────────────────────────────────────────────────────
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
    
    # ─────────────────────────────────────────────────────────────────────────
    # 第六步：启动服务
    # ─────────────────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 6 步：启动服务"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    systemctl restart phantom
    sleep 3
    
    if systemctl is-active --quiet phantom; then
        info "服务启动成功！"
        
        # 获取隧道地址
        local TUNNEL_URL=""
        if [[ "$USE_TUNNEL" == "true" ]]; then
            echo ""
            echo "正在获取隧道地址..."
            sleep 5
            TUNNEL_URL=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
        fi
        
        # ─────────────────────────────────────────────────────────────────────
        # 安装完成，显示信息
        # ─────────────────────────────────────────────────────────────────────
        echo ""
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}${BOLD}           🎉 安装完成！${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${BOLD}【连接信息】${NC}"
        echo ""
        
        # 获取服务器 IP
        local SERVER_IP=$(curl -s4 ip.sb 2>/dev/null || curl -s4 ifconfig.me 2>/dev/null || echo "你的服务器IP")
        
        if [[ -n "$TUNNEL_URL" ]]; then
            echo -e "  隧道地址: ${CYAN}${BOLD}${TUNNEL_URL}${NC}"
            echo ""
        fi
        
        if [[ "$USE_TUNNEL" != "true" ]]; then
            echo -e "  服务器:   ${CYAN}${SERVER_IP}${NC}"
        fi
        
        echo -e "  端口:     ${CYAN}${PORT}${NC}"
        echo -e "  PSK密钥:  ${CYAN}${BOLD}${PSK}${NC}"
        
        if [[ -n "$DOMAIN" ]]; then
            echo -e "  域名:     ${CYAN}${DOMAIN}${NC}"
        fi
        
        echo ""
        echo -e "${BOLD}【客户端配置】${NC}"
        echo ""
        
        if [[ -n "$TUNNEL_URL" ]]; then
            echo "  地址: ${TUNNEL_URL}"
        else
            echo "  地址: ${SERVER_IP}"
        fi
        echo "  端口: ${PORT}"
        echo "  密钥: ${PSK}"
        
        echo ""
        echo -e "${BOLD}【常用命令】${NC}"
        echo ""
        echo "  查看状态: systemctl status phantom"
        echo "  查看日志: journalctl -u phantom -f"
        echo "  重启服务: systemctl restart phantom"
        echo "  管理面板: bash $0"
        
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        if [[ "$TUNNEL_MODE" == "temp" ]]; then
            echo ""
            warn "注意: 临时隧道地址会在服务重启后改变"
            echo "  如需固定地址，请使用 Cloudflare 固定隧道"
        fi
        
    else
        error "服务启动失败"
        echo ""
        echo "请检查日志: journalctl -u phantom -n 50"
        exit 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# 管理菜单（安装后使用）
# ─────────────────────────────────────────────────────────────────────────────
show_menu() {
    while true; do
        print_logo
        
        # 状态
        local status=$(systemctl is-active phantom 2>/dev/null || echo "未安装")
        case "$status" in
            active)   echo -e "状态: ${GREEN}● 运行中${NC}" ;;
            inactive) echo -e "状态: ${YELLOW}○ 已停止${NC}" ;;
            *)        echo -e "状态: ${RED}✗ 未安装${NC}" ;;
        esac
        
        # 显示当前配置
        if [[ -f "$CONFIG_FILE" ]]; then
            local port=$(grep "^listen:" "$CONFIG_FILE" 2>/dev/null | grep -oP '\d+')
            local psk=$(grep "^psk:" "$CONFIG_FILE" 2>/dev/null | awk '{print $2}' | tr -d '"')
            echo ""
            echo -e "端口: ${CYAN}${port}${NC}  PSK: ${CYAN}${psk}${NC}"
            
            # 隧道地址
            local tunnel_on=$(grep -A1 "^tunnel:" "$CONFIG_FILE" | grep "enabled:" | awk '{print $2}')
            if [[ "$tunnel_on" == "true" ]]; then
                local url=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
                [[ -n "$url" ]] && echo -e "隧道: ${CYAN}${url}${NC}"
            fi
        fi
        
        echo ""
        echo -e "${BOLD}════════════ 主菜单 ════════════${NC}"
        echo ""
        echo "  1. 重新安装/升级"
        echo "  2. 卸载"
        echo ""
        echo "  3. 启动服务"
        echo "  4. 停止服务"
        echo "  5. 重启服务"
        echo "  6. 查看日志"
        echo ""
        echo "  7. 修改端口"
        echo "  8. 重置密钥"
        echo "  9. 隧道设置"
        echo ""
        echo "  10. 查看配置"
        echo "  11. 高级设置"
        echo ""
        echo "  0. 退出"
        echo ""
        read -rp "请选择: " choice
        
        case $choice in
            1) guided_install ;;
            2) 
                echo ""
                if confirm "确定要卸载吗？" "n"; then
                    systemctl stop phantom 2>/dev/null
                    systemctl disable phantom 2>/dev/null
                    rm -rf "$INSTALL_DIR" "$CONFIG_DIR" "$SERVICE_FILE"
                    systemctl daemon-reload
                    info "已卸载"
                fi
                press_enter
                ;;
            3) 
                echo ""
                systemctl start phantom && info "已启动" || error "启动失败"
                press_enter
                ;;
            4)
                echo ""
                systemctl stop phantom && info "已停止" || error "停止失败"
                press_enter
                ;;
            5)
                echo ""
                systemctl restart phantom && info "已重启" || error "重启失败"
                press_enter
                ;;
            6)
                echo ""
                echo "按 Ctrl+C 退出日志查看"
                sleep 1
                journalctl -u phantom -f -n 50
                ;;
            7)
                echo ""
                read -rp "新端口: " new_port
                if [[ "$new_port" =~ ^[0-9]+$ ]]; then
                    yaml_set "listen" "\":${new_port}\""
                    yaml_set_section "tunnel" "local_port" "$new_port"
                    yaml_set_section "faketcp" "listen" "\":$((new_port+1))\""
                    yaml_set_section "websocket" "listen" "\":$((new_port+2))\""
                    systemctl restart phantom
                    info "端口已修改"
                fi
                press_enter
                ;;
            8)
                echo ""
                local new_psk=$(openssl rand -base64 16 | tr -d '=+/' | head -c 16)
                yaml_set "psk" "\"${new_psk}\""
                systemctl restart phantom
                info "新密钥: ${CYAN}${new_psk}${NC}"
                press_enter
                ;;
            9)
                echo ""
                echo "隧道设置:"
                echo "  1. 启用临时隧道"
                echo "  2. 启用固定隧道"
                echo "  3. 禁用隧道"
                echo "  4. 查看隧道地址"
                read -rp "选择: " t
                case $t in
                    1)
                        yaml_set_section "tunnel" "enabled" "true"
                        yaml_set_section "tunnel" "mode" "\"temp\""
                        systemctl restart phantom
                        sleep 5
                        local url=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
                        [[ -n "$url" ]] && info "隧道地址: ${url}" || warn "等待隧道建立..."
                        ;;
                    2)
                        read -rp "CF Token: " token
                        if [[ -n "$token" ]]; then
                            yaml_set_section "tunnel" "enabled" "true"
                            yaml_set_section "tunnel" "mode" "\"fixed\""
                            yaml_set_section "tunnel" "token" "\"${token}\""
                            systemctl restart phantom
                            info "固定隧道已配置"
                        fi
                        ;;
                    3)
                        yaml_set_section "tunnel" "enabled" "false"
                        systemctl restart phantom
                        info "隧道已禁用"
                        ;;
                    4)
                        local url=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
                        [[ -n "$url" ]] && info "隧道地址: ${url}" || warn "未找到隧道地址"
                        ;;
                esac
                press_enter
                ;;
            10)
                echo ""
                cat "$CONFIG_FILE" 2>/dev/null || echo "配置文件不存在"
                press_enter
                ;;
            11)
                advanced_menu
                ;;
            0)
                echo ""
                echo "再见！"
                exit 0
                ;;
        esac
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# 高级设置菜单
# ─────────────────────────────────────────────────────────────────────────────
advanced_menu() {
    while true; do
        clear
        echo -e "${BOLD}高级设置${NC}"
        echo ""
        echo "  1. 智能寻路设置"
        echo "  2. TLS/伪装设置"
        echo "  3. 性能调优"
        echo "  4. 协议开关"
        echo "  5. 网卡/eBPF"
        echo "  6. 编辑配置文件"
        echo ""
        echo "  0. 返回主菜单"
        echo ""
        read -rp "选择: " choice
        
        case $choice in
            1)
                echo ""
                echo "智能寻路配置:"
                read -rp "  RTT阈值(ms) [300]: " rtt
                read -rp "  丢包阈值 [0.3]: " loss
                [[ -n "$rtt" ]] && yaml_set_section "switcher" "rtt_threshold_ms" "$rtt"
                [[ -n "$loss" ]] && yaml_set_section "switcher" "loss_threshold" "$loss"
                systemctl restart phantom
                info "已更新"
                press_enter
                ;;
            2)
                echo ""
                echo "TLS 设置:"
                echo "  1. 启用 TLS"
                echo "  2. 禁用 TLS"
                echo "  3. 修改 SNI"
                echo "  4. 修改指纹"
                read -rp "选择: " t
                case $t in
                    1) yaml_set_section "tls" "enabled" "true" ;;
                    2) yaml_set_section "tls" "enabled" "false" ;;
                    3) read -rp "SNI: " s; yaml_set_section "tls" "server_name" "\"${s}\"" ;;
                    4) echo "1.chrome 2.firefox 3.safari"; read -rp ": " f
                       case $f in 1)fp="chrome";;2)fp="firefox";;3)fp="safari";;esac
                       yaml_set_section "tls" "fingerprint" "\"${fp}\"" ;;
                esac
                systemctl restart phantom
                info "已更新"
                press_enter
                ;;
            3)
                echo ""
                echo "性能调优:"
                read -rp "  上行带宽(Mbps) [100]: " up
                read -rp "  下行带宽(Mbps) [100]: " down
                [[ -n "$up" ]] && yaml_set_section "hysteria2" "up_mbps" "$up"
                [[ -n "$down" ]] && yaml_set_section "hysteria2" "down_mbps" "$down"
                systemctl restart phantom
                info "已更新"
                press_enter
                ;;
            4)
                echo ""
                echo "协议开关:"
                echo "  1. FakeTCP"
                echo "  2. WebSocket"
                echo "  3. eBPF"
                read -rp "切换哪个: " p
                case $p in
                    1) local v=$(grep -A1 "^faketcp:" "$CONFIG_FILE" | grep enabled | awk '{print $2}')
                       [[ "$v" == "true" ]] && yaml_set_section "faketcp" "enabled" "false" || yaml_set_section "faketcp" "enabled" "true" ;;
                    2) local v=$(grep -A1 "^websocket:" "$CONFIG_FILE" | grep enabled | awk '{print $2}')
                       [[ "$v" == "true" ]] && yaml_set_section "websocket" "enabled" "false" || yaml_set_section "websocket" "enabled" "true" ;;
                    3) local v=$(grep -A1 "^ebpf:" "$CONFIG_FILE" | grep enabled | awk '{print $2}')
                       [[ "$v" == "true" ]] && yaml_set_section "ebpf" "enabled" "false" || yaml_set_section "ebpf" "enabled" "true" ;;
                esac
                systemctl restart phantom
                info "已切换"
                press_enter
                ;;
            5)
                echo ""
                local iface=$(ip route | grep default | awk '{print $5}' | head -1)
                echo "检测到网卡: $iface"
                read -rp "使用此网卡? [Y/n]: " use
                if [[ -z "$use" || "$use" =~ ^[Yy]$ ]]; then
                    yaml_set_section "ebpf" "interface" "\"${iface}\""
                    yaml_set_section "faketcp" "interface" "\"${iface}\""
                    systemctl restart phantom
                    info "已更新"
                fi
                press_enter
                ;;
            6)
                if command -v nano &>/dev/null; then
                    nano "$CONFIG_FILE"
                elif command -v vim &>/dev/null; then
                    vim "$CONFIG_FILE"
                else
                    cat "$CONFIG_FILE"
                fi
                systemctl restart phantom
                ;;
            0)
                return
                ;;
        esac
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# 主入口
# ─────────────────────────────────────────────────────────────────────────────
main() {
    check_root
    check_system
    
    # 判断是否已安装
    if [[ -f "$CONFIG_FILE" ]] && systemctl is-enabled phantom &>/dev/null; then
        # 已安装，显示管理菜单
        show_menu
    else
        # 未安装，进入引导安装
        guided_install
        echo ""
        press_enter
        show_menu
    fi
}

main "$@"
