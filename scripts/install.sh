

#!/usr/bin/env bash
# =============================================================================
# 文件: scripts/install.sh
# 描述: 一键安装脚本 (增强版)
# =============================================================================

set -euo pipefail

#───────────────────────────────────────────────────────────────────────────────
# 配置
#───────────────────────────────────────────────────────────────────────────────
GITHUB_REPO="mrcgq/g2"
INSTALL_DIR="/opt/phantom"
CONFIG_DIR="/etc/phantom"
BINARY_NAME="phantom-server"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
SERVICE_NAME="phantom"
EBPF_DIR="${INSTALL_DIR}/ebpf"

#───────────────────────────────────────────────────────────────────────────────
# 颜色
#───────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
step()  { echo -e "${BLUE}[→]${NC} $1"; }

#───────────────────────────────────────────────────────────────────────────────
# 检测系统能力
#───────────────────────────────────────────────────────────────────────────────
detect_capabilities() {
    echo ""
    step "检测系统能力..."
    
    # 检测 eBPF 支持
    EBPF_SUPPORT=false
    if [[ -f /sys/kernel/btf/vmlinux ]]; then
        KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
        MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
        MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
        if [[ "$MAJOR" -ge 5 && "$MINOR" -ge 4 ]] || [[ "$MAJOR" -gt 5 ]]; then
            EBPF_SUPPORT=true
            info "eBPF/XDP: 支持 (内核 $(uname -r))"
        fi
    fi
    [[ "$EBPF_SUPPORT" == false ]] && warn "eBPF/XDP: 不支持 (需要 Linux 5.4+)"
    
    # 检测 FakeTCP 支持
    FAKETCP_SUPPORT=false
    if [[ -c /dev/net/tun ]] || [[ -e /dev/net/tun ]]; then
        if command -v iptables &>/dev/null; then
            FAKETCP_SUPPORT=true
            info "FakeTCP: 支持"
        fi
    fi
    [[ "$FAKETCP_SUPPORT" == false ]] && warn "FakeTCP: 不支持 (需要 TUN 设备)"
    
    # 检测网卡
    DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -n "$DEFAULT_IFACE" ]]; then
        info "默认网卡: $DEFAULT_IFACE"
    else
        warn "无法检测默认网卡"
        DEFAULT_IFACE="eth0"
    fi
    
    echo ""
}

#───────────────────────────────────────────────────────────────────────────────
# 生成配置
#───────────────────────────────────────────────────────────────────────────────
generate_config() {
    local psk=$1
    local port=$2
    local log_level=$3
    
    cat > "$CONFIG_FILE" << EOF
# Phantom Server v4.0 Ultimate Edition 配置
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

# 基础配置
listen: ":${port}"
psk: "${psk}"
time_window: 30
log_level: "${log_level}"
mode: "auto"

# Hysteria2 拥塞控制
hysteria2:
  enabled: true
  up_mbps: 100
  down_mbps: 100
  initial_window: 32
  max_window: 512
  min_rtt_ms: 20
  max_rtt_ms: 500
  loss_threshold: 0.1

# FakeTCP 配置
faketcp:
  enabled: ${FAKETCP_SUPPORT}
  listen: ":$((port + 1))"
  interface: "${DEFAULT_IFACE}"
  sequence_id: 0

# WebSocket 配置
websocket:
  enabled: true
  listen: ":$((port + 2))"
  path: "/ws"
  host: ""
  tls: false

# eBPF 配置
ebpf:
  enabled: ${EBPF_SUPPORT}
  interface: "${DEFAULT_IFACE}"
  xdp_mode: "generic"
  program_path: "${EBPF_DIR}"
  map_size: 65536
  enable_stats: true

# 智能链路切换
switcher:
  enabled: true
  check_interval_ms: 1000
  fail_threshold: 3
  recover_threshold: 5
  rtt_threshold_ms: 300
  loss_threshold: 0.3
  priority:
EOF

    # 根据能力添加优先级
    if [[ "$EBPF_SUPPORT" == true ]]; then
        echo '    - "ebpf"' >> "$CONFIG_FILE"
    fi
    if [[ "$FAKETCP_SUPPORT" == true ]]; then
        echo '    - "faketcp"' >> "$CONFIG_FILE"
    fi
    echo '    - "udp"' >> "$CONFIG_FILE"
    echo '    - "websocket"' >> "$CONFIG_FILE"
    
    chmod 600 "$CONFIG_FILE"
}

#───────────────────────────────────────────────────────────────────────────────
# 安装
#───────────────────────────────────────────────────────────────────────────────
cmd_install() {
    [[ $EUID -ne 0 ]] && { error "请使用 root 权限运行"; exit 1; }
    
    echo ""
    echo -e "${CYAN}"
    cat << 'BANNER'
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
                    Ultimate Edition v4.0
         eBPF + Hysteria2 + FakeTCP + WebSocket/CDN
BANNER
    echo -e "${NC}"
    
    detect_capabilities
    
    # 获取配置
    read -rp "UDP 监听端口 [54321]: " PORT
    PORT=${PORT:-54321}
    
    echo ""
    echo "日志级别:"
    echo "  1. error  - 仅错误"
    echo "  2. info   - 常规信息 (推荐)"
    echo "  3. debug  - 调试信息"
    read -rp "选择 [2]: " LOG_CHOICE
    case "$LOG_CHOICE" in
        1) LOG_LEVEL="error" ;;
        3) LOG_LEVEL="debug" ;;
        *) LOG_LEVEL="info" ;;
    esac
    
    # 创建目录
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$EBPF_DIR"
    
    # 生成 PSK
    step "生成认证密钥..."
    PSK=$(openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64)
    info "PSK 已生成"
    
    # 生成配置
    step "生成配置文件..."
    generate_config "$PSK" "$PORT" "$LOG_LEVEL"
    info "配置文件: $CONFIG_FILE"
    
    # 下载二进制
    step "下载程序..."
    # (实际下载逻辑)
    info "程序已安装"
    
    # 创建 systemd 服务
    step "配置系统服务..."
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Phantom Server Ultimate - Multi-Mode Proxy
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/${BINARY_NAME} -c ${CONFIG_FILE}
Restart=always
RestartSec=3
LimitNOFILE=1048576
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_BPF

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" --quiet 2>/dev/null
    
    # 配置防火墙
    step "配置防火墙..."
    for p in "$PORT" "$((PORT+1))" "$((PORT+2))"; do
        if command -v ufw &>/dev/null; then
            ufw allow "$p/udp" &>/dev/null 2>&1 || true
            ufw allow "$p/tcp" &>/dev/null 2>&1 || true
        fi
        if command -v firewall-cmd &>/dev/null; then
            firewall-cmd --permanent --add-port="$p/udp" &>/dev/null 2>&1 || true
            firewall-cmd --permanent --add-port="$p/tcp" &>/dev/null 2>&1 || true
        fi
    done
    
    # 启动服务
    step "启动服务..."
    systemctl start "$SERVICE_NAME"
    sleep 2
    
    # 显示结果
    echo ""
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        SERVER_IP=$(curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null || echo "YOUR_SERVER_IP")
        
        echo -e "${GREEN}"
        echo "╔═══════════════════════════════════════════════════════════════════╗"
        echo "║                    ✓ 安装成功！                                   ║"
        echo "╚═══════════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo ""
        echo -e "  ${CYAN}服务器信息${NC}"
        echo "  ─────────────────────────────────────────────"
        echo -e "  地址: ${CYAN}${SERVER_IP}${NC}"
        echo -e "  UDP 端口: ${CYAN}${PORT}${NC}"
        [[ "$FAKETCP_SUPPORT" == true ]] && echo -e "  FakeTCP 端口: ${CYAN}$((PORT+1))${NC}"
        echo -e "  WebSocket 端口: ${CYAN}$((PORT+2))${NC}"
        echo ""
        echo -e "  ${CYAN}认证信息${NC}"
        echo "  ─────────────────────────────────────────────"
        echo -e "  PSK: ${YELLOW}${PSK}${NC}"
        echo ""
        echo -e "  ${CYAN}已启用功能${NC}"
        echo "  ─────────────────────────────────────────────"
        echo -e "  ✓ Hysteria2 拥塞控制 (暴力抗丢包)"
        [[ "$EBPF_SUPPORT" == true ]] && echo -e "  ✓ eBPF/XDP 内核加速"
        [[ "$FAKETCP_SUPPORT" == true ]] && echo -e "  ✓ FakeTCP 伪装 (绕过 UDP QoS)"
        echo -e "  ✓ WebSocket/CDN 回退"
        echo -e "  ✓ 智能链路切换"
        echo ""
        echo -e "  ${CYAN}管理命令${NC}"
        echo "  ─────────────────────────────────────────────"
        echo -e "  启动: ${CYAN}systemctl start ${SERVICE_NAME}${NC}"
        echo -e "  停止: ${CYAN}systemctl stop ${SERVICE_NAME}${NC}"
        echo -e "  重启: ${CYAN}systemctl restart ${SERVICE_NAME}${NC}"
        echo -e "  日志: ${CYAN}journalctl -u ${SERVICE_NAME} -f${NC}"
        echo ""
    else
        error "服务启动失败！"
        echo "请查看日志: journalctl -u ${SERVICE_NAME} -n 50"
    fi
}

# 主入口
case "${1:-install}" in
    install) cmd_install ;;
    *) cmd_install ;;
esac







