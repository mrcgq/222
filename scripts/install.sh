#!/usr/bin/env bash
# =============================================================================
# 文件: scripts/install.sh
# 版本: v4.2.1-STABLE
# 描述: Phantom Server v4.2 专家级管理面板 - 完美适配 1-96 模块所有逻辑
# 修复: set -e 兼容性 / stdin 管道冲突 / YAML 作用域化注入
# =============================================================================

# 【修复1】移除 set -e，改用手动错误处理
# set -e  # 已移除，防止 systemctl 等命令的非零返回值导致脚本退出

# 【修复2】确保 stdin 可用于交互（解决 bash <(curl ...) 问题）
if [[ ! -t 0 ]]; then
    exec 0</dev/tty
fi

# ───────────────────────────────────────────────────────────────────────────────
# 1. 变量与环境初始化
# ───────────────────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/phantom"
EBPF_DIR="/opt/phantom/ebpf"
CONFIG_DIR="/etc/phantom"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
SERVICE_FILE="/etc/systemd/system/phantom.service"
BINARY_NAME="phantom-server"

# 调色盘
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# 辅助函数
info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERR ]${NC} $1"; }
step()    { echo -e "${BLUE}${BOLD}[STEP]${NC} $1"; }
success() { echo -e "${GREEN}${BOLD}[OK]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "错误: 必须使用 root 权限运行 (sudo)"
        exit 1
    fi
}

get_iface() {
    local iface
    iface=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -1)
    echo "${iface:-eth0}"
}

pause() {
    echo ""
    read -rp "按 Enter 键返回..." _
}

# ───────────────────────────────────────────────────────────────────────────────
# 2. 安全的 YAML 操作函数（核心修复）
# ───────────────────────────────────────────────────────────────────────────────

# 顶级字段修改（如 listen, psk, mode）
yaml_set_top() {
    local key="$1"
    local value="$2"
    local file="${3:-$CONFIG_FILE}"
    
    if [[ ! -f "$file" ]]; then
        echo "${key}: ${value}" > "$file"
        return
    fi
    
    if grep -q "^${key}:" "$file"; then
        sed -i "s|^${key}:.*|${key}: ${value}|" "$file"
    else
        echo "${key}: ${value}" >> "$file"
    fi
}

# 一级嵌套字段修改（如 hysteria2.enabled）
yaml_set_section() {
    local section="$1"
    local key="$2"
    local value="$3"
    local file="${4:-$CONFIG_FILE}"
    
    [[ ! -f "$file" ]] && return 1
    
    awk -v sec="$section" -v k="$key" -v v="$value" '
    BEGIN { in_section=0; found=0 }
    {
        if ($0 ~ "^"sec":") {
            in_section=1
            print
            next
        }
        if (in_section && /^[a-zA-Z_]+:/ && $0 !~ "^"sec":") {
            in_section=0
        }
        if (in_section && !found && $0 ~ "^[[:space:]]+"k":") {
            sub(/:[[:space:]]*.*/, ": "v)
            found=1
        }
        print
    }
    ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

# 二级嵌套字段修改（如 tunnel.duckdns.token）
yaml_set_nested() {
    local section="$1"
    local subsection="$2"
    local key="$3"
    local value="$4"
    local file="${5:-$CONFIG_FILE}"
    
    [[ ! -f "$file" ]] && return 1
    
    awk -v sec="$section" -v subsec="$subsection" -v k="$key" -v v="$value" '
    BEGIN { in_section=0; in_subsection=0; found=0 }
    {
        if ($0 ~ "^"sec":") {
            in_section=1
            print
            next
        }
        if (in_section && /^[a-zA-Z_]+:/ && $0 !~ "^"sec":") {
            in_section=0
            in_subsection=0
        }
        if (in_section && $0 ~ "^[[:space:]]+"subsec":") {
            in_subsection=1
            print
            next
        }
        if (in_subsection && /^[[:space:]][[:space:]][a-zA-Z_]+:/ && $0 !~ "^[[:space:]]+"subsec":") {
            match($0, /^[[:space:]]+/)
            indent = RLENGTH
            if (indent <= 2) {
                in_subsection=0
            }
        }
        if (in_subsection && !found && $0 ~ "^[[:space:]]+"k":") {
            sub(/:[[:space:]]*.*/, ": \""v"\"")
            found=1
        }
        print
    }
    ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

# 动态替换 YAML 数组
yaml_set_array() {
    local section="$1"
    local key="$2"
    local values="$3"
    local file="${4:-$CONFIG_FILE}"
    
    [[ ! -f "$file" ]] && return 1
    
    local tmpfile
    tmpfile=$(mktemp)
    
    awk -v sec="$section" -v k="$key" -v vals="$values" '
    BEGIN {
        in_section=0
        in_array=0
        split(vals, arr, ",")
    }
    {
        if ($0 ~ "^"sec":") {
            in_section=1
            print
            next
        }
        if (in_section && /^[a-zA-Z_]+:/ && $0 !~ "^"sec":") {
            in_section=0
        }
        if (in_section && $0 ~ "^[[:space:]]+"k":") {
            in_array=1
            print
            for (i in arr) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", arr[i])
                print "    - \""arr[i]"\""
            }
            next
        }
        if (in_array && /^[[:space:]]+-/) {
            next
        }
        if (in_array && !/^[[:space:]]+-/) {
            in_array=0
        }
        print
    }
    ' "$file" > "$tmpfile" && mv "$tmpfile" "$file"
}

# 读取 YAML 字段值
yaml_get() {
    local section="$1"
    local key="$2"
    local file="${3:-$CONFIG_FILE}"
    
    [[ ! -f "$file" ]] && return 1
    
    awk -v sec="$section" -v k="$key" '
    BEGIN { in_section=0 }
    {
        if ($0 ~ "^"sec":") { in_section=1; next }
        if (in_section && /^[a-zA-Z_]+:/) { in_section=0 }
        if (in_section && $0 ~ "^[[:space:]]+"k":") {
            sub(/.*:[[:space:]]*/, "")
            gsub(/"/, "")
            print
            exit
        }
    }
    ' "$file"
}

# ───────────────────────────────────────────────────────────────────────────────
# 3. 核心操作逻辑
# ───────────────────────────────────────────────────────────────────────────────

validate_yaml() {
    local file="${1:-$CONFIG_FILE}"
    
    [[ ! -f "$file" ]] && return 1
    
    if command -v python3 &>/dev/null; then
        if python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>/dev/null; then
            return 0
        else
            error "YAML 语法错误！"
            python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>&1 | head -5
            return 1
        fi
    fi
    
    if grep -qP '^\t' "$file"; then
        error "YAML 中不允许使用 Tab 缩进"
        return 1
    fi
    
    return 0
}

apply_config() {
    step "正在验证并部署配置..."
    
    if [[ -f "$CONFIG_FILE" ]] && ! validate_yaml; then
        error "配置验证失败，操作已中止"
        read -rp "是否查看配置文件？[y/N]: " view
        [[ "$view" == "y" ]] && cat -A "$CONFIG_FILE" | head -50
        return 1
    fi
    
    systemctl daemon-reload 2>/dev/null || true
    systemctl restart phantom 2>/dev/null
    sleep 2
    
    # 【修复3】安全检测服务状态，避免 set -e 问题
    local svc_status
    svc_status=$(systemctl is-active phantom 2>/dev/null || echo "unknown")
    
    if [[ "$svc_status" == "active" ]]; then
        success "服务状态: 运行中 (Active)"
        
        local tunnel_enabled tunnel_mode
        tunnel_enabled=$(yaml_get "tunnel" "enabled" 2>/dev/null || echo "false")
        tunnel_mode=$(yaml_get "tunnel" "mode" 2>/dev/null || echo "")
        
        if [[ "$tunnel_enabled" == "true" && "$tunnel_mode" == "temp" ]]; then
            warn "正在检索临时隧道 URL..."
            sleep 3
            local url
            url=$(journalctl -u phantom -n 50 --no-pager 2>/dev/null | \
                  grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1 || true)
            [[ -n "$url" ]] && info "隧道地址: ${CYAN}${url}${NC}"
        fi
    else
        error "启动失败，请使用选项 10 查看日志"
        return 1
    fi
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 1] 深度安装流程
# ───────────────────────────────────────────────────────────────────────────────
install_phantom() {
    step "执行 Phantom Server v4.2 生产级深度部署..."
    mkdir -p "$INSTALL_DIR" "$EBPF_DIR" "$CONFIG_DIR"

    local iface
    iface=$(get_iface)
    info "网络适配: 自动绑定网卡 ${CYAN}${iface}${NC}"

    local PORT PSK
    read -rp "主监听端口 [54321]: " PORT
    PORT=${PORT:-54321}
    read -rp "认证密钥 PSK (留空随机生成): " PSK
    [[ -z "$PSK" ]] && PSK=$(openssl rand -base64 24 2>/dev/null || head -c 24 /dev/urandom | base64)

    cat > "$CONFIG_FILE" << EOF
# ═══════════════════════════════════════════════════════════════════════════════
# Phantom Server v4.2 配置文件
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# ═══════════════════════════════════════════════════════════════════════════════

listen: ":${PORT}"
psk: "${PSK}"
time_window: 30
log_level: "info"
mode: "auto"

# 模块 17: Hysteria2 暴力拥塞控制
hysteria2:
  enabled: true
  up_mbps: 100
  down_mbps: 100
  loss_threshold: 0.1
  disable_mtu_discovery: false

# 模块 40: ARQ 增强层
arq:
  enabled: true
  window_size: 256
  max_retries: 10
  rto_min_ms: 100
  rto_max_ms: 3000
  ack_delay_ms: 20

# 模块 33-39: Switcher 智能寻路
switcher:
  enabled: true
  check_interval_ms: 1000
  rtt_threshold_ms: 300
  loss_threshold: 0.3
  jitter_threshold_ms: 100
  priority:
    - "ebpf"
    - "faketcp"
    - "udp"
    - "websocket"

# 模块 92/93: Cloudflare 隧道
tunnel:
  enabled: false
  mode: "temp"
  cf_token: ""
  local_port: ${PORT}
  acme_use_tunnel: true

# 模块 94: DDNS 动态域名
ddns:
  enabled: false
  provider: "none"
  check_interval: 300
  duckdns:
    token: ""
    domains: ""
  freedns:
    token: ""
  cloudflare:
    api_token: ""
    zone_id: ""
    record_name: ""

# 模块 95/96: TLS 深度伪装
tls:
  enabled: false
  server_name: "www.microsoft.com"
  fingerprint: "chrome"
  alpn:
    - "h2"
    - "http/1.1"
  random_sni: false
  sni_list:
    - "www.microsoft.com"
    - "www.apple.com"
    - "www.amazon.com"
  enable_ech: false
  ech_config: ""
  fragment:
    enabled: true
    size: 40
    sleep_ms: 10
    strategy: "random"
  fallback:
    enabled: true
    addr: "127.0.0.1:80"
    timeout_ms: 5000

# 模块 56: FakeTCP
faketcp:
  enabled: true
  listen: ":$((PORT+1))"
  interface: "${iface}"
  use_ebpf: true
  mtu: 1400

# 模块 70: WebSocket
websocket:
  enabled: true
  listen: ":$((PORT+2))"
  path: "/ws"
  host: ""
  tls: false
  compression: false

# 模块 49/52: eBPF & TC
ebpf:
  enabled: true
  interface: "${iface}"
  xdp_mode: "generic"
  program_path: "${EBPF_DIR}"
  enable_tc: true
  tc_direction: "both"
  pin_maps: true

# 模块 30: Metrics
metrics:
  enabled: true
  listen: ":9100"
  path: "/metrics"
  health_path: "/health"
  pprof_enabled: false
EOF

    if [[ -f "./phantom-server" ]]; then
        cp "./phantom-server" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
        info "二进制文件已部署"
    else
        warn "未找到 phantom-server 二进制文件，请稍后手动部署"
    fi
    
    if [[ -d "./ebpf" ]]; then
        cp ./ebpf/*.o "$EBPF_DIR/" 2>/dev/null && info "eBPF 字节码已部署" || true
    fi

    cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=Phantom Server v4.2 (Expert Edition)
Documentation=https://github.com/phantom-server/phantom
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/phantom
ExecStart=/opt/phantom/phantom-server -c /etc/phantom/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=1048576
LimitNPROC=65535
LimitMEMLOCK=infinity
LimitCORE=infinity
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_BPF CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_RESOURCE CAP_SYS_PTRACE CAP_IPC_LOCK CAP_PERFMON
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
StandardOutput=journal
StandardError=journal
SyslogIdentifier=phantom

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload 2>/dev/null || true
    systemctl enable phantom 2>/dev/null || true
    
    if apply_config; then
        echo ""
        echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}${BOLD}  安装成功！${NC}"
        echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
        echo -e "  监听端口: ${CYAN}${PORT}${NC}"
        echo -e "  FakeTCP:  ${CYAN}$((PORT+1))${NC}"
        echo -e "  WebSocket: ${CYAN}$((PORT+2))${NC}"
        echo -e "  认证密钥: ${CYAN}${PSK}${NC}"
        echo -e "  配置文件: ${CYAN}${CONFIG_FILE}${NC}"
        echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    fi
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 2] 彻底卸载
# ───────────────────────────────────────────────────────────────────────────────
uninstall_phantom() {
    step "正在卸载 Phantom Server..."
    
    echo -e "${RED}警告: 此操作将删除所有配置和数据！${NC}"
    read -rp "确认彻底删除？请输入 'YES' 确认: " confirm
    [[ "$confirm" != "YES" ]] && { info "取消卸载"; return; }
    
    systemctl stop phantom 2>/dev/null || true
    systemctl disable phantom 2>/dev/null || true
    rm -rf "$INSTALL_DIR" "$CONFIG_DIR" "$SERVICE_FILE"
    systemctl daemon-reload 2>/dev/null || true
    
    success "Phantom Server 已完全卸载"
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 9] 基础配置修改
# ───────────────────────────────────────────────────────────────────────────────
manage_basic() {
    while true; do
        clear
        step "基础配置管理"
        
        local port log_level mode
        port=$(grep "^listen:" "$CONFIG_FILE" 2>/dev/null | sed 's/.*:\([0-9]*\)".*/\1/' || echo "未配置")
        log_level=$(grep "^log_level:" "$CONFIG_FILE" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo "info")
        mode=$(grep "^mode:" "$CONFIG_FILE" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo "auto")
        
        echo -e "当前端口: ${CYAN}${port}${NC}"
        echo -e "日志级别: ${CYAN}${log_level}${NC}"
        echo -e "运行模式: ${CYAN}${mode}${NC}"
        echo ""
        echo "─────────────────────────────────────"
        echo "1. 修改监听端口"
        echo "2. 修改/重置 PSK 密钥"
        echo "3. 修改日志级别"
        echo "4. 修改运行模式"
        echo "5. 修改时间窗口 (防重放)"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-5]: " opt
        
        case $opt in
            1)
                read -rp "新端口: " port
                if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
                    yaml_set_top "listen" "\":${port}\""
                    yaml_set_section "tunnel" "local_port" "$port"
                    yaml_set_section "faketcp" "listen" "\":$((port+1))\""
                    yaml_set_section "websocket" "listen" "\":$((port+2))\""
                    apply_config
                else
                    error "无效端口号"
                fi
                ;;
            2)
                read -rp "新 PSK (留空随机生成): " psk
                [[ -z "$psk" ]] && psk=$(openssl rand -base64 24 2>/dev/null || head -c 24 /dev/urandom | base64)
                yaml_set_top "psk" "\"${psk}\""
                apply_config
                info "新 PSK: ${CYAN}${psk}${NC}"
                pause
                ;;
            3)
                echo "可选: debug / info / warn / error"
                read -rp "日志级别: " level
                yaml_set_top "log_level" "\"${level}\""
                apply_config
                ;;
            4)
                echo "可选模式:"
                echo "  auto     - 智能寻路 (推荐)"
                echo "  ebpf     - 强制 eBPF"
                echo "  faketcp  - 强制 FakeTCP"
                echo "  udp      - 强制 UDP"
                echo "  websocket - 强制 WebSocket"
                read -rp "模式: " mode
                yaml_set_top "mode" "\"${mode}\""
                apply_config
                ;;
            5)
                read -rp "时间窗口(秒) [当前30]: " tw
                [[ "$tw" =~ ^[0-9]+$ ]] && yaml_set_top "time_window" "$tw"
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 13] Switcher 智能寻路
# ───────────────────────────────────────────────────────────────────────────────
manage_switcher() {
    while true; do
        clear
        step "Switcher 智能链路控制台"
        
        # 【修复4】安全获取服务状态
        local svc_status
        svc_status=$(systemctl is-active phantom 2>/dev/null || echo "inactive")
        
        if [[ "$svc_status" == "active" ]]; then
            local health
            health=$(curl -s --connect-timeout 2 http://127.0.0.1:9100/health 2>/dev/null || echo "")
            if [[ -n "$health" && "$health" != "fail" ]]; then
                echo -e "${CYAN}┌─────────────────── 实时链路状态 ───────────────────┐${NC}"
                local mode rtt loss
                mode=$(echo "$health" | grep -oP '"mode":\s*"\K[^"]+' | head -1 || echo "探测中")
                rtt=$(echo "$health" | grep -oP '"rtt_ms":\s*\K[0-9.]+' | head -1 || echo "0")
                loss=$(echo "$health" | grep -oP '"loss":\s*\K[0-9.]+' | head -1 || echo "0")
                echo -e "  │ 工作模式: ${GREEN}${mode}${NC}"
                echo -e "  │ 延迟(RTT): ${GREEN}${rtt} ms${NC}"
                echo -e "  │ 丢包率: ${GREEN}${loss}%${NC}"
                echo -e "${CYAN}└────────────────────────────────────────────────────┘${NC}"
            fi
        fi
        
        local interval rtt_th loss_th
        interval=$(yaml_get "switcher" "check_interval_ms" 2>/dev/null || echo "1000")
        rtt_th=$(yaml_get "switcher" "rtt_threshold_ms" 2>/dev/null || echo "300")
        loss_th=$(yaml_get "switcher" "loss_threshold" 2>/dev/null || echo "0.3")
        
        echo ""
        echo -e "检测间隔: ${CYAN}${interval}ms${NC} | RTT阈值: ${CYAN}${rtt_th}ms${NC} | 丢包阈值: ${CYAN}${loss_th}${NC}"
        echo ""
        echo "─────────────────────────────────────"
        echo "1. 修改寻路优先级 (Priority)"
        echo "2. 修改检测频率 (Interval)"
        echo "3. 修改 RTT 阈值"
        echo "4. 修改丢包阈值"
        echo "5. 修改抖动阈值 (Jitter)"
        echo "6. 切换 eBPF 模式"
        echo "7. 锁定传输模式"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-7]: " sw_opt

        case $sw_opt in
            1)
                echo ""
                echo "可用: ebpf, faketcp, udp, tcp, websocket"
                read -rp "输入优先级 (逗号分隔): " priority_str
                [[ -n "$priority_str" ]] && yaml_set_array "switcher" "priority" "$priority_str" && apply_config
                ;;
            2)
                read -rp "检测间隔(ms): " new_interval
                [[ "$new_interval" =~ ^[0-9]+$ ]] && yaml_set_section "switcher" "check_interval_ms" "$new_interval" && apply_config
                ;;
            3)
                read -rp "RTT 阈值(ms): " new_rtt
                [[ "$new_rtt" =~ ^[0-9]+$ ]] && yaml_set_section "switcher" "rtt_threshold_ms" "$new_rtt" && apply_config
                ;;
            4)
                read -rp "丢包阈值 (0.0-1.0): " new_loss
                [[ "$new_loss" =~ ^[0-9]*\.?[0-9]+$ ]] && yaml_set_section "switcher" "loss_threshold" "$new_loss" && apply_config
                ;;
            5)
                local jitter
                jitter=$(yaml_get "switcher" "jitter_threshold_ms" 2>/dev/null || echo "100")
                read -rp "抖动阈值(ms) [当前${jitter}]: " new_jitter
                [[ "$new_jitter" =~ ^[0-9]+$ ]] && yaml_set_section "switcher" "jitter_threshold_ms" "$new_jitter" && apply_config
                ;;
            6)
                echo "1. generic  2. native  3. offload"
                read -rp "选择: " xdp_choice
                case $xdp_choice in
                    1) mode="generic" ;;
                    2) mode="native" ;;
                    3) mode="offload" ;;
                    *) continue ;;
                esac
                yaml_set_section "ebpf" "xdp_mode" "\"${mode}\""
                apply_config
                ;;
            7)
                echo "可选: auto / ebpf / faketcp / udp / tcp / websocket"
                read -rp "锁定为: " lock_mode
                yaml_set_top "mode" "\"${lock_mode}\""
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 14] TLS 深度伪装
# ───────────────────────────────────────────────────────────────────────────────
manage_tls() {
    while true; do
        clear
        step "TLS 深度伪装与 DPI 逃逸"
        
        local tls_enabled sni fp random_sni
        tls_enabled=$(yaml_get "tls" "enabled" 2>/dev/null || echo "false")
        sni=$(yaml_get "tls" "server_name" 2>/dev/null || echo "www.microsoft.com")
        fp=$(yaml_get "tls" "fingerprint" 2>/dev/null || echo "chrome")
        random_sni=$(yaml_get "tls" "random_sni" 2>/dev/null || echo "false")
        
        echo -e "TLS: ${CYAN}${tls_enabled}${NC} | SNI: ${CYAN}${sni}${NC} | 指纹: ${CYAN}${fp}${NC}"
        echo ""
        echo "─────────────────────────────────────"
        echo "1. 启用/禁用 TLS"
        echo "2. 修改 uTLS 指纹"
        echo "3. 修改 SNI"
        echo "4. 分片参数"
        echo "5. 随机 SNI 设置"
        echo "6. 编辑 SNI 列表"
        echo "7. ECH 设置"
        echo "8. 探测回落"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-8]: " t_opt

        case $t_opt in
            1)
                if [[ "$tls_enabled" == "true" ]]; then
                    yaml_set_section "tls" "enabled" "false"
                    info "TLS 已禁用"
                else
                    yaml_set_section "tls" "enabled" "true"
                    info "TLS 已启用"
                fi
                apply_config
                ;;
            2)
                echo "1.chrome 2.firefox 3.safari 4.edge 5.ios 6.android 7.random"
                read -rp "选择: " f_idx
                case $f_idx in
                    1) fp="chrome" ;; 2) fp="firefox" ;; 3) fp="safari" ;;
                    4) fp="edge" ;; 5) fp="ios" ;; 6) fp="android" ;; 7) fp="random" ;;
                    *) continue ;;
                esac
                yaml_set_section "tls" "fingerprint" "\"${fp}\""
                apply_config
                ;;
            3)
                read -rp "SNI: " new_sni
                [[ -n "$new_sni" ]] && yaml_set_section "tls" "server_name" "\"${new_sni}\""
                apply_config
                ;;
            4)
                echo "1.启用/禁用 2.修改大小 3.修改间隔"
                read -rp "选择: " frag_opt
                case $frag_opt in
                    1)
                        local frag_enabled
                        frag_enabled=$(grep -A2 "fragment:" "$CONFIG_FILE" 2>/dev/null | grep "enabled:" | awk '{print $2}' || echo "true")
                        if [[ "$frag_enabled" == "true" ]]; then
                            sed -i '/fragment:/,/fallback:/ s/enabled: .*/enabled: false/' "$CONFIG_FILE"
                        else
                            sed -i '/fragment:/,/fallback:/ s/enabled: .*/enabled: true/' "$CONFIG_FILE"
                        fi
                        ;;
                    2)
                        read -rp "分片大小 [20-50]: " fs
                        [[ "$fs" =~ ^[0-9]+$ ]] && sed -i '/fragment:/,/fallback:/ s/size: .*/size: '"$fs"'/' "$CONFIG_FILE"
                        ;;
                    3)
                        read -rp "分片间隔(ms): " sl
                        [[ "$sl" =~ ^[0-9]+$ ]] && sed -i '/fragment:/,/fallback:/ s/sleep_ms: .*/sleep_ms: '"$sl"'/' "$CONFIG_FILE"
                        ;;
                esac
                apply_config
                ;;
            5)
                if [[ "$random_sni" == "true" ]]; then
                    yaml_set_section "tls" "random_sni" "false"
                else
                    yaml_set_section "tls" "random_sni" "true"
                    warn "请确保已配置 SNI 列表"
                fi
                apply_config
                ;;
            6)
                echo "当前列表:"
                grep -A10 "sni_list:" "$CONFIG_FILE" 2>/dev/null | grep "^\s*-" | sed 's/.*- "/  /' | sed 's/"$//'
                read -rp "输入新列表 (逗号分隔): " sni_list
                [[ -n "$sni_list" ]] && yaml_set_array "tls" "sni_list" "$sni_list" && apply_config
                ;;
            7)
                local ech_enabled
                ech_enabled=$(yaml_get "tls" "enable_ech" 2>/dev/null || echo "false")
                if [[ "$ech_enabled" == "true" ]]; then
                    yaml_set_section "tls" "enable_ech" "false"
                else
                    yaml_set_section "tls" "enable_ech" "true"
                fi
                apply_config
                ;;
            8)
                echo "1.启用/禁用 2.修改地址"
                read -rp "选择: " fb_opt
                case $fb_opt in
                    1)
                        local fb_enabled
                        fb_enabled=$(grep -A2 "fallback:" "$CONFIG_FILE" 2>/dev/null | grep "enabled:" | awk '{print $2}' || echo "true")
                        if [[ "$fb_enabled" == "true" ]]; then
                            sed -i '/fallback:/,/^[a-z]/ s/enabled: .*/enabled: false/' "$CONFIG_FILE"
                        else
                            sed -i '/fallback:/,/^[a-z]/ s/enabled: .*/enabled: true/' "$CONFIG_FILE"
                        fi
                        ;;
                    2)
                        read -rp "回落地址: " fb_addr
                        sed -i '/fallback:/,/^[a-z]/ s|addr: .*|addr: "'"$fb_addr"'"|' "$CONFIG_FILE"
                        ;;
                esac
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 15] Hysteria2 & ARQ
# ───────────────────────────────────────────────────────────────────────────────
manage_perf() {
    while true; do
        clear
        step "传输性能精调 (Hysteria2 & ARQ)"
        
        local h2_enabled up down arq_enabled ws rto_min rto_max
        h2_enabled=$(yaml_get "hysteria2" "enabled" 2>/dev/null || echo "true")
        up=$(yaml_get "hysteria2" "up_mbps" 2>/dev/null || echo "100")
        down=$(yaml_get "hysteria2" "down_mbps" 2>/dev/null || echo "100")
        arq_enabled=$(yaml_get "arq" "enabled" 2>/dev/null || echo "true")
        ws=$(yaml_get "arq" "window_size" 2>/dev/null || echo "256")
        rto_min=$(yaml_get "arq" "rto_min_ms" 2>/dev/null || echo "100")
        rto_max=$(yaml_get "arq" "rto_max_ms" 2>/dev/null || echo "3000")
        
        echo -e "Hysteria2: ${CYAN}${h2_enabled}${NC} | 上行: ${up}Mbps | 下行: ${down}Mbps"
        echo -e "ARQ: ${CYAN}${arq_enabled}${NC} | 窗口: ${ws} | RTO: ${rto_min}-${rto_max}ms"
        echo ""
        echo "─────────────────────────────────────"
        echo "1. 切换 Hysteria2"
        echo "2. 修改带宽"
        echo "3. 切换 ARQ"
        echo "4. 修改窗口大小"
        echo "5. 修改最大重传次数"
        echo "6. 修改 RTO 范围"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-6]: " perf_opt

        case $perf_opt in
            1)
                if [[ "$h2_enabled" == "true" ]]; then
                    yaml_set_section "hysteria2" "enabled" "false"
                else
                    yaml_set_section "hysteria2" "enabled" "true"
                fi
                apply_config
                ;;
            2)
                read -rp "上行 Mbps: " new_up
                read -rp "下行 Mbps: " new_down
                [[ "$new_up" =~ ^[0-9]+$ ]] && yaml_set_section "hysteria2" "up_mbps" "$new_up"
                [[ "$new_down" =~ ^[0-9]+$ ]] && yaml_set_section "hysteria2" "down_mbps" "$new_down"
                apply_config
                ;;
            3)
                if [[ "$arq_enabled" == "true" ]]; then
                    yaml_set_section "arq" "enabled" "false"
                else
                    yaml_set_section "arq" "enabled" "true"
                fi
                apply_config
                ;;
            4)
                read -rp "窗口大小: " new_ws
                [[ "$new_ws" =~ ^[0-9]+$ ]] && yaml_set_section "arq" "window_size" "$new_ws"
                apply_config
                ;;
            5)
                local mr
                mr=$(yaml_get "arq" "max_retries" 2>/dev/null || echo "10")
                read -rp "最大重传 [当前${mr}]: " new_mr
                [[ "$new_mr" =~ ^[0-9]+$ ]] && yaml_set_section "arq" "max_retries" "$new_mr"
                apply_config
                ;;
            6)
                read -rp "RTO 最小(ms): " new_rto_min
                read -rp "RTO 最大(ms): " new_rto_max
                if [[ "$new_rto_min" =~ ^[0-9]+$ && "$new_rto_max" =~ ^[0-9]+$ ]]; then
                    if [ "$new_rto_max" -lt "$new_rto_min" ]; then
                        error "RTO 最大值必须 >= 最小值"
                    else
                        yaml_set_section "arq" "rto_min_ms" "$new_rto_min"
                        yaml_set_section "arq" "rto_max_ms" "$new_rto_max"
                        apply_config
                    fi
                fi
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 16] 协议模块开关
# ───────────────────────────────────────────────────────────────────────────────
manage_protocols() {
    while true; do
        clear
        step "协议模块管理"
        
        local faketcp_st ws_st ebpf_st
        faketcp_st=$(yaml_get "faketcp" "enabled" 2>/dev/null || echo "true")
        ws_st=$(yaml_get "websocket" "enabled" 2>/dev/null || echo "true")
        ebpf_st=$(yaml_get "ebpf" "enabled" 2>/dev/null || echo "true")
        
        echo -e "FakeTCP: ${CYAN}${faketcp_st}${NC} | WebSocket: ${CYAN}${ws_st}${NC} | eBPF: ${CYAN}${ebpf_st}${NC}"
        echo ""
        echo "─────────────────────────────────────"
        echo "1. 切换 FakeTCP"
        echo "2. 切换 WebSocket"
        echo "3. 切换 eBPF"
        echo "4. 修改 WS Path"
        echo "5. 修改 FakeTCP 端口"
        echo "6. 修改 WS 端口"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-6]: " proto_opt

        case $proto_opt in
            1)
                [[ "$faketcp_st" == "true" ]] && yaml_set_section "faketcp" "enabled" "false" || yaml_set_section "faketcp" "enabled" "true"
                apply_config
                ;;
            2)
                [[ "$ws_st" == "true" ]] && yaml_set_section "websocket" "enabled" "false" || yaml_set_section "websocket" "enabled" "true"
                apply_config
                ;;
            3)
                [[ "$ebpf_st" == "true" ]] && yaml_set_section "ebpf" "enabled" "false" || yaml_set_section "ebpf" "enabled" "true"
                apply_config
                ;;
            4)
                read -rp "WS Path: " new_path
                [[ -n "$new_path" ]] && yaml_set_section "websocket" "path" "\"${new_path}\""
                apply_config
                ;;
            5)
                read -rp "FakeTCP 端口: " new_port
                [[ "$new_port" =~ ^[0-9]+$ ]] && yaml_set_section "faketcp" "listen" "\":${new_port}\""
                apply_config
                ;;
            6)
                read -rp "WS 端口: " new_port
                [[ "$new_port" =~ ^[0-9]+$ ]] && yaml_set_section "websocket" "listen" "\":${new_port}\""
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 17] 网卡与 eBPF
# ───────────────────────────────────────────────────────────────────────────────
manage_network() {
    while true; do
        clear
        step "网卡与 eBPF 管理"
        
        local ebpf_iface faketcp_iface tc_enabled
        ebpf_iface=$(yaml_get "ebpf" "interface" 2>/dev/null || echo "eth0")
        faketcp_iface=$(yaml_get "faketcp" "interface" 2>/dev/null || echo "eth0")
        tc_enabled=$(yaml_get "ebpf" "enable_tc" 2>/dev/null || echo "true")
        
        echo -e "eBPF 网卡: ${CYAN}${ebpf_iface}${NC} | FakeTCP 网卡: ${CYAN}${faketcp_iface}${NC}"
        echo -e "TC 加速: ${CYAN}${tc_enabled}${NC}"
        echo ""
        echo "可用网卡:"
        ip -o link show 2>/dev/null | awk -F': ' '{print "  " $2}' | grep -v "lo" || echo "  (检测失败)"
        echo ""
        echo "─────────────────────────────────────"
        echo "1. 自动检测并绑定网卡"
        echo "2. 手动指定网卡"
        echo "3. 更新 eBPF 字节码"
        echo "4. 切换 TC 加速"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-4]: " net_opt

        case $net_opt in
            1)
                local new_iface
                new_iface=$(get_iface)
                yaml_set_section "ebpf" "interface" "\"${new_iface}\""
                yaml_set_section "faketcp" "interface" "\"${new_iface}\""
                info "已绑定: ${new_iface}"
                apply_config
                ;;
            2)
                read -rp "网卡名: " manual_iface
                if ip link show "$manual_iface" &>/dev/null; then
                    yaml_set_section "ebpf" "interface" "\"${manual_iface}\""
                    yaml_set_section "faketcp" "interface" "\"${manual_iface}\""
                    apply_config
                else
                    error "网卡不存在"
                fi
                ;;
            3)
                if [[ -d "./ebpf" ]]; then
                    cp ./ebpf/*.o "$EBPF_DIR/" 2>/dev/null && info "已更新" && apply_config
                else
                    error "未找到 ./ebpf"
                fi
                ;;
            4)
                [[ "$tc_enabled" == "true" ]] && yaml_set_section "ebpf" "enable_tc" "false" || yaml_set_section "ebpf" "enable_tc" "true"
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 18] Metrics
# ───────────────────────────────────────────────────────────────────────────────
manage_metrics() {
    while true; do
        clear
        step "Metrics 配置"
        
        local metrics_st metrics_listen
        metrics_st=$(yaml_get "metrics" "enabled" 2>/dev/null || echo "true")
        metrics_listen=$(yaml_get "metrics" "listen" 2>/dev/null || echo ":9100")
        
        echo -e "状态: ${CYAN}${metrics_st}${NC} | 监听: ${CYAN}${metrics_listen}${NC}"
        echo ""
        echo "─────────────────────────────────────"
        echo "1. 切换 Metrics"
        echo "2. 修改监听地址"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-2]: " metrics_opt

        case $metrics_opt in
            1)
                [[ "$metrics_st" == "true" ]] && yaml_set_section "metrics" "enabled" "false" || yaml_set_section "metrics" "enabled" "true"
                apply_config
                ;;
            2)
                read -rp "监听地址 (如 :9100): " new_listen
                yaml_set_section "metrics" "listen" "\"${new_listen}\""
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 6] 隧道
# ───────────────────────────────────────────────────────────────────────────────
manage_tunnel() {
    while true; do
        clear
        step "Cloudflare 隧道"
        
        local tunnel_st tunnel_mode
        tunnel_st=$(yaml_get "tunnel" "enabled" 2>/dev/null || echo "false")
        tunnel_mode=$(yaml_get "tunnel" "mode" 2>/dev/null || echo "temp")
        
        echo -e "状态: ${CYAN}${tunnel_st}${NC} | 模式: ${CYAN}${tunnel_mode}${NC}"
        echo ""
        echo "─────────────────────────────────────"
        echo "1. 启用临时隧道"
        echo "2. 启用固定隧道"
        echo "3. 禁用隧道"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-3]: " tunnel_opt

        case $tunnel_opt in
            1)
                yaml_set_section "tunnel" "enabled" "true"
                yaml_set_section "tunnel" "mode" "\"temp\""
                info "临时隧道已启用"
                apply_config
                ;;
            2)
                read -rp "Token: " cf_token
                if [[ -n "$cf_token" ]]; then
                    yaml_set_section "tunnel" "enabled" "true"
                    yaml_set_section "tunnel" "mode" "\"fixed\""
                    yaml_set_section "tunnel" "cf_token" "\"${cf_token}\""
                    apply_config
                fi
                ;;
            3)
                yaml_set_section "tunnel" "enabled" "false"
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 7] ACME
# ───────────────────────────────────────────────────────────────────────────────
manage_acme() {
    while true; do
        clear
        step "ACME 证书"
        
        echo "─────────────────────────────────────"
        echo "1. 配置 ACME"
        echo "2. 自签名证书"
        echo "3. 自定义证书"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-3]: " acme_opt

        case $acme_opt in
            1)
                read -rp "域名: " domain
                read -rp "邮箱: " email
                if ! grep -q "^cert:" "$CONFIG_FILE" 2>/dev/null; then
                    cat >> "$CONFIG_FILE" << EOF

cert:
  mode: "acme"
  domain: "${domain}"
  email: "${email}"
EOF
                else
                    yaml_set_section "cert" "mode" "\"acme\""
                    yaml_set_section "cert" "domain" "\"${domain}\""
                    yaml_set_section "cert" "email" "\"${email}\""
                fi
                yaml_set_section "tls" "server_name" "\"${domain}\""
                apply_config
                ;;
            2)
                if grep -q "^cert:" "$CONFIG_FILE" 2>/dev/null; then
                    yaml_set_section "cert" "mode" "\"self-signed\""
                else
                    echo -e "\ncert:\n  mode: \"self-signed\"" >> "$CONFIG_FILE"
                fi
                apply_config
                ;;
            3)
                read -rp "证书路径: " cert_path
                read -rp "私钥路径: " key_path
                if grep -q "^cert:" "$CONFIG_FILE" 2>/dev/null; then
                    yaml_set_section "cert" "mode" "\"manual\""
                    yaml_set_section "cert" "cert_file" "\"${cert_path}\""
                    yaml_set_section "cert" "key_file" "\"${key_path}\""
                else
                    cat >> "$CONFIG_FILE" << EOF

cert:
  mode: "manual"
  cert_file: "${cert_path}"
  key_file: "${key_path}"
EOF
                fi
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 8] DDNS
# ───────────────────────────────────────────────────────────────────────────────
manage_ddns() {
    while true; do
        clear
        step "DDNS 动态域名"
        
        local ddns_enabled ddns_provider
        ddns_enabled=$(yaml_get "ddns" "enabled" 2>/dev/null || echo "false")
        ddns_provider=$(yaml_get "ddns" "provider" 2>/dev/null || echo "none")
        
        echo -e "状态: ${CYAN}${ddns_enabled}${NC} | 提供商: ${CYAN}${ddns_provider}${NC}"
        echo ""
        echo "─────────────────────────────────────"
        echo "1. 配置 DuckDNS"
        echo "2. 配置 FreeDNS"
        echo "3. 配置 Cloudflare"
        echo "4. 禁用 DDNS"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-4]: " ddns_opt

        case $ddns_opt in
            1)
                read -rp "DuckDNS Token: " duck_token
                read -rp "子域名: " duck_domain
                if [[ -n "$duck_token" && -n "$duck_domain" ]]; then
                    yaml_set_section "ddns" "enabled" "true"
                    yaml_set_section "ddns" "provider" "\"duckdns\""
                    yaml_set_nested "ddns" "duckdns" "token" "$duck_token"
                    yaml_set_nested "ddns" "duckdns" "domains" "$duck_domain"
                    apply_config
                fi
                ;;
            2)
                read -rp "FreeDNS Token: " free_token
                if [[ -n "$free_token" ]]; then
                    yaml_set_section "ddns" "enabled" "true"
                    yaml_set_section "ddns" "provider" "\"freedns\""
                    yaml_set_nested "ddns" "freedns" "token" "$free_token"
                    apply_config
                fi
                ;;
            3)
                read -rp "CF API Token: " cf_api
                read -rp "Zone ID: " cf_zone
                read -rp "记录名: " cf_record
                if [[ -n "$cf_api" && -n "$cf_zone" && -n "$cf_record" ]]; then
                    yaml_set_section "ddns" "enabled" "true"
                    yaml_set_section "ddns" "provider" "\"cloudflare\""
                    yaml_set_nested "ddns" "cloudflare" "api_token" "$cf_api"
                    yaml_set_nested "ddns" "cloudflare" "zone_id" "$cf_zone"
                    yaml_set_nested "ddns" "cloudflare" "record_name" "$cf_record"
                    apply_config
                fi
                ;;
            4)
                yaml_set_section "ddns" "enabled" "false"
                yaml_set_section "ddns" "provider" "\"none\""
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 19] 配置文件管理
# ───────────────────────────────────────────────────────────────────────────────
view_config() {
    while true; do
        clear
        step "配置文件管理"
        
        echo "─────────────────────────────────────"
        echo "1. 查看配置"
        echo "2. 编辑 (nano)"
        echo "3. 编辑 (vim)"
        echo "4. 备份配置"
        echo "5. 恢复备份"
        echo "6. 验证语法"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-6]: " cfg_opt

        case $cfg_opt in
            1)
                [[ -f "$CONFIG_FILE" ]] && cat "$CONFIG_FILE" || warn "配置不存在"
                pause
                ;;
            2)
                command -v nano &>/dev/null && nano "$CONFIG_FILE" && apply_config || error "nano 未安装"
                ;;
            3)
                command -v vim &>/dev/null && vim "$CONFIG_FILE" && apply_config || error "vim 未安装"
                ;;
            4)
                local backup_file="${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
                cp "$CONFIG_FILE" "$backup_file" 2>/dev/null && info "备份: ${backup_file}"
                pause
                ;;
            5)
                ls -la "${CONFIG_DIR}/"*.bak.* 2>/dev/null || echo "(无备份)"
                read -rp "备份文件路径: " restore_file
                [[ -f "$restore_file" ]] && cp "$restore_file" "$CONFIG_FILE" && apply_config || error "文件不存在"
                ;;
            6)
                validate_yaml && success "语法正确"
                pause
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 20] 诊断工具
# ───────────────────────────────────────────────────────────────────────────────
diagnostic_tools() {
    while true; do
        clear
        step "诊断工具"
        
        echo "─────────────────────────────────────"
        echo "1. eBPF 内核支持检查"
        echo "2. 端口占用检查"
        echo "3. 网卡特性检查"
        echo "4. 导出诊断报告"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-4]: " diag_opt

        case $diag_opt in
            1)
                echo ""
                echo "内核版本: $(uname -r)"
                echo -n "BPF JIT: "
                local jit
                jit=$(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null || echo "unknown")
                [[ "$jit" == "1" ]] && echo -e "${GREEN}已启用${NC}" || echo -e "${YELLOW}未启用${NC}"
                echo -n "BTF: "
                [[ -f "/sys/kernel/btf/vmlinux" ]] && echo -e "${GREEN}支持${NC}" || echo -e "${YELLOW}不支持${NC}"
                pause
                ;;
            2)
                echo ""
                local main_port ft_port ws_port
                main_port=$(grep "^listen:" "$CONFIG_FILE" 2>/dev/null | grep -oP '\d+' || echo "54321")
                ft_port=$((main_port+1))
                ws_port=$((main_port+2))
                for port in $main_port $ft_port $ws_port 9100; do
                    echo -n "端口 $port: "
                    if ss -tuln 2>/dev/null | grep -q ":${port} "; then
                        echo -e "${YELLOW}占用${NC}"
                    else
                        echo -e "${GREEN}空闲${NC}"
                    fi
                done
                pause
                ;;
            3)
                local iface
                iface=$(yaml_get "ebpf" "interface" 2>/dev/null || echo "eth0")
                echo ""
                echo "网卡: ${iface}"
                ip -d link show "$iface" 2>/dev/null || echo "无法获取信息"
                pause
                ;;
            4)
                local report="/tmp/phantom-diag-$(date +%Y%m%d%H%M%S).txt"
                {
                    echo "=== Phantom 诊断报告 ==="
                    echo "时间: $(date)"
                    echo ""
                    echo "=== 系统信息 ==="
                    uname -a
                    echo ""
                    echo "=== 服务状态 ==="
                    systemctl status phantom --no-pager 2>&1 || echo "未安装"
                    echo ""
                    echo "=== 最近日志 ==="
                    journalctl -u phantom -n 30 --no-pager 2>&1 || echo "无日志"
                    echo ""
                    echo "=== 配置文件 ==="
                    cat "$CONFIG_FILE" 2>/dev/null || echo "不存在"
                } > "$report"
                info "报告: ${report}"
                pause
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# 主菜单
# ───────────────────────────────────────────────────────────────────────────────
show_status() {
    # 【修复5】完全安全的状态检测
    local status
    if ! systemctl list-unit-files phantom.service &>/dev/null; then
        status="未安装"
    else
        status=$(systemctl is-active phantom 2>/dev/null) || status="unknown"
    fi
    
    local color="$RED"
    local display="$status"
    case "$status" in
        active)   color="$GREEN"; display="● 运行中" ;;
        inactive) color="$YELLOW"; display="○ 已停止" ;;
        failed)   color="$RED"; display="✗ 失败" ;;
        *)        color="$RED"; display="✗ 未安装" ;;
    esac
    echo -e "服务状态: ${color}${BOLD}${display}${NC}"
}

show_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
  ____  _                 _                  
 |  _ \| |__   __ _ _ __ | |_ ___  _ __ ___  
 | |_) | '_ \ / _` | '_ \| __/ _ \| '_ ` _ \ 
 |  __/| | | | (_| | | | | || (_) | | | | | |
 |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|
                                        v4.2.1
EOF
    echo -e "${NC}"
}

main_menu() {
    while true; do
        clear
        show_banner
        show_status
        echo ""
        echo -e "${BOLD}═══════════════ 安装管理 ═══════════════${NC}"
        echo "  1. 安装/更新    2. 卸载"
        echo ""
        echo -e "${BOLD}═══════════════ 服务控制 ═══════════════${NC}"
        echo "  3. 启动    4. 停止    5. 重启"
        echo ""
        echo -e "${BOLD}═══════════════ 扩展模块 ═══════════════${NC}"
        echo "  6. 隧道    7. ACME    8. DDNS    9. 基础配置"
        echo ""
        echo -e "${BOLD}═══════════════ ${YELLOW}核心调优${NC}${BOLD} ═══════════════${NC}"
        echo "  13. Switcher    14. TLS/DPI    15. Hysteria2/ARQ"
        echo "  16. 协议开关    17. 网卡/eBPF   18. Metrics"
        echo ""
        echo -e "${BOLD}═══════════════ 运维工具 ═══════════════${NC}"
        echo "  10. 实时日志    11. 服务详情    12. 更新eBPF"
        echo "  19. 配置管理    20. 诊断工具"
        echo ""
        echo "  0. 退出"
        echo ""
        read -rp "请选择 [0-20]: " opt

        case $opt in
            1)  install_phantom; pause ;;
            2)  uninstall_phantom; pause ;;
            3)  systemctl start phantom 2>/dev/null && success "已启动" || error "启动失败"; pause ;;
            4)  systemctl stop phantom 2>/dev/null && success "已停止" || error "停止失败"; pause ;;
            5)  systemctl restart phantom 2>/dev/null && success "已重启" || error "重启失败"; pause ;;
            6)  manage_tunnel ;;
            7)  manage_acme ;;
            8)  manage_ddns ;;
            9)  manage_basic ;;
            10) echo -e "${CYAN}Ctrl+C 退出${NC}"; sleep 1; journalctl -u phantom -f -n 100 2>/dev/null || error "无日志" ;;
            11) systemctl status phantom --no-pager 2>/dev/null || error "服务未安装"; pause ;;
            12) [[ -d "./ebpf" ]] && cp ./ebpf/*.o "$EBPF_DIR/" 2>/dev/null && info "已更新" && apply_config || error "未找到./ebpf"; pause ;;
            13) manage_switcher ;;
            14) manage_tls ;;
            15) manage_perf ;;
            16) manage_protocols ;;
            17) manage_network ;;
            18) manage_metrics ;;
            19) view_config ;;
            20) diagnostic_tools ;;
            0)  echo -e "\n${GREEN}再见！${NC}\n"; exit 0 ;;
            *)  error "无效选项"; sleep 1 ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# 入口
# ───────────────────────────────────────────────────────────────────────────────
check_root
main_menu
