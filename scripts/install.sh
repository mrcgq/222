

#!/usr/bin/env bash
# =============================================================================
# 文件: scripts/install.sh
# 版本: v4.2.0-EXPERT-FINAL
# 描述: Phantom Server v4.2 专家级管理面板 - 完美适配 1-96 模块所有逻辑
# 修复: 作用域化YAML注入 / 动态数组处理 / 完整参数覆盖
# =============================================================================

set -e

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
    [[ $EUID -ne 0 ]] && { error "错误: 必须使用 root 权限运行 (sudo)"; exit 1; }
}

get_iface() {
    local iface=$(ip route | grep default | awk '{print $5}' | head -1)
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
    
    if grep -q "^${key}:" "$file"; then
        sed -i "s|^${key}:.*|${key}: ${value}|" "$file"
    else
        echo "${key}: ${value}" >> "$file"
    fi
}

# 一级嵌套字段修改（如 hysteria2.enabled）
# 用法: yaml_set_section "hysteria2" "enabled" "true"
yaml_set_section() {
    local section="$1"
    local key="$2"
    local value="$3"
    local file="${4:-$CONFIG_FILE}"
    
    # 使用 awk 精准定位 section 内的 key，只修改该 section 内的第一个匹配
    awk -v sec="$section" -v k="$key" -v v="$value" '
    BEGIN { in_section=0; found=0 }
    {
        # 检测进入目标 section
        if ($0 ~ "^"sec":") {
            in_section=1
            print
            next
        }
        # 检测离开 section（遇到新的顶级 key）
        if (in_section && /^[a-zA-Z_]+:/ && $0 !~ "^"sec":") {
            in_section=0
        }
        # 在 section 内查找并替换 key
        if (in_section && !found && $0 ~ "^[[:space:]]+"k":") {
            sub(/:[[:space:]]*.*/, ": "v)
            found=1
        }
        print
    }
    ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

# 二级嵌套字段修改（如 tunnel.duckdns.token）
# 用法: yaml_set_nested "tunnel" "duckdns" "token" "my-token"
yaml_set_nested() {
    local section="$1"
    local subsection="$2"
    local key="$3"
    local value="$4"
    local file="${5:-$CONFIG_FILE}"
    
    awk -v sec="$section" -v subsec="$subsection" -v k="$key" -v v="$value" '
    BEGIN { in_section=0; in_subsection=0; found=0 }
    {
        # 进入主 section
        if ($0 ~ "^"sec":") {
            in_section=1
            print
            next
        }
        # 离开主 section
        if (in_section && /^[a-zA-Z_]+:/ && $0 !~ "^"sec":") {
            in_section=0
            in_subsection=0
        }
        # 进入 subsection
        if (in_section && $0 ~ "^[[:space:]]+"subsec":") {
            in_subsection=1
            print
            next
        }
        # 离开 subsection（遇到同级别的其他 key）
        if (in_subsection && /^[[:space:]][[:space:]][a-zA-Z_]+:/ && $0 !~ "^[[:space:]]+"subsec":") {
            # 检查缩进级别
            match($0, /^[[:space:]]+/)
            indent = RLENGTH
            if (indent <= 2) {
                in_subsection=0
            }
        }
        # 在 subsection 内查找并替换 key
        if (in_subsection && !found && $0 ~ "^[[:space:]]+"k":") {
            sub(/:[[:space:]]*.*/, ": \""v"\"")
            found=1
        }
        print
    }
    ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

# 动态替换 YAML 数组（如 priority, sni_list）
# 用法: yaml_set_array "switcher" "priority" "ebpf,faketcp,udp"
yaml_set_array() {
    local section="$1"
    local key="$2"
    local values="$3"  # 逗号分隔
    local file="${4:-$CONFIG_FILE}"
    
    # 创建临时文件
    local tmpfile=$(mktemp)
    
    # 使用 awk 删除旧数组并插入新数组
    awk -v sec="$section" -v k="$key" -v vals="$values" '
    BEGIN {
        in_section=0
        in_array=0
        split(vals, arr, ",")
    }
    {
        # 进入目标 section
        if ($0 ~ "^"sec":") {
            in_section=1
            print
            next
        }
        # 离开 section
        if (in_section && /^[a-zA-Z_]+:/ && $0 !~ "^"sec":") {
            in_section=0
        }
        # 检测数组开始
        if (in_section && $0 ~ "^[[:space:]]+"k":") {
            in_array=1
            print
            # 打印新数组
            for (i in arr) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", arr[i])
                print "    - \""arr[i]"\""
            }
            next
        }
        # 跳过旧数组元素
        if (in_array && /^[[:space:]]+-/) {
            next
        }
        # 数组结束
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
    
    # 尝试使用 Python 验证
    if command -v python3 &>/dev/null; then
        if python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>/dev/null; then
            return 0
        else
            error "YAML 语法错误！"
            python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>&1 | head -5
            return 1
        fi
    fi
    
    # 备用：基础语法检查
    if grep -qP '^\t' "$file"; then
        error "YAML 中不允许使用 Tab 缩进"
        return 1
    fi
    
    return 0
}

apply_config() {
    step "正在验证并部署配置..."
    
    # 配置文件语法检查
    if ! validate_yaml; then
        error "配置验证失败，操作已中止"
        read -rp "是否查看配置文件？[y/N]: " view
        [[ "$view" == "y" ]] && cat -A "$CONFIG_FILE" | head -50
        return 1
    fi
    
    systemctl daemon-reload
    systemctl restart phantom
    sleep 2
    
    if systemctl is-active --quiet phantom; then
        success "服务状态: 运行中 (Active)"
        
        # 模块 92: 临时隧道 URL 抓取
        local tunnel_enabled=$(yaml_get "tunnel" "enabled")
        local tunnel_mode=$(yaml_get "tunnel" "mode")
        
        if [[ "$tunnel_enabled" == "true" && "$tunnel_mode" == "temp" ]]; then
            warn "正在检索临时隧道 URL..."
            sleep 3
            local url=$(journalctl -u phantom -n 50 --no-pager 2>/dev/null | \
                        grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
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

    local iface=$(get_iface)
    info "网络适配: 自动绑定网卡 ${CYAN}${iface}${NC}"

    read -rp "主监听端口 [54321]: " PORT
    PORT=${PORT:-54321}
    read -rp "认证密钥 PSK (留空随机生成): " PSK
    [[ -z "$PSK" ]] && PSK=$(openssl rand -base64 24)

    # 构造完美适配 1-96 模块所有参数的配置文件
    cat > "$CONFIG_FILE" << EOF
# ═══════════════════════════════════════════════════════════════════════════════
# Phantom Server v4.2 配置文件
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# ═══════════════════════════════════════════════════════════════════════════════

# 基础配置
listen: ":${PORT}"
psk: "${PSK}"
time_window: 30
log_level: "info"
mode: "auto"

# ───────────────────────────────────────────────────────────────────────────────
# 模块 17: Hysteria2 暴力拥塞控制
# ───────────────────────────────────────────────────────────────────────────────
hysteria2:
  enabled: true
  up_mbps: 100
  down_mbps: 100
  loss_threshold: 0.1
  disable_mtu_discovery: false

# ───────────────────────────────────────────────────────────────────────────────
# 模块 40: ARQ 增强层 (抗丢包)
# ───────────────────────────────────────────────────────────────────────────────
arq:
  enabled: true
  window_size: 256
  max_retries: 10
  rto_min_ms: 100
  rto_max_ms: 3000
  ack_delay_ms: 20

# ───────────────────────────────────────────────────────────────────────────────
# 模块 33-39: Switcher 智能寻路决策
# ───────────────────────────────────────────────────────────────────────────────
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

# ───────────────────────────────────────────────────────────────────────────────
# 模块 92/93: Cloudflare 隧道系统
# ───────────────────────────────────────────────────────────────────────────────
tunnel:
  enabled: false
  mode: "temp"
  cf_token: ""
  local_port: ${PORT}
  acme_use_tunnel: true

# ───────────────────────────────────────────────────────────────────────────────
# 模块 94: DDNS 动态域名
# ───────────────────────────────────────────────────────────────────────────────
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

# ───────────────────────────────────────────────────────────────────────────────
# 模块 95/96: TLS 深度伪装 & 嗅探回落
# ───────────────────────────────────────────────────────────────────────────────
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

# ───────────────────────────────────────────────────────────────────────────────
# 模块 56: FakeTCP 协议栈硬模拟
# ───────────────────────────────────────────────────────────────────────────────
faketcp:
  enabled: true
  listen: ":$((PORT+1))"
  interface: "${iface}"
  use_ebpf: true
  mtu: 1400

# ───────────────────────────────────────────────────────────────────────────────
# 模块 70: WebSocket 传输
# ───────────────────────────────────────────────────────────────────────────────
websocket:
  enabled: true
  listen: ":$((PORT+2))"
  path: "/ws"
  host: ""
  tls: false
  compression: false

# ───────────────────────────────────────────────────────────────────────────────
# 模块 49/52: eBPF & TC 内核加速
# ───────────────────────────────────────────────────────────────────────────────
ebpf:
  enabled: true
  interface: "${iface}"
  xdp_mode: "generic"
  program_path: "${EBPF_DIR}"
  enable_tc: true
  tc_direction: "both"
  pin_maps: true

# ───────────────────────────────────────────────────────────────────────────────
# 模块 30: 可观测性监测
# ───────────────────────────────────────────────────────────────────────────────
metrics:
  enabled: true
  listen: ":9100"
  path: "/metrics"
  health_path: "/health"
  pprof_enabled: false
EOF

    # 安装二进制
    if [[ -f "./phantom-server" ]]; then
        cp "./phantom-server" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
        info "二进制文件已部署"
    else
        warn "未找到 phantom-server 二进制文件，请稍后手动部署"
    fi
    
    # 安装 eBPF 字节码
    if [[ -d "./ebpf" ]]; then
        cp ./ebpf/*.o "$EBPF_DIR/" 2>/dev/null && info "eBPF 字节码已部署" || true
    fi

    # 模块 77: Systemd 权限精调（完整权限矩阵）
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

# 资源限制
LimitNOFILE=1048576
LimitNPROC=65535
LimitMEMLOCK=infinity
LimitCORE=infinity

# 完整权限矩阵 (适配 Module 49/52/56/77)
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_BPF CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_RESOURCE CAP_SYS_PTRACE CAP_IPC_LOCK CAP_PERFMON

# 安全设置
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false

# 日志
StandardOutput=journal
StandardError=journal
SyslogIdentifier=phantom

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
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
    systemctl daemon-reload
    
    success "Phantom Server 已完全卸载"
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 9] 基础配置修改
# ───────────────────────────────────────────────────────────────────────────────
manage_basic() {
    while true; do
        clear
        step "基础配置管理"
        
        # 显示当前配置
        local port=$(grep "^listen:" "$CONFIG_FILE" | sed 's/.*:\([0-9]*\)".*/\1/')
        local log_level=$(grep "^log_level:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
        local mode=$(grep "^mode:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
        
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
                    # 自动更新相关端口
                    yaml_set_section "faketcp" "listen" "\":$((port+1))\""
                    yaml_set_section "websocket" "listen" "\":$((port+2))\""
                    apply_config
                else
                    error "无效端口号"
                fi
                ;;
            2)
                read -rp "新 PSK (留空随机生成): " psk
                [[ -z "$psk" ]] && psk=$(openssl rand -base64 24)
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
# [选项 13] Switcher 智能寻路深度调优 (适配模块 33-39)
# ───────────────────────────────────────────────────────────────────────────────
manage_switcher() {
    while true; do
        clear
        step "Switcher 智能链路控制台"
        
        # 实时状态显示
        if systemctl is-active --quiet phantom; then
            local health=$(curl -s --connect-timeout 2 http://127.0.0.1:9100/health 2>/dev/null || echo "")
            if [[ -n "$health" && "$health" != "fail" ]]; then
                echo -e "${CYAN}┌─────────────────── 实时链路状态 ───────────────────┐${NC}"
                local mode=$(echo "$health" | grep -oP '"mode":\s*"\K[^"]+' | head -1)
                local rtt=$(echo "$health" | grep -oP '"rtt_ms":\s*\K[0-9.]+' | head -1)
                local loss=$(echo "$health" | grep -oP '"loss":\s*\K[0-9.]+' | head -1)
                echo -e "  │ 工作模式: ${GREEN}${mode:-探测中}${NC}"
                echo -e "  │ 延迟(RTT): ${GREEN}${rtt:-0} ms${NC}"
                echo -e "  │ 丢包率: ${GREEN}${loss:-0}%${NC}"
                echo -e "${CYAN}└────────────────────────────────────────────────────┘${NC}"
            fi
        fi
        
        # 当前配置
        local interval=$(yaml_get "switcher" "check_interval_ms")
        local rtt_th=$(yaml_get "switcher" "rtt_threshold_ms")
        local loss_th=$(yaml_get "switcher" "loss_threshold")
        
        echo ""
        echo -e "检测间隔: ${CYAN}${interval:-1000}ms${NC} | RTT阈值: ${CYAN}${rtt_th:-300}ms${NC} | 丢包阈值: ${CYAN}${loss_th:-0.3}${NC}"
        echo ""
        echo "─────────────────────────────────────"
        echo "1. 修改寻路优先级 (Priority)"
        echo "2. 修改检测频率 (Interval)"
        echo "3. 修改 RTT 阈值 (触发切换的延迟上限)"
        echo "4. 修改丢包阈值 (触发切换的丢包率上限)"
        echo "5. 修改抖动阈值 (Jitter)"
        echo "6. 切换 eBPF 运行模式 (Generic/Native/Offload)"
        echo "7. 锁定单一传输模式"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-7]: " sw_opt

        case $sw_opt in
            1)
                echo ""
                echo "当前支持的传输方式:"
                echo "  ebpf     - eBPF 内核加速 (最快)"
                echo "  faketcp  - FakeTCP 模拟 (穿透性强)"
                echo "  udp      - 原生 UDP"
                echo "  tcp      - 原生 TCP"
                echo "  websocket - WebSocket (CDN 友好)"
                echo ""
                read -rp "输入优先级顺序 (逗号分隔，如 ebpf,faketcp,udp): " priority_str
                
                if [[ -n "$priority_str" ]]; then
                    yaml_set_array "switcher" "priority" "$priority_str"
                    apply_config
                fi
                ;;
            2)
                read -rp "检测间隔(ms) [当前${interval:-1000}]: " new_interval
                if [[ "$new_interval" =~ ^[0-9]+$ ]]; then
                    yaml_set_section "switcher" "check_interval_ms" "$new_interval"
                    apply_config
                else
                    error "请输入有效数字"
                fi
                ;;
            3)
                read -rp "RTT 阈值(ms) [当前${rtt_th:-300}]: " new_rtt
                if [[ "$new_rtt" =~ ^[0-9]+$ ]]; then
                    yaml_set_section "switcher" "rtt_threshold_ms" "$new_rtt"
                    apply_config
                else
                    error "请输入有效数字"
                fi
                ;;
            4)
                echo "丢包阈值: 0.0 (0%) - 1.0 (100%)"
                read -rp "丢包阈值 [当前${loss_th:-0.3}]: " new_loss
                if [[ "$new_loss" =~ ^[0-9]*\.?[0-9]+$ ]]; then
                    yaml_set_section "switcher" "loss_threshold" "$new_loss"
                    apply_config
                else
                    error "请输入有效数字"
                fi
                ;;
            5)
                local jitter=$(yaml_get "switcher" "jitter_threshold_ms")
                read -rp "抖动阈值(ms) [当前${jitter:-100}]: " new_jitter
                if [[ "$new_jitter" =~ ^[0-9]+$ ]]; then
                    yaml_set_section "switcher" "jitter_threshold_ms" "$new_jitter"
                    apply_config
                fi
                ;;
            6)
                echo ""
                echo "XDP 模式说明:"
                echo "  1. generic  - 通用模式，所有网卡兼容"
                echo "  2. native   - 驱动级，性能极高 (需网卡支持)"
                echo "  3. offload  - 硬件卸载，最高性能 (需智能网卡)"
                read -rp "选择 [1-3]: " xdp_choice
                case $xdp_choice in
                    1) mode="generic" ;;
                    2) mode="native" ;;
                    3) mode="offload" ;;
                    *) error "无效选择"; continue ;;
                esac
                yaml_set_section "ebpf" "xdp_mode" "\"${mode}\""
                apply_config
                ;;
            7)
                echo "可选模式: auto / ebpf / faketcp / udp / tcp / websocket"
                read -rp "锁定为: " lock_mode
                yaml_set_top "mode" "\"${lock_mode}\""
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 14] TLS & DPI 对抗精调 (适配模块 95-96)
# ───────────────────────────────────────────────────────────────────────────────
manage_tls() {
    while true; do
        clear
        step "TLS 深度伪装与 DPI 逃逸设置"
        
        # 当前状态
        local tls_enabled=$(yaml_get "tls" "enabled")
        local sni=$(yaml_get "tls" "server_name")
        local fp=$(yaml_get "tls" "fingerprint")
        local random_sni=$(yaml_get "tls" "random_sni")
        
        echo -e "TLS 状态: ${CYAN}${tls_enabled}${NC} | SNI: ${CYAN}${sni}${NC}"
        echo -e "指纹: ${CYAN}${fp}${NC} | 随机SNI: ${CYAN}${random_sni}${NC}"
        echo ""
        echo "─────────────────────────────────────"
        echo "1. 启用/禁用 TLS 伪装"
        echo "2. 修改 uTLS 指纹"
        echo "3. 修改 SNI (伪装域名)"
        echo "4. 修改分片参数 (绕过 DPI 检测)"
        echo "5. 随机 SNI 设置"
        echo "6. 编辑 SNI 候选列表"
        echo "7. ECH 加密设置"
        echo "8. 探测回落配置"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-8]: " t_opt

        case $t_opt in
            1)
                if [[ "$tls_enabled" == "true" ]]; then
                    yaml_set_section "tls" "enabled" "false"
                    info "TLS 伪装已禁用"
                else
                    yaml_set_section "tls" "enabled" "true"
                    info "TLS 伪装已启用"
                fi
                apply_config
                ;;
            2)
                echo ""
                echo "可用指纹:"
                echo "  1. chrome      5. ios"
                echo "  2. firefox     6. android"
                echo "  3. safari      7. random"
                echo "  4. edge        8. 360browser"
                read -rp "选择指纹 [1-8]: " f_idx
                case $f_idx in
                    1) fp="chrome" ;;
                    2) fp="firefox" ;;
                    3) fp="safari" ;;
                    4) fp="edge" ;;
                    5) fp="ios" ;;
                    6) fp="android" ;;
                    7) fp="random" ;;
                    8) fp="360browser" ;;
                    *) error "无效选择"; continue ;;
                esac
                yaml_set_section "tls" "fingerprint" "\"${fp}\""
                apply_config
                ;;
            3)
                read -rp "伪装域名 SNI (如 www.microsoft.com): " new_sni
                [[ -n "$new_sni" ]] && yaml_set_section "tls" "server_name" "\"${new_sni}\""
                apply_config
                ;;
            4)
                echo ""
                echo "分片可有效对抗 SNI 嗅探型 DPI"
                local frag_enabled=$(yaml_get "tls" "fragment.enabled" 2>/dev/null || echo "true")
                echo -e "当前状态: ${CYAN}${frag_enabled}${NC}"
                echo ""
                echo "1. 启用/禁用分片"
                echo "2. 修改分片大小"
                echo "3. 修改分片间隔"
                echo "4. 修改分片策略"
                read -rp "选择: " frag_opt
                
                case $frag_opt in
                    1)
                        if [[ "$frag_enabled" == "true" ]]; then
                            sed -i '/fragment:/,/fallback:/ s/enabled: .*/enabled: false/' "$CONFIG_FILE"
                            info "分片已禁用"
                        else
                            sed -i '/fragment:/,/fallback:/ s/enabled: .*/enabled: true/' "$CONFIG_FILE"
                            info "分片已启用"
                        fi
                        ;;
                    2)
                        read -rp "分片大小 (推荐 20-50) [当前40]: " fs
                        [[ "$fs" =~ ^[0-9]+$ ]] && sed -i '/fragment:/,/fallback:/ s/size: .*/size: '"$fs"'/' "$CONFIG_FILE"
                        ;;
                    3)
                        read -rp "分片间隔 ms (推荐 5-20) [当前10]: " sl
                        [[ "$sl" =~ ^[0-9]+$ ]] && sed -i '/fragment:/,/fallback:/ s/sleep_ms: .*/sleep_ms: '"$sl"'/' "$CONFIG_FILE"
                        ;;
                    4)
                        echo "策略: random (随机) / sequential (顺序) / reverse (逆序)"
                        read -rp "选择: " strategy
                        sed -i '/fragment:/,/fallback:/ s/strategy: .*/strategy: "'"$strategy"'"/' "$CONFIG_FILE"
                        ;;
                esac
                apply_config
                ;;
            5)
                echo ""
                echo "随机 SNI: 每次连接使用不同的域名，增强匿名性"
                read -rp "启用随机 SNI? [y/N]: " rsni
                if [[ "$rsni" == "y" || "$rsni" == "Y" ]]; then
                    yaml_set_section "tls" "random_sni" "true"
                    warn "请确保已配置 SNI 候选列表（选项 6）"
                else
                    yaml_set_section "tls" "random_sni" "false"
                fi
                apply_config
                ;;
            6)
                echo ""
                echo "编辑 SNI 候选列表 (随机 SNI 将从此列表中选取)"
                echo "当前列表:"
                grep -A10 "sni_list:" "$CONFIG_FILE" | grep "^\s*-" | sed 's/.*- "/  /' | sed 's/"$//'
                echo ""
                read -rp "输入新列表 (逗号分隔): " sni_list
                
                if [[ -n "$sni_list" ]]; then
                    yaml_set_array "tls" "sni_list" "$sni_list"
                    info "SNI 列表已更新"
                    apply_config
                fi
                ;;
            7)
                echo ""
                echo "ECH (Encrypted Client Hello): 加密整个 SNI 字段"
                read -rp "启用 ECH? [y/N]: " ech
                if [[ "$ech" == "y" || "$ech" == "Y" ]]; then
                    yaml_set_section "tls" "enable_ech" "true"
                    read -rp "ECH 配置 (Base64，留空自动获取): " ech_config
                    [[ -n "$ech_config" ]] && yaml_set_section "tls" "ech_config" "\"${ech_config}\""
                else
                    yaml_set_section "tls" "enable_ech" "false"
                fi
                apply_config
                ;;
            8)
                echo ""
                echo "探测回落: 非法嗅探连接将被转发到伪装站点"
                local fb_enabled=$(grep -A2 "fallback:" "$CONFIG_FILE" | grep "enabled:" | awk '{print $2}')
                local fb_addr=$(grep -A3 "fallback:" "$CONFIG_FILE" | grep "addr:" | awk '{print $2}' | tr -d '"')
                
                echo -e "当前状态: ${CYAN}${fb_enabled}${NC} | 回落地址: ${CYAN}${fb_addr}${NC}"
                echo ""
                echo "1. 启用/禁用回落"
                echo "2. 修改回落地址"
                echo "3. 修改回落超时"
                read -rp "选择: " fb_opt
                
                case $fb_opt in
                    1)
                        if [[ "$fb_enabled" == "true" ]]; then
                            sed -i '/fallback:/,/^[a-z]/ s/enabled: .*/enabled: false/' "$CONFIG_FILE"
                            info "回落已禁用"
                        else
                            sed -i '/fallback:/,/^[a-z]/ s/enabled: .*/enabled: true/' "$CONFIG_FILE"
                            info "回落已启用"
                        fi
                        ;;
                    2)
                        read -rp "回落地址 (如 127.0.0.1:80): " new_fb
                        sed -i '/fallback:/,/^[a-z]/ s|addr: .*|addr: "'"$new_fb"'"|' "$CONFIG_FILE"
                        ;;
                    3)
                        read -rp "超时(ms) [当前5000]: " fb_timeout
                        [[ "$fb_timeout" =~ ^[0-9]+$ ]] && \
                            sed -i '/fallback:/,/^[a-z]/ s/timeout_ms: .*/timeout_ms: '"$fb_timeout"'/' "$CONFIG_FILE"
                        ;;
                esac
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 15] Hysteria2 & ARQ 暴力精调 (适配模块 17, 40)
# ───────────────────────────────────────────────────────────────────────────────
manage_perf() {
    while true; do
        clear
        step "传输性能精调 (Hysteria2 & ARQ)"
        
        # 当前配置
        local h2_enabled=$(yaml_get "hysteria2" "enabled")
        local up=$(yaml_get "hysteria2" "up_mbps")
        local down=$(yaml_get "hysteria2" "down_mbps")
        local arq_enabled=$(yaml_get "arq" "enabled")
        local ws=$(yaml_get "arq" "window_size")
        local rto_min=$(yaml_get "arq" "rto_min_ms")
        local rto_max=$(yaml_get "arq" "rto_max_ms")
        
        echo -e "${CYAN}═══════════════ Hysteria2 状态 ═══════════════${NC}"
        echo -e "状态: ${h2_enabled} | 上行: ${up}Mbps | 下行: ${down}Mbps"
        echo ""
        echo -e "${CYAN}═══════════════ ARQ 状态 ═══════════════${NC}"
        echo -e "状态: ${arq_enabled} | 窗口: ${ws} | RTO: ${rto_min}-${rto_max}ms"
        echo ""
        echo "─────────────────────────────────────"
        echo "         Hysteria2 拥塞控制"
        echo "─────────────────────────────────────"
        echo "1. 启用/禁用 Hysteria2"
        echo "2. 修改带宽限制 (上行/下行)"
        echo "3. 修改丢包触发阈值"
        echo ""
        echo "─────────────────────────────────────"
        echo "           ARQ 重传机制"
        echo "─────────────────────────────────────"
        echo "4. 启用/禁用 ARQ"
        echo "5. 修改滑动窗口大小"
        echo "6. 修改最大重传次数"
        echo "7. 修改 RTO 超时范围 (最小/最大)"
        echo "8. 修改 ACK 延迟"
        echo ""
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-8]: " perf_opt

        case $perf_opt in
            1)
                if [[ "$h2_enabled" == "true" ]]; then
                    yaml_set_section "hysteria2" "enabled" "false"
                    info "Hysteria2 已禁用"
                else
                    yaml_set_section "hysteria2" "enabled" "true"
                    info "Hysteria2 已启用"
                fi
                apply_config
                ;;
            2)
                read -rp "带宽上行 Mbps [当前${up}]: " new_up
                read -rp "带宽下行 Mbps [当前${down}]: " new_down
                [[ "$new_up" =~ ^[0-9]+$ ]] && yaml_set_section "hysteria2" "up_mbps" "$new_up"
                [[ "$new_down" =~ ^[0-9]+$ ]] && yaml_set_section "hysteria2" "down_mbps" "$new_down"
                apply_config
                ;;
            3)
                local h2_loss=$(yaml_get "hysteria2" "loss_threshold")
                read -rp "丢包触发阈值 (0.0-1.0) [当前${h2_loss}]: " new_loss
                [[ "$new_loss" =~ ^[0-9]*\.?[0-9]+$ ]] && yaml_set_section "hysteria2" "loss_threshold" "$new_loss"
                apply_config
                ;;
            4)
                if [[ "$arq_enabled" == "true" ]]; then
                    yaml_set_section "arq" "enabled" "false"
                    info "ARQ 已禁用"
                else
                    yaml_set_section "arq" "enabled" "true"
                    info "ARQ 已启用"
                fi
                apply_config
                ;;
            5)
                read -rp "滑动窗口大小 [当前${ws}]: " new_ws
                [[ "$new_ws" =~ ^[0-9]+$ ]] && yaml_set_section "arq" "window_size" "$new_ws"
                apply_config
                ;;
            6)
                local mr=$(yaml_get "arq" "max_retries")
                read -rp "最大重传次数 [当前${mr}]: " new_mr
                [[ "$new_mr" =~ ^[0-9]+$ ]] && yaml_set_section "arq" "max_retries" "$new_mr"
                apply_config
                ;;
            7)
                echo ""
                echo "RTO (Retransmission Timeout) 控制重传等待时间"
                echo "  - 低延迟网络: 建议 50-100 / 1000-2000"
                echo "  - 高延迟网络: 建议 200-500 / 5000-10000"
                echo ""
                read -rp "RTO 最小值 ms [当前${rto_min}]: " new_rto_min
                read -rp "RTO 最大值 ms [当前${rto_max}]: " new_rto_max
                
                # 参数校验: rto_max >= rto_min
                if [[ "$new_rto_min" =~ ^[0-9]+$ && "$new_rto_max" =~ ^[0-9]+$ ]]; then
                    if [ "$new_rto_max" -lt "$new_rto_min" ]; then
                        error "RTO 最大值必须 >= 最小值"
                        pause
                        continue
                    fi
                    yaml_set_section "arq" "rto_min_ms" "$new_rto_min"
                    yaml_set_section "arq" "rto_max_ms" "$new_rto_max"
                    apply_config
                else
                    error "请输入有效数字"
                fi
                ;;
            8)
                local ack_delay=$(yaml_get "arq" "ack_delay_ms")
                read -rp "ACK 延迟 ms [当前${ack_delay}]: " new_ack
                [[ "$new_ack" =~ ^[0-9]+$ ]] && yaml_set_section "arq" "ack_delay_ms" "$new_ack"
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 16] 协议模块独立开关
# ───────────────────────────────────────────────────────────────────────────────
manage_protocols() {
    while true; do
        clear
        step "协议模块开关管理"
        
        # 读取当前状态
        local faketcp_st=$(yaml_get "faketcp" "enabled")
        local ws_st=$(yaml_get "websocket" "enabled")
        local ebpf_st=$(yaml_get "ebpf" "enabled")
        
        echo "─────────────────────────────────────"
        echo "当前协议状态:"
        echo -e "  FakeTCP:   ${CYAN}${faketcp_st}${NC}"
        echo -e "  WebSocket: ${CYAN}${ws_st}${NC}"
        echo -e "  eBPF:      ${CYAN}${ebpf_st}${NC}"
        echo "─────────────────────────────────────"
        echo "1. 切换 FakeTCP 开关"
        echo "2. 切换 WebSocket 开关"
        echo "3. 切换 eBPF 开关"
        echo "4. 修改 WebSocket Path"
        echo "5. 修改 WebSocket Host"
        echo "6. 修改 FakeTCP 端口"
        echo "7. 修改 WebSocket 端口"
        echo "8. 修改 FakeTCP MTU"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-8]: " proto_opt

        case $proto_opt in
            1)
                if [[ "$faketcp_st" == "true" ]]; then
                    yaml_set_section "faketcp" "enabled" "false"
                    info "FakeTCP 已禁用"
                else
                    yaml_set_section "faketcp" "enabled" "true"
                    info "FakeTCP 已启用"
                fi
                apply_config
                ;;
            2)
                if [[ "$ws_st" == "true" ]]; then
                    yaml_set_section "websocket" "enabled" "false"
                    info "WebSocket 已禁用"
                else
                    yaml_set_section "websocket" "enabled" "true"
                    info "WebSocket 已启用"
                fi
                apply_config
                ;;
            3)
                if [[ "$ebpf_st" == "true" ]]; then
                    yaml_set_section "ebpf" "enabled" "false"
                    info "eBPF 已禁用"
                else
                    yaml_set_section "ebpf" "enabled" "true"
                    info "eBPF 已启用"
                fi
                apply_config
                ;;
            4)
                local ws_path=$(yaml_get "websocket" "path")
                read -rp "WebSocket Path [当前${ws_path}]: " new_path
                [[ -n "$new_path" ]] && yaml_set_section "websocket" "path" "\"${new_path}\""
                apply_config
                ;;
            5)
                local ws_host=$(yaml_get "websocket" "host")
                read -rp "WebSocket Host (用于 CDN，留空禁用) [当前${ws_host}]: " new_host
                yaml_set_section "websocket" "host" "\"${new_host}\""
                apply_config
                ;;
            6)
                local ft_port=$(yaml_get "faketcp" "listen" | grep -oP '\d+')
                read -rp "FakeTCP 端口 [当前${ft_port}]: " new_port
                [[ "$new_port" =~ ^[0-9]+$ ]] && yaml_set_section "faketcp" "listen" "\":${new_port}\""
                apply_config
                ;;
            7)
                local ws_port=$(yaml_get "websocket" "listen" | grep -oP '\d+')
                read -rp "WebSocket 端口 [当前${ws_port}]: " new_port
                [[ "$new_port" =~ ^[0-9]+$ ]] && yaml_set_section "websocket" "listen" "\":${new_port}\""
                apply_config
                ;;
            8)
                local mtu=$(yaml_get "faketcp" "mtu")
                read -rp "FakeTCP MTU [当前${mtu}]: " new_mtu
                [[ "$new_mtu" =~ ^[0-9]+$ ]] && yaml_set_section "faketcp" "mtu" "$new_mtu"
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 17] 网卡与 eBPF 管理
# ───────────────────────────────────────────────────────────────────────────────
manage_network() {
    while true; do
        clear
        step "网卡与 eBPF 管理"
        
        # 显示当前绑定
        local ebpf_iface=$(yaml_get "ebpf" "interface")
        local faketcp_iface=$(yaml_get "faketcp" "interface")
        local tc_enabled=$(yaml_get "ebpf" "enable_tc")
        local pin_maps=$(yaml_get "ebpf" "pin_maps")
        
        echo -e "eBPF 网卡:    ${CYAN}${ebpf_iface}${NC}"
        echo -e "FakeTCP 网卡: ${CYAN}${faketcp_iface}${NC}"
        echo -e "TC 加速:      ${CYAN}${tc_enabled}${NC}"
        echo -e "Map Pinning:  ${CYAN}${pin_maps}${NC}"
        echo ""
        
        # 列出可用网卡
        echo "可用网卡列表:"
        ip -o link show | awk -F': ' '{print "  " NR". " $2}' | grep -v "lo"
        echo ""
        
        echo "─────────────────────────────────────"
        echo "1. 重新扫描并绑定网卡 (自动)"
        echo "2. 手动指定网卡名"
        echo "3. 更新 eBPF 字节码文件"
        echo "4. 切换 TC 加速开关"
        echo "5. 切换 Map Pinning"
        echo "6. 修改 TC 方向 (ingress/egress/both)"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-6]: " net_opt

        case $net_opt in
            1)
                local new_iface=$(get_iface)
                info "检测到默认网卡: ${new_iface}"
                # 同时更新 eBPF 和 FakeTCP 的网卡配置
                yaml_set_section "ebpf" "interface" "\"${new_iface}\""
                yaml_set_section "faketcp" "interface" "\"${new_iface}\""
                apply_config
                ;;
            2)
                read -rp "输入网卡名 (如 eth0, ens3): " manual_iface
                if ip link show "$manual_iface" &>/dev/null; then
                    yaml_set_section "ebpf" "interface" "\"${manual_iface}\""
                    yaml_set_section "faketcp" "interface" "\"${manual_iface}\""
                    apply_config
                else
                    error "网卡 ${manual_iface} 不存在"
                fi
                ;;
            3)
                if [[ -d "./ebpf" ]]; then
                    cp ./ebpf/*.o "$EBPF_DIR/" 2>/dev/null
                    info "eBPF 字节码已更新"
                    apply_config
                else
                    error "未找到 ./ebpf 目录"
                fi
                ;;
            4)
                if [[ "$tc_enabled" == "true" ]]; then
                    yaml_set_section "ebpf" "enable_tc" "false"
                    info "TC 加速已禁用"
                else
                    yaml_set_section "ebpf" "enable_tc" "true"
                    info "TC 加速已启用"
                fi
                apply_config
                ;;
            5)
                if [[ "$pin_maps" == "true" ]]; then
                    yaml_set_section "ebpf" "pin_maps" "false"
                    info "Map Pinning 已禁用"
                else
                    yaml_set_section "ebpf" "pin_maps" "true"
                    info "Map Pinning 已启用"
                fi
                apply_config
                ;;
            6)
                echo "TC 方向:"
                echo "  ingress - 仅入站加速"
                echo "  egress  - 仅出站加速"
                echo "  both    - 双向加速 (推荐)"
                read -rp "选择: " tc_dir
                yaml_set_section "ebpf" "tc_direction" "\"${tc_dir}\""
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 18] Metrics 监控配置
# ───────────────────────────────────────────────────────────────────────────────
manage_metrics() {
    while true; do
        clear
        step "Metrics 可观测性配置"
        
        local metrics_st=$(yaml_get "metrics" "enabled")
        local metrics_listen=$(yaml_get "metrics" "listen")
        local metrics_path=$(yaml_get "metrics" "path")
        local health_path=$(yaml_get "metrics" "health_path")
        local pprof=$(yaml_get "metrics" "pprof_enabled")
        
        echo "─────────────────────────────────────"
        echo -e "状态: ${CYAN}${metrics_st}${NC}"
        echo -e "监听: ${CYAN}${metrics_listen}${NC}"
        echo -e "Metrics 路径: ${CYAN}${metrics_path}${NC}"
        echo -e "Health 路径: ${CYAN}${health_path}${NC}"
        echo -e "pprof: ${CYAN}${pprof}${NC}"
        echo "─────────────────────────────────────"
        echo "1. 启用/禁用 Metrics"
        echo "2. 修改监听地址"
        echo "3. 修改 Metrics 路径"
        echo "4. 修改 Health 路径"
        echo "5. 启用/禁用 pprof (性能分析)"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-5]: " metrics_opt

        case $metrics_opt in
            1)
                if [[ "$metrics_st" == "true" ]]; then
                    yaml_set_section "metrics" "enabled" "false"
                    info "Metrics 已禁用"
                else
                    yaml_set_section "metrics" "enabled" "true"
                    info "Metrics 已启用"
                fi
                apply_config
                ;;
            2)
                read -rp "监听地址 (如 :9100 或 127.0.0.1:9100): " new_listen
                yaml_set_section "metrics" "listen" "\"${new_listen}\""
                apply_config
                ;;
            3)
                read -rp "Metrics 路径 (如 /metrics): " m_path
                yaml_set_section "metrics" "path" "\"${m_path}\""
                apply_config
                ;;
            4)
                read -rp "Health 路径 (如 /health): " h_path
                yaml_set_section "metrics" "health_path" "\"${h_path}\""
                apply_config
                ;;
            5)
                if [[ "$pprof" == "true" ]]; then
                    yaml_set_section "metrics" "pprof_enabled" "false"
                    info "pprof 已禁用"
                else
                    yaml_set_section "metrics" "pprof_enabled" "true"
                    warn "pprof 已启用，建议仅在调试时开启"
                fi
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 6] Cloudflare 隧道管理
# ───────────────────────────────────────────────────────────────────────────────
manage_tunnel() {
    while true; do
        clear
        step "Cloudflare 隧道编排"
        
        local tunnel_st=$(yaml_get "tunnel" "enabled")
        local tunnel_mode=$(yaml_get "tunnel" "mode")
        local local_port=$(yaml_get "tunnel" "local_port")
        
        echo "─────────────────────────────────────"
        echo -e "状态: ${CYAN}${tunnel_st}${NC}"
        echo -e "模式: ${CYAN}${tunnel_mode}${NC}"
        echo -e "本地端口: ${CYAN}${local_port}${NC}"
        echo "─────────────────────────────────────"
        echo "1. 启用临时隧道 (无需配置，自动获取 URL)"
        echo "2. 启用固定隧道 (需要 Token)"
        echo "3. 禁用隧道"
        echo "4. 修改本地端口"
        echo "5. 切换 ACME 使用隧道"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-5]: " tunnel_opt

        case $tunnel_opt in
            1)
                yaml_set_section "tunnel" "enabled" "true"
                yaml_set_section "tunnel" "mode" "\"temp\""
                info "临时隧道已启用"
                warn "重启后将在日志中显示隧道 URL"
                apply_config
                ;;
            2)
                read -rp "Cloudflare Tunnel Token: " cf_token
                if [[ -n "$cf_token" ]]; then
                    yaml_set_section "tunnel" "enabled" "true"
                    yaml_set_section "tunnel" "mode" "\"fixed\""
                    yaml_set_section "tunnel" "cf_token" "\"${cf_token}\""
                    info "固定隧道已配置"
                    apply_config
                else
                    error "Token 不能为空"
                fi
                ;;
            3)
                yaml_set_section "tunnel" "enabled" "false"
                info "隧道已禁用"
                apply_config
                ;;
            4)
                read -rp "本地端口: " new_port
                [[ "$new_port" =~ ^[0-9]+$ ]] && yaml_set_section "tunnel" "local_port" "$new_port"
                apply_config
                ;;
            5)
                local acme_tunnel=$(yaml_get "tunnel" "acme_use_tunnel")
                if [[ "$acme_tunnel" == "true" ]]; then
                    yaml_set_section "tunnel" "acme_use_tunnel" "false"
                    info "ACME 将不使用隧道"
                else
                    yaml_set_section "tunnel" "acme_use_tunnel" "true"
                    info "ACME 将通过隧道完成挑战"
                fi
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 7] ACME 证书管理
# ───────────────────────────────────────────────────────────────────────────────
manage_acme() {
    while true; do
        clear
        step "ACME 证书自动化"
        
        echo "─────────────────────────────────────"
        echo "1. 配置 ACME 自动申请 (Let's Encrypt)"
        echo "2. 使用自签名证书"
        echo "3. 使用自定义证书"
        echo "4. 查看当前证书配置"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-4]: " acme_opt

        case $acme_opt in
            1)
                read -rp "域名: " domain
                read -rp "邮箱: " email
                
                # 检查是否已有 cert 配置段
                if ! grep -q "^cert:" "$CONFIG_FILE"; then
                    cat >> "$CONFIG_FILE" << EOF

# ───────────────────────────────────────────────────────────────────────────────
# 证书配置
# ───────────────────────────────────────────────────────────────────────────────
cert:
  mode: "acme"
  domain: "${domain}"
  email: "${email}"
  ca_url: "https://acme-v02.api.letsencrypt.org/directory"
  cert_file: ""
  key_file: ""
EOF
                else
                    yaml_set_section "cert" "mode" "\"acme\""
                    yaml_set_section "cert" "domain" "\"${domain}\""
                    yaml_set_section "cert" "email" "\"${email}\""
                fi
                
                # 同步更新 TLS 的 server_name
                yaml_set_section "tls" "server_name" "\"${domain}\""
                info "ACME 配置完成，将自动申请证书"
                apply_config
                ;;
            2)
                if grep -q "^cert:" "$CONFIG_FILE"; then
                    yaml_set_section "cert" "mode" "\"self-signed\""
                else
                    echo -e "\ncert:\n  mode: \"self-signed\"" >> "$CONFIG_FILE"
                fi
                info "将使用自签名证书"
                apply_config
                ;;
            3)
                read -rp "证书文件路径 (.crt/.pem): " cert_path
                read -rp "私钥文件路径 (.key): " key_path
                
                if [[ ! -f "$cert_path" ]] || [[ ! -f "$key_path" ]]; then
                    error "文件不存在"
                    pause
                    continue
                fi
                
                if grep -q "^cert:" "$CONFIG_FILE"; then
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
                info "自定义证书已配置"
                apply_config
                ;;
            4)
                echo ""
                if grep -q "^cert:" "$CONFIG_FILE"; then
                    echo -e "${CYAN}当前证书配置:${NC}"
                    sed -n '/^cert:/,/^[a-z]/p' "$CONFIG_FILE" | head -10
                else
                    warn "未配置证书"
                fi
                pause
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 8] DDNS 动态域名管理（核心修复：使用作用域化函数）
# ───────────────────────────────────────────────────────────────────────────────
manage_ddns() {
    while true; do
        clear
        step "DDNS 动态域名同步"
        
        local ddns_enabled=$(yaml_get "ddns" "enabled")
        local ddns_provider=$(yaml_get "ddns" "provider")
        
        echo "─────────────────────────────────────"
        echo -e "状态: ${CYAN}${ddns_enabled}${NC}"
        echo -e "提供商: ${CYAN}${ddns_provider}${NC}"
        echo "─────────────────────────────────────"
        echo "1. 配置 DuckDNS"
        echo "2. 配置 FreeDNS"
        echo "3. 配置 Cloudflare DNS"
        echo "4. 修改检测间隔"
        echo "5. 禁用 DDNS"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-5]: " ddns_opt

        case $ddns_opt in
            1)
                read -rp "DuckDNS Token: " duck_token
                read -rp "子域名 (不含 .duckdns.org): " duck_domain
                
                if [[ -n "$duck_token" && -n "$duck_domain" ]]; then
                    yaml_set_section "ddns" "enabled" "true"
                    yaml_set_section "ddns" "provider" "\"duckdns\""
                    # 使用作用域化函数精准修改（核心修复点）
                    yaml_set_nested "ddns" "duckdns" "token" "$duck_token"
                    yaml_set_nested "ddns" "duckdns" "domains" "$duck_domain"
                    info "DuckDNS 已配置"
                    apply_config
                else
                    error "Token 和域名不能为空"
                fi
                ;;
            2)
                read -rp "FreeDNS Update Token (完整 URL 或 Token): " free_token
                
                if [[ -n "$free_token" ]]; then
                    yaml_set_section "ddns" "enabled" "true"
                    yaml_set_section "ddns" "provider" "\"freedns\""
                    yaml_set_nested "ddns" "freedns" "token" "$free_token"
                    info "FreeDNS 已配置"
                    apply_config
                else
                    error "Token 不能为空"
                fi
                ;;
            3)
                read -rp "Cloudflare API Token: " cf_api
                read -rp "Zone ID: " cf_zone
                read -rp "记录名 (如 sub.example.com): " cf_record
                
                if [[ -n "$cf_api" && -n "$cf_zone" && -n "$cf_record" ]]; then
                    yaml_set_section "ddns" "enabled" "true"
                    yaml_set_section "ddns" "provider" "\"cloudflare\""
                    yaml_set_nested "ddns" "cloudflare" "api_token" "$cf_api"
                    yaml_set_nested "ddns" "cloudflare" "zone_id" "$cf_zone"
                    yaml_set_nested "ddns" "cloudflare" "record_name" "$cf_record"
                    info "Cloudflare DDNS 已配置"
                    apply_config
                else
                    error "所有字段都必须填写"
                fi
                ;;
            4)
                local interval=$(yaml_get "ddns" "check_interval")
                read -rp "检测间隔(秒) [当前${interval}]: " new_interval
                [[ "$new_interval" =~ ^[0-9]+$ ]] && yaml_set_section "
                ddns" "check_interval" "$new_interval"
                apply_config
                ;;
            5)
                yaml_set_section "ddns" "enabled" "false"
                yaml_set_section "ddns" "provider" "\"none\""
                info "DDNS 已禁用"
                apply_config
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 19] 查看/编辑配置文件
# ───────────────────────────────────────────────────────────────────────────────
view_config() {
    while true; do
        clear
        step "配置文件管理"
        
        echo "─────────────────────────────────────"
        echo "1. 查看完整配置"
        echo "2. 使用 nano 编辑"
        echo "3. 使用 vim 编辑"
        echo "4. 备份当前配置"
        echo "5. 恢复备份配置"
        echo "6. 验证配置语法"
        echo "7. 重置为默认配置"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-7]: " cfg_opt

        case $cfg_opt in
            1)
                echo -e "\n${CYAN}═══════════════ 配置内容 ═══════════════${NC}"
                cat "$CONFIG_FILE"
                echo -e "${CYAN}═════════════════════════════════════════${NC}"
                pause
                ;;
            2)
                if command -v nano &>/dev/null; then
                    nano "$CONFIG_FILE"
                    apply_config
                else
                    error "nano 未安装"
                fi
                ;;
            3)
                if command -v vim &>/dev/null; then
                    vim "$CONFIG_FILE"
                    apply_config
                else
                    error "vim 未安装"
                fi
                ;;
            4)
                local backup_file="${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
                cp "$CONFIG_FILE" "$backup_file"
                info "配置已备份至: ${backup_file}"
                pause
                ;;
            5)
                echo "可用备份:"
                ls -la "${CONFIG_DIR}/"*.bak.* 2>/dev/null || echo "  (无备份)"
                echo ""
                read -rp "输入要恢复的备份文件完整路径: " restore_file
                if [[ -f "$restore_file" ]]; then
                    cp "$restore_file" "$CONFIG_FILE"
                    info "配置已恢复"
                    apply_config
                else
                    error "文件不存在"
                fi
                ;;
            6)
                echo ""
                if validate_yaml; then
                    success "配置语法正确"
                fi
                pause
                ;;
            7)
                echo -e "${RED}警告: 这将删除所有自定义配置！${NC}"
                read -rp "确认重置？请输入 'RESET' 确认: " confirm
                if [[ "$confirm" == "RESET" ]]; then
                    # 备份当前配置
                    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak.before-reset.$(date +%Y%m%d%H%M%S)"
                    # 重新运行安装
                    install_phantom
                fi
                ;;
            0) return ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 20] 高级诊断工具
# ───────────────────────────────────────────────────────────────────────────────
diagnostic_tools() {
    while true; do
        clear
        step "高级诊断工具"
        
        echo "─────────────────────────────────────"
        echo "1. 检查 eBPF 内核支持"
        echo "2. 检查网卡特性"
        echo "3. 检查端口占用"
        echo "4. 测试隧道连通性"
        echo "5. 查看 eBPF Map 状态"
        echo "6. 导出诊断报告"
        echo "0. 返回主菜单"
        echo "─────────────────────────────────────"
        read -rp "请选择 [0-6]: " diag_opt

        case $diag_opt in
            1)
                echo ""
                echo "═══════════════ eBPF 内核支持检查 ═══════════════"
                
                # 内核版本
                echo -n "内核版本: "
                uname -r
                
                # BPF 系统调用
                echo -n "BPF 系统调用: "
                if grep -q "CONFIG_BPF=y" /boot/config-$(uname -r) 2>/dev/null; then
                    echo -e "${GREEN}支持${NC}"
                else
                    echo -e "${YELLOW}未知 (无法读取内核配置)${NC}"
                fi
                
                # BPF JIT
                echo -n "BPF JIT: "
                local jit=$(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null)
                if [[ "$jit" == "1" ]]; then
                    echo -e "${GREEN}已启用${NC}"
                else
                    echo -e "${YELLOW}未启用 (建议执行: echo 1 > /proc/sys/net/core/bpf_jit_enable)${NC}"
                fi
                
                # XDP 支持
                echo -n "XDP 支持: "
                if ip link show | grep -q "xdp"; then
                    echo -e "${GREEN}支持${NC}"
                else
                    echo -e "${GREEN}可能支持 (需加载程序验证)${NC}"
                fi
                
                # BTF 支持
                echo -n "BTF 支持: "
                if [[ -f "/sys/kernel/btf/vmlinux" ]]; then
                    echo -e "${GREEN}支持 (CO-RE 可用)${NC}"
                else
                    echo -e "${YELLOW}不支持 (需要预编译的 eBPF 程序)${NC}"
                fi
                
                pause
                ;;
            2)
                echo ""
                local iface=$(yaml_get "ebpf" "interface")
                echo "═══════════════ 网卡 ${iface} 特性 ═══════════════"
                
                if command -v ethtool &>/dev/null; then
                    ethtool -i "$iface" 2>/dev/null || echo "无法获取驱动信息"
                    echo ""
                    echo "XDP 模式支持:"
                    ethtool -k "$iface" 2>/dev/null | grep -E "generic|native|offload" || echo "  使用 ip link 检查"
                else
                    echo "ethtool 未安装，使用 ip 命令"
                    ip -d link show "$iface"
                fi
                
                pause
                ;;
            3)
                echo ""
                echo "═══════════════ 端口占用检查 ═══════════════"
                
                local main_port=$(grep "^listen:" "$CONFIG_FILE" | grep -oP '\d+')
                local ft_port=$(yaml_get "faketcp" "listen" | grep -oP '\d+')
                local ws_port=$(yaml_get "websocket" "listen" | grep -oP '\d+')
                local metrics_port=$(yaml_get "metrics" "listen" | grep -oP '\d+')
                
                for port in $main_port $ft_port $ws_port $metrics_port; do
                    echo -n "端口 $port: "
                    if ss -tuln | grep -q ":${port} "; then
                        echo -e "${YELLOW}已占用${NC}"
                        ss -tulnp | grep ":${port} " | head -1
                    else
                        echo -e "${GREEN}空闲${NC}"
                    fi
                done
                
                pause
                ;;
            4)
                echo ""
                echo "═══════════════ 隧道连通性测试 ═══════════════"
                
                echo -n "Cloudflare API: "
                if curl -s --connect-timeout 5 https://api.cloudflare.com/client/v4/ &>/dev/null; then
                    echo -e "${GREEN}可达${NC}"
                else
                    echo -e "${RED}不可达${NC}"
                fi
                
                echo -n "Cloudflare 隧道服务: "
                if curl -s --connect-timeout 5 https://update.argotunnel.com &>/dev/null; then
                    echo -e "${GREEN}可达${NC}"
                else
                    echo -e "${RED}不可达${NC}"
                fi
                
                pause
                ;;
            5)
                echo ""
                echo "═══════════════ eBPF Map 状态 ═══════════════"
                
                if command -v bpftool &>/dev/null; then
                    echo "已加载的 BPF 程序:"
                    bpftool prog list 2>/dev/null || echo "  (无)"
                    echo ""
                    echo "BPF Maps:"
                    bpftool map list 2>/dev/null || echo "  (无)"
                else
                    warn "bpftool 未安装"
                    echo "尝试使用 /sys/fs/bpf 检查..."
                    ls -la /sys/fs/bpf/ 2>/dev/null || echo "  BPF 文件系统未挂载"
                fi
                
                pause
                ;;
            6)
                local report_file="/tmp/phantom-diag-$(date +%Y%m%d%H%M%S).txt"
                {
                    echo "═══════════════════════════════════════════════════════════"
                    echo "Phantom Server 诊断报告"
                    echo "生成时间: $(date)"
                    echo "═══════════════════════════════════════════════════════════"
                    echo ""
                    echo ">>> 系统信息"
                    uname -a
                    echo ""
                    echo ">>> 服务状态"
                    systemctl status phantom --no-pager 2>&1 || echo "服务未安装"
                    echo ""
                    echo ">>> 最近日志 (50行)"
                    journalctl -u phantom -n 50 --no-pager 2>&1 || echo "无日志"
                    echo ""
                    echo ">>> 网络配置"
                    ip addr
                    echo ""
                    echo ">>> 端口监听"
                    ss -tulnp
                    echo ""
                    echo ">>> 配置文件"
                    cat "$CONFIG_FILE" 2>/dev/null || echo "配置文件不存在"
                    echo ""
                    echo ">>> eBPF 状态"
                    bpftool prog list 2>&1 || echo "bpftool 不可用"
                } > "$report_file"
                
                info "诊断报告已生成: ${report_file}"
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
    local status=$(systemctl is-active phantom 2>/dev/null || echo "未安装")
    local color="$RED"
    case "$status" in
        active)   color="$GREEN"; status="● 运行中" ;;
        inactive) color="$YELLOW"; status="○ 已停止" ;;
        failed)   color="$RED"; status="✗ 启动失败" ;;
        *)        color="$RED"; status="✗ 未安装" ;;
    esac
    echo -e "服务状态: ${color}${BOLD}${status}${NC}"
}

show_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
    ____  __                __                  _____                          
   / __ \/ /_  ____ _____  / /_____  ____ ___  / ___/___  ______   _____  _____
  / /_/ / __ \/ __ `/ __ \/ __/ __ \/ __ `__ \ \__ \/ _ \/ ___/ | / / _ \/ ___/
 / ____/ / / / /_/ / / / / /_/ /_/ / / / / / /___/ /  __/ /   | |/ /  __/ /    
/_/   /_/ /_/\__,_/_/ /_/\__/\____/_/ /_/ /_//____/\___/_/    |___/\___/_/     
                                                                         v4.2.0
EOF
    echo -e "${NC}"
}

main_menu() {
    while true; do
        clear
        show_banner
        show_status
        echo ""
        echo -e "${BOLD}═══════════════════ 安装管理 ═══════════════════${NC}"
        echo "  1. 深度安装 / 全量更新"
        echo "  2. 彻底卸载"
        echo ""
        echo -e "${BOLD}═══════════════════ 服务控制 ═══════════════════${NC}"
        echo "  3. 启动服务    4. 停止服务    5. 重启服务"
        echo ""
        echo -e "${BOLD}═══════════════════ 扩展模块 ═══════════════════${NC}"
        echo "  6. Cloudflare 隧道    7. ACME 证书    8. DDNS 动态域名"
        echo "  9. 基础配置 (端口/PSK/日志)"
        echo ""
        echo -e "${BOLD}════════════════ ${YELLOW}核心调优中心${NC}${BOLD} ════════════════${NC}"
        echo -e "  13. ${YELLOW}Switcher 智能寻路${NC}        (模块 33-39)"
        echo -e "  14. ${YELLOW}TLS 深度伪装 & DPI 逃逸${NC}  (模块 95-96)"
        echo -e "  15. ${YELLOW}Hysteria2 & ARQ 精调${NC}     (模块 17, 40)"
        echo -e "  16. ${YELLOW}协议模块开关${NC}             (FakeTCP/WS/eBPF)"
        echo -e "  17. ${YELLOW}网卡与 eBPF 管理${NC}         (模块 49-56)"
        echo -e "  18. ${YELLOW}Metrics 监控配置${NC}         (模块 30)"
        echo ""
        echo -e "${BOLD}═══════════════════ 运维工具 ═══════════════════${NC}"
        echo "  10. 实时日志 (journalctl -f)"
        echo "  11. 服务详情 (systemctl status)"
        echo "  12. 更新 eBPF 字节码"
        echo "  19. 查看/编辑配置文件"
        echo "  20. 高级诊断工具"
        echo ""
        echo -e "${BOLD}═════════════════════════════════════════════════${NC}"
        echo "  0. 退出"
        echo ""
        read -rp "请输入选项 [0-20]: " opt

        case $opt in
            1)  install_phantom; pause ;;
            2)  uninstall_phantom; pause ;;
            3)  
                systemctl start phantom && success "已启动" || error "启动失败"
                pause 
                ;;
            4)  
                systemctl stop phantom && success "已停止" || error "停止失败"
                pause 
                ;;
            5)  
                systemctl restart phantom && success "已重启" || error "重启失败"
                pause 
                ;;
            6)  manage_tunnel ;;
            7)  manage_acme ;;
            8)  manage_ddns ;;
            9)  manage_basic ;;
            10) 
                echo -e "${CYAN}按 Ctrl+C 退出日志查看${NC}"
                sleep 1
                journalctl -u phantom -f -n 100
                ;;
            11) 
                systemctl status phantom --no-pager
                pause 
                ;;
            12) 
                if [[ -d "./ebpf" ]]; then
                    cp ./ebpf/*.o "$EBPF_DIR/" 2>/dev/null
                    info "eBPF 字节码已同步"
                    apply_config
                else
                    error "未找到 ./ebpf 目录"
                fi
                pause
                ;;
            13) manage_switcher ;;
            14) manage_tls ;;
            15) manage_perf ;;
            16) manage_protocols ;;
            17) manage_network ;;
            18) manage_metrics ;;
            19) view_config ;;
            20) diagnostic_tools ;;
            0)  
                echo ""
                echo -e "${GREEN}感谢使用 Phantom Server！${NC}"
                echo ""
                exit 0 
                ;;
            *)  
                error "无效选项"
                sleep 1
                ;;
        esac
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# 入口
# ───────────────────────────────────────────────────────────────────────────────
check_root
main_menu
