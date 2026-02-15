#!/usr/bin/env bash
# =============================================================================
# 文件: scripts/install.sh
# 版本: v4.3.0-COMPLETE
# 描述: Phantom Server 终极管理面板 - 完整功能版
# 新增: 域名/证书/隧道 独立入口 + 自动下载二进制
# =============================================================================

# 确保 stdin 可用于交互
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

# GitHub 仓库信息
GITHUB_REPO="mrcgq/222"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"

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
        error "必须使用 root 权限运行"
        exit 1
    fi
}

get_iface() {
    ip route 2>/dev/null | grep default | awk '{print $5}' | head -1 || echo "eth0"
}

get_arch() {
    case "$(uname -m)" in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        armv7l)  echo "armv7" ;;
        *) uname -m ;;
    esac
}

# ───────────────────────────────────────────────────────────────────────────────
# 2. 自动下载
# ───────────────────────────────────────────────────────────────────────────────
download_binary() {
    step "从 GitHub Releases 下载最新版本..."
    
    local os="linux"
    local arch=$(get_arch)
    info "系统: ${os}/${arch}"
    
    local release_info=$(curl -sfL "$GITHUB_API" 2>/dev/null)
    if [[ -z "$release_info" ]]; then
        error "无法获取 Release 信息，请检查网络"
        return 1
    fi
    
    local version=$(echo "$release_info" | grep -oP '"tag_name":\s*"\K[^"]+' | head -1)
    info "最新版本: ${version}"
    
    # 查找匹配的下载链接
    local download_url=$(echo "$release_info" | grep -oP '"browser_download_url":\s*"\K[^"]*linux[^"]*'"${arch}"'[^"]*' | grep -v ".sha" | head -1)
    
    if [[ -z "$download_url" ]]; then
        # 尝试其他命名格式
        download_url=$(echo "$release_info" | grep -oP '"browser_download_url":\s*"\K[^"]*phantom-server[^"]*' | grep -v ".sha" | head -1)
    fi
    
    if [[ -z "$download_url" ]]; then
        warn "未找到预编译文件，可用文件:"
        echo "$release_info" | grep -oP '"browser_download_url":\s*"\K[^"]+' | while read url; do
            echo "  - $(basename "$url")"
        done
        return 1
    fi
    
    info "下载: ${download_url}"
    
    mkdir -p "$INSTALL_DIR"
    local tmp_file="/tmp/phantom-download"
    
    curl -fL --progress-bar -o "$tmp_file" "$download_url" || {
        error "下载失败"
        return 1
    }
    
    # 处理压缩文件
    local file_type=$(file "$tmp_file" 2>/dev/null)
    if echo "$file_type" | grep -q "gzip"; then
        gunzip -c "$tmp_file" > "$INSTALL_DIR/$BINARY_NAME"
    elif echo "$file_type" | grep -q "tar"; then
        tar -xf "$tmp_file" -C "$INSTALL_DIR/" 2>/dev/null
        find "$INSTALL_DIR" -name "phantom*" -type f -exec mv {} "$INSTALL_DIR/$BINARY_NAME" \; 2>/dev/null
    else
        mv "$tmp_file" "$INSTALL_DIR/$BINARY_NAME"
    fi
    
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    rm -f "$tmp_file"
    
    if [[ -x "$INSTALL_DIR/$BINARY_NAME" ]]; then
        success "二进制文件已部署"
        return 0
    else
        error "部署失败"
        return 1
    fi
}

download_ebpf() {
    step "下载 eBPF 字节码..."
    mkdir -p "$EBPF_DIR"
    
    local release_info=$(curl -sfL "$GITHUB_API" 2>/dev/null)
    local ebpf_url=$(echo "$release_info" | grep -oP '"browser_download_url":\s*"\K[^"]*ebpf[^"]*' | head -1)
    
    if [[ -n "$ebpf_url" ]]; then
        local tmp="/tmp/ebpf-download"
        curl -fL -o "$tmp" "$ebpf_url" 2>/dev/null
        if echo "$ebpf_url" | grep -q "tar"; then
            tar -xf "$tmp" -C "$EBPF_DIR/" 2>/dev/null
        elif echo "$ebpf_url" | grep -q "zip"; then
            unzip -o "$tmp" -d "$EBPF_DIR/" 2>/dev/null
        else
            mv "$tmp" "$EBPF_DIR/"
        fi
        rm -f "$tmp"
        success "eBPF 已下载"
    else
        warn "未找到 eBPF 文件"
    fi
}

# ───────────────────────────────────────────────────────────────────────────────
# 3. YAML 操作函数
# ───────────────────────────────────────────────────────────────────────────────
yaml_set_top() {
    local key="$1" value="$2" file="${3:-$CONFIG_FILE}"
    [[ ! -f "$file" ]] && echo "${key}: ${value}" > "$file" && return
    grep -q "^${key}:" "$file" && sed -i "s|^${key}:.*|${key}: ${value}|" "$file" || echo "${key}: ${value}" >> "$file"
}

yaml_set_section() {
    local section="$1" key="$2" value="$3" file="${4:-$CONFIG_FILE}"
    [[ ! -f "$file" ]] && return 1
    awk -v sec="$section" -v k="$key" -v v="$value" '
    BEGIN{in_sec=0;found=0}
    {
        if($0~"^"sec":"){in_sec=1;print;next}
        if(in_sec && /^[a-zA-Z_]+:/){in_sec=0}
        if(in_sec && !found && $0~"^[[:space:]]+"k":"){sub(/:.*/,": "v);found=1}
        print
    }' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

yaml_set_nested() {
    local section="$1" subsec="$2" key="$3" value="$4" file="${5:-$CONFIG_FILE}"
    [[ ! -f "$file" ]] && return 1
    awk -v sec="$section" -v sub="$subsec" -v k="$key" -v v="$value" '
    BEGIN{in_sec=0;in_sub=0;found=0}
    {
        if($0~"^"sec":"){in_sec=1;print;next}
        if(in_sec && /^[a-zA-Z_]+:/ && $0!~"^"sec":"){in_sec=0;in_sub=0}
        if(in_sec && $0~"^[[:space:]]+"sub":"){in_sub=1;print;next}
        if(in_sub && !found && $0~"^[[:space:]]+"k":"){sub(/:.*/,": \""v"\"");found=1}
        print
    }' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

yaml_set_array() {
    local section="$1" key="$2" values="$3" file="${4:-$CONFIG_FILE}"
    [[ ! -f "$file" ]] && return 1
    awk -v sec="$section" -v k="$key" -v vals="$values" '
    BEGIN{in_sec=0;in_arr=0;split(vals,arr,",")}
    {
        if($0~"^"sec":"){in_sec=1;print;next}
        if(in_sec && /^[a-zA-Z_]+:/){in_sec=0}
        if(in_sec && $0~"^[[:space:]]+"k":"){
            in_arr=1;print
            for(i in arr){gsub(/^[[:space:]]+|[[:space:]]+$/,"",arr[i]);print "    - \""arr[i]"\""}
            next
        }
        if(in_arr && /^[[:space:]]+-/){next}
        if(in_arr && !/^[[:space:]]+-/){in_arr=0}
        print
    }' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

yaml_get() {
    local section="$1" key="$2" file="${3:-$CONFIG_FILE}"
    [[ ! -f "$file" ]] && return
    awk -v sec="$section" -v k="$key" '
    BEGIN{in_sec=0}
    {
        if($0~"^"sec":"){in_sec=1;next}
        if(in_sec && /^[a-zA-Z_]+:/){in_sec=0}
        if(in_sec && $0~"^[[:space:]]+"k":"){sub(/.*:[[:space:]]*/,"");gsub(/"/,"");print;exit}
    }' "$file"
}

# ───────────────────────────────────────────────────────────────────────────────
# 4. 核心操作
# ───────────────────────────────────────────────────────────────────────────────
apply_config() {
    step "应用配置..."
    systemctl daemon-reload 2>/dev/null
    systemctl restart phantom 2>/dev/null
    sleep 2
    
    if systemctl is-active --quiet phantom 2>/dev/null; then
        success "服务运行中"
        
        # 显示隧道 URL
        local tunnel_on=$(yaml_get "tunnel" "enabled")
        local tunnel_mode=$(yaml_get "tunnel" "mode")
        if [[ "$tunnel_on" == "true" && "$tunnel_mode" == "temp" ]]; then
            sleep 3
            local url=$(journalctl -u phantom -n 50 --no-pager 2>/dev/null | grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
            [[ -n "$url" ]] && info "隧道地址: ${CYAN}${url}${NC}"
        fi
        return 0
    else
        error "启动失败，使用选项 10 查看日志"
        return 1
    fi
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 1] 安装
# ───────────────────────────────────────────────────────────────────────────────
install_phantom() {
    step "安装 Phantom Server..."
    echo ""
    
    mkdir -p "$INSTALL_DIR" "$EBPF_DIR" "$CONFIG_DIR"
    
    local iface=$(get_iface)
    info "网卡: ${iface}"
    
    read -rp "监听端口 [54321]: " PORT
    PORT=${PORT:-54321}
    read -rp "PSK密钥 (留空自动生成): " PSK
    [[ -z "$PSK" ]] && PSK=$(openssl rand -base64 24 2>/dev/null || head -c 24 /dev/urandom | base64)
    
    echo ""
    
    # 下载二进制
    if [[ -f "./phantom-server" ]]; then
        cp "./phantom-server" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
        success "使用本地二进制"
    elif [[ ! -x "$INSTALL_DIR/$BINARY_NAME" ]]; then
        download_binary || return 1
    fi
    
    # 下载 eBPF
    if [[ -d "./ebpf" ]] && ls ./ebpf/*.o &>/dev/null; then
        cp ./ebpf/*.o "$EBPF_DIR/"
        success "使用本地 eBPF"
    elif ! ls "$EBPF_DIR"/*.o &>/dev/null 2>&1; then
        download_ebpf
    fi
    
    echo ""
    
    # 生成配置
    step "生成配置..."
    cat > "$CONFIG_FILE" << EOF
# Phantom Server 配置
# 生成: $(date '+%Y-%m-%d %H:%M:%S')

listen: ":${PORT}"
psk: "${PSK}"
time_window: 30
log_level: "info"
mode: "auto"

# Hysteria2 拥塞控制
hysteria2:
  enabled: true
  up_mbps: 100
  down_mbps: 100

# ARQ 重传
arq:
  enabled: true
  window_size: 256
  max_retries: 10
  rto_min_ms: 100
  rto_max_ms: 3000

# 智能寻路
switcher:
  enabled: true
  check_interval_ms: 1000
  rtt_threshold_ms: 300
  loss_threshold: 0.3
  priority:
    - "ebpf"
    - "faketcp"
    - "udp"
    - "websocket"

# Cloudflare 隧道
tunnel:
  enabled: false
  mode: "temp"
  cf_token: ""
  local_port: ${PORT}

# 域名与证书
domain:
  name: ""
  acme_email: ""
  cert_mode: "none"
  cert_file: ""
  key_file: ""

# DDNS
ddns:
  enabled: false
  provider: "none"
  duckdns:
    token: ""
    domain: ""
  cloudflare:
    api_token: ""
    zone_id: ""
    record: ""

# TLS 伪装
tls:
  enabled: false
  server_name: "www.microsoft.com"
  fingerprint: "chrome"
  random_sni: false
  sni_list:
    - "www.microsoft.com"
    - "www.apple.com"
  fragment:
    enabled: true
    size: 40
    sleep_ms: 10
  fallback:
    enabled: true
    addr: "127.0.0.1:80"

# FakeTCP
faketcp:
  enabled: true
  listen: ":$((PORT+1))"
  interface: "${iface}"

# WebSocket
websocket:
  enabled: true
  listen: ":$((PORT+2))"
  path: "/ws"

# eBPF
ebpf:
  enabled: true
  interface: "${iface}"
  xdp_mode: "generic"
  enable_tc: true

# Metrics
metrics:
  enabled: true
  listen: ":9100"
EOF
    success "配置已生成"
    
    # Systemd
    cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=Phantom Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/phantom
ExecStart=/opt/phantom/phantom-server -c /etc/phantom/config.yaml
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
    
    echo ""
    if apply_config; then
        echo ""
        echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}${BOLD}  安装成功！${NC}"
        echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
        echo -e "  端口:     ${CYAN}${PORT}${NC} (主) | ${CYAN}$((PORT+1))${NC} (FakeTCP) | ${CYAN}$((PORT+2))${NC} (WS)"
        echo -e "  PSK:      ${CYAN}${PSK}${NC}"
        echo -e "  配置:     ${CYAN}${CONFIG_FILE}${NC}"
        echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "${YELLOW}提示: 使用选项 21-24 配置域名、证书和隧道${NC}"
    fi
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 2] 卸载
# ───────────────────────────────────────────────────────────────────────────────
uninstall_phantom() {
    echo ""
    echo -e "${RED}警告: 将删除所有数据！${NC}"
    read -rp "输入 YES 确认: " confirm
    [[ "$confirm" != "YES" ]] && return
    
    systemctl stop phantom 2>/dev/null
    systemctl disable phantom 2>/dev/null
    rm -rf "$INSTALL_DIR" "$CONFIG_DIR" "$SERVICE_FILE"
    systemctl daemon-reload
    
    success "已完全卸载"
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 21] 域名配置
# ───────────────────────────────────────────────────────────────────────────────
manage_domain() {
    clear
    step "域名配置"
    echo ""
    
    local current_domain=$(yaml_get "domain" "name")
    local current_mode=$(yaml_get "domain" "cert_mode")
    
    echo -e "当前域名: ${CYAN}${current_domain:-未设置}${NC}"
    echo -e "证书模式: ${CYAN}${current_mode:-none}${NC}"
    echo ""
    echo "─────────────────────────────────────"
    echo "1. 设置域名"
    echo "2. 清除域名"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
        1)
            echo ""
            read -rp "输入域名 (如 vpn.example.com): " domain
            if [[ -n "$domain" ]]; then
                yaml_set_section "domain" "name" "\"${domain}\""
                yaml_set_section "tls" "server_name" "\"${domain}\""
                success "域名已设置: ${domain}"
                echo ""
                echo "接下来请配置证书 (选项 22) 或 DDNS (选项 24)"
            fi
            ;;
        2)
            yaml_set_section "domain" "name" "\"\""
            success "域名已清除"
            ;;
    esac
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 22] 证书配置
# ───────────────────────────────────────────────────────────────────────────────
manage_cert() {
    clear
    step "SSL/TLS 证书配置"
    echo ""
    
    local domain=$(yaml_get "domain" "name")
    local cert_mode=$(yaml_get "domain" "cert_mode")
    
    echo -e "当前域名: ${CYAN}${domain:-未设置}${NC}"
    echo -e "证书模式: ${CYAN}${cert_mode:-none}${NC}"
    echo ""
    echo "─────────────────────────────────────"
    echo "1. ACME 自动申请 (Let's Encrypt)"
    echo "2. 自定义证书 (手动上传)"
    echo "3. 自签名证书"
    echo "4. 禁用证书"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
        1)
            if [[ -z "$domain" ]]; then
                error "请先设置域名 (选项 21)"
                return
            fi
            echo ""
            read -rp "邮箱 (用于证书通知): " email
            yaml_set_section "domain" "cert_mode" "\"acme\""
            yaml_set_section "domain" "acme_email" "\"${email}\""
            yaml_set_section "tls" "enabled" "true"
            success "ACME 证书已配置"
            info "域名: ${domain}"
            info "邮箱: ${email}"
            echo ""
            apply_config
            ;;
        2)
            echo ""
            read -rp "证书文件路径 (.crt/.pem): " cert_file
            read -rp "私钥文件路径 (.key): " key_file
            
            if [[ -f "$cert_file" && -f "$key_file" ]]; then
                yaml_set_section "domain" "cert_mode" "\"manual\""
                yaml_set_section "domain" "cert_file" "\"${cert_file}\""
                yaml_set_section "domain" "key_file" "\"${key_file}\""
                yaml_set_section "tls" "enabled" "true"
                success "自定义证书已配置"
                apply_config
            else
                error "文件不存在"
            fi
            ;;
        3)
            yaml_set_section "domain" "cert_mode" "\"self-signed\""
            yaml_set_section "tls" "enabled" "true"
            success "将使用自签名证书"
            apply_config
            ;;
        4)
            yaml_set_section "domain" "cert_mode" "\"none\""
            yaml_set_section "tls" "enabled" "false"
            success "证书已禁用"
            apply_config
            ;;
    esac
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 23] Cloudflare 隧道配置
# ───────────────────────────────────────────────────────────────────────────────
manage_tunnel() {
    clear
    step "Cloudflare 隧道配置"
    echo ""
    
    local tunnel_on=$(yaml_get "tunnel" "enabled")
    local tunnel_mode=$(yaml_get "tunnel" "mode")
    
    echo -e "状态: ${CYAN}${tunnel_on:-false}${NC}"
    echo -e "模式: ${CYAN}${tunnel_mode:-temp}${NC}"
    echo ""
    echo -e "${YELLOW}隧道说明:${NC}"
    echo "  临时隧道: 无需配置，自动获取随机域名 (重启后变化)"
    echo "  固定隧道: 需要 CF Token，域名固定不变"
    echo ""
    echo "─────────────────────────────────────"
    echo "1. 启用临时隧道 (推荐新手)"
    echo "2. 启用固定隧道 (需要 Token)"
    echo "3. 禁用隧道"
    echo "4. 查看当前隧道 URL"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
        1)
            yaml_set_section "tunnel" "enabled" "true"
            yaml_set_section "tunnel" "mode" "\"temp\""
            success "临时隧道已启用"
            echo ""
            apply_config
            echo ""
            warn "隧道 URL 将在日志中显示"
            ;;
        2)
            echo ""
            echo "获取 Token: https://dash.cloudflare.com → Zero Trust → Tunnels"
            read -rp "Cloudflare Tunnel Token: " token
            
            if [[ -n "$token" ]]; then
                yaml_set_section "tunnel" "enabled" "true"
                yaml_set_section "tunnel" "mode" "\"fixed\""
                yaml_set_section "tunnel" "cf_token" "\"${token}\""
                success "固定隧道已配置"
                apply_config
            else
                error "Token 不能为空"
            fi
            ;;
        3)
            yaml_set_section "tunnel" "enabled" "false"
            success "隧道已禁用"
            apply_config
            ;;
        4)
            echo ""
            local url=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
            if [[ -n "$url" ]]; then
                info "当前隧道: ${CYAN}${url}${NC}"
            else
                warn "未找到隧道 URL (服务可能未启动或隧道未启用)"
            fi
            ;;
    esac
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 24] DDNS 配置
# ───────────────────────────────────────────────────────────────────────────────
manage_ddns() {
    clear
    step "DDNS 动态域名配置"
    echo ""
    
    local ddns_on=$(yaml_get "ddns" "enabled")
    local ddns_provider=$(yaml_get "ddns" "provider")
    
    echo -e "状态: ${CYAN}${ddns_on:-false}${NC}"
    echo -e "提供商: ${CYAN}${ddns_provider:-none}${NC}"
    echo ""
    echo "─────────────────────────────────────"
    echo "1. DuckDNS (免费)"
    echo "2. Cloudflare DNS"
    echo "3. 禁用 DDNS"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
        1)
            echo ""
            echo "获取 Token: https://www.duckdns.org"
            read -rp "DuckDNS Token: " token
            read -rp "子域名 (不含 .duckdns.org): " subdomain
            
            if [[ -n "$token" && -n "$subdomain" ]]; then
                yaml_set_section "ddns" "enabled" "true"
                yaml_set_section "ddns" "provider" "\"duckdns\""
                yaml_set_nested "ddns" "duckdns" "token" "$token"
                yaml_set_nested "ddns" "duckdns" "domain" "$subdomain"
                
                # 同步域名
                yaml_set_section "domain" "name" "\"${subdomain}.duckdns.org\""
                
                success "DuckDNS 已配置"
                info "域名: ${subdomain}.duckdns.org"
                apply_config
            fi
            ;;
        2)
            echo ""
            echo "在 Cloudflare 控制台获取 API Token 和 Zone ID"
            read -rp "API Token: " api_token
            read -rp "Zone ID: " zone_id
            read -rp "记录名 (如 vpn.example.com): " record
            
            if [[ -n "$api_token" && -n "$zone_id" && -n "$record" ]]; then
                yaml_set_section "ddns" "enabled" "true"
                yaml_set_section "ddns" "provider" "\"cloudflare\""
                yaml_set_nested "ddns" "cloudflare" "api_token" "$api_token"
                yaml_set_nested "ddns" "cloudflare" "zone_id" "$zone_id"
                yaml_set_nested "ddns" "cloudflare" "record" "$record"
                
                # 同步域名
                yaml_set_section "domain" "name" "\"${record}\""
                
                success "Cloudflare DDNS 已配置"
                info "域名: ${record}"
                apply_config
            fi
            ;;
        3)
            yaml_set_section "ddns" "enabled" "false"
            yaml_set_section "ddns" "provider" "\"none\""
            success "DDNS 已禁用"
            apply_config
            ;;
    esac
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 9] 基础配置
# ───────────────────────────────────────────────────────────────────────────────
manage_basic() {
    clear
    step "基础配置"
    echo ""
    
    local port=$(grep "^listen:" "$CONFIG_FILE" 2>/dev/null | grep -oP '\d+')
    local psk=$(grep "^psk:" "$CONFIG_FILE" 2>/dev/null | awk '{print $2}' | tr -d '"')
    local mode=$(grep "^mode:" "$CONFIG_FILE" 2>/dev/null | awk '{print $2}' | tr -d '"')
    
    echo -e "端口: ${CYAN}${port:-54321}${NC}"
    echo -e "PSK:  ${CYAN}${psk:-未设置}${NC}"
    echo -e "模式: ${CYAN}${mode:-auto}${NC}"
    echo ""
    echo "─────────────────────────────────────"
    echo "1. 修改端口"
    echo "2. 重置 PSK"
    echo "3. 修改模式"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
        1)
            read -rp "新端口: " p
            if [[ "$p" =~ ^[0-9]+$ ]]; then
                yaml_set_top "listen" "\":${p}\""
                yaml_set_section "tunnel" "local_port" "$p"
                yaml_set_section "faketcp" "listen" "\":$((p+1))\""
                yaml_set_section "websocket" "listen" "\":$((p+2))\""
                apply_config
            fi
            ;;
        2)
            local new_psk=$(openssl rand -base64 24 2>/dev/null)
            yaml_set_top "psk" "\"${new_psk}\""
            apply_config
            info "新 PSK: ${CYAN}${new_psk}${NC}"
            ;;
        3)
            echo "可选: auto / ebpf / faketcp / udp / websocket"
            read -rp "模式: " m
            yaml_set_top "mode" "\"${m}\""
            apply_config
            ;;
    esac
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 13-18] 调优功能 (简化版)
# ───────────────────────────────────────────────────────────────────────────────
manage_switcher() {
    clear
    step "Switcher 智能寻路"
    echo ""
    echo "1. 修改优先级"
    echo "2. 修改检测间隔"
    echo "3. 修改 RTT 阈值"
    echo "4. 修改丢包阈值"
    echo "0. 返回"
    read -rp "选择: " opt
    case $opt in
        1) read -rp "优先级 (逗号分隔): " p; yaml_set_array "switcher" "priority" "$p"; apply_config ;;
        2) read -rp "间隔(ms): " v; yaml_set_section "switcher" "check_interval_ms" "$v"; apply_config ;;
        3) read -rp "RTT(ms): " v; yaml_set_section "switcher" "rtt_threshold_ms" "$v"; apply_config ;;
        4) read -rp "丢包率: " v; yaml_set_section "switcher" "loss_threshold" "$v"; apply_config ;;
    esac
}

manage_tls() {
    clear
    step "TLS/DPI 设置"
    echo ""
    local tls_on=$(yaml_get "tls" "enabled")
    echo -e "TLS: ${CYAN}${tls_on}${NC}"
    echo ""
    echo "1. 启用/禁用 TLS"
    echo "2. 修改指纹"
    echo "3. 修改 SNI"
    echo "4. 分片设置"
    echo "0. 返回"
    read -rp "选择: " opt
    case $opt in
        1) [[ "$tls_on" == "true" ]] && yaml_set_section "tls" "enabled" "false" || yaml_set_section "tls" "enabled" "true"; apply_config ;;
        2) echo "1.chrome 2.firefox 3.safari 4.random"; read -rp ": " f
           case $f in 1)fp="chrome";;2)fp="firefox";;3)fp="safari";;4)fp="random";;esac
           yaml_set_section "tls" "fingerprint" "\"${fp}\""; apply_config ;;
        3) read -rp "SNI: " s; yaml_set_section "tls" "server_name" "\"${s}\""; apply_config ;;
        4) read -rp "分片大小: " s; read -rp "间隔(ms): " m
           sed -i '/fragment:/,/fallback:/ s/size: .*/size: '"$s"'/' "$CONFIG_FILE"
           sed -i '/fragment:/,/fallback:/ s/sleep_ms: .*/sleep_ms: '"$m"'/' "$CONFIG_FILE"
           apply_config ;;
    esac
}

manage_perf() {
    clear
    step "性能调优"
    echo ""
    echo "1. 修改带宽限制"
    echo "2. 修改 ARQ 窗口"
    echo "3. 修改 RTO"
    echo "0. 返回"
    read -rp "选择: " opt
    case $opt in
        1) read -rp "上行Mbps: " u; read -rp "下行Mbps: " d
           yaml_set_section "hysteria2" "up_mbps" "$u"
           yaml_set_section "hysteria2" "down_mbps" "$d"; apply_config ;;
        2) read -rp "窗口大小: " w; yaml_set_section "arq" "window_size" "$w"; apply_config ;;
        3) read -rp "RTO最小(ms): " min; read -rp "RTO最大(ms): " max
           yaml_set_section "arq" "rto_min_ms" "$min"
           yaml_set_section "arq" "rto_max_ms" "$max"; apply_config ;;
    esac
}

manage_protocols() {
    clear
    step "协议开关"
    echo ""
    local ft=$(yaml_get "faketcp" "enabled")
    local ws=$(yaml_get "websocket" "enabled")
    local eb=$(yaml_get "ebpf" "enabled")
    echo -e "FakeTCP: ${CYAN}${ft}${NC} | WebSocket: ${CYAN}${ws}${NC} | eBPF: ${CYAN}${eb}${NC}"
    echo ""
    echo "1. 切换 FakeTCP"
    echo "2. 切换 WebSocket"
    echo "3. 切换 eBPF"
    echo "0. 返回"
    read -rp "选择: " opt
    case $opt in
        1) [[ "$ft" == "true" ]] && yaml_set_section "faketcp" "enabled" "false" || yaml_set_section "faketcp" "enabled" "true"; apply_config ;;
        2) [[ "$ws" == "true" ]] && yaml_set_section "websocket" "enabled" "false" || yaml_set_section "websocket" "enabled" "true"; apply_config ;;
        3) [[ "$eb" == "true" ]] && yaml_set_section "ebpf" "enabled" "false" || yaml_set_section "ebpf" "enabled" "true"; apply_config ;;
    esac
}

manage_network() {
    clear
    step "网卡/eBPF"
    echo ""
    local iface=$(yaml_get "ebpf" "interface")
    echo -e "当前网卡: ${CYAN}${iface}${NC}"
    echo ""
    echo "可用网卡:"
    ip -o link show | awk -F': ' '{print "  "$2}' | grep -v lo
    echo ""
    echo "1. 自动检测"
    echo "2. 手动指定"
    echo "3. 下载 eBPF"
    echo "0. 返回"
    read -rp "选择: " opt
    case $opt in
        1) local i=$(get_iface); yaml_set_section "ebpf" "interface" "\"${i}\""; yaml_set_section "faketcp" "interface" "\"${i}\""; apply_config ;;
        2) read -rp "网卡名: " i; yaml_set_section "ebpf" "interface" "\"${i}\""; yaml_set_section "faketcp" "interface" "\"${i}\""; apply_config ;;
        3) download_ebpf; apply_config ;;
    esac
}

manage_metrics() {
    clear
    step "Metrics"
    echo ""
    local on=$(yaml_get "metrics" "enabled")
    echo -e "状态: ${CYAN}${on}${NC}"
    echo ""
    echo "1. 切换开关"
    echo "2. 修改端口"
    echo "0. 返回"
    read -rp "选择: " opt
    case $opt in
        1) [[ "$on" == "true" ]] && yaml_set_section "metrics" "enabled" "false" || yaml_set_section "metrics" "enabled" "true"; apply_config ;;
        2) read -rp "端口: " p; yaml_set_section "metrics" "listen" "\":${p}\""; apply_config ;;
    esac
}

# ───────────────────────────────────────────────────────────────────────────────
# [选项 19-20] 运维工具
# ───────────────────────────────────────────────────────────────────────────────
view_config() {
    clear
    step "配置管理"
    echo ""
    echo "1. 查看配置"
    echo "2. 编辑 (nano)"
    echo "3. 备份"
    echo "4. 恢复"
    echo "0. 返回"
    read -rp "选择: " opt
    case $opt in
        1) cat "$CONFIG_FILE" 2>/dev/null; echo ""; read -rp "Enter继续..." _ ;;
        2) nano "$CONFIG_FILE" 2>/dev/null && apply_config ;;
        3) cp "$CONFIG_FILE" "${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"; success "已备份" ;;
        4) ls "${CONFIG_DIR}/"*.bak.* 2>/dev/null; read -rp "文件: " f; [[ -f "$f" ]] && cp "$f" "$CONFIG_FILE" && apply_config ;;
    esac
}

diagnostic_tools() {
    clear
    step "诊断"
    echo ""
    echo "内核: $(uname -r)"
    echo -n "BPF JIT: "; [[ "$(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null)" == "1" ]] && echo "启用" || echo "未启用"
    echo -n "BTF: "; [[ -f "/sys/kernel/btf/vmlinux" ]] && echo "支持" || echo "不支持"
    echo ""
    echo "端口检查:"
    local port=$(grep "^listen:" "$CONFIG_FILE" 2>/dev/null | grep -oP '\d+' || echo "54321")
    for p in $port $((port+1)) $((port+2)) 9100; do
        echo -n "  $p: "; ss -tuln | grep -q ":$p " && echo "占用" || echo "空闲"
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# 主菜单
# ───────────────────────────────────────────────────────────────────────────────
show_status() {
    local st=$(systemctl is-active phantom 2>/dev/null || echo "未安装")
    case "$st" in
        active) echo -e "状态: ${GREEN}${BOLD}● 运行中${NC}" ;;
        inactive) echo -e "状态: ${YELLOW}○ 已停止${NC}" ;;
        *) echo -e "状态: ${RED}✗ 未安装${NC}" ;;
    esac
}

show_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
  ____  _                 _                  
 |  _ \| |__   __ _ _ __ | |_ ___  _ __ ___  
 | |_) | '_ \ / _` | '_ \| __/ _ \| '_ ` _ \ 
 |  __/| | | | (_| | | | | || (_) | | | | | |
 |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|
                                        v4.3.0
EOF
    echo -e "${NC}"
}

main_menu() {
    while true; do
        clear
        show_banner
        show_status
        
        # 显示当前配置摘要
        if [[ -f "$CONFIG_FILE" ]]; then
            local domain=$(yaml_get "domain" "name")
            local tunnel=$(yaml_get "tunnel" "enabled")
            local tunnel_mode=$(yaml_get "tunnel" "mode")
            echo ""
            echo -e "域名: ${CYAN}${domain:-未设置}${NC} | 隧道: ${CYAN}${tunnel:-false}${NC} (${tunnel_mode:-temp})"
        fi
        
        echo ""
        echo -e "${BOLD}═══════════════ 安装管理 ═══════════════${NC}"
        echo "  1. 安装/更新      2. 卸载"
        echo ""
        echo -e "${BOLD}═══════════════ 服务控制 ═══════════════${NC}"
        echo "  3. 启动    4. 停止    5. 重启"
        echo ""
        echo -e "${BOLD}═══════════════ ${YELLOW}域名与隧道${NC}${BOLD} ═══════════════${NC}"
        echo -e "  21. ${YELLOW}域名设置${NC}        22. ${YELLOW}证书配置${NC}"
        echo -e "  23. ${YELLOW}CF隧道${NC}          24. ${YELLOW}DDNS${NC}"
        echo ""
        echo -e "${BOLD}═══════════════ 核心调优 ═══════════════${NC}"
        echo "  13. Switcher    14. TLS/DPI    15. 性能"
        echo "  16. 协议开关    17. 网卡/eBPF  18. Metrics"
        echo ""
        echo -e "${BOLD}═══════════════ 基础与运维 ═══════════════${NC}"
        echo "  9. 基础配置   10. 实时日志   11. 服务详情"
        echo "  19. 配置管理  20. 诊断工具"
        echo ""
        echo "  0. 退出"
        echo ""
        read -rp "选择 [0-24]: " opt

        case $opt in
            1)  install_phantom ;;
            2)  uninstall_phantom ;;
            3)  echo ""; systemctl start phantom && success "已启动" || error "失败" ;;
            4)  echo ""; systemctl stop phantom && success "已停止" || error "失败" ;;
            5)  echo ""; systemctl restart phantom && success "已重启" || error "失败" ;;
            9)  manage_basic ;;
            10) echo "Ctrl+C 退出"; journalctl -u phantom -f -n 100 ;;
            11) systemctl status phantom --no-pager; echo ""; read -rp "Enter..." _ ;;
            13) manage_switcher ;;
            14) manage_tls ;;
            15) manage_perf ;;
            16) manage_protocols ;;
            17) manage_network ;;
            18) manage_metrics ;;
            19) view_config ;;
            20) diagnostic_tools; echo ""; read -rp "Enter..." _ ;;
            21) manage_domain ;;
            22) manage_cert ;;
            23) manage_tunnel ;;
            24) manage_ddns ;;
            0)  echo ""; echo "再见！"; exit 0 ;;
            *)  error "无效选项" ;;
        esac
        
        # 非菜单类操作后暂停
        if [[ "$opt" =~ ^(3|4|5)$ ]]; then
            echo ""
            read -rp "Enter继续..." _
        fi
    done
}

# ───────────────────────────────────────────────────────────────────────────────
# 入口
# ───────────────────────────────────────────────────────────────────────────────
check_root
main_menu
