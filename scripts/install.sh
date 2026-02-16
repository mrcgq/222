










#!/usr/bin/env bash
# =============================================================================
# Phantom Server 一键安装脚本 v6.1-fix
# 功能完善版：eBPF + 隧道 + 证书 + DDNS + TLS伪装 + 智能切换
# 修复：cloudflared 权限问题 + 路径统一
# =============================================================================

set -e
[[ ! -t 0 ]] && exec 0</dev/tty

# ─────────────────────────────────────────────────────────────────────────────
# 全局变量
# ─────────────────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/phantom"
EBPF_DIR="/opt/phantom/ebpf"
CONFIG_DIR="/etc/phantom"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
SERVICE_FILE="/etc/systemd/system/phantom.service"
CLOUDFLARED_DIR="/opt/phantom/bin"
CLOUDFLARED_PATH="${CLOUDFLARED_DIR}/cloudflared"

DOWNLOAD_URLS=(
    "https://github.com/mrcgq/222/releases/latest/download"
    "https://ghproxy.com/https://github.com/mrcgq/222/releases/latest/download"
)

# 颜色
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; NC='\033[0m'

# ─────────────────────────────────────────────────────────────────────────────
# 基础函数
# ─────────────────────────────────────────────────────────────────────────────
info()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; }
step()    { echo -e "${BLUE}${BOLD}==>${NC} $1"; }
success() { echo -e "${GREEN}${BOLD}[OK]${NC} $1"; }

check_root() {
    [[ $EUID -ne 0 ]] && { error "请使用 root 运行"; exit 1; }
}

get_arch() {
    case "$(uname -m)" in
        x86_64) echo "amd64" ;; aarch64) echo "arm64" ;; armv7l) echo "arm" ;; *) echo "amd64" ;;
    esac
}

get_iface() {
    ip route 2>/dev/null | grep default | awk '{print $5}' | head -1 || echo "eth0"
}

get_public_ip() {
    curl -s4 --connect-timeout 5 ip.sb 2>/dev/null || \
    curl -s4 --connect-timeout 5 ifconfig.me 2>/dev/null || \
    curl -s4 --connect-timeout 5 ipinfo.io/ip 2>/dev/null || \
    echo "未知"
}

generate_psk() {
    openssl rand -base64 32 2>/dev/null | tr -d '\n' || head -c 32 /dev/urandom | base64 | tr -d '\n'
}

# ─────────────────────────────────────────────────────────────────────────────
# YAML 操作函数
# ─────────────────────────────────────────────────────────────────────────────
yaml_set_top() {
    local key="$1" value="$2" file="${3:-$CONFIG_FILE}"
    if grep -q "^${key}:" "$file"; then
        sed -i "s|^${key}:.*|${key}: ${value}|" "$file"
    else
        echo "${key}: ${value}" >> "$file"
    fi
}

yaml_set_section() {
    local section="$1" key="$2" value="$3" file="${4:-$CONFIG_FILE}"
    awk -v sec="$section" -v k="$key" -v v="$value" '
    BEGIN { in_section=0; found=0 }
    {
        if ($0 ~ "^"sec":") { in_section=1; print; next }
        if (in_section && /^[a-zA-Z_]+:/ && $0 !~ "^"sec":") { in_section=0 }
        if (in_section && !found && $0 ~ "^[[:space:]]+"k":") {
            sub(/:[[:space:]]*.*/, ": "v)
            found=1
        }
        print
    }' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

yaml_get() {
    local section="$1" key="$2" file="${3:-$CONFIG_FILE}"
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
    }' "$file"
}

yaml_set_array() {
    local section="$1" key="$2" values="$3" file="${4:-$CONFIG_FILE}"
    local tmpfile=$(mktemp)
    awk -v sec="$section" -v k="$key" -v vals="$values" '
    BEGIN { in_section=0; in_array=0; split(vals, arr, ",") }
    {
        if ($0 ~ "^"sec":") { in_section=1; print; next }
        if (in_section && /^[a-zA-Z_]+:/ && $0 !~ "^"sec":") { in_section=0 }
        if (in_section && $0 ~ "^[[:space:]]+"k":") {
            in_array=1
            print
            for (i in arr) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", arr[i])
                print "    - \""arr[i]"\""
            }
            next
        }
        if (in_array && /^[[:space:]]+-/) { next }
        if (in_array && !/^[[:space:]]+-/) { in_array=0 }
        print
    }' "$file" > "$tmpfile" && mv "$tmpfile" "$file"
}

# ─────────────────────────────────────────────────────────────────────────────
# 文件验证
# ─────────────────────────────────────────────────────────────────────────────
is_valid_elf() {
    local file="$1"
    [[ ! -f "$file" || ! -s "$file" ]] && return 1
    local magic=$(od -A n -t x1 -N 4 "$file" 2>/dev/null | tr -d ' ')
    [[ "$magic" == "7f454c46" ]]
}

is_valid_executable() {
    local file="$1"
    [[ ! -f "$file" || ! -s "$file" ]] && return 1
    local magic=$(od -A n -t x1 -N 4 "$file" 2>/dev/null | tr -d ' ')
    [[ "$magic" == "7f454c46" ]] && return 0
    local head=$(head -c 2 "$file" 2>/dev/null)
    [[ "$head" == "#!" ]]
}

# ─────────────────────────────────────────────────────────────────────────────
# 系统依赖
# ─────────────────────────────────────────────────────────────────────────────
install_dependencies() {
    echo -n "  检查系统依赖... "
    local need_install=()
    command -v bpftool &>/dev/null || need_install+=("bpftool")
    command -v curl &>/dev/null || need_install+=("curl")
    
    if [[ ${#need_install[@]} -eq 0 ]]; then
        echo -e "${GREEN}完成${NC}"
        return 0
    fi
    
    echo ""
    echo "    安装依赖: ${need_install[*]}"
    
    if command -v apt-get &>/dev/null; then
        apt-get update -qq 2>/dev/null
        for pkg in "${need_install[@]}"; do
            case "$pkg" in
                bpftool)
                    apt-get install -y -qq linux-tools-common 2>/dev/null
                    apt-get install -y -qq "linux-tools-$(uname -r)" 2>/dev/null || \
                    apt-get install -y -qq linux-tools-generic 2>/dev/null || \
                    apt-get install -y -qq bpftool 2>/dev/null
                    ;;
                *) apt-get install -y -qq "$pkg" 2>/dev/null ;;
            esac
        done
    elif command -v yum &>/dev/null; then
        for pkg in "${need_install[@]}"; do yum install -y -q "$pkg" 2>/dev/null; done
    elif command -v dnf &>/dev/null; then
        for pkg in "${need_install[@]}"; do dnf install -y -q "$pkg" 2>/dev/null; done
    fi
    
    info "依赖安装完成"
}

# ─────────────────────────────────────────────────────────────────────────────
# eBPF 环境
# ─────────────────────────────────────────────────────────────────────────────
check_ebpf_support() {
    local supported="full"
    local kv_major=$(uname -r | cut -d. -f1)
    local kv_minor=$(uname -r | cut -d. -f2 | cut -d- -f1)
    
    [[ $kv_major -lt 5 ]] || [[ $kv_major -eq 5 && $kv_minor -lt 4 ]] && supported="none"
    
    local virt=$(systemd-detect-virt 2>/dev/null || echo "none")
    case "$virt" in
        openvz|lxc) supported="none" ;;
        docker|podman) [[ "$supported" == "full" ]] && supported="partial" ;;
    esac
    
    [[ ! -f "/sys/kernel/btf/vmlinux" ]] && [[ "$supported" == "full" ]] && supported="partial"
    
    # 启用 BPF JIT
    local jit=$(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null || echo "0")
    if [[ "$jit" != "1" ]]; then
        echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null
        grep -q "bpf_jit_enable" /etc/sysctl.conf 2>/dev/null || \
            echo "net.core.bpf_jit_enable = 1" >> /etc/sysctl.conf
    fi
    
    echo "$supported"
}

cleanup_ebpf_hooks() {
    local iface=$(get_iface)
    echo -n "  清理旧 eBPF 钩子... "
    
    ip link set dev "$iface" xdp off 2>/dev/null
    ip link set dev "$iface" xdpgeneric off 2>/dev/null
    ip link set dev "$iface" xdpdrv off 2>/dev/null
    
    tc qdisc del dev "$iface" clsact 2>/dev/null
    rm -rf /sys/fs/bpf/phantom 2>/dev/null
    
    if command -v bpftool &>/dev/null; then
        bpftool prog list 2>/dev/null | grep -E "phantom" | \
            awk '{print $1}' | tr -d ':' | while read id; do
                [[ -n "$id" ]] && bpftool prog detach id "$id" 2>/dev/null
            done
    fi
    
    echo -e "${GREEN}完成${NC}"
}

setup_bpf_filesystem() {
    echo -n "  配置 BPF 文件系统... "
    
    # 挂载 BPF 文件系统
    if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
        mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
    fi
    
    # 创建 phantom 目录并设置权限
    mkdir -p /sys/fs/bpf/phantom 2>/dev/null || true
    chmod 755 /sys/fs/bpf/phantom 2>/dev/null || true
    
    echo -e "${GREEN}完成${NC}"
}

# ─────────────────────────────────────────────────────────────────────────────
# 下载功能
# ─────────────────────────────────────────────────────────────────────────────
download_file() {
    local filename="$1" output="$2"
    local temp_file="${output}.tmp"
    
    for base_url in "${DOWNLOAD_URLS[@]}"; do
        echo -n "    尝试 $(echo $base_url | cut -d'/' -f3)... "
        rm -f "$temp_file"
        
        if curl -fsSL --connect-timeout 15 --max-time 60 -o "$temp_file" "${base_url}/${filename}" 2>/dev/null; then
            if [[ -s "$temp_file" ]]; then
                local head=$(head -c 10 "$temp_file" 2>/dev/null)
                if [[ "$head" == "<!DOCTYPE"* ]] || [[ "$head" == "<html"* ]]; then
                    echo -e "${RED}失败 (HTML)${NC}"
                    rm -f "$temp_file"
                    continue
                fi
                mv "$temp_file" "$output"
                echo -e "${GREEN}成功${NC}"
                return 0
            fi
        fi
        echo -e "${RED}失败${NC}"
        rm -f "$temp_file"
    done
    return 1
}

download_ebpf_programs() {
    echo "  下载 eBPF 内核程序..."
    mkdir -p "$EBPF_DIR"
    
    local arch=$(get_arch)
    local files=("xdp_phantom.o" "tc_phantom.o")
    local success_count=0
    
    for file in "${files[@]}"; do
        local downloaded=false
        local paths=("ebpf-${arch}/${file}" "ebpf/${arch}/${file}" "ebpf/${file}" "${file}")
        
        for path in "${paths[@]}"; do
            if download_file "$path" "${EBPF_DIR}/${file}"; then
                if is_valid_elf "${EBPF_DIR}/${file}"; then
                    info "    ${file} 验证通过"
                    ((success_count++))
                    downloaded=true
                    break
                else
                    rm -f "${EBPF_DIR}/${file}"
                fi
            fi
        done
        
        $downloaded || warn "    无法下载 ${file}"
    done
    
    chmod 644 "${EBPF_DIR}"/*.o 2>/dev/null
    
    if [[ $success_count -ge 1 ]] && [[ -f "${EBPF_DIR}/xdp_phantom.o" ]]; then
        info "eBPF 内核程序已就绪 (${success_count}/2)"
        return 0
    else
        warn "eBPF 程序不完整，将使用用户态模式"
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Cloudflared 管理 (重点修复)
# ─────────────────────────────────────────────────────────────────────────────
fix_cloudflared_permissions() {
    echo -n "  修复 cloudflared 权限... "
    
    # 修复所有可能位置的 cloudflared
    local dirs=("$CLOUDFLARED_DIR" "/root/.phantom/bin" "/usr/local/bin" "/opt/phantom/bin")
    
    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            # 修复所有 cloudflared 相关文件的权限
            find "$dir" -type f -name "cloudflared*" -exec chmod +x {} \; 2>/dev/null
        fi
    done
    
    # 创建统一的软链接到 /usr/local/bin
    local found_cf=""
    for dir in "${dirs[@]}"; do
        for cf in "$dir"/cloudflared* ; do
            if [[ -f "$cf" ]] && is_valid_executable "$cf"; then
                found_cf="$cf"
                break 2
            fi
        done
    done
    
    if [[ -n "$found_cf" ]]; then
        ln -sf "$found_cf" /usr/local/bin/cloudflared 2>/dev/null || true
        ln -sf "$found_cf" "${CLOUDFLARED_DIR}/cloudflared" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}完成${NC}"
}

download_cloudflared() {
    mkdir -p "$CLOUDFLARED_DIR"
    mkdir -p "/root/.phantom/bin"
    
    local arch=$(get_arch)
    local cf_file="cloudflared-linux-${arch}"
    
    # 检查是否已存在可用的 cloudflared
    local existing_cf=""
    for path in "$CLOUDFLARED_PATH" "/usr/local/bin/cloudflared" "/root/.phantom/bin/cloudflared"*; do
        if [[ -f "$path" ]] && [[ -x "$path" ]]; then
            existing_cf="$path"
            break
        fi
    done
    
    if [[ -n "$existing_cf" ]]; then
        info "cloudflared 已存在: $existing_cf"
        # 确保权限正确
        chmod +x "$existing_cf"
        # 创建软链接
        ln -sf "$existing_cf" "$CLOUDFLARED_PATH" 2>/dev/null || true
        ln -sf "$existing_cf" /usr/local/bin/cloudflared 2>/dev/null || true
        return 0
    fi
    
    echo "  下载 cloudflared..."
    local cf_urls=(
        "https://github.com/cloudflare/cloudflared/releases/latest/download/${cf_file}"
        "https://ghproxy.com/https://github.com/cloudflare/cloudflared/releases/latest/download/${cf_file}"
    )
    
    for url in "${cf_urls[@]}"; do
        echo -n "    尝试 $(echo $url | cut -d'/' -f3)... "
        if curl -fsSL --connect-timeout 15 -o "$CLOUDFLARED_PATH" "$url" 2>/dev/null; then
            if [[ -s "$CLOUDFLARED_PATH" ]]; then
                chmod +x "$CLOUDFLARED_PATH"
                # 创建多个软链接确保兼容性
                ln -sf "$CLOUDFLARED_PATH" /usr/local/bin/cloudflared 2>/dev/null || true
                ln -sf "$CLOUDFLARED_PATH" /root/.phantom/bin/cloudflared 2>/dev/null || true
                echo -e "${GREEN}成功${NC}"
                info "cloudflared 已安装并设置权限"
                return 0
            fi
        fi
        echo -e "${RED}失败${NC}"
    done
    
    warn "cloudflared 下载失败，隧道功能可能不可用"
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# 服务管理
# ─────────────────────────────────────────────────────────────────────────────
safe_stop_service() {
    echo -n "  停止服务... "
    systemctl stop phantom 2>/dev/null
    
    local max_wait=10 waited=0
    while pgrep -f "phantom-server" &>/dev/null && [[ $waited -lt $max_wait ]]; do
        sleep 1
        ((waited++))
    done
    pkill -9 -f "phantom-server" 2>/dev/null
    echo -e "${GREEN}完成${NC}"
}

pre_start_cleanup() {
    step "执行启动前清理"
    safe_stop_service
    cleanup_ebpf_hooks
    setup_bpf_filesystem
    fix_cloudflared_permissions
    sleep 2
}

apply_config() {
    # 每次应用配置前都修复权限
    fix_cloudflared_permissions
    
    systemctl daemon-reload
    systemctl restart phantom 2>/dev/null
    sleep 3
    
    if systemctl is-active --quiet phantom; then
        success "服务已启动"
        return 0
    else
        error "服务启动失败"
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# 创建权限修复脚本 (关键新增)
# ─────────────────────────────────────────────────────────────────────────────
create_fix_permissions_script() {
    cat > /opt/phantom/fix-permissions.sh << 'FIXSCRIPT'
#!/bin/bash
# Phantom 权限修复脚本 - 每次启动前执行

# 修复 cloudflared 权限
for dir in /opt/phantom/bin /root/.phantom/bin /usr/local/bin; do
    if [[ -d "$dir" ]]; then
        find "$dir" -type f -name "cloudflared*" -exec chmod +x {} \; 2>/dev/null
    fi
done

# 创建软链接
for cf in /root/.phantom/bin/cloudflared* /opt/phantom/bin/cloudflared*; do
    if [[ -f "$cf" && -x "$cf" ]]; then
        ln -sf "$cf" /usr/local/bin/cloudflared 2>/dev/null
        ln -sf "$cf" /opt/phantom/bin/cloudflared 2>/dev/null
        break
    fi
done

# 修复主程序权限
chmod +x /opt/phantom/phantom-server 2>/dev/null

# 设置 BPF 文件系统
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf 2>/dev/null
mkdir -p /sys/fs/bpf/phantom 2>/dev/null
chmod 755 /sys/fs/bpf/phantom 2>/dev/null

exit 0
FIXSCRIPT
    chmod +x /opt/phantom/fix-permissions.sh
}

# ─────────────────────────────────────────────────────────────────────────────
# 显示函数
# ─────────────────────────────────────────────────────────────────────────────
print_logo() {
    clear
    echo -e "${CYAN}"
    echo '  ____  _                 _                  '
    echo ' |  _ \| |__   __ _ _ __ | |_ ___  _ __ ___  '
    echo ' | |_) |  _ \ / _` |  _ \| __/ _ \|  _ ` _ \ '
    echo ' |  __/| | | | (_| | | | | || (_) | | | | | |'
    echo ' |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|'
    echo -e "${NC}"
    echo -e "                                    ${BOLD}v6.1-fix${NC}"
    echo ""
}

show_status() {
    local status=$(systemctl is-active phantom 2>/dev/null || echo "未安装")
    local color="$RED" status_text="✗ 未安装"
    
    case "$status" in
        active)   color="$GREEN"; status_text="● 运行中" ;;
        inactive) color="$YELLOW"; status_text="○ 已停止" ;;
        failed)   color="$RED"; status_text="✗ 启动失败" ;;
    esac
    
    echo -e "状态: ${color}${BOLD}${status_text}${NC}"
    
    if [[ "$status" == "active" ]]; then
        local mode=$(journalctl -u phantom -n 50 --no-pager 2>/dev/null | grep -oP '当前模式: \K\w+' | tail -1)
        [[ -n "$mode" ]] && echo -e "模式: ${CYAN}${mode}${NC}"
    fi
}

show_connection_info() {
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━ 连接信息 ━━━━━━━━━━━━━━━━━${NC}"
    
    local ip=$(get_public_ip)
    local port=$(grep "^listen:" "$CONFIG_FILE" 2>/dev/null | grep -oP ':\K\d+')
    local psk=$(grep "^psk:" "$CONFIG_FILE" 2>/dev/null | awk '{print $2}' | tr -d '"')
    
    echo -e "  📍 IP:   ${CYAN}${ip}${NC}"
    echo -e "  🔌 端口: ${CYAN}${port:-54321}${NC}"
    echo -e "  🔑 PSK:  ${CYAN}${psk:-未配置}${NC}"
    
    # 隧道信息
    local tunnel_enabled=$(yaml_get "tunnel" "enabled")
    if [[ "$tunnel_enabled" == "true" ]]; then
        local tunnel_url=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | \
                          grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
        if [[ -n "$tunnel_url" ]]; then
            echo -e "  🌐 隧道: ${CYAN}${tunnel_url}${NC}"
        else
            echo -e "  🌐 隧道: ${YELLOW}已启用，等待URL...${NC}"
        fi
    fi
    
    # eBPF 状态
    local ebpf_active=$(journalctl -u phantom -n 30 --no-pager 2>/dev/null | grep -q "eBPF.*挂载\|eBPF.*就绪" && echo "true")
    if [[ "$ebpf_active" == "true" ]]; then
        echo -e "  ⚡ eBPF: ${GREEN}已启用${NC}"
    else
        local ebpf_enabled=$(yaml_get "ebpf" "enabled")
        if [[ "$ebpf_enabled" == "true" ]]; then
            echo -e "  ⚡ eBPF: ${YELLOW}已配置${NC}"
        else
            echo -e "  ⚡ eBPF: ${RED}未启用${NC}"
        fi
    fi
    
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
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
    
    # ═══════════════════════════════════════════════════════════════════════
    # 第 1 步：基础配置
    # ═══════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 1 步：基础配置"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    read -rp "  监听端口 [54321]: " input_port
    local PORT=${input_port:-54321}
    info "端口: ${PORT}"
    
    local PSK=$(generate_psk)
    info "PSK 已生成: ${CYAN}${PSK}${NC}"
    
    # ═══════════════════════════════════════════════════════════════════════
    # 第 2 步：环境检测
    # ═══════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 2 步：环境检测"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    install_dependencies
    setup_bpf_filesystem
    
    local ebpf_support=$(check_ebpf_support)
    local ebpf_enabled="false"
    local xdp_mode="generic"
    
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
    
    # ═══════════════════════════════════════════════════════════════════════
    # 第 3 步：选择连接方式
    # ═══════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 3 步：选择连接方式"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${CYAN}1${NC}. IP 直连 ${GREEN}(最简单)${NC}"
    echo -e "  ${CYAN}2${NC}. Cloudflare 隧道 ${GREEN}(推荐，无需公网IP)${NC}"
    echo -e "  ${CYAN}3${NC}. 自己的域名 (需配置DNS)"
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
            echo -e "  ${CYAN}a${NC}. 临时隧道 (无需配置，自动获取URL)"
            echo -e "  ${CYAN}b${NC}. 固定隧道 (需要 Cloudflare Token)"
            read -rp "选择 [a/b，默认 a]: " tm
            
            if [[ "$tm" =~ ^[Bb]$ ]]; then
                TUNNEL_MODE="fixed"
                read -rp "  Cloudflare Tunnel Token: " CF_TOKEN
                [[ -z "$CF_TOKEN" ]] && { TUNNEL_MODE="temp"; warn "Token为空，使用临时隧道"; }
            fi
            info "隧道模式: ${TUNNEL_MODE}"
            
            # 下载 cloudflared
            download_cloudflared
            ;;
        3)
            read -rp "  域名 (如 vpn.example.com): " DOMAIN
            [[ -n "$DOMAIN" ]] && info "域名: ${DOMAIN}"
            ;;
    esac
    
    # ═══════════════════════════════════════════════════════════════════════
    # 第 4 步：下载程序
    # ═══════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 4 步：下载程序"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$EBPF_DIR" "$CLOUDFLARED_DIR"
    local arch=$(get_arch)
    info "系统: linux/${arch}"
    
    # 下载主程序
    echo "  下载主程序..."
    if [[ -f "./phantom-server" ]]; then
        cp "./phantom-server" "$INSTALL_DIR/phantom-server"
        chmod +x "$INSTALL_DIR/phantom-server"
        info "使用本地文件"
    elif [[ -x "$INSTALL_DIR/phantom-server" ]] && is_valid_executable "$INSTALL_DIR/phantom-server"; then
        info "使用已安装版本"
    else
        if ! download_file "phantom-server-linux-${arch}" "$INSTALL_DIR/phantom-server"; then
            download_file "phantom-server" "$INSTALL_DIR/phantom-server" || { error "下载失败"; exit 1; }
        fi
        chmod +x "$INSTALL_DIR/phantom-server"
    fi
    
    # 验证主程序
    is_valid_executable "$INSTALL_DIR/phantom-server" || { error "程序文件无效"; exit 1; }
    
    # 下载 eBPF 程序
    if [[ "$ebpf_support" != "none" ]]; then
        download_ebpf_programs && ebpf_enabled="true"
    fi
    
    # 创建权限修复脚本
    create_fix_permissions_script
    
    # ═══════════════════════════════════════════════════════════════════════
    # 第 5 步：生成配置
    # ═══════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 5 步：生成配置"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    local iface=$(get_iface)
    
    cat > "$CONFIG_FILE" << EOF
# ═══════════════════════════════════════════════════════════════════════════════
# Phantom Server v6.1-fix 配置文件
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# ═══════════════════════════════════════════════════════════════════════════════

# 基础配置
listen: ":${PORT}"
psk: "${PSK}"
time_window: 30
log_level: "info"
mode: "auto"

# ───────────────────────────────────────────────────────────────────────────────
# Cloudflare 隧道
# ───────────────────────────────────────────────────────────────────────────────
tunnel:
  enabled: ${USE_TUNNEL}
  mode: "${TUNNEL_MODE}"
  cf_token: "${CF_TOKEN}"
  local_addr: "127.0.0.1"
  local_port: ${PORT}
  protocol: "http"
  cloudflared_path: "/usr/local/bin/cloudflared"

# ───────────────────────────────────────────────────────────────────────────────
# DDNS 动态域名
# ───────────────────────────────────────────────────────────────────────────────
ddns:
  enabled: false
  provider: "none"
  update_interval: "5m"
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
# 证书配置
# ───────────────────────────────────────────────────────────────────────────────
cert:
  mode: "auto"
  domain: "${DOMAIN}"
  email: ""
  cert_file: ""
  key_file: ""
  acme_provider: "letsencrypt"
  acme_use_tunnel: true

# ───────────────────────────────────────────────────────────────────────────────
# TLS 深度伪装
# ───────────────────────────────────────────────────────────────────────────────
tls:
  enabled: false
  server_name: "${DOMAIN:-www.microsoft.com}"
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
  fragment:
    enabled: true
    size: 40
    sleep_ms: 10
  fallback:
    enabled: true
    addr: "127.0.0.1:80"
    timeout_ms: 5000

# ───────────────────────────────────────────────────────────────────────────────
# eBPF 内核加速
# ───────────────────────────────────────────────────────────────────────────────
ebpf:
  enabled: ${ebpf_enabled}
  interface: "${iface}"
  xdp_mode: "${xdp_mode}"
  program_path: "${EBPF_DIR}"
  map_size: 65536
  enable_stats: true
  enable_tc: true

# ───────────────────────────────────────────────────────────────────────────────
# FakeTCP 伪装
# ───────────────────────────────────────────────────────────────────────────────
faketcp:
  enabled: true
  listen: ":$((PORT+1))"
  interface: "${iface}"
  use_ebpf: false
  mtu: 1400

# ───────────────────────────────────────────────────────────────────────────────
# WebSocket 传输
# ───────────────────────────────────────────────────────────────────────────────
websocket:
  enabled: true
  listen: ":$((PORT+2))"
  path: "/ws"
  host: ""
  tls: false
  compression: false

# ───────────────────────────────────────────────────────────────────────────────
# Hysteria2 拥塞控制
# ───────────────────────────────────────────────────────────────────────────────
hysteria2:
  enabled: true
  up_mbps: 100
  down_mbps: 100
  loss_threshold: 0.1

# ───────────────────────────────────────────────────────────────────────────────
# ARQ 可靠传输
# ───────────────────────────────────────────────────────────────────────────────
arq:
  enabled: true
  window_size: 256
  max_retries: 10
  rto_min_ms: 100
  rto_max_ms: 10000
  enable_sack: true

# ───────────────────────────────────────────────────────────────────────────────
# 智能切换器
# ───────────────────────────────────────────────────────────────────────────────
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

# ───────────────────────────────────────────────────────────────────────────────
# 监控指标
# ───────────────────────────────────────────────────────────────────────────────
metrics:
  enabled: true
  listen: ":9100"
  path: "/metrics"
  health_path: "/health"
  enable_pprof: false
EOF
    
    info "配置已生成"
    
    # ═══════════════════════════════════════════════════════════════════════
    # 第 6 步：配置服务 (关键修复：添加 ExecStartPre 权限修复)
    # ═══════════════════════════════════════════════════════════════════════
    echo ""
    step "第 6 步：配置服务"
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Phantom Server v6.1-fix
Documentation=https://github.com/mrcgq/222
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}

# 启动前执行权限修复脚本
ExecStartPre=/opt/phantom/fix-permissions.sh
ExecStartPre=-/sbin/ip link set dev ${iface} xdp off
ExecStartPre=-/bin/rm -rf /sys/fs/bpf/phantom
ExecStartPre=-/bin/mkdir -p /sys/fs/bpf/phantom
ExecStartPre=-/bin/chmod 755 /sys/fs/bpf/phantom

ExecStart=${INSTALL_DIR}/phantom-server -c ${CONFIG_FILE}

ExecStopPost=-/sbin/ip link set dev ${iface} xdp off
ExecStopPost=-/bin/rm -rf /sys/fs/bpf/phantom

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
    
    # ═══════════════════════════════════════════════════════════════════════
    # 第 7 步：启动服务
    # ═══════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    step "第 7 步：启动服务"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    pre_start_cleanup
    
    echo -n "  启动服务... "
    systemctl start phantom
    sleep 3
    
    if systemctl is-active --quiet phantom; then
        echo -e "${GREEN}成功${NC}"
        
        # 等待隧道URL
        if [[ "$USE_TUNNEL" == "true" ]]; then
            echo -n "  等待隧道URL... "
            local max_wait=15
            local waited=0
            local tunnel_url=""
            
            while [[ $waited -lt $max_wait ]]; do
                sleep 2
                ((waited+=2))
                tunnel_url=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | \
                              grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
                if [[ -n "$tunnel_url" ]]; then
                    echo -e "${GREEN}成功${NC}"
                    echo -e "  隧道地址: ${CYAN}${tunnel_url}${NC}"
                    break
                fi
            done
            
            if [[ -z "$tunnel_url" ]]; then
                echo -e "${YELLOW}等待中${NC}"
                echo "  请稍后执行: journalctl -u phantom | grep trycloudflare"
            fi
        fi
        
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}${BOLD}           🎉 安装完成！${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        show_connection_info
    else
        echo -e "${RED}失败${NC}"
        echo ""
        echo "最近日志:"
        journalctl -u phantom -n 30 --no-pager
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# 管理功能
# ─────────────────────────────────────────────────────────────────────────────

manage_tunnel() {
    print_logo
    step "Cloudflare 隧道管理"
    echo ""
    
    local tunnel_st=$(yaml_get "tunnel" "enabled")
    local tunnel_mode=$(yaml_get "tunnel" "mode")
    
    echo -e "当前状态: ${CYAN}${tunnel_st}${NC}"
    echo -e "模式: ${CYAN}${tunnel_mode}${NC}"
    
    # 显示当前隧道URL
    if [[ "$tunnel_st" == "true" ]]; then
        local tunnel_url=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | \
                          grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
        [[ -n "$tunnel_url" ]] && echo -e "隧道URL: ${CYAN}${tunnel_url}${NC}"
    fi
    
    echo ""
    echo "─────────────────────────────────────"
    echo "1. 启用临时隧道"
    echo "2. 启用固定隧道"
    echo "3. 禁用隧道"
    echo "4. 查看隧道日志"
    echo "5. 修复 cloudflared 权限"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
        1)
            download_cloudflared
            fix_cloudflared_permissions
            yaml_set_section "tunnel" "enabled" "true"
            yaml_set_section "tunnel" "mode" "\"temp\""
            info "临时隧道已启用"
            apply_config
            sleep 5
            echo ""
            echo "隧道日志:"
            journalctl -u phantom -n 30 --no-pager | grep -E "隧道|tunnel|trycloudflare"
            ;;
        2)
            read -rp "Cloudflare Tunnel Token: " cf_token
            if [[ -n "$cf_token" ]]; then
                download_cloudflared
                fix_cloudflared_permissions
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
            echo ""
            journalctl -u phantom -n 50 --no-pager | grep -E "隧道|tunnel|Tunnel|cloudflare|permission"
            ;;
        5)
            fix_cloudflared_permissions
            echo ""
            echo "cloudflared 文件状态:"
            ls -la /opt/phantom/bin/cloudflared* 2>/dev/null || echo "  /opt/phantom/bin/ 无文件"
            ls -la /root/.phantom/bin/cloudflared* 2>/dev/null || echo "  /root/.phantom/bin/ 无文件"
            ls -la /usr/local/bin/cloudflared* 2>/dev/null || echo "  /usr/local/bin/ 无文件"
            ;;
    esac
}

manage_ddns() {
    print_logo
    step "DDNS 动态域名管理"
    echo ""
    
    local ddns_enabled=$(yaml_get "ddns" "enabled")
    local ddns_provider=$(yaml_get "ddns" "provider")
    
    echo -e "当前状态: ${CYAN}${ddns_enabled}${NC}"
    echo -e "提供商: ${CYAN}${ddns_provider}${NC}"
    echo ""
    echo "─────────────────────────────────────"
    echo "1. 配置 DuckDNS"
    echo "2. 配置 FreeDNS"
    echo "3. 配置 Cloudflare DNS"
    echo "4. 禁用 DDNS"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
        1)
            echo ""
            echo "DuckDNS 配置说明:"
            echo "  1. 访问 https://www.duckdns.org 注册"
            echo "  2. 创建子域名并获取 Token"
            echo ""
            read -rp "DuckDNS Token: " duck_token
            read -rp "子域名 (不含 .duckdns.org): " duck_domain
            
            if [[ -n "$duck_token" && -n "$duck_domain" ]]; then
                yaml_set_section "ddns" "enabled" "true"
                yaml_set_section "ddns" "provider" "\"duckdns\""
                # 直接修改配置文件
                sed -i "/duckdns:/,/freedns:/ s/token:.*/token: \"${duck_token}\"/" "$CONFIG_FILE"
                sed -i "/duckdns:/,/freedns:/ s/domains:.*/domains: \"${duck_domain}\"/" "$CONFIG_FILE"
                info "DuckDNS 已配置: ${duck_domain}.duckdns.org"
                apply_config
            else
                error "Token 和域名不能为空"
            fi
            ;;
        2)
            read -rp "FreeDNS Update Token: " free_token
            if [[ -n "$free_token" ]]; then
                yaml_set_section "ddns" "enabled" "true"
                yaml_set_section "ddns" "provider" "\"freedns\""
                sed -i "/freedns:/,/cloudflare:/ s/token:.*/token: \"${free_token}\"/" "$CONFIG_FILE"
                info "FreeDNS 已配置"
                apply_config
            fi
            ;;
        3)
            read -rp "Cloudflare API Token: " cf_api
            read -rp "Zone ID: " cf_zone
            read -rp "记录名 (如 vpn.example.com): " cf_record
            
            if [[ -n "$cf_api" && -n "$cf_zone" && -n "$cf_record" ]]; then
                yaml_set_section "ddns" "enabled" "true"
                yaml_set_section "ddns" "provider" "\"cloudflare\""
                sed -i "/cloudflare:/,/^[a-z]/ s/api_token:.*/api_token: \"${cf_api}\"/" "$CONFIG_FILE"
                sed -i "/cloudflare:/,/^[a-z]/ s/zone_id:.*/zone_id: \"${cf_zone}\"/" "$CONFIG_FILE"
                sed -i "/cloudflare:/,/^[a-z]/ s/record_name:.*/record_name: \"${cf_record}\"/" "$CONFIG_FILE"
                info "Cloudflare DNS 已配置"
                apply_config
            fi
            ;;
        4)
            yaml_set_section "ddns" "enabled" "false"
            info "DDNS 已禁用"
            apply_config
            ;;
    esac
}

manage_cert() {
    print_logo
    step "证书管理"
    echo ""
    
    local cert_mode=$(yaml_get "cert" "mode")
    local domain=$(yaml_get "cert" "domain")
    
    echo -e "当前模式: ${CYAN}${cert_mode}${NC}"
    echo -e "域名: ${CYAN}${domain:-未配置}${NC}"
    echo ""
    echo "─────────────────────────────────────"
    echo "1. 配置 ACME 自动申请 (Let's Encrypt)"
    echo "2. 使用自签名证书"
    echo "3. 使用自定义证书"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
        1)
            read -rp "域名: " domain
            read -rp "邮箱: " email
            
            if [[ -n "$domain" && -n "$email" ]]; then
                yaml_set_section "cert" "mode" "\"acme\""
                yaml_set_section "cert" "domain" "\"${domain}\""
                yaml_set_section "cert" "email" "\"${email}\""
                yaml_set_section "tls" "server_name" "\"${domain}\""
                info "ACME 配置完成"
                echo ""
                echo "证书将在首次连接时自动申请"
                apply_config
            fi
            ;;
        2)
            yaml_set_section "cert" "mode" "\"self-signed\""
            info "将使用自签名证书"
            apply_config
            ;;
        3)
            read -rp "证书文件路径: " cert_path
            read -rp "私钥文件路径: " key_path
            
            if [[ -f "$cert_path" && -f "$key_path" ]]; then
                yaml_set_section "cert" "mode" "\"manual\""
                yaml_set_section "cert" "cert_file" "\"${cert_path}\""
                yaml_set_section "cert" "key_file" "\"${key_path}\""
                info "自定义证书已配置"
                apply_config
            else
                error "文件不存在"
            fi
            ;;
    esac
}

manage_tls() {
    print_logo
    step "TLS 伪装设置"
    echo ""
    
    local tls_enabled=$(yaml_get "tls" "enabled")
    local sni=$(yaml_get "tls" "server_name")
    local fp=$(yaml_get "tls" "fingerprint")
    
    echo -e "TLS 状态: ${CYAN}${tls_enabled}${NC}"
    echo -e "SNI: ${CYAN}${sni}${NC}"
    echo -e "指纹: ${CYAN}${fp}${NC}"
    echo ""
    echo "─────────────────────────────────────"
    echo "1. 启用/禁用 TLS 伪装"
    echo "2. 修改 SNI (伪装域名)"
    echo "3. 修改指纹类型"
    echo "4. 修改分片设置"
    echo "5. 配置回落"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
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
            echo "常用伪装域名:"
            echo "  www.microsoft.com"
            echo "  www.apple.com"
            echo "  www.cloudflare.com"
            read -rp "SNI 域名: " new_sni
            [[ -n "$new_sni" ]] && yaml_set_section "tls" "server_name" "\"${new_sni}\""
            apply_config
            ;;
        3)
            echo ""
            echo "可用指纹: chrome, firefox, safari, edge, ios, android, random"
            read -rp "指纹: " new_fp
            [[ -n "$new_fp" ]] && yaml_set_section "tls" "fingerprint" "\"${new_fp}\""
            apply_config
            ;;
        4)
            echo ""
            echo "分片可绕过 SNI 嗅探"
            read -rp "分片大小 [40]: " frag_size
            read -rp "分片间隔 ms [10]: " frag_sleep
            
            [[ -n "$frag_size" ]] && sed -i "/fragment:/,/fallback:/ s/size:.*/size: ${frag_size}/" "$CONFIG_FILE"
            [[ -n "$frag_sleep" ]] && sed -i "/fragment:/,/fallback:/ s/sleep_ms:.*/sleep_ms: ${frag_sleep}/" "$CONFIG_FILE"
            apply_config
            ;;
        5)
            echo ""
            echo "回落: 非法连接将转发到伪装站点"
            read -rp "回落地址 [127.0.0.1:80]: " fb_addr
            fb_addr=${fb_addr:-127.0.0.1:80}
            sed -i "/fallback:/,/^[a-z]/ s|addr:.*|addr: \"${fb_addr}\"|" "$CONFIG_FILE"
            apply_config
            ;;
    esac
}

manage_switcher() {
    print_logo
    step "智能切换器设置"
    echo ""
    
    local interval=$(yaml_get "switcher" "check_interval_ms")
    local rtt_th=$(yaml_get "switcher" "rtt_threshold_ms")
    local loss_th=$(yaml_get "switcher" "loss_threshold")
    
    echo -e "检测间隔: ${CYAN}${interval:-1000}ms${NC}"
    echo -e "RTT阈值: ${CYAN}${rtt_th:-300}ms${NC}"
    echo -e "丢包阈值: ${CYAN}${loss_th:-0.3}${NC}"
    echo ""
    echo "─────────────────────────────────────"
    echo "1. 修改优先级"
    echo "2. 修改检测间隔"
    echo "3. 修改 RTT 阈值"
    echo "4. 修改丢包阈值"
    echo "5. 锁定单一模式"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
        1)
            echo ""
            echo "可用: ebpf, faketcp, udp, tcp, websocket"
            read -rp "优先级 (逗号分隔): " priority
            [[ -n "$priority" ]] && yaml_set_array "switcher" "priority" "$priority"
            apply_config
            ;;
        2)
            read -rp "检测间隔 ms: " new_interval
            [[ "$new_interval" =~ ^[0-9]+$ ]] && yaml_set_section "switcher" "check_interval_ms" "$new_interval"
            apply_config
            ;;
        3)
            read -rp "RTT 阈值 ms: " new_rtt
            [[ "$new_rtt" =~ ^[0-9]+$ ]] && yaml_set_section "switcher" "rtt_threshold_ms" "$new_rtt"
            apply_config
            ;;
        4)
            read -rp "丢包阈值 (0-1): " new_loss
            [[ "$new_loss" =~ ^[0-9]*\.?[0-9]+$ ]] && yaml_set_section "switcher" "loss_threshold" "$new_loss"
            apply_config
            ;;
        5)
            echo "可选: auto, ebpf, faketcp, udp, websocket"
            read -rp "锁定模式: " lock_mode
            yaml_set_top "mode" "\"${lock_mode}\""
            apply_config
            ;;
    esac
}

manage_basic() {
    print_logo
    step "基础配置"
    echo ""
    
    local port=$(grep "^listen:" "$CONFIG_FILE" | grep -oP ':\K\d+')
    local psk=$(grep "^psk:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
    local log_level=$(grep "^log_level:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
    
    echo -e "端口: ${CYAN}${port}${NC}"
    echo -e "PSK: ${CYAN}${psk}${NC}"
    echo -e "日志级别: ${CYAN}${log_level}${NC}"
    echo ""
    echo "─────────────────────────────────────"
    echo "1. 修改端口"
    echo "2. 重置 PSK"
    echo "3. 修改日志级别"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
        1)
            read -rp "新端口: " new_port
            if [[ "$new_port" =~ ^[0-9]+$ ]]; then
                yaml_set_top "listen" "\":${new_port}\""
                yaml_set_section "tunnel" "local_port" "$new_port"
                yaml_set_section "faketcp" "listen" "\":$((new_port+1))\""
                yaml_set_section "websocket" "listen" "\":$((new_port+2))\""
                info "端口已更新"
                apply_config
            fi
            ;;
        2)
            local new_psk=$(generate_psk)
            yaml_set_top "psk" "\"${new_psk}\""
            info "新 PSK: ${CYAN}${new_psk}${NC}"
            apply_config
            ;;
        3)
            echo "可选: debug, info, warn, error"
            read -rp "日志级别: " level
            yaml_set_top "log_level" "\"${level}\""
            apply_config
            ;;
    esac
}

manage_protocols() {
    print_logo
    step "协议模块开关"
    echo ""
    
    local faketcp_st=$(yaml_get "faketcp" "enabled")
    local ws_st=$(yaml_get "websocket" "enabled")
    local ebpf_st=$(yaml_get "ebpf" "enabled")
    
    echo -e "FakeTCP:   ${CYAN}${faketcp_st}${NC}"
    echo -e "WebSocket: ${CYAN}${ws_st}${NC}"
    echo -e "eBPF:      ${CYAN}${ebpf_st}${NC}"
    echo ""
    echo "─────────────────────────────────────"
    echo "1. 切换 FakeTCP"
    echo "2. 切换 WebSocket"
    echo "3. 切换 eBPF"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
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
    esac
}

manage_perf() {
    print_logo
    step "性能调优 (Hysteria2 & ARQ)"
    echo ""
    
    local h2_enabled=$(yaml_get "hysteria2" "enabled")
    local up=$(yaml_get "hysteria2" "up_mbps")
    local down=$(yaml_get "hysteria2" "down_mbps")
    local arq_enabled=$(yaml_get "arq" "enabled")
    local ws=$(yaml_get "arq" "window_size")
    
    echo -e "${CYAN}═══ Hysteria2 ═══${NC}"
    echo -e "状态: ${h2_enabled} | 上行: ${up}Mbps | 下行: ${down}Mbps"
    echo ""
    echo -e "${CYAN}═══ ARQ ═══${NC}"
    echo -e "状态: ${arq_enabled} | 窗口: ${ws}"
    echo ""
    echo "─────────────────────────────────────"
    echo "1. 切换 Hysteria2"
    echo "2. 修改带宽限制"
    echo "3. 切换 ARQ"
    echo "4. 修改 ARQ 窗口"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
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
            read -rp "上行 Mbps: " new_up
            read -rp "下行 Mbps: " new_down
            [[ "$new_up" =~ ^[0-9]+$ ]] && yaml_set_section "hysteria2" "up_mbps" "$new_up"
            [[ "$new_down" =~ ^[0-9]+$ ]] && yaml_set_section "hysteria2" "down_mbps" "$new_down"
            apply_config
            ;;
        3)
            if [[ "$arq_enabled" == "true" ]]; then
                yaml_set_section "arq" "enabled" "false"
                info "ARQ 已禁用"
            else
                yaml_set_section "arq" "enabled" "true"
                info "ARQ 已启用"
            fi
            apply_config
            ;;
        4)
            read -rp "窗口大小: " new_ws
            [[ "$new_ws" =~ ^[0-9]+$ ]] && yaml_set_section "arq" "window_size" "$new_ws"
            apply_config
            ;;
    esac
}

view_config() {
    print_logo
    step "配置文件"
    echo ""
    
    echo "─────────────────────────────────────"
    echo "1. 查看完整配置"
    echo "2. 编辑配置 (nano)"
    echo "3. 编辑配置 (vim)"
    echo "4. 备份配置"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
        1)
            echo ""
            cat "$CONFIG_FILE"
            ;;
        2)
            nano "$CONFIG_FILE"
            apply_config
            ;;
        3)
            vim "$CONFIG_FILE"
            apply_config
            ;;
        4)
            local backup="${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
            cp "$CONFIG_FILE" "$backup"
            info "备份: ${backup}"
            ;;
    esac
}

status_check() {
    print_logo
    step "状态检查"
    echo ""
    
    echo "═══════════════ 服务状态 ═══════════════"
    systemctl status phantom --no-pager 2>/dev/null || echo "服务未安装"
    
    echo ""
    echo "═══════════════ cloudflared 状态 ═══════════════"
    echo "文件检查:"
    for path in /opt/phantom/bin/cloudflared* /root/.phantom/bin/cloudflared* /usr/local/bin/cloudflared*; do
        if [[ -f "$path" ]]; then
            local perm=$(ls -la "$path" 2>/dev/null | awk '{print $1}')
            echo "  $path -> $perm"
        fi
    done
    
    echo ""
    echo "═══════════════ eBPF 状态 ═══════════════"
    if command -v bpftool &>/dev/null; then
        echo "BPF 程序:"
        bpftool prog list 2>/dev/null | head -10 || echo "  无"
    else
        echo "bpftool 未安装"
    fi
    
    echo ""
    echo "═══════════════ 网卡 XDP ═══════════════"
    local iface=$(get_iface)
    ip link show "$iface" 2>/dev/null | grep -E "xdp|prog" || echo "  无 XDP 程序"
    
    echo ""
    echo "═══════════════ 端口监听 ═══════════════"
    ss -tulnp 2>/dev/null | grep -E "phantom|54321|54322|54323|9100" || echo "  无"
    
 
    echo ""
    echo "═══════════════ eBPF 文件 ═══════════════"
    ls -la "${EBPF_DIR}/" 2>/dev/null || echo "  目录不存在"
    
    echo ""
    echo "═══════════════ BPF 文件系统 ═══════════════"
    if mountpoint -q /sys/fs/bpf 2>/dev/null; then
        echo "  /sys/fs/bpf 已挂载"
        ls -la /sys/fs/bpf/phantom/ 2>/dev/null || echo "  phantom 目录不存在"
    else
        echo "  /sys/fs/bpf 未挂载"
    fi
    
    echo ""
    echo "═══════════════ 最近错误日志 ═══════════════"
    journalctl -u phantom -n 20 --no-pager 2>/dev/null | grep -iE "error|failed|permission|denied" || echo "  无错误"
}

# ─────────────────────────────────────────────────────────────────────────────
# 快速修复函数
# ─────────────────────────────────────────────────────────────────────────────
quick_fix() {
    print_logo
    step "快速修复工具"
    echo ""
    
    echo "─────────────────────────────────────"
    echo "1. 修复所有权限问题"
    echo "2. 重新下载 cloudflared"
    echo "3. 重置 BPF 文件系统"
    echo "4. 完全重置服务"
    echo "5. 一键全部修复"
    echo "0. 返回"
    echo "─────────────────────────────────────"
    read -rp "选择: " opt
    
    case $opt in
        1)
            step "修复权限..."
            fix_cloudflared_permissions
            chmod +x "$INSTALL_DIR/phantom-server" 2>/dev/null
            chmod +x /opt/phantom/fix-permissions.sh 2>/dev/null
            info "权限修复完成"
            ;;
        2)
            step "重新下载 cloudflared..."
            rm -f "$CLOUDFLARED_PATH" /usr/local/bin/cloudflared /root/.phantom/bin/cloudflared* 2>/dev/null
            download_cloudflared
            fix_cloudflared_permissions
            info "cloudflared 重新下载完成"
            ;;
        3)
            step "重置 BPF 文件系统..."
            cleanup_ebpf_hooks
            setup_bpf_filesystem
            info "BPF 文件系统已重置"
            ;;
        4)
            step "完全重置服务..."
            safe_stop_service
            cleanup_ebpf_hooks
            systemctl daemon-reload
            sleep 2
            systemctl start phantom
            sleep 3
            systemctl status phantom --no-pager
            ;;
        5)
            step "执行一键全部修复..."
            echo ""
            
            echo "  [1/5] 停止服务..."
            safe_stop_service
            
            echo "  [2/5] 清理 eBPF..."
            cleanup_ebpf_hooks
            
            echo "  [3/5] 设置 BPF 文件系统..."
            setup_bpf_filesystem
            
            echo "  [4/5] 修复 cloudflared..."
            # 检查是否存在，不存在则下载
            local cf_exists=false
            for cf in /opt/phantom/bin/cloudflared* /root/.phantom/bin/cloudflared*; do
                if [[ -f "$cf" ]]; then
                    cf_exists=true
                    break
                fi
            done
            
            if ! $cf_exists; then
                download_cloudflared
            fi
            fix_cloudflared_permissions
            
            echo "  [5/5] 修复主程序权限..."
            chmod +x "$INSTALL_DIR/phantom-server" 2>/dev/null
            chmod +x /opt/phantom/fix-permissions.sh 2>/dev/null
            
            echo ""
            step "重新启动服务..."
            systemctl daemon-reload
            systemctl start phantom
            sleep 5
            
            if systemctl is-active --quiet phantom; then
                success "服务已成功启动！"
                echo ""
                
                # 检查隧道
                local tunnel_enabled=$(yaml_get "tunnel" "enabled")
                if [[ "$tunnel_enabled" == "true" ]]; then
                    echo "等待隧道 URL..."
                    sleep 5
                    local tunnel_url=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | \
                                      grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
                    if [[ -n "$tunnel_url" ]]; then
                        echo -e "隧道地址: ${CYAN}${tunnel_url}${NC}"
                    else
                        # 检查是否有权限错误
                        local perm_err=$(journalctl -u phantom -n 50 --no-pager 2>/dev/null | grep -i "permission denied")
                        if [[ -n "$perm_err" ]]; then
                            warn "仍有权限问题，尝试额外修复..."
                            chmod 755 /root/.phantom/bin/cloudflared* 2>/dev/null
                            ln -sf /root/.phantom/bin/cloudflared* /usr/local/bin/cloudflared 2>/dev/null
                            systemctl restart phantom
                            sleep 5
                            tunnel_url=$(journalctl -u phantom -n 100 --no-pager 2>/dev/null | \
                                        grep -oP 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1)
                            [[ -n "$tunnel_url" ]] && echo -e "隧道地址: ${CYAN}${tunnel_url}${NC}"
                        fi
                    fi
                fi
                
                show_connection_info
            else
                error "服务启动失败"
                echo ""
                echo "最近日志:"
                journalctl -u phantom -n 30 --no-pager
            fi
            ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# 主菜单
# ─────────────────────────────────────────────────────────────────────────────
show_menu() {
    while true; do
        print_logo
        show_status
        echo ""
        
        echo -e "${BOLD}═══════════════════ 安装管理 ═══════════════════${NC}"
        echo "  1. 安装/重装"
        echo "  2. 卸载"
        echo ""
        echo -e "${BOLD}═══════════════════ 服务控制 ═══════════════════${NC}"
        echo "  3. 启动    4. 停止    5. 重启"
        echo ""
        echo -e "${BOLD}═══════════════════ 核心设置 ═══════════════════${NC}"
        echo "  6. 基础配置    7. 隧道管理    8. DDNS"
        echo "  9. 证书管理   10. TLS伪装    11. 智能切换"
        echo " 12. 协议开关   13. 性能调优"
        echo ""
        echo -e "${BOLD}═══════════════════ 运维工具 ═══════════════════${NC}"
        echo " 14. 查看日志   15. 查看配置   16. 状态检查"
        echo " 17. 连接信息   ${RED}18. 快速修复${NC}"
        echo ""
        echo "  0. 退出"
        echo ""
        read -rp "选择 [0-18]: " opt
        
        case $opt in
            1)  guided_install ;;
            2)  
                echo ""
                read -rp "确认卸载？输入 YES 确认: " confirm
                if [[ "$confirm" == "YES" ]]; then
                    pre_start_cleanup
                    rm -rf "$INSTALL_DIR" "$CONFIG_DIR" "$SERVICE_FILE"
                    rm -rf /root/.phantom 2>/dev/null
                    systemctl daemon-reload
                    info "已卸载"
                fi
                ;;
            3)  
                pre_start_cleanup
                systemctl start phantom
                sleep 2
                systemctl status phantom --no-pager
                ;;
            4)  
                safe_stop_service
                cleanup_ebpf_hooks
                ;;
            5)  
                pre_start_cleanup
                systemctl start phantom
                sleep 2
                systemctl status phantom --no-pager
                ;;
            6)  manage_basic ;;
            7)  manage_tunnel ;;
            8)  manage_ddns ;;
            9)  manage_cert ;;
            10) manage_tls ;;
            11) manage_switcher ;;
            12) manage_protocols ;;
            13) manage_perf ;;
            14) journalctl -u phantom -f -n 100 ;;
            15) view_config ;;
            16) status_check ;;
            17) show_connection_info ;;
            18) quick_fix ;;
            0)  echo ""; info "再见！"; exit 0 ;;
        esac
        
        echo ""
        read -rp "按 Enter 继续..."
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# 命令行参数支持
# ─────────────────────────────────────────────────────────────────────────────
show_help() {
    echo "Phantom Server 管理脚本 v6.1-fix"
    echo ""
    echo "用法: $0 [命令]"
    echo ""
    echo "命令:"
    echo "  install     安装向导"
    echo "  start       启动服务"
    echo "  stop        停止服务"
    echo "  restart     重启服务"
    echo "  status      查看状态"
    echo "  logs        查看日志"
    echo "  fix         快速修复"
    echo "  fix-perm    修复权限"
    echo "  info        显示连接信息"
    echo "  uninstall   卸载"
    echo ""
    echo "无参数时进入交互式菜单"
}

# ─────────────────────────────────────────────────────────────────────────────
# 入口
# ─────────────────────────────────────────────────────────────────────────────
check_root

# 处理命令行参数
case "${1:-}" in
    install)
        guided_install
        ;;
    start)
        pre_start_cleanup
        systemctl start phantom
        sleep 2
        systemctl status phantom --no-pager
        show_connection_info
        ;;
    stop)
        safe_stop_service
        cleanup_ebpf_hooks
        info "服务已停止"
        ;;
    restart)
        pre_start_cleanup
        systemctl start phantom
        sleep 2
        systemctl status phantom --no-pager
        show_connection_info
        ;;
    status)
        systemctl status phantom --no-pager 2>/dev/null || echo "服务未安装"
        show_connection_info
        ;;
    logs)
        journalctl -u phantom -f -n 100
        ;;
    fix)
        # 执行一键修复
        step "执行快速修复..."
        safe_stop_service
        cleanup_ebpf_hooks
        setup_bpf_filesystem
        fix_cloudflared_permissions
        chmod +x "$INSTALL_DIR/phantom-server" 2>/dev/null
        systemctl daemon-reload
        systemctl start phantom
        sleep 5
        systemctl status phantom --no-pager
        show_connection_info
        ;;
    fix-perm)
        fix_cloudflared_permissions
        chmod +x "$INSTALL_DIR/phantom-server" 2>/dev/null
        info "权限修复完成"
        echo ""
        echo "cloudflared 文件:"
        ls -la /opt/phantom/bin/cloudflared* 2>/dev/null
        ls -la /root/.phantom/bin/cloudflared* 2>/dev/null
        ls -la /usr/local/bin/cloudflared* 2>/dev/null
        ;;
    info)
        show_connection_info
        ;;
    uninstall)
        read -rp "确认卸载？输入 YES 确认: " confirm
        if [[ "$confirm" == "YES" ]]; then
            safe_stop_service
            cleanup_ebpf_hooks
            rm -rf "$INSTALL_DIR" "$CONFIG_DIR" "$SERVICE_FILE"
            rm -rf /root/.phantom 2>/dev/null
            systemctl daemon-reload
            info "已卸载"
        fi
        ;;
    -h|--help|help)
        show_help
        ;;
    "")
        # 无参数，进入交互式菜单
        
        # 挂载 BPF 文件系统
        mountpoint -q /sys/fs/bpf 2>/dev/null || mount -t bpf bpf /sys/fs/bpf 2>/dev/null
        
        # 确保目录存在
        mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$CLOUDFLARED_DIR" 2>/dev/null
        
        if [[ -f "$CONFIG_FILE" ]]; then
            show_menu
        else
            guided_install
            echo ""
            read -rp "按 Enter 进入管理菜单..."
            show_menu
        fi
        ;;
    *)
        error "未知命令: $1"
        show_help
        exit 1
        ;;
esac
