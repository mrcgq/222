


#!/usr/bin/env bash
# =============================================================================
# 文件: scripts/check_env.sh
# 描述: Phantom Server v4.0 环境预检脚本
# 功能: 检测系统是否满足 eBPF 加速的硬性要求
# 完整检测 sudo ./scripts/check_env.sh
# 静默模式 sudo ./scripts/check_env.sh --quiet
# JSON 输出 (便于自动化) sudo ./scripts/check_env.sh --json
# 跳过编译工具检测 sudo ./scripts/check_env.sh --skip-compile
# =============================================================================

set -euo pipefail

# =============================================================================
# 颜色定义
# =============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# =============================================================================
# 版本要求
# =============================================================================
readonly MIN_KERNEL_MAJOR=5
readonly MIN_KERNEL_MINOR=4

# =============================================================================
# 全局状态
# =============================================================================
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNINGS=0

# eBPF 能力标志
EBPF_CAPABLE=true
COMPILE_CAPABLE=true

# =============================================================================
# 输出函数
# =============================================================================
print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗ ║
║   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║ ║
║   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║ ║
║   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║ ║
║   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║ ║
║   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝ ║
║                                                                   ║
║              Environment Check Script v4.0                        ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    ((WARNINGS++))
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_check() {
    echo -e "${CYAN}[CHECK]${NC} $1"
}

print_section() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
}

# =============================================================================
# 检测函数
# =============================================================================

# 检查内核版本
check_kernel_version() {
    print_section "🔍 内核版本检测"
    ((TOTAL_CHECKS++))
    
    local kernel_release
    kernel_release=$(uname -r)
    log_check "当前内核版本: ${kernel_release}"
    
    # 提取主版本号和次版本号
    local major minor
    major=$(echo "$kernel_release" | cut -d. -f1)
    minor=$(echo "$kernel_release" | cut -d. -f2)
    
    # 验证是否为数字
    if ! [[ "$major" =~ ^[0-9]+$ ]] || ! [[ "$minor" =~ ^[0-9]+$ ]]; then
        log_error "无法解析内核版本号"
        ((FAILED_CHECKS++))
        EBPF_CAPABLE=false
        return 1
    fi
    
    log_info "解析结果: 主版本=${major}, 次版本=${minor}"
    log_info "要求版本: >=${MIN_KERNEL_MAJOR}.${MIN_KERNEL_MINOR}"
    
    # 版本比较
    if [[ "$major" -gt "$MIN_KERNEL_MAJOR" ]] || \
       [[ "$major" -eq "$MIN_KERNEL_MAJOR" && "$minor" -ge "$MIN_KERNEL_MINOR" ]]; then
        log_success "内核版本满足要求 (${kernel_release} >= ${MIN_KERNEL_MAJOR}.${MIN_KERNEL_MINOR})"
        ((PASSED_CHECKS++))
        
        # 额外检查更高版本特性
        if [[ "$major" -ge 5 && "$minor" -ge 8 ]]; then
            log_info "  └─ 支持 BPF ring buffer (5.8+)"
        fi
        if [[ "$major" -ge 5 && "$minor" -ge 10 ]]; then
            log_info "  └─ 支持 BPF LSM (5.10+)"
        fi
        if [[ "$major" -ge 5 && "$minor" -ge 15 ]]; then
            log_info "  └─ 支持 BPF 计时器 (5.15+)"
        fi
        return 0
    else
        log_error "内核版本过低: ${kernel_release} < ${MIN_KERNEL_MAJOR}.${MIN_KERNEL_MINOR}"
        log_error "  └─ eBPF/XDP 加速需要 Linux 5.4 或更高版本"
        log_warning "  └─ 解决方案: 升级内核或使用非 eBPF 模式运行"
        ((FAILED_CHECKS++))
        EBPF_CAPABLE=false
        return 1
    fi
}

# 检查 BTF 支持
check_btf_support() {
    print_section "🔍 BTF (BPF Type Format) 检测"
    ((TOTAL_CHECKS++))
    
    local btf_path="/sys/kernel/btf/vmlinux"
    log_check "检测 BTF 文件: ${btf_path}"
    
    if [[ -f "$btf_path" ]]; then
        local btf_size
        btf_size=$(stat -c%s "$btf_path" 2>/dev/null || stat -f%z "$btf_path" 2>/dev/null || echo "unknown")
        log_success "BTF 已启用"
        log_info "  └─ 文件大小: ${btf_size} bytes"
        ((PASSED_CHECKS++))
        
        # 检查 BTF 模块目录
        if [[ -d "/sys/kernel/btf" ]]; then
            local module_count
            module_count=$(ls -1 /sys/kernel/btf/ 2>/dev/null | wc -l)
            log_info "  └─ 已加载 BTF 模块数: ${module_count}"
        fi
        return 0
    else
        log_error "BTF 未启用: ${btf_path} 不存在"
        log_error "  └─ CO-RE (Compile Once - Run Everywhere) 功能不可用"
        ((FAILED_CHECKS++))
        EBPF_CAPABLE=false
        
        # 提供解决方案
        echo ""
        log_warning "解决方案:"
        log_info "  1. 检查内核配置是否启用 CONFIG_DEBUG_INFO_BTF=y"
        log_info "  2. 某些发行版需要安装额外包:"
        log_info "     - Debian/Ubuntu: apt install linux-image-\$(uname -r)-dbg"
        log_info "     - CentOS/RHEL:   yum install kernel-debuginfo"
        log_info "     - Fedora:        dnf install kernel-debuginfo"
        log_info "  3. 或者重新编译内核并启用 BTF"
        return 1
    fi
}

# 检查特权/权限
check_privileges() {
    print_section "🔍 权限检测"
    ((TOTAL_CHECKS++))
    
    log_check "检测当前用户权限..."
    
    # 检查是否为 root
    if [[ $EUID -eq 0 ]]; then
        log_success "当前用户为 root (UID=0)"
        ((PASSED_CHECKS++))
        return 0
    fi
    
    log_info "当前用户: $(whoami) (UID=${EUID})"
    log_info "非 root 用户，检测 Linux Capabilities..."
    
    # 检查是否有 capsh 命令
    if ! command -v capsh &>/dev/null; then
        log_warning "capsh 命令不存在，无法精确检测 capabilities"
        log_warning "  └─ 安装: apt install libcap2-bin 或 yum install libcap"
    fi
    
    # 检查关键 capabilities
    local has_cap_sys_admin=false
    local has_cap_bpf=false
    local has_cap_net_admin=false
    
    # 方法1: 通过 /proc 检测
    if [[ -f "/proc/self/status" ]]; then
        local cap_eff
        cap_eff=$(grep -i "CapEff" /proc/self/status 2>/dev/null | awk '{print $2}')
        
        if [[ -n "$cap_eff" ]]; then
            log_info "当前进程 CapEff: 0x${cap_eff}"
            
            # CAP_SYS_ADMIN = bit 21 (0x200000)
            # CAP_BPF = bit 39 (0x8000000000)
            # CAP_NET_ADMIN = bit 12 (0x1000)
            
            local cap_val=$((16#$cap_eff))
            
            if (( (cap_val >> 21) & 1 )); then
                has_cap_sys_admin=true
                log_info "  └─ CAP_SYS_ADMIN: 已授权"
            fi
            
            if (( (cap_val >> 39) & 1 )); then
                has_cap_bpf=true
                log_info "  └─ CAP_BPF: 已授权"
            fi
            
            if (( (cap_val >> 12) & 1 )); then
                has_cap_net_admin=true
                log_info "  └─ CAP_NET_ADMIN: 已授权"
            fi
        fi
    fi
    
    # 方法2: 通过 capsh 检测 (如果可用)
    if command -v capsh &>/dev/null; then
        local current_caps
        current_caps=$(capsh --print 2>/dev/null | grep -i "current" | head -1)
        if [[ -n "$current_caps" ]]; then
            log_info "capsh 检测结果: ${current_caps}"
        fi
    fi
    
    # 评估权限是否足够
    if $has_cap_sys_admin || ($has_cap_bpf && $has_cap_net_admin); then
        log_success "具备 eBPF 所需权限"
        ((PASSED_CHECKS++))
        return 0
    else
        log_error "权限不足: 需要 root 或 CAP_SYS_ADMIN/CAP_BPF + CAP_NET_ADMIN"
        ((FAILED_CHECKS++))
        EBPF_CAPABLE=false
        
        echo ""
        log_warning "解决方案:"
        log_info "  1. 使用 root 运行: sudo $0"
        log_info "  2. 或授予 capabilities:"
        log_info "     sudo setcap cap_sys_admin,cap_bpf,cap_net_admin+ep /path/to/phantom-server"
        return 1
    fi
}

# 检查编译工具链
check_compile_tools() {
    print_section "🔍 eBPF 编译工具链检测"
    
    local tools=("clang" "llvm-strip" "bpftool")
    local optional_tools=("llc" "opt" "llvm-objdump")
    local all_required_present=true
    
    echo ""
    log_info "必需工具:"
    
    for tool in "${tools[@]}"; do
        ((TOTAL_CHECKS++))
        log_check "检测 ${tool}..."
        
        if command -v "$tool" &>/dev/null; then
            local version
            case "$tool" in
                clang)
                    version=$($tool --version 2>/dev/null | head -1)
                    ;;
                llvm-strip)
                    version=$($tool --version 2>/dev/null | head -1 || echo "版本未知")
                    ;;
                bpftool)
                    version=$($tool version 2>/dev/null | head -1 || echo "版本未知")
                    ;;
                *)
                    version="已安装"
                    ;;
            esac
            log_success "${tool}: ${version}"
            ((PASSED_CHECKS++))
        else
            log_error "${tool}: 未安装"
            ((FAILED_CHECKS++))
            all_required_present=false
            COMPILE_CAPABLE=false
        fi
    done
    
    echo ""
    log_info "可选工具:"
    
    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_success "${tool}: 已安装"
        else
            log_warning "${tool}: 未安装 (可选)"
        fi
    done
    
    # 检查 clang 版本是否足够
    if command -v clang &>/dev/null; then
        local clang_version
        clang_version=$(clang --version 2>/dev/null | grep -oP 'clang version \K[0-9]+' | head -1)
        
        if [[ -n "$clang_version" ]] && [[ "$clang_version" -ge 10 ]]; then
            log_info "Clang 版本 ${clang_version} 满足要求 (>= 10)"
        elif [[ -n "$clang_version" ]]; then
            log_warning "Clang 版本 ${clang_version} 较低，建议升级到 10+"
        fi
    fi
    
    # 检查 libbpf 开发库
    echo ""
    log_info "开发库检测:"
    
    local libbpf_found=false
    
    # 检查 pkg-config
    if command -v pkg-config &>/dev/null; then
        if pkg-config --exists libbpf 2>/dev/null; then
            local libbpf_version
            libbpf_version=$(pkg-config --modversion libbpf 2>/dev/null)
            log_success "libbpf: ${libbpf_version} (via pkg-config)"
            libbpf_found=true
        fi
    fi
    
    # 检查头文件
    if [[ -f "/usr/include/bpf/libbpf.h" ]] || [[ -f "/usr/local/include/bpf/libbpf.h" ]]; then
        if ! $libbpf_found; then
            log_success "libbpf: 头文件已找到"
            libbpf_found=true
        fi
    fi
    
    if ! $libbpf_found; then
        log_warning "libbpf: 未检测到 (编译 eBPF 程序可能需要)"
        log_info "  └─ 安装: apt install libbpf-dev 或 yum install libbpf-devel"
    fi
    
    # 检查内核头文件
    local kernel_headers="/lib/modules/$(uname -r)/build"
    if [[ -d "$kernel_headers" ]]; then
        log_success "内核头文件: ${kernel_headers}"
    else
        log_warning "内核头文件未找到: ${kernel_headers}"
        log_info "  └─ 安装: apt install linux-headers-\$(uname -r)"
    fi
    
    if ! $all_required_present; then
        echo ""
        log_warning "安装缺失的编译工具:"
        log_info "  Debian/Ubuntu:"
        log_info "    apt update && apt install -y clang llvm libbpf-dev linux-tools-common"
        log_info "  CentOS/RHEL 8+:"
        log_info "    dnf install -y clang llvm bpftool libbpf-devel"
        log_info "  Fedora:"
        log_info "    dnf install -y clang llvm bpftool libbpf-devel"
        log_info "  Arch Linux:"
        log_info "    pacman -S clang llvm bpf libbpf"
    fi
    
    return 0
}

# 检查 BPF 文件系统
check_bpf_filesystem() {
    print_section "🔍 BPF 文件系统检测"
    ((TOTAL_CHECKS++))
    
    log_check "检测 BPF 文件系统挂载状态..."
    
    if mount | grep -q "type bpf"; then
        local bpf_mount
        bpf_mount=$(mount | grep "type bpf" | awk '{print $3}')
        log_success "BPF 文件系统已挂载: ${bpf_mount}"
        ((PASSED_CHECKS++))
        
        # 检查是否可写
        if [[ -w "$bpf_mount" ]]; then
            log_info "  └─ 可写: 是"
        else
            log_warning "  └─ 可写: 否 (Map pinning 可能受影响)"
        fi
        return 0
    else
        log_warning "BPF 文件系统未挂载"
        ((PASSED_CHECKS++))  # 这只是警告，不是硬性要求
        
        log_info "  └─ 可通过以下命令挂载:"
        log_info "     mount -t bpf bpf /sys/fs/bpf"
        log_info "  └─ 或添加到 /etc/fstab:"
        log_info "     bpf /sys/fs/bpf bpf defaults 0 0"
        return 0
    fi
}

# 检查网络接口
check_network_interface() {
    print_section "🔍 网络接口检测"
    ((TOTAL_CHECKS++))
    
    log_check "枚举可用网络接口..."
    
    local interfaces
    interfaces=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -v "^lo$" | head -10)
    
    if [[ -z "$interfaces" ]]; then
        log_warning "未检测到网络接口"
        ((PASSED_CHECKS++))
        return 0
    fi
    
    log_success "检测到以下网络接口:"
    
    while IFS= read -r iface; do
        # 获取接口信息
        local state driver mtu
        state=$(cat "/sys/class/net/${iface}/operstate" 2>/dev/null || echo "unknown")
        driver=$(basename "$(readlink -f /sys/class/net/${iface}/device/driver 2>/dev/null)" 2>/dev/null || echo "unknown")
        mtu=$(cat "/sys/class/net/${iface}/mtu" 2>/dev/null || echo "unknown")
        
        # 检查 XDP 支持
        local xdp_support="未知"
        if [[ -f "/sys/class/net/${iface}/device/driver" ]]; then
            # 已知支持 XDP native 模式的驱动
            case "$driver" in
                i40e|ixgbe|mlx5_core|virtio_net|veth|bond)
                    xdp_support="${GREEN}native${NC}"
                    ;;
                e1000|e1000e|r8169|tg3)
                    xdp_support="${YELLOW}generic${NC}"
                    ;;
                *)
                    xdp_support="${YELLOW}generic${NC} (可能)"
                    ;;
            esac
        fi
        
        echo -e "  └─ ${BOLD}${iface}${NC}: 状态=${state}, 驱动=${driver}, MTU=${mtu}, XDP=${xdp_support}"
        
    done <<< "$interfaces"
    
    ((PASSED_CHECKS++))
    return 0
}

# 检查系统资源
check_system_resources() {
    print_section "🔍 系统资源检测"
    
    log_info "内存信息:"
    if [[ -f "/proc/meminfo" ]]; then
        local total_mem available_mem
        total_mem=$(grep "MemTotal" /proc/meminfo | awk '{print $2}')
        available_mem=$(grep "MemAvailable" /proc/meminfo | awk '{print $2}')
        
        # 转换为 MB
        total_mb=$((total_mem / 1024))
        available_mb=$((available_mem / 1024))
        
        log_info "  └─ 总内存: ${total_mb} MB"
        log_info "  └─ 可用内存: ${available_mb} MB"
        
        if [[ $available_mb -lt 512 ]]; then
            log_warning "可用内存较低，可能影响 eBPF Map 分配"
        fi
    fi
    
    log_info "CPU 信息:"
    if [[ -f "/proc/cpuinfo" ]]; then
        local cpu_count cpu_model
        cpu_count=$(grep -c "processor" /proc/cpuinfo)
        cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
        
        log_info "  └─ CPU 核心数: ${cpu_count}"
        log_info "  └─ CPU 型号: ${cpu_model}"
    fi
    
    log_info "RLIMIT 配置:"
    if command -v ulimit &>/dev/null; then
        local memlock_limit
        memlock_limit=$(ulimit -l 2>/dev/null)
        log_info "  └─ MEMLOCK 限制: ${memlock_limit} KB"
        
        if [[ "$memlock_limit" != "unlimited" ]] && [[ "$memlock_limit" -lt 65536 ]]; then
            log_warning "MEMLOCK 限制较低，可能影响 eBPF Map 大小"
            log_info "    └─ 建议: ulimit -l unlimited 或修改 /etc/security/limits.conf"
        fi
    fi
    
    return 0
}

# 检查 Go 环境 (可选)
check_go_environment() {
    print_section "🔍 Go 环境检测 (用于从源码构建)"
    
    if command -v go &>/dev/null; then
        local go_version
        go_version=$(go version 2>/dev/null)
        log_success "Go: ${go_version}"
        
        # 检查版本
        local go_ver
        go_ver=$(echo "$go_version" | grep -oP 'go\K[0-9]+\.[0-9]+')
        local go_major go_minor
        go_major=$(echo "$go_ver" | cut -d. -f1)
        go_minor=$(echo "$go_ver" | cut -d. -f2)
        
        if [[ "$go_major" -ge 1 ]] && [[ "$go_minor" -ge 21 ]]; then
            log_info "  └─ 版本满足要求 (>= 1.21)"
        else
            log_warning "  └─ 版本较低，建议升级到 1.21+"
        fi
        
        # 检查 GOPATH
        if [[ -n "${GOPATH:-}" ]]; then
            log_info "  └─ GOPATH: ${GOPATH}"
        fi
    else
        log_warning "Go: 未安装 (从源码构建需要)"
        log_info "  └─ 安装: https://golang.org/dl/"
    fi
    
    return 0
}

# =============================================================================
# 汇总报告
# =============================================================================
print_summary() {
    print_section "📊 检测汇总报告"
    
    echo ""
    echo -e "${BOLD}检测统计:${NC}"
    echo -e "  ├─ 总检测项: ${TOTAL_CHECKS}"
    echo -e "  ├─ ${GREEN}通过${NC}: ${PASSED_CHECKS}"
    echo -e "  ├─ ${RED}失败${NC}: ${FAILED_CHECKS}"
    echo -e "  └─ ${YELLOW}警告${NC}: ${WARNINGS}"
    
    echo ""
    echo -e "${BOLD}能力评估:${NC}"
    
    if $EBPF_CAPABLE; then
        echo -e "  ├─ eBPF/XDP 加速: ${GREEN}✓ 支持${NC}"
    else
        echo -e "  ├─ eBPF/XDP 加速: ${RED}✗ 不支持${NC}"
    fi
    
    if $COMPILE_CAPABLE; then
        echo -e "  ├─ eBPF 程序编译: ${GREEN}✓ 支持${NC}"
    else
        echo -e "  ├─ eBPF 程序编译: ${RED}✗ 缺少工具${NC}"
    fi
    
    # 最终建议
    echo ""
    echo -e "${BOLD}运行建议:${NC}"
    
    if $EBPF_CAPABLE && $COMPILE_CAPABLE; then
        echo -e "  ${GREEN}★ 系统完全支持 eBPF 加速模式${NC}"
        echo -e "  └─ 推荐配置: mode: \"ebpf\" 或 mode: \"auto\""
    elif $EBPF_CAPABLE && ! $COMPILE_CAPABLE; then
        echo -e "  ${YELLOW}★ 系统支持 eBPF，但缺少编译工具${NC}"
        echo -e "  └─ 可使用预编译的 eBPF 程序"
        echo -e "  └─ 或安装编译工具后从源码构建"
    elif ! $EBPF_CAPABLE; then
        echo -e "  ${YELLOW}★ 系统不支持 eBPF，将使用用户态模式${NC}"
        echo -e "  └─ 推荐配置: mode: \"udp\" 或 mode: \"faketcp\""
        echo -e "  └─ 性能会有所下降，但功能完整"
    fi
    
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    
    if [[ $FAILED_CHECKS -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}所有必要检测均已通过！可以继续安装 Phantom Server。${NC}"
        return 0
    else
        echo -e "${YELLOW}${BOLD}存在 ${FAILED_CHECKS} 项检测未通过，请查看上述建议进行修复。${NC}"
        echo -e "${YELLOW}${BOLD}您仍可继续安装，但某些高级功能可能不可用。${NC}"
        return 1
    fi
}

# =============================================================================
# 使用帮助
# =============================================================================
print_usage() {
    cat << EOF
使用方法: $0 [选项]

选项:
  -h, --help      显示此帮助信息
  -q, --quiet     静默模式 (仅输出关键信息)
  -v, --verbose   详细模式 (显示所有检测细节)
  --json          以 JSON 格式输出结果
  --skip-compile  跳过编译工具链检测
  --skip-network  跳过网络接口检测

示例:
  $0                 # 完整检测
  $0 --quiet         # 静默检测
  $0 --skip-compile  # 跳过编译工具检测

EOF
}

# =============================================================================
# 主函数
# =============================================================================
main() {
    local quiet_mode=false
    local skip_compile=false
    local skip_network=false
    local json_output=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                print_usage
                exit 0
                ;;
            -q|--quiet)
                quiet_mode=true
                shift
                ;;
            -v|--verbose)
                # 详细模式 (默认)
                shift
                ;;
            --json)
                json_output=true
                shift
                ;;
            --skip-compile)
                skip_compile=true
                shift
                ;;
            --skip-network)
                skip_network=true
                shift
                ;;
            *)
                echo "未知选项: $1"
                print_usage
                exit 1
                ;;
        esac
    done
    
    if ! $quiet_mode; then
        print_banner
    fi
    
    log_info "开始环境检测..."
    log_info "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
    log_info "主机名: $(hostname)"
    log_info "操作系统: $(uname -o 2>/dev/null || uname -s)"
    log_info "架构: $(uname -m)"
    
    # 执行检测
    check_kernel_version
    check_btf_support
    check_privileges
    
    if ! $skip_compile; then
        check_compile_tools
    fi
    
    check_bpf_filesystem
    
    if ! $skip_network; then
        check_network_interface
    fi
    
    check_system_resources
    check_go_environment
    
    # 输出汇总
    if $json_output; then
        # JSON 格式输出
        cat << EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "kernel_version": "$(uname -r)",
  "total_checks": ${TOTAL_CHECKS},
  "passed_checks": ${PASSED_CHECKS},
  "failed_checks": ${FAILED_CHECKS},
  "warnings": ${WARNINGS},
  "ebpf_capable": ${EBPF_CAPABLE},
  "compile_capable": ${COMPILE_CAPABLE}
}
EOF
    else
        print_summary
    fi
    
    # 返回状态码
    if [[ $FAILED_CHECKS -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# 执行主函数
main "$@"













