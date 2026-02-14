
<div align="center">

# Phantom Server v4.0 Ultimate Edition

### 不止于代码，更是对底层系统的极致编排

![版本](https://img.shields.io/badge/version-4.0.0-blue?style=for-the-badge)
![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge)
![平台](https://img.shields.io/badge/platform-Linux_(eBPF)-lightgrey?style=for-the-badge)
![授权](https://img.shields.io/badge/license-MIT/GPL-green?style=for-the-badge)

</div>

**Phantom Server v4.0** 是一款基于“底层设计法”思想构建的新生代高性能代理。它将 Go 语言的并发调度能力与 Linux 内核的 eBPF/XDP 极限性能相结合，通过智能链路切换引擎，动态编排 Hysteria2、ARQ、FakeTCP、WebSocket 等多种传输模式，旨在为最严苛的网络环境提供极致的连接性能与可靠性。



### 📖 设计哲学：从“代码执行者”到“系统调度师”

传统代理软件是“代码执行者”，数据流经的每个环节都需用户态代码处理，这带来了不可避免的性能瓶颈。

Phantom v4.0 颠覆了这一模式，将自身定位为**“系统调度师”**。其核心 Go 代码仅在连接建立的最初阶段扮演**控制平面 (Control Plane)** 的角色。一旦连接建立，数据转发的**数据平面 (Data Plane)** 将被彻底**卸载 (Offload)** 给操作系统内核（通过 eBPF）或硬件本身。

这就像大脑（Go 程序）负责思考和下达指令，而脊髓反射（eBPF 程序）则以纳秒级速度处理高频、机械的数据包转发。这种“接完线就走”的哲学，将性能极限从应用代码拔高到了硬件与网络的物理极限。



### ✨ 核心特性：五大引擎协同作战

| 引擎 | 核心技术 | 解决的问题 |
| :--- | :--- | :--- |
| **智能链路切换引擎** | 异步质量评估、主动探测、动态决策 | 网络抖动、QoS、IP封锁下的自动寻路与故障转移 |
| **eBPF 内核加速引擎** | XDP/TC、Map Pinning、平滑重启 | 消除内核/用户态切换，实现近乎零拷贝的极限吞吐量 |
| **可靠性与拥塞控制引擎** | ARQ、Hysteria2 拥塞控制、拥塞适配器 | 在高丢包UDP链路上实现可靠传输与暴力带宽压榨 |
| **金融级安全引擎** | TSKD、时间分片布隆过滤器、权限降级 | 0-RTT 认证、抵御大规模重放攻击、最小化攻击面 |
| **企业级可观测性引擎** | Prometheus 自定义 Collector & 实时埋点 | 提供深度、多维度的系统性能与状态监控 |



### 🏗️ 架构深度解析


┌─────────────────────────────────────────────────────────────────┐
│                         Phantom Server v4.0                     │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                ① 智能链路切换引擎 (大脑)                  │  │
│  │     (异步质量评估、主动探测、动态决策)                     │  │
│  └─────────────────────────────────────────────────────────┘  │
│           │           │           │           │               │
│           ▼           ▼           ▼           ▼               │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────┐        │
│  │② eBPF   │ │ FakeTCP │ │   UDP   │ │  WebSocket  │        │
│  │  (内核) │ │  (伪装) │ │  (基础) │ │    (回退)   │        │
│  └────┬────┘ └────┬────┘ └────┬────┘ └──────┬──────┘        │
│       │           │           │             │                 │
│       └───────────┴─────┬─────┴─────────────┘                 │
│                         ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │           ③ 可靠性与拥塞控制引擎 (心脏)                  │  │
│  │    (ARQ滑动窗口 + Hysteria2暴力模式 + 拥塞控制适配器)      │  │
│  └─────────────────────────────────────────────────────────┘  │
│                         │                                     │
│                         ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │          ④ 金融级安全引擎 (护盾)                          │  │
│  │ (时间窗口密钥派生 + 时间分片布隆过滤器 + 权限降级)         │  │
│  └─────────────────────────────────────────────────────────┘  │
│                         │                                     │
│                         ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                ⑤ 可观测性引擎 (眼睛)                      │  │
│  │      (自定义Collector + 实时Gauge/Counter)              │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘



### 🚀 快速开始

#### 1. 一键安装 (推荐)

# 脚本会自动检测系统能力并生成优化配置
curl -fsSL https://raw.githubusercontent.com/mrcgq/211/main/scripts/install.sh | sudo bash


#### 2. 手动构建与运行

# 1. 克隆项目
git clone https://github.com/mrcgq/211.git
cd 211

# 2. 构建 (需要 Go 1.21+ 和 clang/llvm)
make build-all

# 3. 生成配置并填入 PSK
cp configs/config.example.yaml /etc/phantom/config.yaml
PSK=$(./phantom-server -gen-psk)
sed -i "s/YOUR_PSK_HERE/$PSK/" /etc/phantom/config.yaml
# 根据需要编辑 /etc/phantom/config.yaml

# 4. 运行
sudo ./phantom-server -c /etc/phantom/config.yaml


#### 3. Docker 部署

# 注意: Docker 部署需开启特权以支持 eBPF
docker run -d \
  --name phantom \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add SYS_ADMIN \
  --cap-add BPF \
  -v /path/to/your/config.yaml:/etc/phantom/config.yaml \
  --restart always \
  ghcr.io/mrcgq/211:latest




### ⚙️ 核心配置 (`config.yaml`)

<details>
<summary><b>基础与智能切换配置</b></summary>


# 基础设置
listen: ":54321"           # 主监听端口 (UDP)
psk: "YOUR_PSK_HERE"        # 认证密钥
log_level: "info"
mode: "auto"                # 模式: auto, udp, faketcp, websocket, ebpf

# 智能链路切换
switcher:
  enabled: true
  check_interval_ms: 1000   # 链路质量检查间隔
  fail_threshold: 3         # 连续失败多少次后触发切换
  rtt_threshold_ms: 300     # RTT 超过此值视为劣化
  loss_threshold: 0.3       # 丢包率超过此值视为劣化
  priority:                 # 链路优先级 (从优到劣)
    - "ebpf"
    - "faketcp"
    - "udp"
    - "websocket"

</details>

<details>
<summary><b>Hysteria2 与 ARQ 配置</b></summary>


# Hysteria2 拥塞控制
hysteria2:
  enabled: true
  up_mbps: 100        # 上行带宽 (Mbps)
  down_mbps: 100      # 下行带宽 (Mbps)

# ARQ 可靠传输 (UDP增强层)
arq:
  enabled: true
  window_size: 256    # 滑动窗口大小
  max_retries: 10     # 最大重传次数

</details>

<details>
<summary><b>eBPF 与 FakeTCP 配置</b></summary>


# eBPF 内核加速
ebpf:
  enabled: true
  interface: "eth0"         # 绑定的物理网卡
  xdp_mode: "generic"       # XDP 模式 (native/generic)
  program_path: "/opt/phantom/ebpf" # eBPF 程序路径

# FakeTCP 伪装
faketcp:
  enabled: true
  listen: ":54322"          # FakeTCP 监听端口
  interface: "eth0"
  use_ebpf: true            # 启用 TC eBPF 加速 FakeTCP

</details>



### 📊 性能指标 (实验室数据)

| 模式 | 单连接吞吐量 | CPU 占用 (10Gbps) | P99 延迟 | 适用场景 |
| :--- | :--- | :--- | :--- | :--- |
| **eBPF/XDP** | ~18 Gbps | ~15% | < 0.3ms | 追求极致性能的优质线路 |
| **原生 UDP+Hysteria2** | ~10 Gbps | ~45% | < 1.5ms | 高丢包、长距离的通用场景 |
| **FakeTCP (TC加速)** | ~8 Gbps | ~50% | < 2.0ms | 运营商 UDP QoS 限制 |
| **WebSocket** | ~5 Gbps | ~60% | < 5.0ms | 高隐蔽性、CDN 加速、终极回退 |



### 📦 项目结构


phantom-server/
├── cmd/phantom-server/       # 主程序入口
├── internal/
│   ├── config/               # 配置管理
│   ├── congestion/           # Hysteria2 拥塞控制
│   ├── crypto/               # 加密与安全 (TSKD, 防重放)
│   ├── handler/              # 统一业务处理器
│   ├── metrics/              # Prometheus 监控
│   ├── protocol/             # 应用层协议
│   ├── switcher/             # 智能链路切换引擎
│   ├── transport/            # 多模式传输层 (UDP, TCP, ARQ, FakeTCP, WS, eBPF)
│   └── tunnel/               # Cloudflare 隧道与权限管理
├── ebpf/                     # eBPF 内核程序 (C)
│   ├── lib/                  # 内核态解耦库 (parsing.h, session.h, stats.h)
│   ├── xdp_phantom.c         # XDP 主加速程序
│   └── tc_faketcp.c          # FakeTCP 内核伪装程序
├── scripts/
│   └── install.sh            # 一键安装脚本
├── go.mod
├── Makefile
└── Dockerfile



### 🛠️ 系统要求

*   **基础功能 (非 eBPF)**:
    *   Go 1.21+
    *   Linux / macOS / Windows
*   **eBPF 极限加速功能**:
    *   **Linux 内核 5.4+**
    *   **root 权限** 或 `CAP_SYS_ADMIN`, `CAP_BPF`
    *   BTF (BPF Type Format) 支持 (`/sys/kernel/btf/vmlinux` 文件存在)
    *   `clang`, `llvm`, `bpftool` (用于编译 eBPF 程序)



### 🔐 安全模型

*   **认证加密**: `ChaCha20-Poly1305` AEAD
*   **密钥派生**: TSKD (Time-Stale Key Derivation) 时间窗口密钥，提供前向保密性。
*   **防重放攻击**: 采用时间分片布隆过滤器 + LRU 缓存，可抵御大规模重放攻击。
*   **进程安全**: 通过 `PrivilegeManager` 实现对子进程（如 `cloudflared`）的权限降级，遵循最小权限原则。



### 📄 授权协议

本项目采用 **MIT / GPLv3** 双重授权。

<div align="center">

**为极限连接而生 (Born for Ultimate Connectivity)**

</div>
