# NMS Agent

部署在分布式边缘节点（机房 / POP）上的网络探测 Agent。首次启动用一次性 provisioning token 向 NMS Server 申请 mTLS 证书，之后持续轮询服务端下发的探测任务（ping、tcpping、httpcheck、dnscheck、traceroute、mtr、snmp_poll），把结果批量回传服务端。探测目标、类型、周期、源 IP 绑定、软件升级全部由服务端动态驱动 —— 本地配置只需要身份信息和服务端地址。

[![Build and Release](https://github.com/Cion-1221/NMS_Agent/actions/workflows/release.yml/badge.svg)](https://github.com/Cion-1221/NMS_Agent/actions/workflows/release.yml)
![Go Version](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go)
![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20windows%20%7C%20macOS-lightgrey)

---

## 📖 目录

- **[1. 项目概览](#1-项目概览)**
  - [1.1 一句话架构](#11-一句话架构)
  - [1.2 核心特性一览](#12-核心特性一览)
  - [1.3 架构图](#13-架构图)
  - [1.4 目录结构](#14-目录结构)
- **[2. 快速开始](#2-快速开始)**
  - [2.1 下载预编译二进制](#21-下载预编译二进制)
  - [2.2 从源码构建](#22-从源码构建)
  - [2.3 命令行参数](#23-命令行参数)
  - [2.4 验证启动](#24-验证启动)
- **[3. 配置说明](#3-配置说明)**
  - [3.1 agent 块 — 身份](#31-agent-块--身份)
  - [3.2 server 块 — 服务端与同步节奏](#32-server-块--服务端与同步节奏)
  - [3.3 runtime 块 — 日志与运行时](#33-runtime-块--日志与运行时)
  - [3.4 certs 块 — 证书目录](#34-certs-块--证书目录)
  - [3.5 敏感信息与环境变量](#35-敏感信息与环境变量)
- **[4. 功能模块](#4-功能模块)**（一个菜单一个功能）
  - [4.1 证书与身份 — internal/cert](#41-证书与身份--internalcert)
  - [4.2 任务调度 — internal/scheduler](#42-任务调度--internalscheduler)
  - [4.3 探测引擎 — internal/probe](#43-探测引擎--internalprobe)
    - [4.3.1 ping / meshping](#431-ping--meshping)
    - [4.3.2 tcpping](#432-tcpping)
    - [4.3.3 httpcheck](#433-httpcheck)
    - [4.3.4 dnscheck](#434-dnscheck)
    - [4.3.5 traceroute](#435-traceroute)
    - [4.3.6 mtr / meshmtr](#436-mtr--meshmtr)
    - [4.3.7 snmp_poll — SNMP 探针代理](#437-snmp_poll--snmp-探针代理)
  - [4.4 结果上报 — internal/reporter](#44-结果上报--internalreporter)
  - [4.5 OTA 自动升级 — internal/updater](#45-ota-自动升级--internalupdater)
  - [4.6 结构化日志 — internal/logger](#46-结构化日志--internallogger)
  - [4.7 公网 IP 自发现 — main.go](#47-公网-ip-自发现--maingo)
- **[5. 高级主题](#5-高级主题)**
  - [5.1 Source IP 绑定](#51-source-ip-绑定)
  - [5.2 双栈 IPv4/IPv6 与 address_family](#52-双栈-ipv4ipv6-与-address_family)
  - [5.3 安全设计](#53-安全设计)
- **[6. 部署运维](#6-部署运维)**
  - [6.1 systemd 方式一：自包含目录（root）](#61-systemd-方式一自包含目录root)
  - [6.2 systemd 方式二：专用账户（生产推荐）](#62-systemd-方式二专用账户生产推荐)
  - [6.3 Windows 部署注意事项](#63-windows-部署注意事项)
  - [6.4 常用管理命令](#64-常用管理命令)
  - [6.5 故障排查](#65-故障排查)
- **[7. 构建与发布（CI）](#7-构建与发布ci)**
- **[8. 平台支持矩阵](#8-平台支持矩阵)**
- **[9. 服务端 API 契约](#9-服务端-api-契约)**
- **[10. License](#10-license)**

---

## 1. 项目概览

### 1.1 一句话架构

**服务端驱动的瘦探针**：Agent 本地零业务配置，每 `task_poll_interval` 拉取一次任务清单，diff 式增删探测协程；结果攒批经 mTLS 通道回传；证书续签、源 IP 变更、版本升级全部在同一条同步链路上完成，无需人工登录节点。

### 1.2 核心特性一览

| # | 特性 | 说明 |
|---|------|------|
| 1 | **服务端驱动** | 探测目标 / 类型 / 周期由 `GET /agent-sync/tasks` 下发，调整策略无需重启 Agent |
| 2 | **mTLS 双向认证** | 首启用 provisioning token 换证书，之后所有通信走双向验证的 mTLS 通道 |
| 3 | **证书热更新** | mTLS 客户端通过 `DialTLSContext` 在每次新建 TLS 连接时从磁盘重读证书，续签 / CA 轮换即时生效、零重启 |
| 4 | **证书自动续签** | 每日检查有效期，剩余 < 30 天自动调用 `renew-cert` 续签 |
| 5 | **Source IP 绑定** | 服务端按族下发 `source_ipv4` / `source_ipv6`，所有探测 socket 绑定指定源地址；变更即全量重启探测协程 |
| 6 | **全协议双栈** | 7 种探测原生支持 IPv4/IPv6；域名解析族由任务级 `address_family`（auto/v4/v6/both）控制 |
| 7 | **SNMP 探针代理** | 服务端把指派设备合成 `snmp_poll` 任务（目标/凭证/节奏随任务下发），支持 v1/v2c/v3、自定义 OID、接口表采集；凭证仅内存持有 |
| 8 | **OTA 自动升级** | 服务端在任务响应中携带 `update` 指令，Agent 优雅停机 → 下载校验 SHA-256 → 原子替换二进制 → 原地重启 |
| 9 | **批量上报 + 失败重试** | 双内存队列（探测 / SNMP）攒批，按批次大小或刷新间隔上传；失败批次保留缓冲、指数退避重试，不再整批丢弃 |
| 10 | **公网 IP 自发现** | 强制 tcp4/tcp6 各连一次服务端 `/my-ip` 反射端点，穿透云 NAT 上报真实公网双栈地址 |
| 11 | **优雅停机** | 捕获 SIGINT/SIGTERM，宽限期内等待在途探测与上传完成 |
| 12 | **跨平台静态编译** | 纯 Go + `CGO_ENABLED=0`，一套代码交叉编译 Linux / Windows / macOS × amd64 / arm64 |

### 1.3 架构图

```
  ┌───────────────────────────────────────────────────────────┐
  │                        NMS Server                          │
  │  :8443  POST /api/v1/agents/enroll        (一次性，单向 TLS)│
  │  :8444  GET  /api/v1/agent-sync/tasks             (mTLS)  │
  │  :8444  POST /api/v1/agent-sync/results           (mTLS)  │
  │  :8444  POST /api/v1/agent-sync/snmp-results      (mTLS)  │
  │  :8444  POST /api/v1/agent-sync/renew-cert        (mTLS)  │
  │  :8444  GET  /api/v1/agent-sync/my-ip             (mTLS)  │
  │  :8444  GET  /api/v1/agent-sync/binary/{id}       (mTLS)  │
  └───────────────────────────┬───────────────────────────────┘
                              │ mTLS
                              │ + X-Agent-Version / OS / Arch / IPv4 / IPv6 头
  ┌───────────────────────────▼───────────────────────────────┐
  │  main.go                                                   │
  │   1. 加载 configs/config.yaml                              │
  │   2. 证书检查 → 首次 enroll → 初始化 mTLS 客户端             │
  │   3. 后台协程：证书续签（每日）+ 公网 IP 刷新（每 24h）        │
  │   4. 启动 Reporter + Scheduler；等待信号或 OTA 指令          │
  └────────┬──────────────────────────────────┬───────────────┘
           │                                  │
  ┌────────▼───────────┐            ┌─────────▼───────────────┐
  │     Scheduler       │  Results   │        Reporter          │
  │ 每 poll_interval 拉  │ ─────────> │ 双队列攒批（probe/SNMP）  │
  │ 任务，diff 式管理    │  SNMP      │ 按 batch_size 或         │
  │ 探测协程；透传 OTA   │  Results   │ flush_interval 批量 POST │
  └────────┬───────────┘            └─────────────────────────┘
           │ 并发信号量（max_concurrency）
  ┌────────▼──────────────────────────────────────────────────┐
  │  internal/probe/                                           │
  │   probe.go      — Dispatch() 按 type 路由 + 双栈族展开       │
  │   ping.go       — ICMP（pro-bing，source IP 绑定）          │
  │   tcpping.go    — TCP 拨号（net.Dialer.LocalAddr）          │
  │   httpcheck.go  — HTTP(S)（Transport.DialContext 强制族）   │
  │   dnscheck.go   — DNS（net.Resolver，UDP 源绑定）           │
  │   traceroute.go — 原始 ICMP 套接字（Linux/macOS）            │
  │   mtr.go        — 调用系统 mtr 二进制（Linux/macOS）         │
  │   snmp.go       — SNMP v1/v2c/v3（gosnmp，代理采集）        │
  └───────────────────────────────────────────────────────────┘
```

### 1.4 目录结构

```
NMS_Agent/
├── go.mod / go.sum
├── main.go                      # 入口：配置 / 证书 / mTLS / 后台协程 / OTA 编排
├── configs/
│   └── config.yaml              # Bootstrap 配置（4 个顶级块）
├── .certs/                      # 证书目录（运行时生成，勿提交版本库）
│   ├── ca.crt                   #   服务端 CA 证书
│   ├── client.crt               #   Agent 客户端证书
│   ├── client.key               #   Agent 私钥（0600）
│   └── agent_id                 #   服务端分配的 AgentID
├── logs/                        # 日志目录（运行时生成）
├── .github/workflows/
│   └── release.yml              # 打 v* Tag 自动交叉编译 + 发布 Release
└── internal/
    ├── cert/cert.go             # 证书生命周期：enroll / 到期检查 / renew / mTLS 客户端
    ├── config/config.go         # viper 加载 + 默认值 + 校验
    ├── logger/logger.go         # slog JSON + lumberjack 轮转 + 每日零点切割
    ├── probe/                   # 7 种探测实现（同一 package）
    ├── reporter/reporter.go     # 双队列攒批上传（results / snmp-results）
    ├── scheduler/scheduler.go   # 任务拉取 + diff 式协程管理 + OTA 指令透传
    └── updater/
        ├── updater.go           # 下载 / SHA-256 校验 / 原子替换二进制
        ├── restart_unix.go      # Linux/macOS：syscall.Exec 原地换像（PID 不变）
        └── restart_windows.go   # Windows：干净退出，交由服务管理器重启
```

---

## 2. 快速开始

### 2.1 下载预编译二进制

从 [Releases](https://github.com/Cion-1221/NMS_Agent/releases) 下载对应平台压缩包（`nms-agent_<version>_<os>_<arch>.{tar.gz|zip}`），内含二进制、示例配置与本 README：

```bash
tar -xzf nms-agent_1.0.0_linux_amd64.tar.gz
cd nms-agent_1.0.0_linux_amd64

# 编辑配置：填写 enroll_url、report_url、provisioning_token
vim configs/config.yaml

# 首次运行自动 enroll，拿到证书后进入正常运行模式
./nms-agent -config configs/config.yaml
```

### 2.2 从源码构建

要求 Go 1.25+：

```bash
git clone https://github.com/Cion-1221/NMS_Agent.git
cd NMS_Agent
go build -o nms-agent .
./nms-agent -config configs/config.yaml
```

### 2.3 命令行参数

```
nms-agent -config <path>   指定配置文件路径（默认 configs/config.yaml）
nms-agent -version         打印版本 / commit / 构建时间后退出
```

### 2.4 验证启动

成功启动输出 JSON 结构化日志：

```json
{"time":"...","level":"INFO","msg":"nms-agent starting","version":"1.0.0","region":"HKG"}
{"time":"...","level":"INFO","msg":"enrolling with NMS server","enroll_url":"https://..."}
{"time":"...","level":"INFO","msg":"enrollment successful — certificates saved","agent_id":"agent-abc123"}
{"time":"...","level":"INFO","msg":"scheduler: task started","task_id":1,"type":"ping","interval_s":30}
```

`Ctrl+C`（或 `kill -TERM <pid>`）触发优雅停机；SIGHUP 被忽略（SSH 断连不影响运行）。

---

## 3. 配置说明

完整示例见 [`configs/config.yaml`](configs/config.yaml)。所有 duration 字段接受 Go 格式（`30s`、`1m`）。

### 3.1 agent 块 — 身份

```yaml
agent:
  id: ""                  # 留空；enroll 后从 .certs/agent_id 读取
  region: "HKG"           # 区域标识（当前仅用于本地日志）
  tags:                   # 自定义标签（当前仅本地保留，暂未随协议上报）
    role: "edge"
  hostname_override: ""   # 留空时 enroll 用 os.Hostname()
```

### 3.2 server 块 — 服务端与同步节奏

| 字段 | 默认 | 说明 |
|------|------|------|
| `enroll_url` | — | 单向 TLS 注册端点，仅首次 enroll 使用 |
| `report_url` | —（必填） | mTLS 同步端点：任务拉取 / 结果上传 / 续签 / OTA |
| `provisioning_token` | — | 一次性注册 token，enroll 成功后即可清空 |
| `insecure_enroll` | `false` | 仅放宽 enroll 端点的 TLS 验证（自签场景）；mTLS 通道不受影响 |
| `task_poll_interval` | `30s` | 拉取任务清单的间隔 |
| `flush_interval` | `30s` | 结果上传的最大等待时间 |
| `batch_size` | `100` | 攒够即刻上传（不等 flush_interval） |
| `request_timeout` | `30s` | 单次 HTTP 请求超时 |

### 3.3 runtime 块 — 日志与运行时

| 字段 | 默认 | 说明 |
|------|------|------|
| `log.file` | `logs/nms-agent.log` | 留空输出 stderr；systemd 场景建议绝对路径 |
| `log.level` | `info` | 日志级别：`debug` / `info` / `warn` / `error`（排障时开 debug 可看到调度调和、上传明细） |
| `log.max_size_mb` | `100` | 按大小轮转（lumberjack） |
| `log.max_age_days` | `30` | 轮转文件保留天数 |
| `log.max_backups` | `30` | 轮转文件保留个数 |
| `log.compress` | `true` | gzip 压缩旧日志 |
| `grace_period` | `30s` | 收到停机信号后等待在途工作的上限 |
| `max_concurrency` | `20` | 并发探测任务上限（信号量） |

### 3.4 certs 块 — 证书目录

```yaml
certs:
  dir: ".certs"   # 存放 ca.crt / client.crt / client.key / agent_id
```

### 3.5 敏感信息与环境变量

配置文件在加载前整体做 `${ENV_VAR}` 展开，`provisioning_token: "${NMS_TOKEN}"` 即可从环境变量注入，配置文件本身可安全入库。推荐 systemd `EnvironmentFile=` 或容器 Secret 注入。

---

## 4. 功能模块

> 本章按「一个菜单一个功能」组织：每个小节对应一个独立模块 / 一种探测类型，可直接跳转查阅。

### 4.1 证书与身份 — internal/cert

```
首次启动
  └─ .certs/ 缺任一文件
       └─ POST /api/v1/agents/enroll（单向 HTTPS + provisioning_token + hostname）
            └─ 落盘 ca.crt / client.crt / client.key(0600) / agent_id（目录 0700）

后续启动
  └─ 读取 agent_id → 直接初始化 mTLS 客户端

运行中自动续签
  ├─ 后台协程每 24h 检查 client.crt 的 NotAfter
  ├─ 剩余 < 30 天 → POST /agent-sync/renew-cert（mTLS）
  │    └─ 先校验新 cert/key 配对，再经「临时文件 + rename」原子落盘（CA 有则一并更新）
  └─ mTLS 客户端的 DialTLSContext 在每次新建 TLS 连接时从磁盘重读 CA + 客户端证书
       └─ 续签 / CA 轮换零重启生效
```

关键设计：**不缓存 TLS 配置**。`NewMTLSClient` 不用静态 `tls.Config`，而是自定义 `DialTLSContext` 每次拨号读盘 —— 这是 CA 轮换不掉线的关键（也是 OTA 期间握手不 EOF 的修复点）。启动时会先做一次证书解析校验，让配置错误立刻暴露。

另有 `NewMTLSClientForFamily(dir, timeout, "tcp4"|"tcp6")` 变体，强制单一地址族拨号，供公网 IP 自发现使用（见 [4.7](#47-公网-ip-自发现--maingo)）。

### 4.2 任务调度 — internal/scheduler

- **拉取**：启动立即拉一次，之后每 `task_poll_interval` 拉取 `GET /agent-sync/tasks`，响应含任务数组、`source_ipv4/ipv6`、可选 `update` OTA 指令。
- **diff 式调和**：维护 `map[taskID]*taskRunner`。服务端移除的任务 → cancel 协程；新增任务 → 启动协程；参数变化（interval / type / targets / address_family / skip_tls_verify / SNMP 参数块）→ 先 cancel 再重建。未变化的任务不受影响。
- **源 IP 变更**：任一族源 IP 变化 → 取消全部 runner，同一轮调和内以新绑定重建。
- **并发控制**：全局共享一个 `max_concurrency` 容量的限流器，按**单个探测执行**（每个 target × 地址族）占坑，而非按任务 tick —— 多目标任务也不会突破并发上限。
- **执行节奏**：每个任务独立 ticker（`interval_seconds`，≤0 时回退 60s），启动后立即执行首轮。执行是同步的 —— 单轮超时不会造成同一任务自身重叠执行。
- **SNMP 错峰**：`snmp_poll` 任务按 `task_id % interval` 加确定性启动偏移，避免同机房设备被同秒齐射（所有 runner 共享同一个调和时刻，不加偏移会永久锁相）。
- **OTA 透传**：响应携带 `update` 时经容量 1 的 channel 通知 main（重复指令去重），由 main 执行优雅停机 + 升级（见 [4.5](#45-ota-自动升级--internalupdater)）。

### 4.3 探测引擎 — internal/probe

`Dispatch()` 按 `type` 路由。所有探测类型由服务端指定，本地不声明。通用规则：

- **target 形态**：字面 IPv4/IPv6 地址或域名；tcpping/httpcheck 可带 `:port`；httpcheck 亦可为完整 `http(s)://` URL。
- **address_family**（任务级，只作用于**域名** target）：缺省/`auto` 跟随系统解析偏好；`v4`/`v6` 限定单族；`both` 每域名双族各测一次，结果 target 加 ` (v4)` / ` (v6)` 后缀成两条独立序列（该后缀是与 NMS 前端的跨仓库契约，勿单方面改动）。字面 IP 永远按自身族探测一次。
- **源 IP 选择**：按解析后的目标地址族取对应的 `source_ipv4` / `source_ipv6`；该族未配置源地址时不绑定、走系统默认路由（见 [5.1](#51-source-ip-绑定)）。

#### 4.3.1 ping / meshping

`pro-bing` 库 ICMP echo，count 3 / 间隔 1s / 超时 5s，取平均 RTT。`SetPrivileged(true)` 走原始套接字（Linux 需 root 或 `CAP_NET_RAW`，Windows 需管理员）。域名族限定用 `SetNetwork("ip4"/"ip6")`；`Resolve()` 后按实际地址族选源 IP（`pinger.Source`）。全部丢包按失败上报 `100% packet loss`。

#### 4.3.2 tcpping

TCP 三次握手可达性 + 建连耗时。目标格式解析：

| 输入 | 实际拨号 |
|------|---------|
| `192.168.1.1` | `192.168.1.1:80`（无端口默认 80） |
| `192.168.1.1:8080` | `192.168.1.1:8080` |
| `2001:db8::1`（裸 IPv6） | `[2001:db8::1]:80` |
| `[2001:db8::1]:8080` | `[2001:db8::1]:8080` |

域名先按任务族显式 `LookupIP` 解析成字面 IP 再拨号（取第一条记录）—— 保证实际拨号族与源 IP 绑定选择永远一致。源绑定：`net.Dialer{LocalAddr: &net.TCPAddr{...}}`，拨号超时 5s。

#### 4.3.3 httpcheck

标准库 `net/http` 发 GET，2xx/3xx 记成功，记录整体耗时。要点：

- **scheme 推断**：无 `http(s)://` 前缀的 `host:443` / `host:8443` 默认按 https 探测（避免向 TLS 端口发明文得到误导性 EOF）；其余默认 http。需要非常规组合时显式写全 URL。
- **skip_tls_verify**（任务级）：跳过证书校验，用于裸 IP / 自签设备。
- **族强制**：URL 保留域名（Host 头 / TLS SNI 不变），在 `DialContext` 层用 `tcp4`/`tcp6` 强制拨号族。
- IPv6 字面地址必须用 RFC 3986 括号格式：`https://[2001:db8::1]:8443/api`。

#### 4.3.4 dnscheck

`net.Resolver`（PreferGo）对目标域名做解析探测：`auto` = A+AAAA 合并；`v4`/`v6` = 只查 A / 只查 AAAA；`both` = A、AAAA 各出一条结果（可单独监控某族解析是否损坏）。第一个解析结果写入 `detail`。UDP socket 按上游 DNS 服务器地址族绑定源 IP，单次拨号超时 5s。

#### 4.3.5 traceroute

自实现逐跳追踪：原始 ICMP 套接字（IPv4 走 `ip4:icmp` + TTL，IPv6 走 `ip6:ipv6-icmp` + HopLimit），最多 30 跳、每跳等待 3s，`detail` 输出 JSON hop 数组（ttl/ip/rtt_ms/timeout）及 `reached` 标记。回包按 Echo ID + 序号精确匹配（TimeExceeded 解析内嵌的原始报文校验），每次追踪使用独立 ID —— 多个 traceroute 任务并发时不会互认对方的回包。需要 root / `CAP_NET_RAW`；**Windows 下返回说明性错误结果，不执行**。同一任务内的多个 target 串行执行 —— 并发原始套接字会互抢 ICMP 回包导致跳数归属错乱。

#### 4.3.6 mtr / meshmtr

调用系统 `mtr` 二进制（`--report --json --no-dns`，10 循环、30 跳上限），解析 JSON 输出为 hop 数组（loss/avg/best/worst/stddev）写入 `detail`。族限定传 `-4`/`-6`，源绑定传 `--address`。要求节点已安装 `mtr` 或 `mtr-tiny`；**Windows 下返回说明性错误结果**。

#### 4.3.7 snmp_poll — SNMP 探针代理

与其余类型不同：任务由服务端从设备表**逐台合成**（一台设备一条任务，虚拟 TaskID），`snmp` 参数块携带全部采集要素，Agent 本地零配置：

| 参数 | 说明 |
|------|------|
| `version` | `1` / `2c` / `3` |
| `community` | v1/v2c 团体名 |
| `v3_user` + `v3_auth_proto/pass` + `v3_priv_proto/pass` | v3 USM：认证 MD5/SHA/SHA224/SHA256/SHA384/SHA512，加密 DES/AES/AES192/AES256/AES192C/AES256C；按填写程度自动升级 NoAuthNoPriv → AuthNoPriv → AuthPriv |
| `port` / `timeout_seconds` / `retries` | 连接参数（默认 161 / 3s / 保底非负） |
| `inventory_every_n` | 快慢节奏：每 N 次采一次完整 system 组 |
| `extra_oids` | 自定义标量 OID 列表，每次 poll 随行 |
| `collect_interfaces` | 每周期 WALK `ifTable` + `ifXTable`（v2c/v3 GETBULK、v1 GETNEXT），上限 512 接口 |

**采集节奏**：每周期只采 `sysUpTime`（最小报文，兼做存活判定）+ 自定义 OID；每 `inventory_every_n` 次附带完整 system 组（sysName/sysDescr/sysObjectID/sysLocation/sysContact）—— 资产信息变化少，无需每轮取。

**接口表**：上报原始计数器（HC 64 位优先，缺 ifXTable 回退 32 位），由服务端按 `collected_at` 换算速率；WALK 失败不影响本次采集结论（`has_interfaces` 区分「walk 成功零行」与「walk 未执行」）。

**错误分类**：结果携带 `error_kind`（`unreachable` / `snmp_timeout` / `snmp_error` / `auth_fail`）。v3 USM 认证失败显式归 `auth_fail`；`notInTimeWindow` 是 v3 时间窗重同步信号（gosnmp 自动重试），残留场景归 `snmp_error` 而非误报凭证问题；v1/v2c 下错误团体名表现为超时（协议限制）。

**安全**：凭证只存在于内存任务快照 —— 每个同步周期从服务端全量重建，从不落盘、不打日志。

### 4.4 结果上报 — internal/reporter

- **双队列**：普通探测结果与 SNMP 结论各一条内存队列（容量 `max(batch_size×10, 1000)`），分别攒批 POST 到 `/agent-sync/results` 与 `/agent-sync/snmp-results` —— SNMP 结论是状态快照（驱动服务端设备状态机），不能混入时序 ingest 通道。
- **触发条件**：任一 buffer 达到 `batch_size`，或 `flush_interval` 到期。
- **失败重试**：上传失败（网络错误 / 5xx / 429）的批次保留在缓冲中，指数退避重试（5s 起、翻倍、上限 2min）；4xx 视为服务端明确拒绝、直接丢弃避免卡死缓冲。缓冲上限 `max(batch_size×10, 1000)`，超限淘汰最旧数据（断连期间保新弃旧）。
- **背压策略**：入口队列满时丢弃新结果并告警日志 —— 宁丢单点数据也不阻塞探测协程（SNMP 结论天然可丢：下轮 poll 覆盖）。
- **时间基准**：每条探测结果携带 `collected_at`（unix 秒，探测完成时刻）—— 攒批最多延迟 `flush_interval` 上传，服务端应以该字段而非入库时间作为样本时间戳。
- **优雅停机**：ctx 取消后先排空两条队列、无视退避窗口做最后一次 flush 再退出。

### 4.5 OTA 自动升级 — internal/updater

```
服务端任务响应携带 update{version, binary_id, sha256, file_size}
  └─ Scheduler 经 channel 通知 main
       └─ 优雅停机（等 Reporter 排空 + 探测协程退出，上限 grace_period）
            └─ mTLS 下载 /agent-sync/binary/{id}（10 分钟超时，按 file_size 预分配）
                 └─ SHA-256 校验 → chmod 755 → os.Rename 原子替换自身二进制
                      ├─ Linux/macOS：syscall.Exec 原地换像（PID 不变，systemd 无感知）
                      └─ Windows：os.Exit(0)，交由服务管理器重启
```

关键约束：**临时文件必须写在可执行文件同目录**（`os.Rename` 只在同一文件系统内原子）。systemd `ProtectSystem=strict` 场景必须把**安装目录本身**列入 `ReadWritePaths`，且二进制属主为服务账户，否则更新陷入失败循环（见 [6.5](#65-故障排查)）。下载失败 / 校验失败时退出交由服务管理器重启，下个同步周期自动重试。

### 4.6 结构化日志 — internal/logger

slog JSON 格式；`log.file` 配置后由 lumberjack 托管轮转（大小 / 天数 / 份数 / gzip），另有独立协程在每日本地时间零点强制切割一次 —— 即使没写满 `max_size_mb` 也按天分文件。留空 `log.file` 输出 stderr（容器 / journald 场景）。

### 4.7 公网 IP 自发现 — main.go

启动时及之后每 24h，分别用强制 `tcp4` / `tcp6` 的 mTLS 客户端请求服务端 `GET /agent-sync/my-ip` 反射端点，取服务端视角的公网双栈地址 —— 正确处理云 NAT（GCP/AWS 内网卡地址 ≠ 公网地址）。发现结果注入后续所有 mTLS 请求的 `X-Agent-IPv4` / `X-Agent-IPv6` 头；某族探测失败不清空已缓存地址。

---

## 5. 高级主题

### 5.1 Source IP 绑定

服务端在任务响应中按族下发 `source_ipv4` / `source_ipv6`（可为空）。各协议绑定方式：

| 协议 | 绑定实现 |
|------|---------|
| ICMP（ping） | `pinger.Source = src` |
| TCP（tcpping / httpcheck） | `net.Dialer{LocalAddr: &net.TCPAddr{IP: ...}}` |
| DNS（dnscheck） | `net.Resolver{Dial: ...}` 内 `net.Dialer{LocalAddr: &net.UDPAddr{...}}` |
| 原始 ICMP（traceroute） | `icmp.ListenPacket(network, src)` |
| mtr | `mtr --address src` |

规则：

- 源 IP 按**解析后目标的地址族**选取，不会出现 v4 源绑 v6 目标的非法组合。
- 某族未配置源地址 → 该族探测不绑定、走系统默认路由，**不会因缺配而失败**。
- 任一族源 IP 变更（含有值 ↔ 空）→ 所有探测协程当轮重启，立即以新地址重建 socket。
- Agent 本身缺某族出网能力（如无 IPv6 链路）时，`address_family=both` 下该族探测持续失败 —— 这是可见的诊断信号，属预期行为。

### 5.2 双栈 IPv4/IPv6 与 address_family

所有探测原生双栈，无全局开关；域名解析族由任务级 `address_family` 控制。各协议强制族的机制：

| 探测 | 族强制方式 |
|------|-----------|
| ping | pro-bing `SetNetwork("ip4"/"ip6")` |
| tcpping / traceroute | 先按族 `LookupIP` 解析成字面 IP 再探测 |
| httpcheck | URL 保留域名（Host / SNI 不变），拨号层 `tcp4`/`tcp6` |
| dnscheck | 族映射为只查 A / 只查 AAAA |
| mtr | 透传 `-4` / `-6` |

`both` 模式下每域名产出两条结果序列（target 后缀 ` (v4)` / ` (v6)`），可分别观测两族链路质量。

### 5.3 安全设计

- **双向 mTLS**：任务拉取、结果上传、续签、OTA 下载全部走 mTLS；任一方证书失效即拒连。
- **最小化本地机密**：私钥 `0600`、证书目录 `0700`；SNMP 凭证仅内存持有，不落盘不打日志。
- **`insecure_enroll` 影响面受限**：只放宽 enroll 端点（首次注册）的验证，mTLS 同步通道始终完整校验。
- **provisioning token 一次性**：enroll 成功即失效，配置中可删除；后续鉴权全凭证书。
- **OTA 完整性**：新二进制经 mTLS 通道下载 + SHA-256 校验后才替换。
- **请求头指纹**：所有 mTLS 请求注入 `X-Agent-Version / X-Agent-OS / X-Agent-Arch / X-Agent-IPv4 / X-Agent-IPv6`，供服务端做版本管理与地址展示。

---

## 6. 部署运维

### 6.1 systemd 方式一：自包含目录（root）

所有文件同目录，适合快速部署 / 单机场景。

**目录布局**

```
/opt/nms-agent/
├── nms-agent            # 二进制
├── configs/config.yaml
├── env                  # 敏感变量（chmod 600）
├── .certs/              # enroll 后自动生成
└── logs/
```

`config.yaml` 用相对路径即可（`WorkingDirectory` 固定工作目录）。

**注入 token**

```bash
cat > /opt/nms-agent/env <<'EOF'
NMS_TOKEN=your-one-time-provisioning-token
EOF
chmod 600 /opt/nms-agent/env
```

**unit 文件**

```bash
tee /etc/systemd/system/nms-agent.service > /dev/null <<'EOF'
[Unit]
Description=NMS Agent — network probe edge node
Documentation=https://github.com/Cion-1221/NMS_Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
# 关键：config.yaml 中的相对路径（logs/、.certs/）以此为基准
WorkingDirectory=/opt/nms-agent
ExecStart=/opt/nms-agent/nms-agent -config /opt/nms-agent/configs/config.yaml
Restart=on-failure
RestartSec=10s
# 略长于 grace_period（30s），保证优雅停机走完再 SIGKILL
TimeoutStopSec=35s

EnvironmentFile=-/opt/nms-agent/env

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# ⚠️ 必须包含安装目录本身（而不仅是 logs/.certs 子目录）：
# OTA 要在可执行文件旁写临时二进制做原子替换，目录只读会陷入更新失败循环
ReadWritePaths=/opt/nms-agent

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now nms-agent
```

### 6.2 systemd 方式二：专用账户（生产推荐）

独立账户 + FHS 路径 + 最小权限。

```bash
useradd -r -s /sbin/nologin -d /var/lib/nms-agent -m nms-agent

# 二进制放服务账户可写目录：OTA 要求进程能替换自身二进制。
# 若安全策略要求二进制目录只读，装回 /usr/local/bin 并放弃 OTA、改用外部分发。
mkdir -p /var/lib/nms-agent/bin
install -o nms-agent -g nms-agent -m 755 nms-agent /var/lib/nms-agent/bin/nms-agent

mkdir -p /etc/nms-agent
install -o root -g nms-agent -m 640 configs/config.yaml /etc/nms-agent/config.yaml

mkdir -p /var/log/nms-agent && chown nms-agent:nms-agent /var/log/nms-agent
mkdir -p /var/lib/nms-agent/.certs && chown -R nms-agent:nms-agent /var/lib/nms-agent

tee /etc/nms-agent/env > /dev/null <<'EOF'
NMS_TOKEN=your-one-time-provisioning-token
EOF
chmod 600 /etc/nms-agent/env
```

`config.yaml` 改绝对路径：

```yaml
server:
  provisioning_token: "${NMS_TOKEN}"
runtime:
  log:
    file: "/var/log/nms-agent/nms-agent.log"
certs:
  dir: "/var/lib/nms-agent/.certs"
```

**unit 文件**

```bash
tee /etc/systemd/system/nms-agent.service > /dev/null <<'EOF'
[Unit]
Description=NMS Agent — network probe edge node
Documentation=https://github.com/Cion-1221/NMS_Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nms-agent
Group=nms-agent
ExecStart=/var/lib/nms-agent/bin/nms-agent -config /etc/nms-agent/config.yaml
Restart=on-failure
RestartSec=10s
TimeoutStopSec=35s

EnvironmentFile=-/etc/nms-agent/env

# 非 root 需要 CAP_NET_RAW 才能用 ping / traceroute 的原始套接字
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# /var/lib/nms-agent 同时覆盖 .certs 与 bin/（OTA 在 bin/ 写临时二进制原子替换）
ReadWritePaths=/var/log/nms-agent /var/lib/nms-agent

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now nms-agent
```

### 6.3 Windows 部署注意事项

- Agent 不含 Windows 服务集成，需借助 **NSSM / WinSW / 任务计划程序** 常驻，并配置「退出后自动重启」（OTA 完成时 Agent 以退出码 0 结束，依赖外部管理器拉起新二进制）。
- ICMP ping 需要管理员权限（原始套接字）或放行防火墙。
- traceroute / mtr 任务在 Windows 上返回说明性错误结果并上报，不影响其他探测。

### 6.4 常用管理命令

```bash
systemctl status nms-agent          # 运行状态
systemctl restart nms-agent         # 重启（改配置后执行）
systemctl stop nms-agent            # 停止

journalctl -u nms-agent -f          # 实时 journald 日志
tail -f /opt/nms-agent/logs/nms-agent.log   # 或直接看滚动日志文件
```

### 6.5 故障排查

| 现象 | 原因 | 解决 |
|------|------|------|
| `status=1/FAILURE`，日志报权限错误 | `ProtectSystem=strict` 开启但 `ReadWritePaths` 缺目录 | unit 中列全所有需写入的目录 |
| OTA 反复失败重启，日志报 `create temp file: ... read-only file system` | 安装目录不可写（`ReadWritePaths` 只放行了 logs/.certs，或二进制属主不对） | `systemctl edit nms-agent` 追加 `[Service]` + `ReadWritePaths=<安装目录>`，restart 后下个同步周期自动完成更新 |
| 证书 / 日志路径不存在 | 未设 `WorkingDirectory`，相对路径解析到 `/` | 加 `WorkingDirectory` 或改绝对路径 |
| enroll 报 `x509: certificate signed by unknown authority` | enroll 端点用了系统不信任的证书 | 临时设 `insecure_enroll: true`，enroll 成功后改回 |
| 日志 `no certificates found and server.provisioning_token is empty` | 证书目录缺文件且无 token 可注册 | 补发 token 重新 enroll，或恢复完整 `.certs/` |

> **提示**：首次 enroll 成功（日志出现 `enrollment successful`）后，可删除 env 文件中的 `NMS_TOKEN` —— 之后全凭 mTLS 证书鉴权。

---

## 7. 构建与发布（CI）

[`.github/workflows/release.yml`](.github/workflows/release.yml) 在推送 `v*` Tag 时自动执行三阶段：

1. **verify**：`go mod tidy && go vet ./... && go test ./...`（只跑一次，不进矩阵重复跑）。
2. **build**：矩阵交叉编译 `{linux, windows, darwin} × {amd64, arm64}` 共 6 目标，全部 `CGO_ENABLED=0` 静态编译于单个 ubuntu runner；`-ldflags` 注入 `version / commit / buildDate`（`-version` 可查）；每目标打包为「二进制 + configs/config.yaml + README.md」压缩包。
3. **release**：汇总产物生成 `SHA256SUMS.txt`，按上一 Tag 起的 commit 自动生成 Changelog，`softprops/action-gh-release` 发布。

`workflow_dispatch` 可手动跑完整编译矩阵做预验证，不产生 Release。

发布新版本：

```bash
git tag v1.0.0
git push origin v1.0.0
```

本地交叉编译示例（Linux arm64）：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags "-s -w -X main.version=1.0.0" -o nms-agent_linux_arm64 .
```

---

## 8. 平台支持矩阵

| 功能 | Linux | macOS | Windows |
|------|:-----:|:-----:|:-------:|
| ping（ICMP） | ✅ 需 root / `CAP_NET_RAW` | ✅ 需 sudo | ✅ 需管理员 |
| tcpping / httpcheck / dnscheck | ✅ | ✅ | ✅ |
| traceroute | ✅ 需 root / `CAP_NET_RAW` | ✅ 需 sudo | ❌ 返回说明性错误 |
| mtr | ✅ 需安装 `mtr`/`mtr-tiny` | ✅ 需安装 `mtr` | ❌ 返回说明性错误 |
| snmp_poll | ✅ | ✅ | ✅ |
| OTA 自升级 | ✅ `syscall.Exec` 原地换像 | ✅ 同左 | ⚠️ 退出后依赖服务管理器拉起 |
| 日志轮转 | ✅ | ✅ | ✅ |

traceroute / mtr 在 Windows 上不可用时 Agent 不会崩溃 —— 对应任务返回说明性错误结果并上报，其余探测正常运行。

---

## 9. 服务端 API 契约

Agent 消费的全部服务端接口（`{enroll}` = `enroll_url`，`{sync}` = `report_url`）：

| 方法 | 路径 | 通道 | 用途 |
|------|------|------|------|
| POST | `{enroll}/api/v1/agents/enroll` | 单向 TLS | 首次注册：token + hostname → 证书四件套 + agent_id |
| GET | `{sync}/api/v1/agent-sync/tasks` | mTLS | 拉取任务清单 + source_ipv4/ipv6 + OTA update 指令 |
| POST | `{sync}/api/v1/agent-sync/results` | mTLS | 批量上传探测结果 |
| POST | `{sync}/api/v1/agent-sync/snmp-results` | mTLS | 批量上传 SNMP 采集结论 |
| POST | `{sync}/api/v1/agent-sync/renew-cert` | mTLS | 证书续签 |
| GET | `{sync}/api/v1/agent-sync/my-ip` | mTLS | 公网 IP 反射（tcp4/tcp6 各查一次） |
| GET | `{sync}/api/v1/agent-sync/binary/{id}` | mTLS | 下载 OTA 新二进制 |

**任务对象**（`tasks` 数组元素）：`task_id`、`type`、`interval_seconds`、`targets[]`、`address_family`（可选）、`skip_tls_verify`（httpcheck 专用）、`snmp{...}`（snmp_poll 专用）。

**探测结果**：`task_id`、`type`、`target`、`success`、`latency_ms`、`detail`（traceroute/mtr 的 detail 为 hop 数组 JSON）、`collected_at`（unix 秒，探测完成时刻 —— 服务端应以此为样本时间戳，而非入库时间）。

**SNMP 结论**：`device_id`、`collected_at`（unix 秒，服务端速率换算的时间基准）、`success`、`error_kind`、`latency_ms`、`uptime_ticks`、`has_inventory` + system 组字段、`values[]`（自定义 OID）、`has_interfaces` + `interfaces[]`（原始计数器）。

**每请求注入头**：`X-Agent-Version`、`X-Agent-OS`、`X-Agent-Arch`、`X-Agent-IPv4`、`X-Agent-IPv6`。

---

## 10. License

本项目为 CION 内部专有软件（见 [LICENSE](LICENSE)），仅限 CION 及其关联方内部部署与使用，未经书面授权不得对外分发、公开或再许可。如未来需要对外开源，请先将 LICENSE 替换为相应的开源许可证。
