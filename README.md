# NMS Agent

部署在分布式边缘节点（机房 / POP）上的网络探测 Agent。启动后自动向 NMS Server 申请 mTLS 证书，随后持续轮询服务端下发的探测任务（ping、tcpping、httpcheck、dnscheck、traceroute、mtr），将结果批量上传回服务端。所有探测目标、探测类型、执行周期均由服务端动态下发，本地配置只需填写身份信息和服务端地址。

[![Build and Release](https://github.com/Cion-1221/NMS_Agent/actions/workflows/release.yml/badge.svg)](https://github.com/Cion-1221/NMS_Agent/actions/workflows/release.yml)
![Go Version](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go)
![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20windows%20%7C%20macOS-lightgrey)

## 目录

- [核心特性](#核心特性)
- [架构设计](#架构设计)
- [目录结构](#目录结构)
- [探测类型](#探测类型)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [证书工作流](#证书工作流)
- [Source IP 绑定](#source-ip-绑定)
- [双栈支持（IPv4/IPv6）](#双栈支持ipv4ipv6)
- [安全设计](#安全设计)
- [构建与发布](#构建与发布)
- [配置 systemd 服务常驻](#配置-systemd-服务常驻)
- [平台限制](#平台限制)
- [License](#license)

## 核心特性

- **服务端驱动**：探测目标、类型、周期全部由服务端 `GET /api/v1/agent-sync/tasks` 下发；本地配置仅含身份信息与服务端地址，无需重启即可调整探测策略。
- **mTLS 双向认证**：首次启动时用一次性 provisioning token 向服务端申请证书，后续所有通信（任务拉取、结果上传、证书续签）走互相验证的 mTLS 通道。
- **证书热更新**：mTLS 客户端使用 `GetClientCertificate` 回调，续签后的证书在下一次 TLS 握手时即时生效，无需重启。
- **证书自动续签**：后台 goroutine 每日检查证书有效期，剩余不足 30 天时自动调用 `POST /api/v1/agent-sync/renew-cert` 续签。
- **Source IP 绑定**：服务端可为每个 Agent 指定出站源 IP（IPv4 或 IPv6），所有探测的发包 socket 均绑定到该地址，确保流量从指定网卡出站。源 IP 变更时探测 goroutine 自动重启，立即生效。
- **SNMP 探针代理**：服务端把指派给本 Agent 的设备合成为 `snmp_poll` 任务（目标 IP / 凭证 / 周期随任务下发，本地零配置），Agent 采集 RFC 1213 system 组并把结论批量回传 `POST /agent-sync/snmp-results`，驱动服务端的设备运行状态。凭证仅内存持有、不落盘、不入日志。
- **全协议双栈**：ping、tcpping、httpcheck、dnscheck、traceroute、mtr 均原生支持 IPv4 和 IPv6 目标，无需额外配置。
- **批量上报**：探测结果写入内存队列，按批次大小或刷新间隔批量 POST 到服务端，避免高频小请求。
- **优雅停机**：捕获 `SIGINT`/`SIGTERM`，等待正在执行的探测和上传在宽限期内完成后退出。
- **跨平台静态编译**：纯 Go + `CGO_ENABLED=0`，单一代码库交叉编译出 Linux / Windows / macOS（amd64 与 arm64）六个平台的静态二进制。

## 架构设计

```
  ┌──────────────────────────────────────────────────────┐
  │                    NMS Server                         │
  │                                                        │
  │  :8443  POST /api/v1/agents/enroll  (一次性，单向 TLS) │
  │  :8444  GET  /api/v1/agent-sync/tasks        (mTLS)   │
  │  :8444  POST /api/v1/agent-sync/results      (mTLS)   │
  │  :8444  POST /api/v1/agent-sync/snmp-results (mTLS)   │
  │  :8444  POST /api/v1/agent-sync/renew-cert   (mTLS)   │
  └────────────────────┬─────────────────────────────────┘
                        │
              mTLS + X-Agent-Version header
                        │
  ┌─────────────────────▼─────────────────────────────────┐
  │  main.go                                               │
  │   1. 加载 configs/config.yaml                          │
  │   2. 证书检查 → 首次 enroll → 初始化 mTLS 客户端        │
  │   3. 启动 cert renewal goroutine（每日检查）             │
  │   4. 启动 Reporter + Scheduler                         │
  └──────┬──────────────────────────────┬─────────────────┘
         │                              │
  ┌──────▼──────────┐         ┌─────────▼──────────────┐
  │   Scheduler      │         │      Reporter           │
  │ 每隔 poll_interval│ probe   │ 内存队列攒批            │
  │ 拉取任务，diff 式 │ Results │ 按批次大小 / 刷新间隔   │
  │ 管理 probe 协程  │ ──────> │ POST /results           │
  └──────┬──────────┘         └────────────────────────┘
         │  并发信号量（max_concurrency）
  ┌──────▼──────────────────────────────────────────────┐
  │  internal/probe/                                     │
  │   probe.go     — Dispatch() 路由到对应实现            │
  │   ping.go      — ICMP（pro-bing，source IP 绑定）     │
  │   tcpping.go   — TCP 拨号（net.Dialer.LocalAddr）    │
  │   httpcheck.go — HTTP(S)（Transport.DialContext）    │
  │   dnscheck.go  — DNS（net.Resolver，UDP bind）       │
  │   traceroute.go— 原始 ICMP 套接字（Linux/macOS）     │
  │   mtr.go       — 调用系统 mtr 二进制（Linux/macOS）  │
  │   snmp.go      — SNMP v1/v2c GET（gosnmp，代理采集） │
  └─────────────────────────────────────────────────────┘
```

**任务调和逻辑**：`Scheduler` 维护一个 `map[taskID]*taskRunner`。每次从服务端拉取任务后，取消服务端已移除的任务对应的 goroutine，为新增任务启动 goroutine，已有任务保持不变（不重启）。若服务端返回的 `source_ip` 发生变化，则取消所有运行中的 goroutine，在同一轮调和中重新启动，以使新的 IP 绑定立即生效。

## 目录结构

```
NMS_Agent/
├── go.mod / go.sum
├── main.go                       # 入口：配置 / 证书 / mTLS 客户端 / 启动
├── configs/
│   └── config.yaml               # Bootstrap 配置（4 个顶级块）
├── .certs/                       # 证书目录（运行时生成，不提交版本库）
│   ├── ca.crt                    # 服务端 CA 证书
│   ├── client.crt                # Agent 客户端证书
│   ├── client.key                # Agent 私钥（权限 0600）
│   └── agent_id                  # 服务端分配的 AgentID
├── logs/                         # 日志目录（运行时生成）
├── .github/workflows/
│   └── release.yml               # 打 Tag 自动交叉编译并发布 Release
└── internal/
    ├── cert/cert.go              # 证书生命周期：enroll / expiry / renew / mTLS 客户端
    ├── config/config.go          # viper 加载 + 配置结构体
    ├── logger/logger.go          # slog JSON 日志 + lumberjack 文件轮转
    ├── probe/                    # 所有探测实现（同一个 package）
    │   ├── probe.go              #   Dispatch()：task type → 实现路由
    │   ├── ping.go               #   ICMP Ping
    │   ├── tcpping.go            #   TCP 端口可达性
    │   ├── httpcheck.go          #   HTTP(S) 健康检查
    │   ├── dnscheck.go           #   DNS 解析探测
    │   ├── traceroute.go         #   逐跳路由追踪
    │   ├── mtr.go                #   MTR（调用系统二进制）
    │   └── snmp.go               #   SNMP 代理采集（system 组，快/慢两档）
    ├── reporter/reporter.go      # 攒批 + HTTP POST 到 /results 与 /snmp-results（双队列）
    └── scheduler/scheduler.go   # 任务拉取 + diff 式协程管理（snmp_poll 带启动错峰）
```

## 探测类型

所有探测类型均由服务端在任务列表中指定，本地配置中不声明。

| type 字段 | 协议 / 工具 | IPv4 | IPv6 | Linux | Windows | macOS |
|-----------|------------|:----:|:----:|:-----:|:-------:|:-----:|
| `ping` / `meshping` | ICMP（pro-bing） | ✅ | ✅ | ✅ | ✅* | ✅ |
| `tcpping` | TCP | ✅ | ✅ | ✅ | ✅ | ✅ |
| `httpcheck` | HTTP(S) | ✅ | ✅† | ✅ | ✅ | ✅ |
| `dnscheck` | DNS UDP | ✅ | ✅ | ✅ | ✅ | ✅ |
| `traceroute` | 原始 ICMP | ✅ | ✅ | ✅ | ❌‡ | ✅ |
| `mtr` | `mtr` 二进制 | ✅ | ✅ | ✅ | ❌‡ | ✅ |
| `snmp_poll` | SNMP v1/v2c UDP（gosnmp） | ✅ | ✅ | ✅ | ✅ | ✅ |

\* Windows 下 ICMP ping 通常需要管理员权限或放行防火墙。  
† httpcheck 的 IPv6 目标 URL 须使用 RFC 3986 括号格式：`http://[2001:db8::1]/path`。  
‡ Windows 上 traceroute 和 mtr 任务返回明确的不支持错误结果，不会导致 Agent 崩溃。

**snmp_poll（SNMP 探针代理）**与其余类型不同：任务由服务端从设备表**逐台合成**（虚拟 TaskID，一台设备一条任务），参数块携带目标 IP、SNMP 版本（v1/v2c/**v3**）、凭证（community 或 v3 的 USM 用户/认证/加密协议与口令）、端口、超时与重试、快慢采集节奏（`inventory_every_n`）、**自定义标量 OID 列表**（`extra_oids`）以及**接口表开关**（`collect_interfaces`——每周期 WALK `ifTable`/`ifXTable` 两个子树，v2c/v3 用 GETBULK、v1 退回 GETNEXT，随结果上报原始计数器由服务端换算速率；WALK 失败不影响本次采集结论）。Agent 每周期只采 `sysUpTime` + 自定义 OID（最小报文，兼做存活判定），每 N 次附带完整 system 组（sysName/sysDescr/sysObjectID/sysLocation/sysContact）；结论走独立队列批量回传 `POST /agent-sync/snmp-results`，每条携带采集时刻 `collected_at`（unix 秒）——服务端以它为 counter 速率换算与时序时间轴的基准，批量攒批不会扭曲速率。v3 的认证失败（USM 错误）显式归类为 `auth_fail` 上报（notInTimeWindow 时间窗重同步除外，gosnmp 自动处理）。多台设备的采集相位按 TaskID 在周期内错开，避免同机房设备被同秒齐射。凭证只存在于内存中的任务快照——每个同步周期从服务端全量重建，从不写盘、不打日志。

## 快速开始

### 方式一：下载预编译二进制

从 [Releases](https://github.com/Cion-1221/NMS_Agent/releases) 下载对应平台的压缩包（`nms-agent_<version>_<os>_<arch>.{tar.gz|zip}`），解压后内含二进制、示例配置与 README：

```bash
tar -xzf nms-agent_1.0.0_linux_amd64.tar.gz
cd nms-agent_1.0.0_linux_amd64

# 编辑配置：填写 enroll_url、report_url、provisioning_token
vim configs/config.yaml

# 首次运行自动 enroll，获取证书后进入正常运行模式
./nms-agent -config configs/config.yaml
```

### 方式二：从源码构建

要求 Go 1.25 及以上。

```bash
git clone https://github.com/Cion-1221/NMS_Agent.git
cd NMS_Agent
go build -o nms-agent .
./nms-agent -config configs/config.yaml
```

### 命令行参数

```
nms-agent -config <path>   指定配置文件路径（默认 configs/config.yaml）
nms-agent -version         打印版本 / commit / 构建时间后退出
```

### 验证启动

成功启动后会输出 JSON 结构化日志：

```json
{"time":"...","level":"INFO","msg":"nms-agent starting","version":"1.0.0","region":"HKG"}
{"time":"...","level":"INFO","msg":"enrolling with NMS server","enroll_url":"https://..."}
{"time":"...","level":"INFO","msg":"enrollment successful — certificates saved","agent_id":"agent-abc123"}
{"time":"...","level":"INFO","msg":"scheduler: task started","task_id":1,"type":"ping","interval_s":30}
```

按 `Ctrl+C`（或 `kill -TERM <pid>`）触发优雅停机。

## 配置说明

完整示例见 [`configs/config.yaml`](configs/config.yaml)，分为四个顶级块：

```yaml
agent:
  id: ""                        # 留空；enrollment 后从 .certs/agent_id 读取
  region: "HKG"                 # 区域标识，随结果一并上报
  tags:
    role: "edge"
    datacenter: "DC1"
  hostname_override: ""         # 留空时使用 os.Hostname()

server:
  enroll_url: "https://nms.example.com:8443"    # 单向 TLS，仅首次 enroll 使用
  report_url: "https://nms.example.com:8444"    # mTLS，任务拉取 + 结果上传
  provisioning_token: "${NMS_TOKEN}"            # 一次性 token，enroll 后可清空
  insecure_enroll: false        # 仅在 enroll 端点使用自签名证书时设 true
  task_poll_interval: "30s"     # 拉取任务列表的间隔
  flush_interval: "30s"         # 结果上传的最大等待时间
  batch_size: 100               # 攒够此数量立即上传（不等 flush_interval）
  request_timeout: "30s"        # 单次 HTTP 请求超时

runtime:
  log:
    file: "logs/nms-agent.log"  # 留空则输出到 stderr
    max_size_mb: 100            # 按大小轮转
    max_age_days: 30            # 保留天数
    max_backups: 30             # 保留文件数
    compress: true              # gzip 压缩旧日志
  grace_period: "30s"           # SIGTERM 后等待探测/上传完成的最长时间
  max_concurrency: 20           # 同时执行的探测任务上限

certs:
  dir: ".certs"                 # 证书存放目录（含 ca.crt / client.crt / client.key / agent_id）
```

**敏感信息处理**：`provisioning_token` 等字段支持 `${ENV_VAR}` 占位符，在启动时从环境变量展开，配置文件本身可安全提交版本库。推荐通过 systemd `EnvironmentFile=` 或容器 Secret 注入。

## 证书工作流

```
首次启动
  └─ .certs/ 不存在或不完整
       └─ POST /api/v1/agents/enroll（单向 HTTPS，带 provisioning_token）
            └─ 写入 ca.crt、client.crt、client.key（0600）、agent_id
               └─ 初始化 mTLS 客户端，进入正常运行

后续启动
  └─ .certs/ 存在
       └─ 读取 agent_id，直接初始化 mTLS 客户端

证书热更新（运行中）
  ├─ 后台 goroutine 每 24h 检查 client.crt 有效期
  ├─ 剩余 < 30 天 → POST /api/v1/agent-sync/renew-cert（mTLS）
  │    └─ 服务端返回新 cert/key，覆盖写入磁盘
  └─ 下一次 TLS 握手自动加载新证书（GetClientCertificate 回调）
       └─ 无需重启 Agent
```

## Source IP 绑定

服务端在任务响应中携带 `source_ip` 字段（可为空，支持 IPv4 或 IPv6）。Agent 将其传递给所有探测函数，各协议的绑定方式如下：

| 协议 | 绑定实现 |
|------|---------|
| ICMP（ping） | `pinger.Source = sourceIP` |
| TCP（tcpping / httpcheck） | `net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(sourceIP)}}` |
| DNS（dnscheck） | `net.Resolver{Dial: func() { net.Dialer{LocalAddr: &net.UDPAddr{IP: ...}} }}` |
| 原始 ICMP（traceroute） | `icmp.ListenPacket(network, sourceIP)` |
| mtr | `mtr --address sourceIP` |

`source_ip` 为空时各探测使用操作系统默认路由出站接口，行为与普通工具一致。

服务端下发的 `source_ip` 变更（包括从有值变为空或反之）会触发所有探测 goroutine 立即重启，在同一个调和周期内以新地址重建连接。

**地址族约束**：`source_ip` 与探测目标必须属于同一地址族。IPv4 源地址配合 IPv6 目标（或反之）会导致 socket 绑定失败；服务端在下发任务时应保证两者一致。

## 双栈支持（IPv4/IPv6）

所有探测均原生支持 IPv4 和 IPv6，无需额外配置开关。各协议的实现细节：

**ping / meshping**  
`pro-bing` 对目标地址执行 `Resolve()` 后，依据解析结果自动选择 ICMPv4 或 ICMPv6。目标可填 IPv4 字面地址、IPv6 字面地址或域名（域名同时有 A/AAAA 记录时由操作系统决策优先级）。

**tcpping**  
使用 `net.SplitHostPort` + `net.JoinHostPort` 解析目标，正确处理所有格式：

| 输入格式 | 解析结果 |
|----------|---------|
| `192.168.1.1` | → `192.168.1.1:80` |
| `192.168.1.1:8080` | → `192.168.1.1:8080` |
| `2001:db8::1`（裸 IPv6） | → `[2001:db8::1]:80` |
| `[2001:db8::1]:8080` | → `[2001:db8::1]:8080` |

**httpcheck**  
使用标准库 `net/http`，原生支持 IPv6。IPv6 字面地址在 URL 中须遵循 RFC 3986 括号格式：

```
http://[2001:db8::1]/path        ✅
https://[2001:db8::1]:8443/api   ✅
http://2001:db8::1/path          ❌ 不合法，stdlib 解析失败
```

**dnscheck**  
`net.Resolver.LookupIPAddr` 同时返回 A（IPv4）和 AAAA（IPv6）记录，结果中的第一个地址记入 `detail` 字段。DNS 查询通过绑定了 `source_ip` 的 UDP socket 发出，支持 IPv4 和 IPv6 上游 DNS 服务器。

**traceroute**  
代码内部按目标地址族分叉：IPv4 目标走 `ip4:icmp`（ICMPv4 Echo + TTL），IPv6 目标走 `ip6:ipv6-icmp`（ICMPv6 EchoRequest + HopLimit）。Source IP 通过 `icmp.ListenPacket(network, sourceIP)` 绑定，对两个地址族均有效。

**mtr**  
`mtr` 二进制本身支持双栈，目标为 IPv6 地址时自动使用 ICMPv6。`--address` 参数接受 IPv4 或 IPv6 源地址。

## 安全设计

- **双向 mTLS**：任务拉取、结果上传、证书续签均走 mTLS 通道。服务端 CA 签发 Agent 证书，Agent 信任服务端 CA；双方互相验证，任意一方证书失效即连接拒绝。
- **`X-Agent-Version` 请求头**：所有 mTLS 请求都注入该头（值为编译时 `-ldflags` 写入的版本号），供服务端记录 Agent 软件版本，无需额外鉴权字段。
- **证书文件权限**：私钥 `client.key` 写入权限为 `0600`；`certs.dir` 目录权限为 `0700`。
- **insecure_enroll 仅限首次**：`insecure_enroll: true` 只影响 enroll 端点（端口 8443）的 TLS 验证，mTLS 同步通道（端口 8444）始终执行完整证书验证，不受该选项影响。
- **provisioning_token 一次性**：Enroll 成功后该 token 即失效；配置中可将其清空或删除，后续所有连接凭证书鉴权。

## 构建与发布

[`.github/workflows/release.yml`](.github/workflows/release.yml) 在推送 `v*` Tag 时自动执行：

1. **verify**：`go mod tidy && go vet ./... && go test ./...`，只跑一次（不重复跑 6 遍）。
2. **build**：矩阵交叉编译 `{linux, windows, darwin} × {amd64, arm64}` 共 6 个目标，均基于 `CGO_ENABLED=0` 纯 Go 静态编译，全部在单个 `ubuntu-latest` runner 上完成。通过 `-ldflags` 写入 `version`/`commit`/`buildDate`，可用 `-version` 查看。每个目标打包成含二进制 + `configs/config.yaml` + `README.md` 的压缩包。
3. **release**：汇总产物，生成 `SHA256SUMS.txt`，按 Tag 间 commit 自动生成 Changelog，调用 `softprops/action-gh-release` 发布。

`workflow_dispatch` 可手动触发完整编译矩阵做预验证，不会创建 Release。

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

## 配置 systemd 服务常驻

以下步骤适用于 Linux（systemd），使 NMS Agent 开机自启并在崩溃后自动重启。提供两种部署布局：**自包含目录**（简单，以 root 运行）和**专用账户**（生产推荐）。

---

### 方式一：自包含目录（root）

所有文件放在同一个目录下，适合快速部署或单机场景。

**目录布局**

```
/opt/nms-agent/
├── nms-agent            # 二进制
├── configs/
│   └── config.yaml
├── env                  # 敏感变量（chmod 600）
├── .certs/              # enrollment 后自动生成
└── logs/                # 日志文件
```

**config.yaml 使用相对路径即可**（`WorkingDirectory` 会将工作目录固定为 `/opt/nms-agent`）：

```yaml
runtime:
  log:
    file: "logs/nms-agent.log"

certs:
  dir: ".certs"
```

**注入 provisioning token**

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
# WorkingDirectory 是关键：config.yaml 中的相对路径（logs/、.certs/）
# 均以此目录为基准解析，不设则默认为 /，路径全部错误。
WorkingDirectory=/opt/nms-agent
ExecStart=/opt/nms-agent/nms-agent -config /opt/nms-agent/configs/config.yaml
Restart=on-failure
RestartSec=10s
# 略长于 grace_period（30s），确保 Agent 完成优雅停机后 systemd 再发 SIGKILL
TimeoutStopSec=35s

# 从独立文件注入敏感变量；前置 - 表示文件不存在时不报错
EnvironmentFile=-/opt/nms-agent/env

# 安全加固（root 运行时无需 AmbientCapabilities）
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# ProtectSystem=strict 将文件系统设为只读；运行时需要写入的目录必须在此列出。
# ⚠️ 必须包含安装目录本身（而不仅是 logs/.certs 子目录）：OTA 自更新要在可执行
# 文件旁写入临时二进制再原子替换（rename 只在同一文件系统内原子），目录只读会让
# 更新陷入失败重启循环，日志表现为 "create temp file: ... read-only file system"
ReadWritePaths=/opt/nms-agent

[Install]
WantedBy=multi-user.target
EOF
```

```bash
systemctl daemon-reload
systemctl enable --now nms-agent
```

---

### 方式二：专用账户（生产推荐）

独立账户 + FHS 标准路径，配合最小权限原则。

**创建系统账户**

```bash
useradd -r -s /sbin/nologin -d /var/lib/nms-agent -m nms-agent
```

**安装文件**

```bash
# 二进制放在服务账户可写的目录：OTA 自更新要求进程能替换自身二进制
# （非 root 账户替换不了 /usr/local/bin 下 root 属主的文件）。
# 若安全策略要求二进制目录只读，请装回 /usr/local/bin 并放弃 OTA、改用外部方式分发更新。
mkdir -p /var/lib/nms-agent/bin
install -o nms-agent -g nms-agent -m 755 nms-agent /var/lib/nms-agent/bin/nms-agent

mkdir -p /etc/nms-agent
install -o root -g nms-agent -m 640 configs/config.yaml /etc/nms-agent/config.yaml

mkdir -p /var/log/nms-agent && chown nms-agent:nms-agent /var/log/nms-agent
mkdir -p /var/lib/nms-agent/.certs && chown -R nms-agent:nms-agent /var/lib/nms-agent
```

**注入 provisioning token**

```bash
tee /etc/nms-agent/env > /dev/null <<'EOF'
NMS_TOKEN=your-one-time-provisioning-token
EOF
chmod 600 /etc/nms-agent/env
```

**config.yaml 使用绝对路径**

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

# 非 root 账户需要 CAP_NET_RAW 才能使用 ping / traceroute 的原始套接字
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# /var/lib/nms-agent 同时覆盖 .certs 与 bin/（OTA 自更新在 bin/ 写临时二进制做原子替换）
ReadWritePaths=/var/log/nms-agent /var/lib/nms-agent

[Install]
WantedBy=multi-user.target
EOF
```

```bash
systemctl daemon-reload
systemctl enable --now nms-agent
```

---

### 常用管理命令

```bash
systemctl status nms-agent          # 运行状态
systemctl restart nms-agent         # 重启（修改配置后执行）
systemctl stop nms-agent            # 停止

journalctl -u nms-agent -f          # 实时跟踪 journald 日志
tail -f /opt/nms-agent/logs/nms-agent.log   # 或直接查看滚动日志文件
```

### 常见启动失败原因

| 现象 | 原因 | 解决 |
|------|------|------|
| `status=1/FAILURE`，日志提示权限错误 | `ProtectSystem=strict` 开启但 `ReadWritePaths` 未配置，Agent 无法写日志或证书 | 在 unit 文件中正确填写 `ReadWritePaths`，列出所有需要写入的目录 |
| OTA 更新反复失败重启，日志报 `create temp file: ... read-only file system` | 安装目录不可写：OTA 需在可执行文件旁写临时二进制做原子替换，但 `ReadWritePaths` 只放行了 logs/.certs 子目录（或二进制属主不是服务账户） | `systemctl edit nms-agent`，drop-in 中追加 `[Service]` + `ReadWritePaths=<安装目录>`（列表型配置自动与原有合并），保存后 `systemctl restart nms-agent`，下个同步周期自动完成更新 |
| 证书/日志路径不存在 | 未设 `WorkingDirectory`，config.yaml 中的相对路径被解析到 `/` 下 | 添加 `WorkingDirectory=<安装目录>` 或在 config.yaml 中改用绝对路径 |
| enrollment 报 `x509: certificate signed by unknown authority` | enroll 端点使用了系统不信任的证书（自签名或私有 CA） | 在 config.yaml 中设置 `insecure_enroll: true`，enrollment 成功后可改回 `false` |

> **提示**：首次 enrollment 成功后（日志出现 `enrollment successful`），可将 `env` 文件中的 `NMS_TOKEN` 行删除——之后凭 mTLS 证书鉴权，provisioning token 不再使用。

## 平台限制

| 功能 | Linux | macOS | Windows |
|------|:-----:|:-----:|:-------:|
| ping / tcpping / httpcheck / dnscheck | ✅ | ✅ | ✅ |
| traceroute | ✅（需 root 或 `CAP_NET_RAW`） | ✅（需 sudo） | ❌ 返回明确错误 |
| mtr | ✅（需安装 `mtr-tiny`） | ✅（需安装 `mtr`） | ❌ 返回明确错误 |
| 日志文件轮转 | ✅ | ✅ | ✅ |

traceroute 和 mtr 在 Windows 上不可用时，Agent 不会崩溃——对应任务会返回说明性错误结果并上报给服务端，其他探测任务继续正常运行。

## License

本项目尚未指定开源许可证。当前仅限 CION 内部使用；如需对外开源，请补充 `LICENSE` 文件。
