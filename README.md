# 🛰️ NMS Agent — 分布式网络拨测与 SNMP 代理边缘探针

**NMS Agent** 是配套 **[CION NMS](https://github.com/Cion-1221/NMS)** 部署在全球机房、POP 边缘节点与内网隔离区的轻量级纯 Go 守护进程。探针遵循**「零本地业务配置、全链路服务端驱动」**的设计哲学：首次启动凭一次性注册码（Provisioning Token）自动换取 mTLS 客户端证书，此后所有探测目标、协议类型、执行周期、双栈地址族策略、出口源 IP 绑定、SNMP 代理采集凭证、Root CA 信任链热轮换及二进制 OTA 自升级均经由双向验证的 mTLS 通道自动完成，运维人员无需二次登录边缘节点。

[![Build and Release](https://github.com/Cion-1221/NMS_Agent/actions/workflows/release.yml/badge.svg)](https://github.com/Cion-1221/NMS_Agent/actions/workflows/release.yml)
![Go Version](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go)
![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20windows%20%7C%20macOS-0078D6)
![Arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-orange)

---

## 📖 目录

- [1. 架构与核心特性](#1-架构与核心特性)
  - [1.1 核心能力矩阵](#11-核心能力矩阵)
  - [1.2 进程内部数据流与模块拓扑](#12-进程内部数据流与模块拓扑)
  - [1.3 仓库目录结构](#13-仓库目录结构)
- [2. 快速开始](#2-快速开始)
  - [2.1 使用预编译发行包运行](#21-使用预编译发行包运行)
  - [2.2 从源码构建与测试](#22-从源码构建与测试)
  - [2.3 命令行参数与信号处理](#23-命令行参数与信号处理)
- [3. 配置文件详解（`configs/config.yaml`）](#3-配置文件详解configsconfigyaml)
  - [3.1 `agent` — 节点身份与元数据](#31-agent--节点身份与元数据)
  - [3.2 `server` — 服务端地址与同步节奏](#32-server--服务端地址与同步节奏)
  - [3.3 `runtime` — 日志轮转与并发控制](#33-runtime--日志轮转与并发控制)
  - [3.4 `certs` — 凭证持久化目录](#34-certs--凭证持久化目录)
  - [3.5 严格的 `${ENV_VAR}` 环境变量注入规则](#35-严格的-env_var-环境变量注入规则)
- [4. 核心模块与七大探测引擎](#4-核心模块与七大探测引擎)
  - [4.1 证书生命周期、连接池与三阶段平滑 CA 轮换（`internal/cert`）](#41-证书生命周期连接池与三阶段平滑-ca-轮换internalcert)
  - [4.2 双栈公网 IP 自发现与协议栈声明（`main.go`）](#42-双栈公网-ip-自发现与协议栈声明maingo)
  - [4.3 Diff 式协程调度器（`internal/scheduler`）](#43-diff-式协程调度器internalscheduler)
  - [4.4 七大探测引擎详解（`internal/probe`）](#44-七大探测引擎详解internalprobe)
    - [4.4.1 `ping` / `meshping` — 原生双栈 ICMP 回显探测](#441-ping--meshping--原生双栈-icmp-回显探测)
    - [4.4.2 `tcpping` — TCP 建连可达性与握手耗时](#442-tcpping--tcp-建连可达性与握手耗时)
    - [4.4.3 `httpcheck` — HTTP/HTTPS 状态与响应延迟](#443-httpcheck--httphttps-状态与响应延迟)
    - [4.4.4 `dnscheck` — 支持自定义上游与 TCP 回退的域名解析探测](#444-dnscheck--支持自定义上游与-tcp-回退的域名解析探测)
    - [4.4.5 `traceroute` — 自研原始套接字逐跳追踪](#445-traceroute--自研原始套接字逐跳追踪)
    - [4.4.6 `mtr` / `meshmtr` — 路径丢包与抖动统计](#446-mtr--meshmtr--路径丢包与抖动统计)
    - [4.4.7 `snmp_poll` — 零落盘 SNMP v1/v2c/v3 代理采集](#447-snmp_poll--零落盘-snmp-v1v2cv3-代理采集)
  - [4.5 分片攒批上报与指数退避缓冲（`internal/reporter`）](#45-分片攒批上报与指数退避缓冲internalreporter)
  - [4.6 跨平台原子 OTA 自升级（`internal/updater`）](#46-跨平台原子-ota-自升级internalupdater)
- [5. Source IP 出口绑定与双栈 `address_family` 契约](#5-source-ip-出口绑定与双栈-address_family-契约)
- [6. 生产环境部署指南](#6-生产环境部署指南)
  - [6.1 Linux systemd 最小权限部署（生产推荐）](#61-linux-systemd-最小权限部署生产推荐)
  - [6.2 Linux systemd 单目录快速部署（`/opt/nms-agent`）](#62-linux-systemd-单目录快速部署optnms-agent)
  - [6.3 Windows 服务常驻注意事项](#63-windows-服务常驻注意事项)
  - [6.4 常见故障排查速查表](#64-常见故障排查速查表)
- [7. CI/CD 交叉编译与发布流水线](#7-cicd-交叉编译与发布流水线)
- [8. 跨平台能力支持矩阵](#8-跨平台能力支持矩阵)
- [9. 服务端通信协议契约一览](#9-服务端通信协议契约一览)
- [10. License](#10-license)

---

## 1. 架构与核心特性

### 1.1 核心能力矩阵

| 维度 | 核心能力 | 实现机制 |
|------|----------|----------|
| **零接触引导** | 一次性 Token 注册 | 首次启动调用单向 TLS `:8443/api/v1/agents/enroll` 校验密钥配对并原子落盘四件套，此后永久切换至 `:8444` 双向 mTLS |
| **零中断 PKI 演进** | 三阶段 CA 热同步 + 自动续签 | 基于文件 `(ModTime, Size)` 内存缓存证书池；随 `/tasks` 自动热更新预分发 `ca_bundle_pem`、响应 `renew_cert` 立即换证，并每日巡检提前 30 天续签 |
| **穿透 NAT 双栈感知** | `/my-ip` 双族反射 + `X-Agent-Stack` | 启动时同步使用 `tcp4`/`tcp6` 探测服务端反射端点并声明可用协议栈，驱动服务端精准裁剪全网 Mesh 互测目标 |
| **全协议双栈与源绑定** | 7 类探测 + 精准出口绑定 | 全部主动拨测及 `snmp_poll` 均支持按目标实际解析地址族自动绑定 `source_ipv4` / `source_ipv6`；域名支持 `auto` / `v4` / `v6` / `both` |
| **高可靠抗弱网回传** | 双通道分片上报 + 退避环形缓冲 | 拨测结果与 SNMP 状态快照物理分流；断网恢复后按 `batch_size` 逐片排空（已成功分片即时清退并缩容底层数组），杜绝大包超时死循环与内存驻留 |
| **跨平台无感 OTA** | SHA-256 校验 + 原地换像/回滚 | 慢探测超时不阻断挂起的 OTA 升级；Linux/macOS 通过 `syscall.Exec` 原地无缝换像（PID 不变），Windows 采用 `.old` 暂存替换与失败自动回滚 |
| **内网零落盘代理** | SNMP v1 / v2c / v3 USM 采集 | 凭证随同步周期仅存于内存、绝不落盘或打印日志；内置确定性相位错峰（`task_id % interval`）、HC 64 位接口计数器优先与 `Counter64` 防溢出解码 |

### 1.2 进程内部数据流与模块拓扑

```text
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                               NMS Server                                │
  │  • :8443 (HTTPS)  POST /api/v1/agents/enroll                            │
  │  • :8444 (mTLS)   GET  /api/v1/agent-sync/{tasks,my-ip,binary/:id}      │
  │                   POST /api/v1/agent-sync/{results,snmp-results,        │
  │                                            renew-cert}                  │
  └───────────────────────────────────▲─────────────────────────────────────┘
                                      │ mTLS（Keep-Alive 连接池 + ModTime 按需热加载）
                                      │ 注入头：X-Agent-{Version,OS,Arch,IPv4,IPv6,Stack,CA-FP}
  ┌───────────────────────────────────▼─────────────────────────────────────┐
  │ main.go（生命周期编排）                                                   │
  │  ├─ 启动清理残留 <exe>.old → 严格 ${ENV_VAR} 加载 config.yaml             │
  │  ├─ 首次 Enroll 或读取 .certs/ → 构建 mTLS Client                        │
  │  ├─ 同步双栈公网 IP 自发现（/my-ip）+ 后台 24h 刷新 & 每日证书到期巡检      │
  │  └─ 协调 Scheduler + Reporter 优雅停机 → 执行挂起的 Updater.Apply         │
  └───────────────┬──────────────────────────────────────┬──────────────────┘
                  │                                      │
  ┌───────────────▼──────────────────┐   ┌───────────────▼──────────────────┐
  │ internal/scheduler               │   │ internal/reporter                │
  │  • 周期拉取 /tasks Diff 调和协程  │   │  • 独立队列：probe / snmp        │
  │  • 热更新 ca_bundle_pem & 续签   │──►│  • 按 batch_size 分片逐批上传     │
  │  • 源 IP 变更即时全量重启探测协程 │   │  • 5s→2m 指数退避 + 底层切片缩容 │
  └───────────────┬──────────────────┘   └──────────────────────────────────┘
                  │ 共享信号量 Limiter（max_concurrency，按单目标×地址族占槽）
  ┌───────────────▼─────────────────────────────────────────────────────────┐
  │ internal/probe（全链路 5s Context 感知 DNS 解析 + 协议级硬超时守卫）       │
  │  • ping.go (ICMPv4/v6)   • tcpping.go (TCP)     • httpcheck.go (HTTP/S) │
  │  • dnscheck.go (UDP/TCP) • traceroute.go (Raw)  • mtr.go (mtr --json)   │
  │  • snmp.go (gosnmp v1/v2c/v3 + LocalAddr 源绑定 + ifTable/ifXTable)      │
  └─────────────────────────────────────────────────────────────────────────┘
```

### 1.3 仓库目录结构

```text
NMS_Agent/
├── go.mod / go.sum
├── main.go                          # 进程入口：初始化、公网 IP 自发现、请求头注入、优雅停机与 OTA 编排
├── myip_test.go                     # /my-ip 响应解析单元测试
├── configs/
│   ├── config.yaml                  # 探针启动配置模板（仅需服务端地址与身份信息）
│   └── nms-agent.service            # 生产级最小权限 systemd 单元模板（非 root + CAP_NET_RAW）
├── .github/workflows/
│   └── release.yml                  # CI/CD：go vet + go test -race + 6 平台静态交叉编译与 Release 发布
└── internal/
    ├── cert/                        # Enroll 注册、ModTime/Size 证书缓存热加载、CA 信任包热更新、自动续签
    ├── config/                      # Viper 配置读取、严格 ${ENV_VAR} 占位符展开与参数校验
    ├── logger/                      # slog JSON 结构化日志 + lumberjack 大小轮转 + 每日零点强制切割
    ├── probe/                       # 7 类网络探测与 SNMP 代理采集实现（含协议级单元测试）
    ├── reporter/                    # 双通道分片批量上报、指数退避重试与环形淘汰内存回收
    ├── scheduler/                   # 任务拉取、Diff 协程生命周期管理、CA/证书同步回调与并发限流
    └── updater/
        ├── updater.go               # 流式下载、SHA-256 校验、Unix 覆盖与 Windows .old 暂存回滚替换
        ├── restart_unix.go          # Linux / macOS：syscall.Exec 原地无缝换像（保持同一 PID）
        └── restart_windows.go       # Windows：干净退出交由外部服务管理器拉起新镜像
```

---

## 2. 快速开始

### 2.1 使用预编译发行包运行

从 [GitHub Releases](https://github.com/Cion-1221/NMS_Agent/releases) 下载对应操作系统与 CPU 架构的压缩包（Linux 压缩包内已附带 `nms-agent`、`configs/config.yaml`、`configs/nms-agent.service` 与 `README.md`）：

```bash
tar -xzf nms-agent_0.12.0_linux_amd64.tar.gz
cd nms-agent_0.12.0_linux_amd64

# 填写 NMS Server 的 enroll_url / report_url，并通过环境变量注入一次性注册码
export NMS_TOKEN="在 NMS 管理界面「注册码」Tab 生成的一次性 Token"
./nms-agent -config configs/config.yaml
```

### 2.2 从源码构建与测试

要求 **Go 1.25+**（纯 Go 实现，`CGO_ENABLED=0` 零外部 C 依赖）：

```bash
git clone https://github.com/Cion-1221/NMS_Agent.git
cd NMS_Agent

# 静态检查与竞态单元测试
go vet ./...
go test -race ./...

# 编译当前平台二进制（生产构建建议通过 -ldflags 注入版本号）
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=0.12.0" -o nms-agent .
```

### 2.3 命令行参数与信号处理

```text
nms-agent -config <path>    指定配置文件路径（默认 configs/config.yaml）
nms-agent -version          打印版本号、Git Commit 与构建时间后退出
```

- **`SIGHUP`**：显式忽略，SSH 会话断开不会误杀前台/后台探针进程。
- **`SIGINT` / `SIGTERM`**：触发优雅停机——立即通过 Context 取消在途探测（含唤醒阻塞中的原始 ICMP Socket），排空队列并强制执行最后一次结果上报后干净退出。

---

## 3. 配置文件详解（`configs/config.yaml`）

所有时间间隔字段均采用标准 Go `time.Duration` 语法（如 `"30s"`、`"1m"`）。

### 3.1 `agent` — 节点身份与元数据

```yaml
agent:
  id: ""                  # 已弃用/运行时忽略；首次注册后权威 AgentID 固定从 <certs.dir>/agent_id 读取
  region: "HKG"           # 区域标识（首次 enroll 时随请求上报，并输出至启动日志）
  tags:                   # 自定义节点标签（首次 enroll 时随请求上报）
    role: "edge"
    datacenter: "DC1"
  hostname_override: ""   # 留空时默认取系统 os.Hostname() 作为注册主机名
```

### 3.2 `server` — 服务端地址与同步节奏

| 字段 | 默认值 | 必填 | 说明 |
|------|--------|:----:|------|
| `enroll_url` | — | 首次注册必填 | 服务端单向 HTTPS 注册地址（如 `https://nms.example.com:8443`） |
| `report_url` | — | **是** | 服务端双向 mTLS 同步地址（如 `https://nms.example.com:8444`，必须直连） |
| `provisioning_token` | `""` | 首次注册必填 | 一次性注册 Token（推荐写 `"${NMS_TOKEN}"`）；注册成功后即作废，可安全清空 |
| `insecure_enroll` | `false` | 否 | 仅在首次访问 `:8443` 注册时跳过服务端证书校验（内置自签 CA 首连引导常用）；`:8444` mTLS 通道始终强制完整双向校验 |
| `task_poll_interval` | `"30s"` | 否 | 拉取任务清单与同步配置/CA 信任包的周期（同时承担探针心跳） |
| `flush_interval` | `"30s"` | 否 | 结果缓冲队列的最大刷新间隔 |
| `batch_size` | `100` | 否 | 单批上传条数阈值（达到即刻触发上传，且作为断网积压排空时的单次请求分片上限） |
| `request_timeout` | `"30s"` | 否 | 任务拉取与结果上报的单次 HTTP 请求超时 |

### 3.3 `runtime` — 日志轮转与并发控制

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `log.file` | `"logs/nms-agent.log"` | 日志文件路径（留空则直接输出至 `stderr`；systemd 部署建议使用绝对路径） |
| `log.level` | `"info"` | 日志级别：`debug` / `info` / `warn` / `error` |
| `log.max_size_mb` | `100` | 单文件触发切割的体积上限（MiB） |
| `log.max_age_days` / `log.max_backups` | `30` / `30` | 历史轮转日志保留天数与最大份数 |
| `log.compress` | `true` | 是否使用 gzip 压缩切割后的历史日志（除按体积切割外，每日零点亦会自动切割一次） |
| `grace_period` | `"30s"` | 收到停机信号后等待在途探测与上报收尾的最长宽限期（注：若因 OTA 升级停机，宽限期满后仍会继续完成升级替换，不会放弃更新） |
| `max_concurrency` | `20` | 全局并发探测信号量上限（按单目标 × 地址族粒度占槽，正整数） |

### 3.4 `certs` — 凭证持久化目录

```yaml
certs:
  dir: ".certs"   # 存放 ca.crt (0644)、client.crt (0644)、client.key (0600)、agent_id (0644)，目录权限 0700
```

### 3.5 严格的 `${ENV_VAR}` 环境变量注入规则

配置加载器采用**严格花括号占位符解析**：
- 跳过所有以 `#` 开头的注释行；
- 仅展开显式的 `${VAR_NAME}` 语法，**完整保留密码或 URL 中出现的裸 `$` 字符**（避免 `os.ExpandEnv` 误删 `$1` 等字面量）；
- 当引用的 `${VAR_NAME}` 未在环境变量中定义时，主动输出结构化 `WARN` 日志提示排障。

---

## 4. 核心模块与七大探测引擎

### 4.1 证书生命周期、连接池与三阶段平滑 CA 轮换（`internal/cert`）

1. **防损坏原子落盘**：无论是首次 `Enroll`、客户端证书 `Renew` 还是 `UpdateCABundle`，均先在内存中完成 `tls.X509KeyPair` 私钥配对校验与 X.509 PEM 规范化去重，随后写入同目录隐藏临时文件再 `os.Rename` 覆盖，杜绝异常断电产生半截坏证书。
2. **按需热重载与连接池调优**：`certReloader` 通过比对磁盘文件的 `(ModTime, Size)` 元数据缓存解析好的 `x509.CertPool` 与 `tls.Certificate`（常规复用零磁盘解析开销）；`http.Transport` 配置 `MaxIdleConns: 16`、`MaxIdleConnsPerHost: 8`、`IdleConnTimeout: 90s`（严格小于服务端默认 `120s` 空闲超时，避免复用半关闭连接触发 EOF）。
3. **配合服务端三阶段平滑 CA 轮换**：
   - 每次请求自动携带 `X-Agent-CA-FP`（本地 `ca.crt` 中全部 CA 证书的 16 位 SHA-256 排序指纹）；
   - 当 `/agent-sync/tasks` 下发新的 `ca_bundle_pem` 时，自动校验并热更新本地 `ca.crt`，同时主动调用 `CloseIdleConnections()` 使后续连接立即加载新信任锚；
   - 当服务端切换到新 CA 并返回 `renew_cert: true` 时（或每日巡检发现证书剩余有效期 `< 30 天` 时），自动调用 `/agent-sync/renew-cert` 换发新客户端证书并刷新连接池，全程无需重启探针。

### 4.2 双栈公网 IP 自发现与协议栈声明（`main.go`）

针对 AWS / GCP 等云主机网卡仅配置私网地址的 NAT 场景：
- **启动同步探测**：在拉取第一轮任务前，分别使用强制 `tcp4` 与 `tcp6` 的独立 mTLS 客户端（用完即刻释放连接）请求服务端 `/api/v1/agent-sync/my-ip`（各 10s 超时），获取服务端视角下的真实公网 IPv4 / IPv6 地址。
- **权威协议栈声明（`X-Agent-Stack`）**：启动探测成功后，所有后续请求携带 `X-Agent-IPv4`、`X-Agent-IPv6` 及 `X-Agent-Stack`（`v4` / `v6` / `v4,v6`）。若某节点撤掉了 IPv6 能力，重启探针后服务端即可根据新的 `X-Agent-Stack` 自动将其移出 IPv6 Mesh 互测目标。
- **容错快重试与日常保鲜**：若启动瞬间因网络未就绪导致双栈均失败，后台以 **1 分钟**短间隔快速重试直至完成首次权威声明，随后转入每 **24 小时**一次的无损合并刷新（临时单族抖动不会清空已登记地址）。

### 4.3 Diff 式协程调度器（`internal/scheduler`）

- 启动即刻拉取首轮任务，此后按 `task_poll_interval` 周期对账：仅对新增、移除或参数发生变更（周期、目标列表、`address_family`、`skip_tls_verify` 或任意 SNMP 参数字段）的任务精准启停对应协程，未变更任务平稳运行不重置计时器。
- 当服务端下发的 `source_ipv4` 或 `source_ipv6` 发生变化时，当轮立即取消并重建全部任务协程，确保所有探测 Socket 即刻切换至新出口源地址。

### 4.4 七大探测引擎详解（`internal/probe`）

所有域名解析均通过带 **5 秒硬超时**的 Context 感知解析器完成，彻底杜绝上游 DNS 卡死拖垮并发槽位或阻塞停机。

#### 4.4.1 `ping` / `meshping` — 原生双栈 ICMP 回显探测
基于 `pro-bing` 特权原始 ICMP 套接字（Linux 需 `CAP_NET_RAW` 或 `root`），先按任务地址族完成受控域名解析并匹配对应族的出口源 IP，再发送 3 个间隔 1s、总超时 5s 的 Echo 报文，上报平均 RTT（全丢包记为失败并标注 `100% packet loss`）。

#### 4.4.2 `tcpping` — TCP 建连可达性与握手耗时
测量目标端口 TCP 三次握手耗时（5s 超时）。支持 `192.0.2.1`（省略端口默认 `80`）、`example.com:443`、裸 IPv6 `2001:db8::1`（默认 `80`）及 `[2001:db8::1]:8443` 格式；先完成单次地址族受控解析再拨号，确保实际连接地址族与 `LocalAddr` 源地址族 100% 一致。

#### 4.4.3 `httpcheck` — HTTP/HTTPS 状态与响应延迟
发起 HTTP `GET` 请求，`2xx` / `3xx` 判定为成功：
- **智能协议推断**：未写 `http(s)://` 前缀时，`:443` 与 `:8443` 自动推断为 `https://`，其余默认 `http://`。
- **SNI 完整保留的地址族强制**：URL 始终保留原始域名（确保 `Host` 头与 TLS SNI 正确），在底层 `DialContext` 通过 `tcp4` / `tcp6` 强制指定协议栈；支持任务级 `skip_tls_verify`，内置 `10s` TLS 握手超时、`20s` 响应头超时与 `4 KiB` 响应体安全排空。

#### 4.4.4 `dnscheck` — 支持自定义上游与 TCP 回退的域名解析探测
使用纯 Go `PreferGo` 解析器验证域名解析耗时（10s 总上限，单次拨号 5s 超时）：
- **支持指定目标 DNS 服务器**：除直接填写待解析域名（如 `example.com`，走系统默认 DNS）外，还支持 **`domain@server`** 或 **`domain@server:port`** 语法（如 `example.com@1.1.1.1`、`example.com@8.8.8.8:5353`、`example.com@[2001:4860:4860::8888]:53`）。
- **完整 RFC 5966 TCP 回退支持**：自定义拨号器同时识别 `udp` 与 `tcp` 请求并分别绑定匹配的 `net.UDPAddr` / `net.TCPAddr` 源地址，当大体积 DNSSEC / TXT / 多记录响应触发 `TC=1` 截断标志时可无缝回退至 TCP 完成解析。

#### 4.4.5 `traceroute` — 自研原始套接字逐跳追踪
基于 `ip4:icmp` 与 `ip6:ipv6-icmp` 原始套接字逐跳递增 TTL / HopLimit（上限 30 跳，单跳等待 3s，单目标硬超时 95s）：
- 每次追踪分配独立原子递增 Echo ID，并深入解析 `TimeExceeded` 内嵌原始 IPv4（动态计算可变 IHL 头长）/ IPv6 载荷核对 `ID` 与 `Seq`，多任务运行时绝不串包；
- 通过 `context.AfterFunc` 监听取消信号，一旦触发停机或 OTA 升级立即将读截止时间置为当前时刻唤醒阻塞的 `ReadFrom`；Windows 环境安全返回说明性提示而不崩溃。

#### 4.4.6 `mtr` / `meshmtr` — 路径丢包与抖动统计
调用系统 `mtr` 二进制（`--report --json --no-dns --report-cycles 10 --max-ttl 30`，固定 `LC_ALL=C`，单目标 45s 硬超时），解析各跳丢包率与 `avg / best / worst / stddev` JSON 数组。内置**双重参数注入防护**：前置拦截以 `-` 开头的非法目标，并固定使用 `--` 终结选项解析。

#### 4.4.7 `snmp_poll` — 零落盘 SNMP v1/v2c/v3 代理采集
消费服务端按设备动态合成的代理任务（`gosnmp` 驱动）：
- 支持 `v1`、`v2c` 及完整 `v3 USM`（认证涵盖 `MD5` / `SHA` / `SHA224` / `SHA256` / `SHA384` / `SHA512`，加密涵盖 `DES` / `AES` / `AES192` / `AES256` / `AES192C` / `AES256C`）；
- 自动按目标设备地址族绑定出口 `LocalAddr` 源地址（满足受管交换机/路由器严格的 SNMP ACL 源地址白名单要求），并全程透传 `Context` 支持随时中断长耗时接口表遍历；
- 支持快慢双档系统组轮询、自定义标量 OID（`Counter64` 经 `big.Float` 无溢出解码）、`ifTable`+`ifXTable` 接口表遍历（512 端口上限，64 位 HC 计数器优先）以及精准区分 `usmStatsNotInTimeWindows` 时钟同步信号与 `auth_fail` 认证失败。

### 4.5 分片攒批上报与指数退避缓冲（`internal/reporter`）

- 拨测结果（`/agent-sync/results`）与 SNMP 状态结论（`/agent-sync/snmp-results`）拥有各自独立的内存通道与重试缓冲区（容量上限 `max(batch_size × 10, 1000)`）。
- **按 `batch_size` 分片排空**：即使断网期间积压了 1000 条记录，网络恢复后也会按 `batch_size`（如 100 条/批）逐片发送；若中途某一片遇到网络抖动失败，前面已成功的分片会立即从缓冲移除并调用 `clear()` 释放底层大字符串引用，剩余分片进入 `5s → 10s → ... → 2m` 指数退避，队列排空后自动缩容超大底层切片。
- 遇到服务端返回不可恢复的 `4xx`（除 `429` 外）主动丢弃坏批次并记录响应体摘要，防止单条脏数据永久阻塞后续上报。

### 4.6 跨平台原子 OTA 自升级（`internal/updater`）

当 `/agent-sync/tasks` 返回 `update` 指令时：
1. 主进程通知调度器与上报器优雅收尾（即便个别慢探测超出 `grace_period`，挂起的 OTA 升级仍会继续执行而不会半途放弃）；
2. 使用 10 分钟长超时经 mTLS 下载 `/agent-sync/binary/{id}` 至**可执行文件同级目录**隐藏临时文件（按 `file_size` 预分配空间），流式计算并严格比对 SHA-256；
3. **平台自适应原子替换**：
   - **Linux / macOS**：`chmod 0755` → `os.Rename` 原子覆盖原文件 → 调用 `syscall.Exec` 原地替换为新版本进程镜像（PID 保持不变，systemd 无重启抖动）；
   - **Windows**：针对运行中 `.exe` 无法直接覆盖的系统限制，先将运行中的自身重命名为 `<exe>.old`，再移入新 `.exe`（若移入失败自动回滚恢复原镜像），随后以状态码 `0` 退出交由服务管理器拉起新进程；新进程启动时自动调用 `CleanupOldBinary()` 清理残留的 `.old` 文件。

> ⚠️ **运维提示**：在 NMS Web 界面上传升级文件时，请务必先解压 GitHub Release 的 `.tar.gz` / `.zip` 压缩包，**只上传解压出的 `nms-agent`（或 `nms-agent.exe`）二进制本体**。

---

## 5. Source IP 出口绑定与双栈 `address_family` 契约

- **各协议源地址绑定实现**：
  - `ping` / `meshping`：`pinger.Source`
  - `tcpping` / `httpcheck`：`net.Dialer{LocalAddr: &net.TCPAddr{IP: ...}}`
  - `dnscheck`：按实际传输协议绑定 `&net.UDPAddr{IP: ...}` 或 `&net.TCPAddr{IP: ...}`
  - `traceroute`：`icmp.ListenPacket("ip4:icmp" | "ip6:ipv6-icmp", src)`
  - `mtr` / `meshmtr`：`mtr --address <src>`
  - `snmp_poll`：`gosnmp.GoSNMP{LocalAddr: src}`
- **`address_family` 跨仓库序列契约**：仅作用于**域名**目标（字面 IP 恒按自身协议栈探测一次）。设为 `both` 时，每个域名分别按 IPv4 与 IPv6 各探测一次，上报结果的 `target` 自动追加 `" (v4)"` 与 `" (v6)"` 后缀以拆分为两条独立时序曲线（该后缀格式与 NMS 前端徽标解析器严格绑定）。

---

## 6. 生产环境部署指南

Linux 节点如需启用 `mtr` / `meshmtr` 任务，请预先安装 `mtr-tiny`（Debian/Ubuntu：`apt install -y mtr-tiny`）。

### 6.1 Linux systemd 最小权限部署（生产推荐）

发行包已内置加固版单元模板 [`configs/nms-agent.service`](configs/nms-agent.service)，通过专用非特权系统账户配合 `CAP_NET_RAW` 能力运行原始 ICMP 套接字，无需赋予完整 `root` 权限：

```bash
# 1. 创建专用低权限账户与目录结构（注意：bin/ 置于 /var/lib/nms-agent 下以支持 ProtectSystem=strict 下的 OTA 原子自替换）
sudo useradd -r -s /sbin/nologin -d /var/lib/nms-agent -m nms-agent
sudo mkdir -p /var/lib/nms-agent/bin /var/lib/nms-agent/.certs /var/log/nms-agent /etc/nms-agent

# 2. 安装二进制与配置
sudo install -o nms-agent -g nms-agent -m 0755 nms-agent /var/lib/nms-agent/bin/nms-agent
sudo install -o root -g nms-agent -m 0640 configs/config.yaml /etc/nms-agent/config.yaml
sudo chown -R nms-agent:nms-agent /var/lib/nms-agent /var/log/nms-agent

# 3. 修改 /etc/nms-agent/config.yaml 中的日志与证书为绝对路径：
#    runtime.log.file: "/var/log/nms-agent/nms-agent.log"
#    certs.dir: "/var/lib/nms-agent/.certs"
#    server.enroll_url / server.report_url: 指向实际 NMS Server

# 4. 写入一次性注册码环境变量文件（首次注册成功后可随时清空该文件）
sudo tee /etc/nms-agent/env > /dev/null <<'EOF'
NMS_TOKEN=在此填入一次性注册码
EOF
sudo chmod 0600 /etc/nms-agent/env

# 5. 安装并启动内置的 systemd 单元
sudo cp configs/nms-agent.service /etc/systemd/system/nms-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now nms-agent
```

### 6.2 Linux systemd 单目录快速部署（`/opt/nms-agent`）

若希望二进制、配置、证书与日志全部收纳于 `/opt/nms-agent` 单目录：
- 在单元文件中设置 `WorkingDirectory=/opt/nms-agent`，`ExecStart=/opt/nms-agent/nms-agent -config /opt/nms-agent/configs/config.yaml`；
- **关键项**：若开启了 `ProtectSystem=strict`，`ReadWritePaths=/opt/nms-agent` **必须放行整个安装目录本身**（而不能只放行 `logs` 与 `.certs` 子目录），否则 OTA 升级时无法在可执行文件旁创建临时文件做同分区原子重命名。

### 6.3 Windows 服务常驻注意事项

- 推荐使用 **WinSW** 或 **NSSM** 将 `nms-agent.exe -config C:\nms-agent\configs\config.yaml` 注册为系统服务，并将进程退出策略配置为**始终自动重启（Restart on exit code 0 / failure）**，以便 OTA 替换完 `nms-agent.exe` 并退出后由服务管理器自动拉起新版本。
- Windows 下执行原生 ICMP `ping` 需以管理员/LocalSystem 服务身份运行并放行系统防火墙 ICMP 回显；`traceroute` 与 `mtr` 在 Windows 下会安全上报说明性提示信息，不影响其余 5 类探测与 SNMP 代理采集正常运行。

### 6.4 常见故障排查速查表

| 故障现象 | 根因定位 | 解决方案 |
|----------|----------|----------|
| OTA 升级失败，日志报 `create temp file: ... read-only file system` | systemd 开启了 `ProtectSystem=strict` 但未将二进制所在目录纳入 `ReadWritePaths`，或二进制目录属主非运行账户 | 将二进制所在目录加入 `ReadWritePaths=` 并修正目录属主后执行 `systemctl daemon-reload && systemctl restart nms-agent` |
| 首次启动报 `x509: certificate signed by unknown authority` | `:8443` 注册端口使用了内置自签证书 | 将 `server.insecure_enroll` 设为 `true` 完成首次注册（`:8444` mTLS 通道会自动使用拿到的 `ca.crt` 做严格双向验证） |
| mTLS 同步报 `x509: certificate is valid for ..., not ...` | 服务端 `config.yaml` 的 `agent_pki.server_san` 未包含 `report_url` 中的域名或 IP | 在服务端补齐 `server_san` 并重启 `nms-server` |
| `ping` / `traceroute` 报 `operation not permitted` | 非 root 运行且缺少原始套接字能力 | 在 systemd 单元中配置 `AmbientCapabilities=CAP_NET_RAW` 与 `CapabilityBoundingSet=CAP_NET_RAW` |
| `mtr` 报 `mtr binary not found in PATH` | 宿主机未安装 `mtr` | 执行 `apt install -y mtr-tiny` 或 `yum install -y mtr` |

---

## 7. CI/CD 交叉编译与发布流水线

[`.github/workflows/release.yml`](.github/workflows/release.yml) 支持手动预检（`workflow_dispatch`，仅验证编译不发版）与 **`v*` Tag 自动发版**：

```bash
git tag v0.13.0
git push origin main v0.13.0
```

1. **Verify 阶段**：在 `ubuntu-latest` 上执行 `go mod tidy`、`go vet ./...` 与 `go test -race ./...` 并发竞态单测；
2. **Build 矩阵阶段**：纯静态（`CGO_ENABLED=0`）交叉编译 `{linux, windows, darwin} × {amd64, arm64}` 共 6 个平台目标，通过 `-ldflags` 注入 `version / commit / buildDate`，并打包二进制、`README.md`、`configs/config.yaml`（Linux 额外包含 `configs/nms-agent.service`）；
3. **Release 阶段**：汇总全部压缩包生成 `SHA256SUMS.txt`，自动提取自上一个 Tag 以来的 Git 提交记录生成 Changelog 并发布 GitHub Release。

---

## 8. 跨平台能力支持矩阵

| 模块 / 能力 | Linux (`amd64` / `arm64`) | macOS (`amd64` / `arm64`) | Windows (`amd64` / `arm64`) |
|-------------|:-------------------------:|:-------------------------:|:---------------------------:|
| `ping` / `meshping`（ICMP） | ✅（`root` 或 `CAP_NET_RAW`） | ✅（需 `sudo`） | ✅（需管理员/系统服务权限） |
| `tcpping` / `httpcheck` / `dnscheck` | ✅ | ✅ | ✅ |
| `snmp_poll`（v1 / v2c / v3 USM） | ✅ | ✅ | ✅ |
| `traceroute`（原始 ICMP Socket） | ✅（`root` 或 `CAP_NET_RAW`） | ✅（需 `sudo`） | ⚠️ 安全降级返回说明文本 |
| `mtr` / `meshmtr` | ✅（需安装 `mtr` / `mtr-tiny`） | ✅（需安装 `mtr`） | ⚠️ 安全降级返回说明文本 |
| OTA 自动升级 | ✅ `syscall.Exec` 原地换像 | ✅ `syscall.Exec` 原地换像 | ✅ `.old` 原子替换 + 服务管理器重启 |
| 三阶段 CA 热同步 & 自动续签 | ✅ | ✅ | ✅ |

---

## 9. 服务端通信协议契约一览

| 方法与端点 | 通道 | 请求 / 响应核心契约 |
|------------|------|---------------------|
| `POST {enroll}/api/v1/agents/enroll` | 单向 TLS | 请求 `{provisioning_token, hostname, region, tags}` → 返回 `{agent_id, cert_pem, key_pem, ca_cert_pem, cert_expiry, sync_port}` |
| `GET {sync}/api/v1/agent-sync/tasks` | 双向 mTLS | 返回 `{agent_id, source_ipv4, source_ipv6, tasks[], update, ca_bundle_pem, renew_cert}` |
| `POST {sync}/api/v1/agent-sync/results` | 双向 mTLS | 批量提交 `{results: [{task_id, type, target, success, latency_ms, detail, collected_at}]}` |
| `POST {sync}/api/v1/agent-sync/snmp-results` | 双向 mTLS | 批量提交 `{results: [{device_id, collected_at, success, error_kind, latency_ms, uptime_ticks, has_inventory, ..., values[], has_interfaces, interfaces[]}]}` |
| `POST {sync}/api/v1/agent-sync/renew-cert` | 双向 mTLS | 凭当前有效客户端证书换发新 `{cert_pem, key_pem, ca_cert_pem, cert_expiry}` |
| `GET {sync}/api/v1/agent-sync/my-ip` | 双向 mTLS | 返回服务端视角的客户端连接地址 `{"ip": "..."}`（兼容纯文本 IP） |
| `GET {sync}/api/v1/agent-sync/binary/{id}` | 双向 mTLS | 流式下载对应 `binary_id` 的新版本探针可执行二进制文件 |

**全局 mTLS 请求头**：`X-Agent-Version` · `X-Agent-OS` · `X-Agent-Arch` · `X-Agent-IPv4` · `X-Agent-IPv6` · `X-Agent-Stack` · `X-Agent-CA-FP`。

---

## 10. License

本项目为 CION 内部专有软件（详见 [LICENSE](LICENSE)），仅限 CION 及其关联方内部部署与使用；未经书面授权，不得复制、修改、公开或向第三方分发。
