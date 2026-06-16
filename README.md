# NMS Agent

部署在分布式边缘节点（机房 / POP）上的网络管理 Agent：纯配置驱动，周期性采集网络状态、轮询设备、执行运维动作，并将结果统一上报回中心 NMS Server。内置全球节点间的网状延迟探测（MeshPing），为 Looking Glass 延迟矩阵提供数据源。

[![Build and Release](https://github.com/Cion-1221/NMS_Agent/actions/workflows/release.yml/badge.svg)](https://github.com/Cion-1221/NMS_Agent/actions/workflows/release.yml)
![Go Version](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go)
![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20windows%20%7C%20macOS-lightgrey)

## 目录

- [核心特性](#核心特性)
- [架构设计](#架构设计)
- [目录结构](#目录结构)
- [功能模块一览](#功能模块一览)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [Looking Glass 延迟矩阵（MeshPing）](#looking-glass-延迟矩阵meshping)
- [安全基线](#安全基线)
- [构建与发布](#构建与发布)
- [开发指南](#开发指南)
- [已知限制与路线图](#已知限制与路线图)
- [License](#license)

## 核心特性

- **纯配置驱动**：所有行为——模块开关、执行周期、目标列表、鉴权信息——都来自 [`configs/config.yaml`](configs/config.yaml)，代码中不出现硬编码业务参数。敏感字段（Token、密钥、密码）支持 `${ENV_VAR}` 占位符，启动时从环境变量展开，不需要写进配置文件明文。
- **高并发**：每个模块独立 goroutine 调度，模块内部按需使用 worker pool（如 MeshPing）/ 并发 fan-out（如 Ping、SNMP）探测多个目标，互不阻塞。
- **故障隔离**：任何模块的 `panic` 都会被 Scheduler 逐层 `recover`，不会波及其他模块或整个进程；常驻型模块（Syslog、NetFlow、Script Engine）异常退出后按指数退避（1s→2s→4s→…→30s 封顶）自动重启。
- **优雅停机**：捕获 `SIGINT`/`SIGTERM`，通过统一的 `context.Context` 通知所有模块与上报队列在限定的 `shutdown_grace_period` 内收尾，超时则强制退出而不是无限期挂起。
- **开箱即用的安全基线**：远程命令执行模块默认拒绝一切命令，必须命中白名单正则且不命中黑名单才会执行；高危操作还可要求中心侧二次确认令牌。
- **跨平台**：纯 Go + `CGO_ENABLED=0`，单一代码库交叉编译出 Linux / Windows / macOS（amd64 与 arm64）六个平台的静态二进制。

## 架构设计

```
                         ┌───────────────────────┐
                         │     configs/config.yaml │
                         └───────────┬────────────┘
                                     │ viper.Load
                                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ main.go                                                          │
│  · 加载配置 / 初始化 slog / 注册 SIGINT・SIGTERM → ctx            │
│  · buildTasks(): 按 enabled=true 实例化各模块，组装 scheduler.Task │
└───────────────────────────┬───────────────────────────────────────┘
                             │
              ┌──────────────┴───────────────┐
              ▼                               ▼
   ┌─────────────────────┐         ┌─────────────────────────┐
   │ scheduler.Scheduler  │         │ reporter.Reporter         │
   │ 每个模块一个 goroutine │  Result │ 攒批(BatchSize/Flush      │
   │ ticker 周期触发 Run() │ ------> │ Interval) -> HTTP POST    │
   │ 或常驻调度 Serve()    │  channel│ 重试 + 指数退避            │
   │ panic recover 兜底    │         └────────────┬─────────────┘
   └──────────┬────────────┘                      │
              │ module.Module / module.Emitter     ▼
              ▼                          ┌────────────────────┐
   ┌────────────────────────┐            │   中心 NMS Server    │
   │ 15 + 1 个功能模块        │            └────────────────────┘
   │ ping / snmp_poll / ...  │
   │ mesh_ping（核心焦点）    │
   └─────────────────────────┘
```

整个程序只依赖两个接口（[`internal/module/module.go`](internal/module/module.go)）：

| 接口 | 适用场景 | Scheduler 调度方式 |
|------|----------|---------------------|
| `Module`（`Run(ctx) ([]Result, error)`） | 周期性任务：Ping、SNMP、HTTP Check… | 按 `interval` 起 `time.Ticker` 反复调用 |
| `Emitter`（`Serve(ctx, emit)`，组合 `Module`） | 常驻监听/调度：Syslog、NetFlow、Script Engine | 常驻 goroutine，异常退出指数退避自动重启 |

`Scheduler`/`Reporter` 完全不知道 Ping、SNMP 这些具体业务模块的存在——新增一个功能模块只需要实现上述接口并在 [`main.go`](main.go) 的 `buildTasks` 里补一行装配代码，不需要改动框架代码。

## 目录结构

```
NMS_Agent/
├── go.mod / go.sum
├── main.go                              # 入口：配置加载/日志/信号/模块装配
├── configs/
│   └── config.yaml                      # 唯一的行为来源
├── .github/workflows/
│   └── release.yml                      # 打 Tag 自动交叉编译并发布 Release
└── internal/
    ├── module/module.go                 # Module / Emitter 接口、Result、Identity
    ├── config/config.go                 # viper 加载 + 全量配置结构体 + Validate
    ├── logger/logger.go                 # slog 初始化（json/text，stdout/文件）
    ├── scheduler/scheduler.go           # goroutine 调度、panic 隔离、daemon 退避重启
    ├── reporter/reporter.go             # 攒批 + HTTP POST + 重试退避
    ├── probe/                           # 一、网络主动探测
    │   ├── ping/                        #   ICMP Ping（pro-bing）
    │   ├── tcpping/                     #   TCP 端口可达性
    │   ├── httpcheck/                   #   HTTP(S) 健康检查
    │   ├── dnscheck/                    #   DNS 解析探测
    │   ├── traceroute/                  #   IPv4 TTL 递增路由探测（x/net/icmp）
    │   ├── mtr/                         #   逐跳丢包/延迟统计（调用系统 mtr）
    │   ├── speedtest/                   #   带宽测速（speedtest-go）
    │   └── meshping/                    #   ★ 核心焦点：Looking Glass 矩阵数据源
    ├── netmon/                          # 二、网络设备监控
    │   ├── snmpclient/                  #   共享：SNMP v1/v2c/v3 客户端构造
    │   ├── snmppoll/                    #   按 OID 列表周期 GET
    │   ├── ifdiscovery/                 #   walk IF-MIB::ifTable 发现接口
    │   ├── netflow/                     #   NetFlow/sFlow 接收器或转发器
    │   └── bgpcheck/                    #   BGP Peer 状态（SNMP / SSH）
    ├── ops/                             # 三、运维执行类
    │   ├── configbackup/                #   SSH 拉取设备配置并落盘
    │   ├── scriptengine/                #   按 cron 执行本地脚本（robfig/cron）
    │   └── remotecmd/                   #   远程命令执行（白名单/黑名单/二次确认）
    └── logcollect/
        └── syslog/                      # 四、Syslog 接收与转发
```

## 功能模块一览

| 模块 | config.yaml 键 | 默认 enabled | 推荐第三方库 | 调度方式 |
|------|-----------------|:---:|--------------|----------|
| Ping | `ping` | ✅ | `prometheus-community/pro-bing` | 周期 |
| TCP Ping | `tcp_ping` | ✅ | 标准库 `net` | 周期 |
| HTTP Check | `http_check` | ✅ | 标准库 `net/http` | 周期 |
| DNS Check | `dns_check` | ✅ | 标准库 `net` | 周期 |
| Traceroute | `traceroute` | ❌ | `golang.org/x/net/icmp` + `ipv4` | 周期 |
| MTR | `mtr` | ❌ | 系统 `mtr` 二进制（`--report --json`） | 周期 |
| Speedtest | `speedtest` | ❌ | `showwin/speedtest-go` | 周期 |
| **MeshPing** | `mesh_ping` | ✅ | `prometheus-community/pro-bing` | 周期（worker pool） |
| SNMP Polling | `snmp_poll` | ✅ | `gosnmp/gosnmp` | 周期 |
| Interface Discovery | `interface_discovery` | ✅ | `gosnmp/gosnmp`（walk IF-MIB） | 周期 |
| NetFlow/sFlow | `netflow` | ❌ | 自带 v5 头解析；v9/IPFIX/sFlow 建议接 `netsampler/goflow2` | 常驻（Emitter） |
| BGP Check | `bgp_check` | ❌ | SNMP 走 `gosnmp`（BGP4-MIB）；SSH 走 `x/crypto/ssh` | 周期 |
| Config Backup | `config_backup` | ✅ | `golang.org/x/crypto/ssh` | 周期 |
| Script Engine | `script_engine` | ✅ | `robfig/cron/v3` | 常驻（Emitter） |
| Remote Command | `remote_command` | ✅ | 标准库 `os/exec` + `regexp` | 周期（轮询） |
| Syslog | `syslog` | ✅ | `mcuadros/go-syslog.v2` | 常驻（Emitter） |

完整字段含义见 [配置说明](#配置说明) 与 [`configs/config.yaml`](configs/config.yaml) 内的逐行注释。

## 快速开始

### 方式一：下载预编译二进制

从 [Releases](https://github.com/Cion-1221/NMS_Agent/releases) 下载对应平台的压缩包（命名规则 `nms-agent_<version>_<os>_<arch>.{tar.gz|zip}`），解压后内含二进制、示例配置与 README：

```bash
tar -xzf nms-agent_1.0.0_linux_amd64.tar.gz
cd nms-agent_1.0.0_linux_amd64
vim configs/config.yaml        # 按需修改 agent.id / site / server.report_url 等
./nms-agent -config configs/config.yaml
```

### 方式二：从源码构建

要求 Go 1.26 及以上。

```bash
git clone https://github.com/Cion-1221/NMS_Agent.git
cd NMS_Agent
go build -o nms-agent .
./nms-agent -config configs/config.yaml
```

```bash
./nms-agent -version     # 查看版本/commit/构建时间
./nms-agent -config /etc/nms-agent/config.yaml
```

### 验证

成功启动后会以 JSON 结构化日志输出已装配的模块列表；按 `Ctrl+C`（或 `kill -TERM <pid>`）触发优雅停机，会看到 `shutdown signal received` 与 `all modules stopped cleanly` 日志。

## 配置说明

完整示例见 [`configs/config.yaml`](configs/config.yaml)，分为四大块：

```yaml
agent:    # Agent 身份：id / site（机房名）/ region / tags
runtime:  # 进程级参数：日志格式与级别、并发上限、停机等待时长
server:   # 上报地址、鉴权 Token、TLS、重试策略
modules:  # 15 + 1 个功能模块各自的 enabled / interval / 业务参数
```

**敏感信息处理**：`server.auth_token`、SNMPv3 密钥、SSH 密码等字段支持写成 `${ENV_VAR}` 占位符，[`internal/config/config.go`](internal/config/config.go) 在加载时用 `os.ExpandEnv` 展开，真正的值通过环境变量（如 systemd 的 `EnvironmentFile=`，或 `.env` + 进程管理器）注入，配置文件本身可以安全提交到版本库。

**模块开关**：每个模块块都有 `enabled: true/false`；大部分模块还有 `interval`（如 `30s`）。`netflow` / `script_engine` / `syslog` 三个常驻模块没有 `interval` 字段——它们不是"定期触发一次"，而是持续监听/调度。

## Looking Glass 延迟矩阵（MeshPing）

前端需要的是一张 N×N 的全球节点延迟交叉矩阵，但**单个 Agent 只能产出矩阵里"以自己为 source"的那一整行**——它既不可能、也不需要知道其它任意两个 peer 之间的延迟。完整矩阵由 NMS Server 把所有 N 个 Agent 各自上报的边，按 `(source, destination)` 拼接、去重后聚合出来。

配置（`modules.mesh_ping`）：

```yaml
mesh_ping:
  enabled: true
  interval: "15s"
  concurrency: 10        # worker pool 大小，避免瞬间打出大量 ICMP 自我拥塞
  self_name: "HKG1"      # 必须等于 agent.site，否则启动时 Validate 直接报错拒绝启动
  peers:
    - name: "SGN1"
      address: "203.0.113.10"
    - name: "NRT1"
      address: "203.0.113.20"
```

每轮探测产出的上报数据形如：

```json
{
  "module": "mesh_ping",
  "agent_id": "agent-hkg1-001",
  "site": "HKG1",
  "data": {
    "source": "HKG1",
    "destination": "SGN1",
    "latency_ms": 45.2,
    "loss_rate": 0,
    "reachable": true
  }
}
```

服务端把所有机房的 Agent 上报的这类边收集起来，即可拼出完整矩阵；前端按 `source` 取行、`destination` 取列渲染交叉表即可。核心实现见 [`internal/probe/meshping/meshping.go`](internal/probe/meshping/meshping.go)。

## 安全基线

- **远程命令执行**（`modules.remote_command`）默认拒绝一切命令：必须命中 `whitelist` 中的某条正则，且不命中 `blacklist` 任意一条，命令才会被执行；命中 `require_confirmation_for` 的命令即使在白名单内也会被挂起为 `pending_confirmation`，等待中心侧签发的 `confirmation_token`。
- **脚本引擎**（`modules.script_engine`）只会执行 `allowed_interpreters` 白名单内的解释器，配置里出现白名单之外的解释器会被直接拒绝并记录日志，而不是静默忽略。
- **密钥管理**：见上文「配置说明」的 `${ENV_VAR}` 展开机制，避免明文密钥提交进版本库。
- **已知待加强项**（详见下方路线图）：SSH 相关模块（`config_backup`、`bgp_check` 的 SSH 路径）目前用 `ssh.InsecureIgnoreHostKey()` 跳过主机指纹校验，便于跑通骨架；生产部署前必须替换为校验设备指纹的 `FixedHostKey`。

## 构建与发布

[`.github/workflows/release.yml`](.github/workflows/release.yml) 在推送 `v*` 标签时自动执行三个阶段：

1. **verify**：`go mod tidy && go vet ./... && go test ./...`，只跑一次。
2. **build**：矩阵交叉编译 `{linux, windows, darwin} × {amd64, arm64}` 共 6 个目标。全部基于 `CGO_ENABLED=0` 的纯 Go 静态编译，因此不需要真实的 Windows/macOS 机器，单个 `ubuntu-latest` runner 即可完成全部平台的产出；通过 `-ldflags "-X main.version=... -X main.commit=... -X main.buildDate=..."` 把版本信息编译进二进制（对应 [`main.go`](main.go) 里的 `version`/`commit`/`buildDate` 变量,可用 `-version` 查看)。每个平台打包成 `nms-agent_<version>_<os>_<arch>.{tar.gz|zip}`，内含二进制、`README.md` 与示例 `configs/config.yaml`。
3. **release**：汇总全部产物，生成 `SHA256SUMS.txt` 校验文件，按上一个 Tag 到当前 Tag 之间的 commit 自动生成 Changelog，调用 `softprops/action-gh-release` 发布 GitHub Release。

也支持手动触发（Actions 页面 `Run workflow`，不依赖 Tag）跑完整的编译矩阵验证是否能跨平台编译通过，但不会创建 Release（仅 Tag 推送才会执行发布阶段）。

发布一个新版本：

```bash
git tag v1.0.0
git push origin v1.0.0
```

本地手动交叉编译（示例：Linux arm64）：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o nms-agent_linux_arm64 .
```

## 开发指南

新增一个功能模块的标准步骤：

1. 在 `internal/<group>/<modulename>/` 下新建包，定义该模块的 `Stat`/结果结构体；
2. 实现 `Name() string` 与 `Run(ctx context.Context) ([]module.Result, error)`（常驻型模块改为实现 `Serve(ctx, emit)`，参考 [`internal/logcollect/syslog`](internal/logcollect/syslog/syslog.go)）；
3. 在 [`internal/config/config.go`](internal/config/config.go) 的 `ModulesConfig` 里补一个对应的配置结构体，并在 [`configs/config.yaml`](configs/config.yaml) 补上默认配置块；
4. 在 [`main.go`](main.go) 的 `buildTasks` 里补一行 `if m.XXX.Enabled { tasks = append(...) }`。

Scheduler、Reporter 不需要任何改动。

代码规范：`gofmt`/`go vet` 必须通过（CI 会强制检查）；模块间公共逻辑（如 SNMP 客户端构造）下沉到 `internal/netmon/snmpclient` 这类共享包，避免重复实现。

## 已知限制与路线图

诚实列出当前骨架里有意保留为 TODO、而不是伪造成"已完成"的部分：

- `bgp_check` 的 SSH 路径只搭好了登录取回原始输出的骨架，厂商命令输出解析器 `vendorParsers` 是空注册表——不同厂商 CLI 格式差异很大，需要真实设备输出样本才能补全；SNMP 路径（BGP4-MIB）是完整实现。
- `netflow` 只对 NetFlow v5 定长包头做了真实解析；v9/IPFIX/sFlow 是模板型可变长格式，需要接入 `netsampler/goflow2` 的解码链。
- `mtr` 依赖系统 `mtr`/`mtr-tiny` 二进制（Linux 发行版自带或需手动安装），Windows 节点应将该模块设为 `enabled: false`。
- `server.protocol: grpc` 目前只是预留字段，Reporter 只实现了 HTTP POST 上报。
- 尚未补充单元测试（CI 中的 `go test ./...` 目前等价于占位检查）。
- SSH 相关模块的主机指纹校验（见「安全基线」一节）。

## License

本项目尚未指定开源许可证。如需对外开源发布，请补充 `LICENSE` 文件；当前默认仅限 CION 内部使用。
