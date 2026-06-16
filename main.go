// Command nms-agent 是部署在各边缘节点（机房/POP）的网络管理 Agent：
// 按 config.yaml 驱动的周期任务采集网络状态、轮询设备、执行运维动作，
// 并把结果统一上报回中心 NMS Server。
//
// 用法：
//
//	nms-agent [-config /path/to/config.yaml]
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/logger"
	"github.com/Cion-1221/NMS_Agent/internal/module"
	"github.com/Cion-1221/NMS_Agent/internal/reporter"
	"github.com/Cion-1221/NMS_Agent/internal/scheduler"

	"github.com/Cion-1221/NMS_Agent/internal/probe/dnscheck"
	"github.com/Cion-1221/NMS_Agent/internal/probe/httpcheck"
	"github.com/Cion-1221/NMS_Agent/internal/probe/meshping"
	"github.com/Cion-1221/NMS_Agent/internal/probe/mtr"
	"github.com/Cion-1221/NMS_Agent/internal/probe/ping"
	"github.com/Cion-1221/NMS_Agent/internal/probe/speedtest"
	"github.com/Cion-1221/NMS_Agent/internal/probe/tcpping"
	"github.com/Cion-1221/NMS_Agent/internal/probe/traceroute"

	"github.com/Cion-1221/NMS_Agent/internal/netmon/bgpcheck"
	"github.com/Cion-1221/NMS_Agent/internal/netmon/ifdiscovery"
	"github.com/Cion-1221/NMS_Agent/internal/netmon/netflow"
	"github.com/Cion-1221/NMS_Agent/internal/netmon/snmppoll"

	"github.com/Cion-1221/NMS_Agent/internal/ops/configbackup"
	"github.com/Cion-1221/NMS_Agent/internal/ops/remotecmd"
	"github.com/Cion-1221/NMS_Agent/internal/ops/scriptengine"

	"github.com/Cion-1221/NMS_Agent/internal/logcollect/syslog"
)

// version/commit/buildDate 在发布构建时通过
//
//	go build -ldflags "-X main.version=v1.2.3 -X main.commit=<sha> -X main.buildDate=<rfc3339>"
//
// 注入（见 .github/workflows/release.yml）；本地 go run/go build 时保持默认值，
// 用于和 -version 标志、启动日志一起辨认"线上跑的到底是哪个版本的二进制"。
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to config.yaml")
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("nms-agent %s (commit %s, built %s)\n", version, commit, buildDate)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("load config failed", "error", err, "path", *configPath)
		os.Exit(1)
	}

	log, closeLogger, err := logger.New(cfg.Runtime)
	if err != nil {
		slog.Error("init logger failed", "error", err)
		os.Exit(1)
	}
	defer closeLogger()

	log.Info("nms-agent starting",
		"agent_id", cfg.Agent.ID, "site", cfg.Agent.Site, "config", *configPath,
		"version", version, "commit", commit, "build_date", buildDate)

	// signal.NotifyContext 把 SIGINT/SIGTERM 转换成 ctx 取消信号，
	// 这是贯穿 Scheduler/Reporter/各模块的统一"优雅停机"开关。
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	id := module.Identity{AgentID: cfg.Agent.ID, Site: cfg.Agent.Site, Tags: cfg.Agent.Tags}

	rep := reporter.New(cfg.Server, log)
	sched := scheduler.New(log, rep, cfg.Runtime.MaxModuleConcurrency)

	tasks := buildTasks(cfg, id, log)
	log.Info("modules assembled", "enabled_count", len(tasks))

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		rep.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		sched.Run(ctx, tasks)
	}()

	<-ctx.Done()
	log.Info("shutdown signal received", "grace_period", cfg.Runtime.ShutdownGracePeriod)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info("all modules stopped cleanly, exiting")
	case <-time.After(cfg.Runtime.ShutdownGracePeriod):
		log.Warn("shutdown grace period exceeded, forcing exit")
		os.Exit(1)
	}
}

// buildTasks 把 config.yaml 中 enabled=true 的模块逐一实例化为
// scheduler.Task。这是整个程序里唯一知道"有哪 15+1 个模块、它们叫什么名字"
// 的地方——Scheduler/Reporter 本身完全不感知具体业务模块，新增模块只需要
// 在这里补一行装配代码。
//
// Interval 留空（零值）的任务对应实现了 module.Emitter 的常驻模块
// （netflow receiver/forwarder、script_engine、syslog），由 Scheduler
// 自动识别并改为常驻调度，而不是按周期调用 Run。
func buildTasks(cfg *config.Config, id module.Identity, log *slog.Logger) []scheduler.Task {
	var tasks []scheduler.Task
	m := cfg.Modules

	if m.Ping.Enabled {
		tasks = append(tasks, scheduler.Task{Module: ping.New(m.Ping, id), Interval: m.Ping.Interval})
	}
	if m.TCPPing.Enabled {
		tasks = append(tasks, scheduler.Task{Module: tcpping.New(m.TCPPing, id), Interval: m.TCPPing.Interval})
	}
	if m.HTTPCheck.Enabled {
		tasks = append(tasks, scheduler.Task{Module: httpcheck.New(m.HTTPCheck, id), Interval: m.HTTPCheck.Interval})
	}
	if m.DNSCheck.Enabled {
		tasks = append(tasks, scheduler.Task{Module: dnscheck.New(m.DNSCheck, id), Interval: m.DNSCheck.Interval})
	}
	if m.Traceroute.Enabled {
		tasks = append(tasks, scheduler.Task{Module: traceroute.New(m.Traceroute, id), Interval: m.Traceroute.Interval})
	}
	if m.MTR.Enabled {
		tasks = append(tasks, scheduler.Task{Module: mtr.New(m.MTR, id), Interval: m.MTR.Interval})
	}
	if m.Speedtest.Enabled {
		tasks = append(tasks, scheduler.Task{Module: speedtest.New(m.Speedtest, id), Interval: m.Speedtest.Interval})
	}

	// MeshPing：15 个基础模块之外的核心焦点，独立配置块 mesh_ping。
	if m.MeshPing.Enabled {
		tasks = append(tasks, scheduler.Task{Module: meshping.New(m.MeshPing, id), Interval: m.MeshPing.Interval})
	}

	if m.SNMPPoll.Enabled {
		tasks = append(tasks, scheduler.Task{Module: snmppoll.New(m.SNMPPoll, id), Interval: m.SNMPPoll.Interval})
	}
	if m.InterfaceDiscovery.Enabled {
		tasks = append(tasks, scheduler.Task{Module: ifdiscovery.New(m.InterfaceDiscovery, id), Interval: m.InterfaceDiscovery.Interval})
	}
	if m.Netflow.Enabled {
		tasks = append(tasks, scheduler.Task{Module: netflow.New(m.Netflow, id)})
	}
	if m.BGPCheck.Enabled {
		tasks = append(tasks, scheduler.Task{Module: bgpcheck.New(m.BGPCheck, id), Interval: m.BGPCheck.Interval})
	}

	if m.ConfigBackup.Enabled {
		tasks = append(tasks, scheduler.Task{Module: configbackup.New(m.ConfigBackup, id), Interval: m.ConfigBackup.Interval})
	}
	if m.ScriptEngine.Enabled {
		tasks = append(tasks, scheduler.Task{Module: scriptengine.New(m.ScriptEngine, id, log)})
	}
	if m.RemoteCommand.Enabled {
		rc, err := remotecmd.New(m.RemoteCommand, id)
		if err != nil {
			log.Error("remote_command disabled: invalid whitelist/blacklist config", "error", err)
		} else {
			tasks = append(tasks, scheduler.Task{Module: rc, Interval: m.RemoteCommand.PollInterval})
		}
	}

	if m.Syslog.Enabled {
		tasks = append(tasks, scheduler.Task{Module: syslog.New(m.Syslog, id)})
	}

	return tasks
}
