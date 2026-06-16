// Package mtr 实现"实时路由质量"探测（My Traceroute 风格：逐跳统计丢包率、
// 延迟分布，比一次性的 traceroute 更能反映链路抖动情况）。
//
// 推荐做法：复用系统自带、久经考验的 mtr/mtr-tiny 命令行工具
// （Debian/Ubuntu: apt install mtr-tiny；RHEL/CentOS: yum install mtr），
// 通过 `mtr --report --json` 一次性输出结构化逐跳统计，而不是用纯 Go
// 重新实现一遍 MTR 的统计算法——多路径丢包率统计涉及大量边界情况
// （ECMP 多路径乱序、报文重排序等），复用社区维护多年的 C 实现风险更低。
// 若需要彻底摆脱外部二进制依赖，可在 internal/probe/traceroute 的
// golang.org/x/net/icmp 方案基础上，对每一跳重复采样 Cycles 次并自行统计，
// 工作量与正确性成本会显著高于直接调用 mtr。
//
// 注意：mtr 是 Linux/Unix 工具，本模块在 Windows 边缘节点上不可用，
// 应在 config.yaml 中将该机型节点的 mtr.enabled 设为 false。
package mtr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
)

const moduleName = "mtr"

type HopStat struct {
	TTL        int     `json:"ttl"`
	Host       string  `json:"host,omitempty"`
	LossRate   float64 `json:"loss_rate"`
	AvgRttMs   float64 `json:"avg_rtt_ms"`
	BestRttMs  float64 `json:"best_rtt_ms"`
	WorstRttMs float64 `json:"worst_rtt_ms"`
	StdDevMs   float64 `json:"stddev_rtt_ms"`
}

type Stat struct {
	Name    string    `json:"name"`
	Address string    `json:"address"`
	Hops    []HopStat `json:"hops"`
	Error   string    `json:"error,omitempty"`
}

type Module struct {
	cfg    config.MTRConfig
	id     module.Identity
	binary string // exec.LookPath 的缓存结果，避免每个调度周期重复扫描 PATH
}

func New(cfg config.MTRConfig, id module.Identity) *Module {
	binary, _ := exec.LookPath("mtr")
	return &Module{cfg: cfg, id: id, binary: binary}
}

func (m *Module) Name() string { return moduleName }

func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	if len(m.cfg.Targets) == 0 {
		return nil, nil
	}
	if m.binary == "" {
		return nil, fmt.Errorf("mtr: binary not found in PATH, install mtr/mtr-tiny on this host first")
	}

	stats := make([]Stat, len(m.cfg.Targets))
	var wg sync.WaitGroup
	for i, target := range m.cfg.Targets {
		i, target := i, target
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats[i] = m.probe(ctx, target)
		}()
	}
	wg.Wait()

	results := make([]module.Result, len(stats))
	for i, s := range stats {
		results[i] = m.id.NewResult(moduleName, s)
	}
	return results, nil
}

// mtrJSONReport 对应 `mtr --report --json` 的输出结构（字段名取自 mtr 官方
// report_json.c）。不同 mtr 版本字段可能略有差异，上线前建议在目标
// 发行版上跑一次 `mtr --report --json 8.8.8.8` 核对实际输出。
type mtrJSONReport struct {
	Report struct {
		Hubs []struct {
			Host  string  `json:"host"`
			Loss  float64 `json:"Loss%"`
			Avg   float64 `json:"Avg"`
			Best  float64 `json:"Best"`
			Wrst  float64 `json:"Wrst"`
			StDev float64 `json:"StDev"`
		} `json:"hubs"`
	} `json:"report"`
}

func (m *Module) probe(ctx context.Context, target config.NamedTarget) Stat {
	stat := Stat{Name: target.Name, Address: target.Address}

	cycles := m.cfg.Cycles
	if cycles <= 0 {
		cycles = 10
	}
	maxHops := m.cfg.MaxHops
	if maxHops <= 0 {
		maxHops = 30
	}

	// 整体超时交给 ctx + exec.CommandContext 控制，cfg.Timeout 在调度层面
	// 已经体现为 Scheduler 调用 Run 时使用的 ctx 的截止时间。
	cmd := exec.CommandContext(ctx, m.binary,
		"--report", "--json",
		"--report-cycles", strconv.Itoa(cycles),
		"--max-ttl", strconv.Itoa(maxHops),
		target.Address,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "LC_ALL=C") // 避免本地化输出影响 JSON 之外的诊断信息

	if err := cmd.Run(); err != nil {
		stat.Error = fmt.Sprintf("run mtr: %v (stderr: %s)", err, stderr.String())
		return stat
	}

	var report mtrJSONReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		stat.Error = fmt.Sprintf("parse mtr json: %v", err)
		return stat
	}

	stat.Hops = make([]HopStat, 0, len(report.Report.Hubs))
	for i, hub := range report.Report.Hubs {
		stat.Hops = append(stat.Hops, HopStat{
			TTL:        i + 1,
			Host:       hub.Host,
			LossRate:   hub.Loss,
			AvgRttMs:   hub.Avg,
			BestRttMs:  hub.Best,
			WorstRttMs: hub.Wrst,
			StdDevMs:   hub.StDev,
		})
	}
	return stat
}
