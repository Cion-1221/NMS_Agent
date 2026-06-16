// Package ping 实现 ICMP Ping 主动探测模块。
//
// 推荐第三方库：github.com/prometheus-community/pro-bing
// （原 sparrc/go-ping、go-ping/ping 的维护延续版本，纯 Go 实现 ICMP 编解码，
// 同时支持特权原始 ICMP socket 与非特权 ICMP datagram socket 两种模式，
// 避免了自己手写 raw socket + ICMP 报文编解码的复杂度）。
package ping

import (
	"context"
	"fmt"
	"sync"
	"time"

	probing "github.com/prometheus-community/pro-bing"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
)

const moduleName = "ping"

// Stat 对应 config.yaml 中 ping.targets 里的一项探测结果。
type Stat struct {
	Name     string  `json:"name"`
	Address  string  `json:"address"`
	Sent     int     `json:"sent"`
	Recv     int     `json:"recv"`
	LossRate float64 `json:"loss_rate"`
	MinRttMs float64 `json:"min_rtt_ms"`
	AvgRttMs float64 `json:"avg_rtt_ms"`
	MaxRttMs float64 `json:"max_rtt_ms"`
	StdDevMs float64 `json:"stddev_rtt_ms"`
	Error    string  `json:"error,omitempty"`
}

// Module 实现 module.Module 接口。
type Module struct {
	cfg config.PingConfig
	id  module.Identity
}

func New(cfg config.PingConfig, id module.Identity) *Module {
	return &Module{cfg: cfg, id: id}
}

func (m *Module) Name() string { return moduleName }

// Run 对所有 targets 并发发起 Ping，互不阻塞；任意一个目标超时/失败
// 只会反映在它自己的 Stat.Error 上，不影响其它目标。
func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	if len(m.cfg.Targets) == 0 {
		return nil, nil
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

func (m *Module) probe(ctx context.Context, target config.NamedTarget) Stat {
	stat := Stat{Name: target.Name, Address: target.Address}

	pinger, err := probing.NewPinger(target.Address)
	if err != nil {
		stat.Error = fmt.Sprintf("resolve: %v", err)
		return stat
	}

	pinger.SetPrivileged(m.cfg.Privileged)
	pinger.Count = m.cfg.PacketCount
	pinger.Interval = time.Second
	// pro-bing 的 Timeout 是"整次探测的总预算"，必须能覆盖 Count*Interval 的
	// 发送总时长，否则会在所有包发完之前被提前掐断；cfg.Timeout 在这里
	// 语义上是"最后一个包的额外容忍余量"。
	pinger.Timeout = time.Duration(m.cfg.PacketCount)*pinger.Interval + m.cfg.Timeout

	if err := pinger.RunWithContext(ctx); err != nil {
		stat.Error = err.Error()
		return stat
	}

	st := pinger.Statistics()
	stat.Sent = st.PacketsSent
	stat.Recv = st.PacketsRecv
	stat.LossRate = st.PacketLoss
	stat.MinRttMs = msOf(st.MinRtt)
	stat.AvgRttMs = msOf(st.AvgRtt)
	stat.MaxRttMs = msOf(st.MaxRtt)
	stat.StdDevMs = msOf(st.StdDevRtt)
	return stat
}

func msOf(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}
