// Package tcpping 实现 TCP 端口可达性探测：对目标 "host:port" 发起 TCP 连接，
// 三次握手成功即视为端口可达，握手耗时记为延迟。
//
// 仅依赖标准库 net，无需第三方库——相比 ICMP Ping，TCP Ping 不需要原始 socket
// 权限，更适合用来判断"应用层端口是否真的在监听"（例如设备开了 ICMP 但防火墙
// 仍然拦截了 SSH/HTTPS 端口的场景）。
package tcpping

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
)

const moduleName = "tcp_ping"

type Stat struct {
	Name      string  `json:"name"`
	Address   string  `json:"address"`
	Reachable bool    `json:"reachable"`
	LatencyMs float64 `json:"latency_ms"`
	Error     string  `json:"error,omitempty"`
}

type Module struct {
	cfg config.TCPPingConfig
	id  module.Identity
}

func New(cfg config.TCPPingConfig, id module.Identity) *Module {
	return &Module{cfg: cfg, id: id}
}

func (m *Module) Name() string { return moduleName }

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

	dialer := net.Dialer{Timeout: m.cfg.Timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", target.Address)
	elapsed := time.Since(start)
	if err != nil {
		stat.Error = err.Error()
		return stat
	}
	defer conn.Close()

	stat.Reachable = true
	stat.LatencyMs = float64(elapsed) / float64(time.Millisecond)
	return stat
}
