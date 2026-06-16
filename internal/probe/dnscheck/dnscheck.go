// Package dnscheck 实现 DNS 解析探测：向指定 resolver 发起查询，校验
// 域名能否解析、解析结果是否包含期望子串，并记录解析耗时。
//
// 仅依赖标准库 net。net.Resolver 本身没有"指定服务器地址"的字段，
// 这里通过覆盖 Resolver.Dial 把连接强制指向 cfg.Resolver 来实现，
// 这是 Go 标准库里公认的"自定义 DNS 服务器"写法。
package dnscheck

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
)

const moduleName = "dns_check"

type Stat struct {
	Domain     string   `json:"domain"`
	RecordType string   `json:"record_type"`
	Resolved   bool     `json:"resolved"`
	Answers    []string `json:"answers,omitempty"`
	LatencyMs  float64  `json:"latency_ms"`
	Error      string   `json:"error,omitempty"`
}

type Module struct {
	cfg      config.DNSCheckConfig
	id       module.Identity
	resolver *net.Resolver
}

func New(cfg config.DNSCheckConfig, id module.Identity) *Module {
	resolverAddr := cfg.Resolver
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: cfg.Timeout}
			if resolverAddr != "" {
				address = resolverAddr
			}
			return d.DialContext(ctx, network, address)
		},
	}
	return &Module{cfg: cfg, id: id, resolver: resolver}
}

func (m *Module) Name() string { return moduleName }

func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	if len(m.cfg.Queries) == 0 {
		return nil, nil
	}

	stats := make([]Stat, len(m.cfg.Queries))
	var wg sync.WaitGroup
	for i, q := range m.cfg.Queries {
		i, q := i, q
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats[i] = m.probe(ctx, q)
		}()
	}
	wg.Wait()

	results := make([]module.Result, len(stats))
	for i, s := range stats {
		results[i] = m.id.NewResult(moduleName, s)
	}
	return results, nil
}

func (m *Module) probe(ctx context.Context, q config.DNSQuery) Stat {
	stat := Stat{Domain: q.Domain, RecordType: q.RecordType}

	reqCtx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer cancel()

	start := time.Now()
	answers, err := m.lookup(reqCtx, q)
	stat.LatencyMs = float64(time.Since(start)) / float64(time.Millisecond)

	if err != nil {
		stat.Error = err.Error()
		return stat
	}

	stat.Resolved = true
	stat.Answers = answers

	if q.ExpectContains != "" && !containsSubstring(answers, q.ExpectContains) {
		stat.Resolved = false
		stat.Error = fmt.Sprintf("expect_contains %q not found in answers %v", q.ExpectContains, answers)
	}
	return stat
}

func (m *Module) lookup(ctx context.Context, q config.DNSQuery) ([]string, error) {
	switch strings.ToUpper(q.RecordType) {
	case "", "A", "AAAA":
		ips, err := m.resolver.LookupIPAddr(ctx, q.Domain)
		if err != nil {
			return nil, err
		}
		answers := make([]string, len(ips))
		for i, ip := range ips {
			answers[i] = ip.String()
		}
		return answers, nil

	case "CNAME":
		cname, err := m.resolver.LookupCNAME(ctx, q.Domain)
		if err != nil {
			return nil, err
		}
		return []string{cname}, nil

	case "MX":
		mxs, err := m.resolver.LookupMX(ctx, q.Domain)
		if err != nil {
			return nil, err
		}
		answers := make([]string, len(mxs))
		for i, mx := range mxs {
			answers[i] = fmt.Sprintf("%s:%d", mx.Host, mx.Pref)
		}
		return answers, nil

	case "TXT":
		return m.resolver.LookupTXT(ctx, q.Domain)

	default:
		return nil, fmt.Errorf("unsupported record_type %q", q.RecordType)
	}
}

func containsSubstring(answers []string, want string) bool {
	for _, a := range answers {
		if strings.Contains(a, want) {
			return true
		}
	}
	return false
}
