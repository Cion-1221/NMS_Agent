// Package traceroute 实现基于 IPv4 TTL 递增的路由探测。
//
// 推荐第三方库：golang.org/x/net/icmp + golang.org/x/net/ipv4
// （官方 x/net 子仓库，提供 ICMP 报文编解码与设置单个报文 TTL 的能力，
// 是 Go 生态里实现 traceroute 的标准做法；也可参考开源实现
// github.com/aeden/traceroute 的思路）。
//
// 原理：依次把发出的 ICMP Echo Request 的 TTL 设为 1..MaxHops，途经的每一台
// 路由器在 TTL 减为 0 时都会回送 ICMP TimeExceeded，携带"是谁回的"这一信息
// （即这一跳路由器的地址）；当目的主机本身回复 EchoReply 时说明已到达终点。
//
// 权限要求：本实现使用特权原始 ICMP socket（"ip4:icmp"），Linux 下需要 root
// 或 CAP_NET_RAW，Windows 下需要以管理员身份运行——这与系统自带的
// traceroute/tracert 命令的权限要求一致。
package traceroute

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
)

const (
	moduleName = "traceroute"

	// protocolICMP 是 IANA 分配给 ICMP 的协议号。golang.org/x/net/icmp 的
	// 官方示例里也是这样手写常量——内部的 iana 包不对外暴露，无法直接 import。
	protocolICMP = 1
)

type Hop struct {
	TTL     int     `json:"ttl"`
	Address string  `json:"address,omitempty"`
	RttMs   float64 `json:"rtt_ms,omitempty"`
	Timeout bool    `json:"timeout"`
}

type Stat struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Hops    []Hop  `json:"hops"`
	Reached bool   `json:"reached"`
	Error   string `json:"error,omitempty"`
}

type Module struct {
	cfg config.TracerouteConfig
	id  module.Identity
}

func New(cfg config.TracerouteConfig, id module.Identity) *Module {
	return &Module{cfg: cfg, id: id}
}

func (m *Module) Name() string { return moduleName }

// Run 对所有 targets 依次执行 trace（每个 target 内部已经是一连串串行的
// TTL 探测，多个 target 之间用 goroutine 并发没有意义反而会引入更多原始
// socket 资源竞争，因此这里保持串行)。
func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	if len(m.cfg.Targets) == 0 {
		return nil, nil
	}

	results := make([]module.Result, 0, len(m.cfg.Targets))
	for _, target := range m.cfg.Targets {
		if ctx.Err() != nil {
			break
		}
		stat := m.trace(ctx, target)
		results = append(results, m.id.NewResult(moduleName, stat))
	}
	return results, nil
}

func (m *Module) trace(ctx context.Context, target config.NamedTarget) Stat {
	stat := Stat{Name: target.Name, Address: target.Address}

	dstAddr, err := net.ResolveIPAddr("ip4", target.Address)
	if err != nil {
		stat.Error = fmt.Sprintf("resolve: %v", err)
		return stat
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		stat.Error = fmt.Sprintf("listen icmp (need root/CAP_NET_RAW or Windows admin): %v", err)
		return stat
	}
	defer conn.Close()

	pconn := conn.IPv4PacketConn()
	id := os.Getpid() & 0xffff

	maxHops := m.cfg.MaxHops
	if maxHops <= 0 {
		maxHops = 30
	}

	for ttl := 1; ttl <= maxHops; ttl++ {
		if ctx.Err() != nil {
			stat.Error = ctx.Err().Error()
			return stat
		}

		if err := pconn.SetTTL(ttl); err != nil {
			stat.Error = fmt.Sprintf("set ttl: %v", err)
			return stat
		}

		hop := m.probeHop(conn, dstAddr, ttl, id)
		stat.Hops = append(stat.Hops, hop)
		if !hop.Timeout && hop.Address == dstAddr.String() {
			stat.Reached = true
			break
		}
	}

	return stat
}

// probeHop 发送单个 TTL 的 Echo Request 并等待一次回复（中间路由器的
// TimeExceeded，或目的主机的 EchoReply）。
func (m *Module) probeHop(conn *icmp.PacketConn, dst net.Addr, ttl, id int) Hop {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  ttl,
			Data: []byte("nms-agent-traceroute"),
		},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return Hop{TTL: ttl, Timeout: true}
	}

	sendAt := time.Now()
	if _, err := conn.WriteTo(wb, dst); err != nil {
		return Hop{TTL: ttl, Timeout: true}
	}

	if err := conn.SetReadDeadline(time.Now().Add(m.cfg.Timeout)); err != nil {
		return Hop{TTL: ttl, Timeout: true}
	}

	buf := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return Hop{TTL: ttl, Timeout: true} // 读超时或 socket 错误，视为本跳无响应
		}

		rm, err := icmp.ParseMessage(protocolICMP, buf[:n])
		if err != nil {
			continue // 无法解析的报文，继续等待下一个，直到 deadline
		}

		switch body := rm.Body.(type) {
		case *icmp.TimeExceeded:
			return Hop{TTL: ttl, Address: peer.String(), RttMs: msOf(time.Since(sendAt))}
		case *icmp.Echo:
			if body.ID == id {
				return Hop{TTL: ttl, Address: peer.String(), RttMs: msOf(time.Since(sendAt))}
			}
		}
	}
}

func msOf(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}
