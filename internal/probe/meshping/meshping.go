// Package meshping 实现全球节点间的网状延迟探测（Looking Glass 矩阵的数据源）。
//
// 推荐第三方库：github.com/prometheus-community/pro-bing（与 ping 模块相同）。
//
// 核心架构说明——这是理解本模块输出数据如何变成前端 NxN 矩阵的关键：
// 单个 Agent 只能主动探测"自己 -> 其它 peer"这一条条边，也就是矩阵里以
// 本节点为行的那一整行；它既不可能、也不需要知道其它任意两个 peer 之间
// 的延迟。真正的 NxN 矩阵是 NMS Server 把所有 N 个 Agent 各自上报的"一行"
// 边数据按 (source, destination) 拼接、去重后聚合出来的。因此每条边都
// 必须携带明确的 source 与 destination 字段，而不是只报"对某个 peer 的
// 延迟"——这正是 MeshEdge 结构体的设计意图。
package meshping

import (
	"context"
	"fmt"
	"sync"
	"time"

	probing "github.com/prometheus-community/pro-bing"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
)

const moduleName = "mesh_ping"

// MeshEdge 是延迟矩阵里的一条有向边：source 固定为本 Agent 的节点名
// （= config.yaml 的 mesh_ping.self_name，启动时已校验与 agent.site 一致），
// destination 是某个 peer 的节点名。
type MeshEdge struct {
	Source      string  `json:"source"`
	Destination string  `json:"destination"`
	LatencyMs   float64 `json:"latency_ms"`
	LossRate    float64 `json:"loss_rate"`
	Reachable   bool    `json:"reachable"`
	Error       string  `json:"error,omitempty"`
}

type Module struct {
	cfg config.MeshPingConfig
	id  module.Identity
}

func New(cfg config.MeshPingConfig, id module.Identity) *Module {
	return &Module{cfg: cfg, id: id}
}

func (m *Module) Name() string { return moduleName }

// Run 用固定大小的 worker pool 并发探测全部 peers，pool 大小由
// cfg.Concurrency 控制。
//
// 为什么要限流，而不是像其它探测模块一样直接为每个 target 开一个 goroutine：
// mesh_peers 的规模是"全球节点两两互联"，节点数稍多就会是几十上百个 peer，
// 不加控制地瞬间打出这么多并发 ICMP 报文，一是会在本机网卡上造成自我拥塞、
// 反过来污染本应测量"真实网络延迟"的结果，二是某些云厂商安全组/IDS 会把
// 突发的大量 ICMP 出流量误判为扫描行为。worker pool 把"并发探测"和
// "并发数上限"两个维度解耦，由 concurrency 配置项显式控制。
func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	peers := m.cfg.Peers
	if len(peers) == 0 {
		return nil, nil
	}

	workerCount := m.cfg.Concurrency
	if workerCount <= 0 || workerCount > len(peers) {
		workerCount = len(peers)
	}

	jobs := make(chan config.NamedTarget)
	edges := make(chan MeshEdge, len(peers)) // 缓冲到 len(peers)，worker 发送结果时绝不会被阻塞

	var workers sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go m.worker(ctx, &workers, jobs, edges)
	}

	// 派单 goroutine：把所有 peer 喂给 jobs，遇到 ctx 取消立即停止派单。
	go func() {
		defer close(jobs)
		for _, peer := range peers {
			select {
			case jobs <- peer:
			case <-ctx.Done():
				return
			}
		}
	}()

	// 收尾 goroutine：所有 worker 退出后关闭 edges，让下面的 range 能结束。
	go func() {
		workers.Wait()
		close(edges)
	}()

	results := make([]module.Result, 0, len(peers))
	for edge := range edges {
		results = append(results, m.id.NewResult(moduleName, edge))
	}
	return results, nil
}

func (m *Module) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan config.NamedTarget, edges chan<- MeshEdge) {
	defer wg.Done()
	for peer := range jobs {
		select {
		case <-ctx.Done():
			return // 关闭中，不再处理新任务；已入队但未处理的 peer 直接放弃
		default:
		}
		edges <- m.probe(ctx, peer)
	}
}

func (m *Module) probe(ctx context.Context, peer config.NamedTarget) MeshEdge {
	edge := MeshEdge{Source: m.cfg.SelfName, Destination: peer.Name}

	pinger, err := probing.NewPinger(peer.Address)
	if err != nil {
		edge.Error = fmt.Sprintf("resolve: %v", err)
		return edge
	}

	pinger.SetPrivileged(m.cfg.Privileged)
	pinger.Count = m.cfg.PacketCount
	// mesh 场景下 peer 数量可能很多，用比默认 1s 更短的发包间隔缩短单个 peer
	// 的探测耗时，让一轮 mesh_ping 整体更快收敛；与 ping 模块同理，
	// Timeout 必须覆盖 Count*Interval 的发送总时长再加一点尾部余量。
	pinger.Interval = 200 * time.Millisecond
	pinger.Timeout = time.Duration(m.cfg.PacketCount)*pinger.Interval + m.cfg.Timeout

	if err := pinger.RunWithContext(ctx); err != nil {
		edge.Error = err.Error()
		return edge
	}

	st := pinger.Statistics()
	edge.LossRate = st.PacketLoss
	edge.Reachable = st.PacketsRecv > 0
	if edge.Reachable {
		edge.LatencyMs = float64(st.AvgRtt) / float64(time.Millisecond)
	}
	return edge
}
