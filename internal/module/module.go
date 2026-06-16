// Package module 定义所有功能模块必须遵守的统一契约。
//
// Scheduler 只依赖本包中的接口，对 Ping/SNMP/Syslog 等具体实现一无所知，
// 这是整个 Agent 实现"高度模块化、可插拔"的核心边界。新增一个功能模块
// 只需实现 Module（或 Emitter），并在 main.go 的装配阶段注册即可，
// 不需要修改 Scheduler 或 Reporter 任何一行代码。
package module

import (
	"context"
	"time"
)

// Result 是所有模块统一的上报数据封装，最终会被 Reporter 序列化为 JSON 并
// POST 给中心 NMS Server。Data 字段承载各模块自定义的业务负载
// （例如 ping 的延迟、snmp 的 OID 取值、meshping 的矩阵边等）。
type Result struct {
	Module    string            `json:"module"`         // 模块名，如 "ping"、"mesh_ping"
	AgentID   string            `json:"agent_id"`       // 产生该结果的 Agent 唯一标识
	Site      string            `json:"site"`           // 产生该结果的机房/节点名称
	Timestamp time.Time         `json:"timestamp"`      // 探测/采集发生的时间
	Tags      map[string]string `json:"tags,omitempty"` // 继承自 agent.tags，便于服务端按标签聚合
	Data      any               `json:"data"`           // 模块自定义负载，必须是可 json.Marshal 的类型
}

// Module 是 15 个功能模块（以及 MeshPing）必须实现的最小接口。
//
// 实现约束：
//  1. Run 必须尊重 ctx 的取消/超时信号，不能无限阻塞；
//  2. Run 内部即使发生 panic，也会被 Scheduler 兜底 recover，但实现本身
//     仍应在可预见的错误路径上返回 error 而不是依赖 panic；
//  3. 同一个 Module 实例的 Run 会被并发安全地反复调用（每个调度周期一次），
//     实现必须是可重入的（不持有跨调用的可变共享状态，或自行加锁保护）。
type Module interface {
	// Name 返回模块唯一标识，用于日志、任务命名与 Result.Module 字段。
	Name() string

	// Run 执行一次完整的探测/采集/运维动作，返回本次产生的全部 Result。
	// 没有数据可上报时返回 (nil, nil) 即可，Scheduler 不会上报空批次。
	Run(ctx context.Context) ([]Result, error)
}

// Identity 携带 Result 中与"产生该数据的 Agent 是谁"相关的字段。
// 每个模块的构造函数都接收一份 Identity，从而在 Run 内部用 NewResult
// 统一拼装 Result，避免在 15 个模块里重复 AgentID/Site/Tags 的赋值代码。
type Identity struct {
	AgentID string
	Site    string
	Tags    map[string]string
}

// NewResult 用当前 Identity 拼装一条 Result，Timestamp 取调用时刻的 UTC 时间。
func (id Identity) NewResult(moduleName string, data any) Result {
	return Result{
		Module:    moduleName,
		AgentID:   id.AgentID,
		Site:      id.Site,
		Timestamp: time.Now().UTC(),
		Tags:      id.Tags,
		Data:      data,
	}
}

// Emitter 是可选的扩展接口，供需要长期独占一个 goroutine 的"常驻型"模块实现，
// 典型场景：Syslog UDP 监听、Netflow/sFlow 接收器。
//
// 这类模块没有"周期性触发一次"的语义，而是启动后持续运行直到 ctx 被取消；
// 产出的数据通过 emit 回调随时推送，而不是像 Module.Run 那样一次性返回切片。
// Scheduler 在调度这类模块时，会在其异常退出后按指数退避自动重启。
type Emitter interface {
	Module
	Serve(ctx context.Context, emit func(...Result)) error
}
