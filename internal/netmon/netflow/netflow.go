// Package netflow 实现 NetFlow/sFlow 流量数据的接收器或转发器
// （对应 config.yaml 的 modules.netflow，mode=receiver|forwarder）。
//
// 推荐第三方库：github.com/netsampler/goflow2
// （业界主流的 NetFlow v5/v9、IPFIX、sFlow 解码引擎，模板缓存、字段映射等
// 复杂逻辑都已经过大规模生产验证）。本骨架只对结构简单、字段定长的
// NetFlow v5 头部做了真实解析用于演示；v9/IPFIX/sFlow 采用模板描述字段，
// 解码逻辑复杂得多，正式接入时应该用 goflow2 的 decoder 链替换掉
// decode() 里的 TODO，而不是从零手写模板缓存。
package netflow

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
)

const moduleName = "netflow"

// V5Header 是 NetFlow v5 定长包头（24 字节）的解析结果。
type V5Header struct {
	Version      uint16 `json:"version"`
	Count        uint16 `json:"count"`
	SysUptimeMs  uint32 `json:"sys_uptime_ms"`
	UnixSecs     uint32 `json:"unix_secs"`
	FlowSequence uint32 `json:"flow_sequence"`
}

type Packet struct {
	Peer     string    `json:"peer"`
	Bytes    int       `json:"bytes"`
	V5Header *V5Header `json:"v5_header,omitempty"`
}

// Module 同时实现 module.Module 与 module.Emitter：
// 它没有"周期性触发一次"的语义，Run 只是为了满足接口，真正的逻辑在 Serve 里，
// Scheduler 检测到 Emitter 后会改用 Serve 常驻调度。
type Module struct {
	cfg config.NetflowConfig
	id  module.Identity
}

func New(cfg config.NetflowConfig, id module.Identity) *Module {
	return &Module{cfg: cfg, id: id}
}

func (m *Module) Name() string { return moduleName }

func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	return nil, nil
}

// Serve 监听 UDP 端口，receiver 模式下解码并 emit；forwarder 模式下原样转发
// 给上游采集器，不在本地解码（典型场景：边缘节点只做"接力"，集中解码放在
// 中心机房，降低边缘节点 CPU 开销）。
func (m *Module) Serve(ctx context.Context, emit func(...module.Result)) error {
	addr, err := net.ResolveUDPAddr("udp", m.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("resolve listen_address %q: %w", m.cfg.ListenAddress, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp %q: %w", m.cfg.ListenAddress, err)
	}
	defer conn.Close()

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close() // 解除下面 ReadFromUDP 的阻塞，使 Serve 能及时返回
		case <-stop:
		}
	}()
	defer close(stop)

	var forwardConn *net.UDPConn
	if m.cfg.Mode == "forwarder" {
		if m.cfg.ForwardTo == "" {
			return fmt.Errorf("mode=forwarder requires forward_to to be set")
		}
		forwardAddr, err := net.ResolveUDPAddr("udp", m.cfg.ForwardTo)
		if err != nil {
			return fmt.Errorf("resolve forward_to %q: %w", m.cfg.ForwardTo, err)
		}
		forwardConn, err = net.DialUDP("udp", nil, forwardAddr)
		if err != nil {
			return fmt.Errorf("dial forward_to %q: %w", m.cfg.ForwardTo, err)
		}
		defer forwardConn.Close()
	}

	buf := make([]byte, 65535)
	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil // ctx 取消导致的 Close，是正常退出路径
			}
			return fmt.Errorf("read udp: %w", err)
		}

		data := append([]byte(nil), buf[:n]...) // 复制出来，避免下一轮循环复用 buf 时数据被覆盖

		if forwardConn != nil {
			_, _ = forwardConn.Write(data) // 转发尽力而为，单个包失败不阻塞接收循环
			continue
		}

		emit(m.id.NewResult(moduleName, decode(peer.String(), data, m.cfg.Protocol)))
	}
}

func decode(peer string, data []byte, protocol string) Packet {
	pkt := Packet{Peer: peer, Bytes: len(data)}

	if protocol == "netflow_v5" && len(data) >= 24 {
		pkt.V5Header = &V5Header{
			Version:      binary.BigEndian.Uint16(data[0:2]),
			Count:        binary.BigEndian.Uint16(data[2:4]),
			SysUptimeMs:  binary.BigEndian.Uint32(data[4:8]),
			UnixSecs:     binary.BigEndian.Uint32(data[8:12]),
			FlowSequence: binary.BigEndian.Uint32(data[16:20]),
		}
		return pkt
	}

	// TODO: netflow_v9 / ipfix / sflow 是基于模板描述字段的可变长格式，
	// 接入 github.com/netsampler/goflow2 的 decoder 在这里替换掉这条分支。
	return pkt
}
