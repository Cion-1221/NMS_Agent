// Package snmppoll 实现 SNMP 周期性指标采集（对应 config.yaml 的
// modules.snmp_poll）：按设备配置的 OID 列表发起 GET，取回当前值。
//
// 推荐第三方库：github.com/gosnmp/gosnmp
// （事实上的 Go SNMP 标准库，支持 v1/v2c/v3 与 GET/GETBULK/WALK 等操作）。
package snmppoll

import (
	"context"
	"fmt"
	"sync"

	"github.com/gosnmp/gosnmp"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
	"github.com/Cion-1221/NMS_Agent/internal/netmon/snmpclient"
)

const moduleName = "snmp_poll"

// maxOidsPerGet 是单次 GET 请求携带的 OID 数量上限，超出按批切分，
// 避免单个 UDP 报文过大被设备拒绝（gosnmp 默认 MaxOids 同样是这个量级）。
const maxOidsPerGet = 60

type MetricValue struct {
	Name  string `json:"name"`
	OID   string `json:"oid"`
	Value any    `json:"value"`
	Type  string `json:"type"`
}

type DeviceStat struct {
	Device  string        `json:"device"`
	Address string        `json:"address"`
	Metrics []MetricValue `json:"metrics,omitempty"`
	Error   string        `json:"error,omitempty"`
}

type Module struct {
	cfg config.SNMPPollConfig
	id  module.Identity
}

func New(cfg config.SNMPPollConfig, id module.Identity) *Module {
	return &Module{cfg: cfg, id: id}
}

func (m *Module) Name() string { return moduleName }

func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	if len(m.cfg.Devices) == 0 {
		return nil, nil
	}

	stats := make([]DeviceStat, len(m.cfg.Devices))
	var wg sync.WaitGroup
	for i, dev := range m.cfg.Devices {
		i, dev := i, dev
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats[i] = m.poll(ctx, dev)
		}()
	}
	wg.Wait()

	results := make([]module.Result, len(stats))
	for i, s := range stats {
		results[i] = m.id.NewResult(moduleName, s)
	}
	return results, nil
}

func (m *Module) poll(ctx context.Context, dev config.SNMPPollDevice) DeviceStat {
	stat := DeviceStat{Device: dev.Name, Address: dev.Address}

	if len(dev.OIDs) == 0 {
		return stat
	}

	client, err := snmpclient.New(ctx, dev.SNMPDevice, m.cfg.Timeout, m.cfg.Retries)
	if err != nil {
		stat.Error = err.Error()
		return stat
	}
	if err := client.Connect(); err != nil {
		stat.Error = fmt.Sprintf("connect: %v", err)
		return stat
	}
	defer client.Conn.Close()

	for start := 0; start < len(dev.OIDs); start += maxOidsPerGet {
		end := min(start+maxOidsPerGet, len(dev.OIDs))
		batchItems := dev.OIDs[start:end]

		oids := make([]string, len(batchItems))
		for i, item := range batchItems {
			oids[i] = item.OID
		}

		packet, err := client.Get(oids)
		if err != nil {
			stat.Error = fmt.Sprintf("get %v: %v", oids, err)
			return stat
		}
		for j, pdu := range packet.Variables {
			stat.Metrics = append(stat.Metrics, MetricValue{
				Name:  batchItems[j].Name,
				OID:   pdu.Name,
				Value: normalizeValue(pdu),
				Type:  pdu.Type.String(),
			})
		}
	}
	return stat
}

// normalizeValue 把 gosnmp 返回的原始 PDU 值转换成更适合 JSON 序列化的形式：
// OctetString 类型的底层值是 []byte，原样序列化会变成 base64，
// 这里转成 string 以便服务端直接可读。
func normalizeValue(pdu gosnmp.SnmpPDU) any {
	if pdu.Type == gosnmp.OctetString {
		if b, ok := pdu.Value.([]byte); ok {
			return string(b)
		}
	}
	return pdu.Value
}
