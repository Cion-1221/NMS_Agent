// Package ifdiscovery 通过 SNMP 走查 IF-MIB::ifTable，发现设备上的全部接口
// 及其基本状态（管理/运行状态、速率、MAC 地址），用于感知拓扑变化。
//
// 推荐第三方库：github.com/gosnmp/gosnmp（与 snmp_poll 共用 internal/netmon/snmpclient）。
package ifdiscovery

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/gosnmp/gosnmp"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
	"github.com/Cion-1221/NMS_Agent/internal/netmon/snmpclient"
)

const moduleName = "interface_discovery"

// ifTableOID 是 IF-MIB::ifTable 的根 OID，WalkAll 会返回它下面全部
// "列(column).行(ifIndex)" 组合的叶子节点。
const ifTableOID = "1.3.6.1.2.1.2.2.1"

// IF-MIB ifEntry 各列在 OID 中的相对位置。
const (
	colIfDescr     = 2
	colIfType      = 3
	colIfMtu       = 4
	colIfSpeed     = 5
	colIfPhysAddr  = 6
	colIfAdminStat = 7
	colIfOperStat  = 8
)

type Interface struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	Type        int    `json:"type"`
	MTU         int    `json:"mtu"`
	SpeedBps    uint64 `json:"speed_bps"`
	PhysAddress string `json:"phys_address,omitempty"`
	AdminStatus string `json:"admin_status"`
	OperStatus  string `json:"oper_status"`
}

type DeviceInterfaces struct {
	Device     string      `json:"device"`
	Address    string      `json:"address"`
	Interfaces []Interface `json:"interfaces,omitempty"`
	Error      string      `json:"error,omitempty"`
}

type Module struct {
	cfg config.InterfaceDiscoveryConfig
	id  module.Identity
}

func New(cfg config.InterfaceDiscoveryConfig, id module.Identity) *Module {
	return &Module{cfg: cfg, id: id}
}

func (m *Module) Name() string { return moduleName }

func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	if len(m.cfg.Devices) == 0 {
		return nil, nil
	}

	stats := make([]DeviceInterfaces, len(m.cfg.Devices))
	var wg sync.WaitGroup
	for i, dev := range m.cfg.Devices {
		i, dev := i, dev
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats[i] = m.discover(ctx, dev)
		}()
	}
	wg.Wait()

	results := make([]module.Result, len(stats))
	for i, s := range stats {
		results[i] = m.id.NewResult(moduleName, s)
	}
	return results, nil
}

func (m *Module) discover(ctx context.Context, dev config.SNMPDevice) DeviceInterfaces {
	stat := DeviceInterfaces{Device: dev.Name, Address: dev.Address}

	client, err := snmpclient.New(ctx, dev, m.cfg.Timeout, 1)
	if err != nil {
		stat.Error = err.Error()
		return stat
	}
	if err := client.Connect(); err != nil {
		stat.Error = fmt.Sprintf("connect: %v", err)
		return stat
	}
	defer client.Conn.Close()

	pdus, err := client.WalkAll(ifTableOID)
	if err != nil {
		stat.Error = fmt.Sprintf("walk ifTable: %v", err)
		return stat
	}

	byIndex := make(map[int]*Interface)
	for _, pdu := range pdus {
		col, idx, err := splitColumnIndex(pdu.Name)
		if err != nil {
			continue
		}
		iface := byIndex[idx]
		if iface == nil {
			iface = &Interface{Index: idx}
			byIndex[idx] = iface
		}
		applyColumn(iface, col, pdu)
	}

	stat.Interfaces = make([]Interface, 0, len(byIndex))
	for _, iface := range byIndex {
		stat.Interfaces = append(stat.Interfaces, *iface)
	}
	sort.Slice(stat.Interfaces, func(i, j int) bool {
		return stat.Interfaces[i].Index < stat.Interfaces[j].Index
	})

	return stat
}

// splitColumnIndex 把 WalkAll 返回的完整 OID（如 ".1.3.6.1.2.1.2.2.1.2.7"）
// 拆解为表列号（2=ifDescr）与行号（7=ifIndex）。
func splitColumnIndex(oid string) (col, index int, err error) {
	suffix := strings.TrimPrefix(oid, ".")
	prefix := strings.TrimPrefix(ifTableOID, ".")
	suffix = strings.TrimPrefix(suffix, prefix+".")
	parts := strings.SplitN(suffix, ".", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("unexpected oid suffix %q", oid)
	}
	if col, err = strconv.Atoi(parts[0]); err != nil {
		return 0, 0, err
	}
	if index, err = strconv.Atoi(parts[1]); err != nil {
		return 0, 0, err
	}
	return col, index, nil
}

func applyColumn(iface *Interface, col int, pdu gosnmp.SnmpPDU) {
	switch col {
	case colIfDescr:
		if b, ok := pdu.Value.([]byte); ok {
			iface.Name = string(b)
		}
	case colIfType:
		iface.Type = toInt(pdu.Value)
	case colIfMtu:
		iface.MTU = toInt(pdu.Value)
	case colIfSpeed:
		iface.SpeedBps = uint64(toInt(pdu.Value))
	case colIfPhysAddr:
		if b, ok := pdu.Value.([]byte); ok {
			iface.PhysAddress = fmt.Sprintf("%X", b)
		}
	case colIfAdminStat:
		iface.AdminStatus = statusString(toInt(pdu.Value))
	case colIfOperStat:
		iface.OperStatus = statusString(toInt(pdu.Value))
	}
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case uint:
		return int(n)
	case uint32:
		return int(n)
	case uint64:
		return int(n)
	case int64:
		return int(n)
	default:
		return 0
	}
}

func statusString(code int) string {
	switch code {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	case 4:
		return "unknown"
	case 5:
		return "dormant"
	case 6:
		return "notPresent"
	case 7:
		return "lowerLayerDown"
	default:
		return fmt.Sprintf("unspecified(%d)", code)
	}
}
