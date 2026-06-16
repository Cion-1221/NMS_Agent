// Package bgpcheck 检查 BGP Peer 状态。
//
//   - method=snmp：通过 BGP4-MIB::bgpPeerState 直接 GET（索引就是对端 IPv4
//     地址，无需整表 walk），推荐库 github.com/gosnmp/gosnmp。
//     注意 BGP4-MIB（RFC 1657）只覆盖 IPv4 Peer；IPv6/多协议 BGP 的状态在
//     不同厂商实现里分散于私有 MIB 或 BGP4V2-MIB，按需扩展。
//   - method=ssh：登录设备执行厂商命令解析输出，推荐库
//     golang.org/x/crypto/ssh（与 config_backup 模块一致）。不同厂商命令、
//     输出格式差异很大，这里提供登录取回原始输出的骨架与可插拔的
//     vendorParsers 注册表，具体解析器按目标设备型号补充。
package bgpcheck

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
	"github.com/Cion-1221/NMS_Agent/internal/netmon/snmpclient"
)

const moduleName = "bgp_check"

// bgpPeerStateOID 是 BGP4-MIB::bgpPeerState 的前缀；对端 203.0.113.1 对应
// OID "1.3.6.1.2.1.15.3.1.2.203.0.113.1"，取值 1-6 分别是
// idle/connect/active/opensent/openconfirm/established。
const bgpPeerStateOID = "1.3.6.1.2.1.15.3.1.2"

const defaultSNMPTimeout = 5 * time.Second

type PeerStat struct {
	Name          string `json:"name"`
	DeviceAddress string `json:"device_address"`
	PeerIP        string `json:"peer_ip"`
	State         string `json:"state"`
	ExpectState   string `json:"expect_state"`
	Healthy       bool   `json:"healthy"`
	Error         string `json:"error,omitempty"`
}

type Module struct {
	cfg config.BGPCheckConfig
	id  module.Identity
}

func New(cfg config.BGPCheckConfig, id module.Identity) *Module {
	return &Module{cfg: cfg, id: id}
}

func (m *Module) Name() string { return moduleName }

func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	if len(m.cfg.Peers) == 0 {
		return nil, nil
	}

	stats := make([]PeerStat, len(m.cfg.Peers))
	var wg sync.WaitGroup
	for i, peer := range m.cfg.Peers {
		i, peer := i, peer
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats[i] = m.check(ctx, peer)
		}()
	}
	wg.Wait()

	results := make([]module.Result, len(stats))
	for i, s := range stats {
		results[i] = m.id.NewResult(moduleName, s)
	}
	return results, nil
}

func (m *Module) check(ctx context.Context, peer config.BGPPeer) PeerStat {
	stat := PeerStat{
		Name:          peer.Name,
		DeviceAddress: peer.DeviceAddress,
		PeerIP:        peer.PeerIP,
		ExpectState:   peer.ExpectState,
	}

	var state string
	var err error
	if m.cfg.Method == "ssh" {
		state, err = m.checkViaSSH(peer)
	} else {
		state, err = m.checkViaSNMP(ctx, peer)
	}

	if err != nil {
		stat.Error = err.Error()
		return stat
	}

	stat.State = state
	stat.Healthy = strings.EqualFold(state, peer.ExpectState)
	return stat
}

func (m *Module) checkViaSNMP(ctx context.Context, peer config.BGPPeer) (string, error) {
	dev := config.SNMPDevice{
		Address:   peer.DeviceAddress,
		Version:   m.cfg.SNMP.Version,
		Community: m.cfg.SNMP.Community,
	}
	client, err := snmpclient.New(ctx, dev, defaultSNMPTimeout, 1)
	if err != nil {
		return "", err
	}
	if err := client.Connect(); err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer client.Conn.Close()

	oid := bgpPeerStateOID + "." + peer.PeerIP
	packet, err := client.Get([]string{oid})
	if err != nil {
		return "", fmt.Errorf("get %s: %w", oid, err)
	}
	if len(packet.Variables) == 0 {
		return "", fmt.Errorf("empty response for peer %s", peer.PeerIP)
	}

	return bgpStateString(toInt(packet.Variables[0].Value)), nil
}

func (m *Module) checkViaSSH(peer config.BGPPeer) (string, error) {
	sshCfg := m.cfg.SSH

	var authMethods []ssh.AuthMethod
	if sshCfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(sshCfg.Password))
	}
	// TODO: authMethod == "key" 时读取 sshCfg.PrivateKeyPath，用
	// ssh.ParsePrivateKey 解析为 ssh.Signer 后通过 ssh.PublicKeys(signer)
	// 加入 authMethods——写法与 internal/ops/configbackup 的登录逻辑一致。

	clientCfg := &ssh.ClientConfig{
		User:            sshCfg.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // TODO: 生产环境应替换为校验设备指纹的 FixedHostKey
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", peer.DeviceAddress+":22", clientCfg)
	if err != nil {
		return "", fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh new session: %w", err)
	}
	defer session.Close()

	cmd := vendorCommand(sshCfg.Vendor)
	output, err := session.Output(cmd)
	if err != nil {
		return "", fmt.Errorf("run %q: %w", cmd, err)
	}

	parser, ok := vendorParsers[sshCfg.Vendor]
	if !ok {
		return "", fmt.Errorf("no output parser registered for vendor %q (got raw output, %d bytes)", sshCfg.Vendor, len(output))
	}
	return parser(string(output), peer.PeerIP)
}

func vendorCommand(vendor string) string {
	switch vendor {
	case "cisco":
		return "show ip bgp summary"
	case "juniper":
		return "show bgp summary"
	default: // huawei
		return "display bgp peer"
	}
}

// vendorParsers 是 厂商名 -> 输出解析函数 的注册表。
// TODO: 按目标设备的真实命令输出补充实现，例如：
//
//	vendorParsers["huawei"] = func(output, peerIP string) (string, error) { ... }
var vendorParsers = map[string]func(output, peerIP string) (string, error){}

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

func bgpStateString(code int) string {
	switch code {
	case 1:
		return "idle"
	case 2:
		return "connect"
	case 3:
		return "active"
	case 4:
		return "opensent"
	case 5:
		return "openconfirm"
	case 6:
		return "established"
	default:
		return fmt.Sprintf("unknown(%d)", code)
	}
}
