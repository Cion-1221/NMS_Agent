// SNMP polling for the agent-proxy collection mode: the server assigns devices
// to this agent (Devices → Polling Mode → Agent Proxy) and synthesizes one
// snmp_poll task per device carrying target/credentials/cadence. We GET the
// RFC 1213 system group and report conclusions to /agent-sync/snmp-results.
//
// Fast/slow cadence: every poll fetches sysUpTime only (minimal packet, doubles
// as the liveness check); every InventoryEveryN-th poll adds the full system
// group (sysName/sysDescr/sysObjectID/sysLocation/sysContact) — asset facts
// change rarely, no need to fetch them each cycle.
package probe

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// RFC 1213 system-group scalar OIDs (fixed set, no MIB required).
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysContact  = "1.3.6.1.2.1.1.4.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidSysLocation = "1.3.6.1.2.1.1.6.0"
)

// v3 protocol name → gosnmp constant maps (must stay in sync with the server's
// validation enums in controllers/device_api.go).
var v3AuthProtos = map[string]gosnmp.SnmpV3AuthProtocol{
	"MD5": gosnmp.MD5, "SHA": gosnmp.SHA, "SHA224": gosnmp.SHA224,
	"SHA256": gosnmp.SHA256, "SHA384": gosnmp.SHA384, "SHA512": gosnmp.SHA512,
}

var v3PrivProtos = map[string]gosnmp.SnmpV3PrivProtocol{
	"DES": gosnmp.DES, "AES": gosnmp.AES, "AES192": gosnmp.AES192,
	"AES256": gosnmp.AES256, "AES192C": gosnmp.AES192C, "AES256C": gosnmp.AES256C,
}

// classifySNMPError buckets a gosnmp error into the server's error_kind enum.
// v3 has explicit authentication failures; under v1/v2c a wrong community just
// looks like a timeout — protocol limitation, the server wording covers it.
// notInTimeWindow must be checked BEFORE the usm match: it is the v3 time-sync
// signal (gosnmp resyncs via the Report PDU and retries automatically); a rare
// leftover is clock drift, not a credential problem — classify as snmp_error
// so the server does not surface a misleading auth_fail.
func classifySNMPError(err error) string {
	e := strings.ToLower(err.Error())
	switch {
	case strings.Contains(e, "time window"), strings.Contains(e, "timewindow"):
		return "snmp_error"
	case strings.Contains(e, "usm"), strings.Contains(e, "authent"),
		strings.Contains(e, "unknown user"), strings.Contains(e, "wrong digest"),
		strings.Contains(e, "decryption"):
		return "auth_fail"
	case strings.Contains(e, "timeout"):
		return "snmp_timeout"
	default:
		return "snmp_error"
	}
}

// RunSNMPPoll executes one poll against the task's single target device.
// full=true fetches the complete system group, false only sysUpTime. Custom
// OIDs (params.ExtraOIDs) ride along on every poll regardless of cadence.
func RunSNMPPoll(task Task, full bool) SNMPResult {
	p := task.SNMP
	res := SNMPResult{DeviceID: p.DeviceID, HasInventory: full, CollectedAt: time.Now().Unix()}

	if len(task.Targets) == 0 || task.Targets[0] == "" {
		res.ErrorKind, res.Error = "unreachable", "no target in task payload"
		return res
	}
	target := task.Targets[0]

	timeout := time.Duration(p.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	retries := p.Retries
	if retries < 0 {
		retries = 1
	}
	port := p.Port
	if port <= 0 || port > 65535 {
		port = 161
	}

	g := &gosnmp.GoSNMP{
		Target:  target,
		Port:    uint16(port),
		Timeout: timeout,
		Retries: retries,
	}
	switch p.Version {
	case "3":
		flags := gosnmp.NoAuthNoPriv
		sp := &gosnmp.UsmSecurityParameters{UserName: p.V3User}
		if p.V3AuthProto != "" {
			flags = gosnmp.AuthNoPriv
			sp.AuthenticationProtocol = v3AuthProtos[p.V3AuthProto]
			sp.AuthenticationPassphrase = p.V3AuthPass
			if p.V3PrivProto != "" {
				flags = gosnmp.AuthPriv
				sp.PrivacyProtocol = v3PrivProtos[p.V3PrivProto]
				sp.PrivacyPassphrase = p.V3PrivPass
			}
		}
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = flags
		g.SecurityParameters = sp
	case "1":
		g.Version = gosnmp.Version1
		g.Community = p.Community
	default: // "2c"
		g.Version = gosnmp.Version2c
		g.Community = p.Community
	}
	if err := g.Connect(); err != nil {
		res.ErrorKind, res.Error = "unreachable", "connect: "+err.Error()
		return res
	}
	defer g.Conn.Close()

	oids := []string{oidSysUpTime}
	if full {
		oids = []string{oidSysUpTime, oidSysName, oidSysDescr, oidSysObjectID, oidSysLocation, oidSysContact}
	}
	oids = append(oids, p.ExtraOIDs...)

	start := time.Now()
	pkt, err := g.Get(oids)
	if err != nil {
		res.ErrorKind, res.Error = classifySNMPError(err), err.Error()
		return res
	}
	if pkt.Error != gosnmp.NoError {
		res.ErrorKind, res.Error = "snmp_error", "SNMP error status: "+pkt.Error.String()
		return res
	}

	res.Success = true
	res.LatencyMs = msPtr(time.Since(start))

	asString := func(v gosnmp.SnmpPDU) string {
		switch val := v.Value.(type) {
		case []byte:
			return string(val)
		case string:
			return val
		default:
			return ""
		}
	}
	// Interface table: a failed walk must not fail the poll (the scalar GET
	// already succeeded) — the server keeps the last known interface state.
	if p.CollectIfaces {
		if ifs, werr := collectInterfaces(g); werr == nil {
			res.HasInterfaces = true
			res.Interfaces = ifs
		}
	}

	extras := make(map[string]bool, len(p.ExtraOIDs))
	for _, o := range p.ExtraOIDs {
		extras[o] = true
	}

	// NoSuchObject/NoSuchInstance values are skipped silently for the system
	// group — some slim firmwares omit sysLocation/sysContact; that must not
	// fail the poll. Custom OIDs report those states explicitly instead.
	for _, v := range pkt.Variables {
		oid := strings.TrimPrefix(v.Name, ".")
		switch oid {
		case oidSysUpTime:
			if v.Type == gosnmp.TimeTicks {
				ticks := gosnmp.ToBigInt(v.Value).Int64()
				res.UptimeTicks = &ticks
			}
		case oidSysName:
			res.SysName = asString(v)
		case oidSysDescr:
			res.SysDescr = asString(v)
		case oidSysObjectID:
			res.SysObjectID = asString(v)
		case oidSysLocation:
			res.SysLocation = asString(v)
		case oidSysContact:
			res.SysContact = asString(v)
		default:
			if extras[oid] {
				res.Values = append(res.Values, decodeOIDValue(oid, v))
			}
		}
	}
	return res
}

// ifTable / ifXTable entry subtrees (one walk each, dispatched by column id).
const (
	oidIfTableEntry  = "1.3.6.1.2.1.2.2.1"
	oidIfXTableEntry = "1.3.6.1.2.1.31.1.1.1"
)

// maxInterfaces caps runaway walks on chassis with thousands of logical ports.
const maxInterfaces = 512

// collectInterfaces walks ifTable + ifXTable and assembles interface rows —
// mirrors the server-side collectSNMPInterfaces in device_snmp_poller.go.
// A missing ifXTable is tolerated (old/v1 devices: 32-bit counters, ifDescr).
func collectInterfaces(g *gosnmp.GoSNMP) ([]SNMPInterface, error) {
	walk := g.BulkWalkAll
	if g.Version == gosnmp.Version1 {
		walk = g.WalkAll
	}

	type ifRow struct {
		SNMPInterface
		descr       string
		spdBps      int64
		spdMbps     int64
		hcIn, hcOut *uint64
	}
	rows := map[int]*ifRow{}
	get := func(idx int) *ifRow {
		r, ok := rows[idx]
		if !ok {
			r = &ifRow{}
			r.IfIndex = idx
			rows[idx] = r
		}
		return r
	}
	asStr := func(v gosnmp.SnmpPDU) string {
		if b, ok := v.Value.([]byte); ok {
			return strings.TrimSpace(string(b))
		}
		if s, ok := v.Value.(string); ok {
			return strings.TrimSpace(s)
		}
		return ""
	}
	asInt := func(v gosnmp.SnmpPDU) int64 {
		if n := gosnmp.ToBigInt(v.Value); n != nil {
			return n.Int64()
		}
		return 0
	}
	asUint := func(v gosnmp.SnmpPDU) uint64 {
		if n := gosnmp.ToBigInt(v.Value); n != nil {
			return n.Uint64()
		}
		return 0
	}
	dispatch := func(pdus []gosnmp.SnmpPDU, entry string, handle func(r *ifRow, col int, v gosnmp.SnmpPDU)) {
		prefix := entry + "."
		for _, v := range pdus {
			rest := strings.TrimPrefix(strings.TrimPrefix(v.Name, "."), prefix)
			if rest == strings.TrimPrefix(v.Name, ".") {
				continue
			}
			parts := strings.SplitN(rest, ".", 2)
			if len(parts) != 2 {
				continue
			}
			col, err1 := strconv.Atoi(parts[0])
			idx, err2 := strconv.Atoi(parts[1])
			if err1 != nil || err2 != nil {
				continue
			}
			handle(get(idx), col, v)
		}
	}

	pdus, err := walk(oidIfTableEntry)
	if err != nil {
		return nil, err
	}
	dispatch(pdus, oidIfTableEntry, func(r *ifRow, col int, v gosnmp.SnmpPDU) {
		switch col {
		case 2:
			r.descr = asStr(v)
		case 3:
			r.IfType = int(asInt(v))
		case 5:
			r.spdBps = asInt(v)
		case 7:
			r.AdminStatus = int(asInt(v))
		case 8:
			r.OperStatus = int(asInt(v))
		case 10:
			r.InOctets = asUint(v)
		case 14:
			r.InErrors = asInt(v)
		case 16:
			r.OutOctets = asUint(v)
		case 20:
			r.OutErrors = asInt(v)
		}
	})
	if xpdus, xerr := walk(oidIfXTableEntry); xerr == nil {
		dispatch(xpdus, oidIfXTableEntry, func(r *ifRow, col int, v gosnmp.SnmpPDU) {
			switch col {
			case 1:
				r.Name = asStr(v)
			case 6:
				u := asUint(v)
				r.hcIn = &u
			case 10:
				u := asUint(v)
				r.hcOut = &u
			case 15:
				r.spdMbps = asInt(v)
			case 18:
				r.Alias = asStr(v)
			}
		})
	}

	idxs := make([]int, 0, len(rows))
	for idx := range rows {
		idxs = append(idxs, idx)
	}
	sort.Ints(idxs)
	if len(idxs) > maxInterfaces {
		idxs = idxs[:maxInterfaces]
	}
	out := make([]SNMPInterface, 0, len(idxs))
	for _, idx := range idxs {
		r := rows[idx]
		if r.Name == "" {
			r.Name = r.descr
		}
		if r.spdMbps > 0 {
			r.SpeedMbps = r.spdMbps
		} else {
			r.SpeedMbps = r.spdBps / 1_000_000
		}
		if r.hcIn != nil {
			r.InOctets = *r.hcIn
		}
		if r.hcOut != nil {
			r.OutOctets = *r.hcOut
		}
		out = append(out, r.SNMPInterface)
	}
	return out, nil
}

// decodeOIDValue renders one custom-OID PDU as string + optional numeric —
// mirrors the server-side decodeSNMPValue in device_snmp_poller.go.
func decodeOIDValue(oid string, v gosnmp.SnmpPDU) SNMPOIDValue {
	res := SNMPOIDValue{OID: oid}
	switch v.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance:
		res.Err = "no_such_object"
	case gosnmp.Null:
		res.Err = "null"
	case gosnmp.OctetString:
		if b, ok := v.Value.([]byte); ok {
			res.Value = string(b)
		}
	case gosnmp.ObjectIdentifier, gosnmp.IPAddress:
		if s, ok := v.Value.(string); ok {
			res.Value = s
		}
	case gosnmp.OpaqueFloat:
		if f, ok := v.Value.(float32); ok {
			f64 := float64(f)
			res.Numeric = &f64
			res.Value = strconv.FormatFloat(f64, 'f', -1, 64)
		}
	case gosnmp.OpaqueDouble:
		if f, ok := v.Value.(float64); ok {
			res.Numeric = &f
			res.Value = strconv.FormatFloat(f, 'f', -1, 64)
		}
	default:
		// Integer / Counter32 / Gauge32 / Counter64 / TimeTicks / Uinteger32
		if n := gosnmp.ToBigInt(v.Value); n != nil {
			f := float64(n.Int64())
			res.Numeric = &f
			res.Value = n.String()
		}
	}
	return res
}
