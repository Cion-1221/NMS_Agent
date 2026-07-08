// Package probe implements all server-dispatched probe types with optional
// source-IP binding for precise egress control.
package probe

import (
	"context"
	"net"
	"time"
)

// Task mirrors the task object returned by GET /api/v1/agent-sync/tasks.
// SNMP is only present on synthesized snmp_poll tasks (server-side, one per
// assigned device); it is nil for every other task type.
type Task struct {
	TaskID          int         `json:"task_id"`
	Type            string      `json:"type"`
	IntervalSeconds int         `json:"interval_seconds"`
	Targets         []string    `json:"targets"`
	SNMP            *SNMPParams `json:"snmp,omitempty"`
}

// SNMPParams mirrors the "snmp" block the server attaches to snmp_poll tasks.
// Credentials (community / v3 passphrases) live in memory only — tasks are
// re-fetched on every sync cycle and never persisted to disk. Do not log them.
type SNMPParams struct {
	DeviceID        uint     `json:"device_id"`
	Version         string   `json:"version"` // "1" / "2c" / "3"
	Community       string   `json:"community"`
	Port            int      `json:"port"`
	TimeoutSeconds  int      `json:"timeout_seconds"`
	Retries         int      `json:"retries"`
	InventoryEveryN int      `json:"inventory_every_n"` // every Nth poll carries the full system group
	V3User          string   `json:"v3_user"`           // ── SNMPv3 (USM) ──
	V3AuthProto     string   `json:"v3_auth_proto"`     // MD5/SHA/SHA224/SHA256/SHA384/SHA512
	V3AuthPass      string   `json:"v3_auth_pass"`
	V3PrivProto     string   `json:"v3_priv_proto"` // DES/AES/AES192/AES256/AES192C/AES256C
	V3PrivPass      string   `json:"v3_priv_pass"`
	ExtraOIDs       []string `json:"extra_oids"`         // custom scalar OIDs, fetched on every poll
	CollectIfaces   bool     `json:"collect_interfaces"` // walk ifTable/ifXTable each poll
}

// SNMPInterface is one interface row inside an SNMPResult (raw counters — the
// server converts them to rates using consecutive samples).
type SNMPInterface struct {
	IfIndex     int    `json:"if_index"`
	Name        string `json:"name"`
	Alias       string `json:"alias"`
	IfType      int    `json:"if_type"`
	SpeedMbps   int64  `json:"speed_mbps"`
	AdminStatus int    `json:"admin_status"`
	OperStatus  int    `json:"oper_status"`
	InOctets    uint64 `json:"in_octets"`
	OutOctets   uint64 `json:"out_octets"`
	InErrors    int64  `json:"in_errors"`
	OutErrors   int64  `json:"out_errors"`
}

// Result is what we POST to /api/v1/agent-sync/results.
type Result struct {
	TaskID    int      `json:"task_id"`
	Type      string   `json:"type"`
	Target    string   `json:"target"`
	Success   bool     `json:"success"`
	LatencyMs *float64 `json:"latency_ms,omitempty"`
	Detail    string   `json:"detail,omitempty"`
}

// SNMPOIDValue is one custom-OID reading inside an SNMPResult.
type SNMPOIDValue struct {
	OID     string   `json:"oid"`
	Value   string   `json:"value"`
	Numeric *float64 `json:"numeric,omitempty"`
	Err     string   `json:"error,omitempty"` // no_such_object etc.
}

// SNMPResult is what we POST to /api/v1/agent-sync/snmp-results. Field names
// match the server-side snmpResultIn struct one-to-one.
// CollectedAt (unix seconds) is the poll instant — the server must use it (not
// ingest time) as the time base for counter-rate conversion and series points:
// batched uploads can deliver several polls of one device milliseconds apart.
type SNMPResult struct {
	DeviceID     uint           `json:"device_id"`
	CollectedAt  int64          `json:"collected_at"`
	Success      bool           `json:"success"`
	ErrorKind    string         `json:"error_kind,omitempty"` // unreachable / snmp_timeout / snmp_error / auth_fail
	Error        string         `json:"error,omitempty"`
	LatencyMs    *float64       `json:"latency_ms,omitempty"`
	UptimeTicks  *int64         `json:"uptime_ticks,omitempty"`
	HasInventory bool           `json:"has_inventory"`
	SysName      string         `json:"sys_name,omitempty"`
	SysDescr     string         `json:"sys_descr,omitempty"`
	SysObjectID  string         `json:"sys_object_id,omitempty"`
	SysLocation  string         `json:"sys_location,omitempty"`
	SysContact   string         `json:"sys_contact,omitempty"`
	Values       []SNMPOIDValue `json:"values,omitempty"` // custom-OID readings
	// HasInterfaces distinguishes "walk succeeded with zero rows" (server clears
	// the table) from "walk skipped/failed" (server keeps last known state).
	HasInterfaces bool            `json:"has_interfaces"`
	Interfaces    []SNMPInterface `json:"interfaces,omitempty"`
}

// Dispatch routes a task to its probe implementation.
// sourceIPv4 and sourceIPv6 may each be empty; probes select the correct one
// per target based on address family. Both empty means the OS picks source.
func Dispatch(ctx context.Context, task Task, sourceIPv4, sourceIPv6 string) []Result {
	switch task.Type {
	case "ping", "meshping":
		return runPing(ctx, task, sourceIPv4, sourceIPv6)
	case "tcpping":
		return runTCPPing(ctx, task, sourceIPv4, sourceIPv6)
	case "httpcheck":
		return runHTTPCheck(ctx, task, sourceIPv4, sourceIPv6)
	case "dnscheck":
		return runDNSCheck(ctx, task, sourceIPv4, sourceIPv6)
	case "traceroute":
		return runTraceroute(ctx, task, sourceIPv4, sourceIPv6)
	case "mtr", "meshmtr":
		return runMTR(ctx, task, sourceIPv4, sourceIPv6)
	default:
		return nil
	}
}

// pickSourceIP returns the source IP that matches the address family of host.
// It checks net.ParseIP first (no I/O) and falls back to a DNS lookup for
// hostnames. Returns "" when the family cannot be determined.
func pickSourceIP(host, sourceIPv4, sourceIPv6 string) string {
	if sourceIPv4 == "" && sourceIPv6 == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return sourceIPv4
		}
		return sourceIPv6
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return sourceIPv4
	}
	if ip := net.ParseIP(addrs[0]); ip != nil && ip.To4() == nil {
		return sourceIPv6
	}
	return sourceIPv4
}

// msPtr converts a duration to a *float64 milliseconds pointer for the Result field.
func msPtr(d time.Duration) *float64 {
	v := float64(d) / float64(time.Millisecond)
	return &v
}
