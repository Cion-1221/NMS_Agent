// Package probe implements all server-dispatched probe types with optional
// source-IP binding for precise egress control.
package probe

import (
	"context"
	"net"
	"time"
)

// Task mirrors the task object returned by GET /api/v1/agent-sync/tasks.
type Task struct {
	TaskID          int      `json:"task_id"`
	Type            string   `json:"type"`
	IntervalSeconds int      `json:"interval_seconds"`
	Targets         []string `json:"targets"`
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
