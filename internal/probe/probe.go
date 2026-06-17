// Package probe implements all server-dispatched probe types with optional
// source-IP binding for precise egress control.
package probe

import (
	"context"
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

// Dispatch routes a task to its probe implementation. sourceIP may be empty,
// in which case the OS chooses the source address.
func Dispatch(ctx context.Context, task Task, sourceIP string) []Result {
	switch task.Type {
	case "ping", "meshping":
		return runPing(ctx, task, sourceIP)
	case "tcpping":
		return runTCPPing(ctx, task, sourceIP)
	case "httpcheck":
		return runHTTPCheck(ctx, task, sourceIP)
	case "dnscheck":
		return runDNSCheck(ctx, task, sourceIP)
	case "traceroute":
		return runTraceroute(ctx, task, sourceIP)
	case "mtr":
		return runMTR(ctx, task, sourceIP)
	default:
		return nil
	}
}

// msPtr converts a duration to a *float64 milliseconds pointer for the Result field.
func msPtr(d time.Duration) *float64 {
	v := float64(d) / float64(time.Millisecond)
	return &v
}
