package probe

import (
	"context"
	"fmt"
	"net"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

func runPing(ctx context.Context, task Task, sourceIPv4, sourceIPv6 string, lim Limiter) []Result {
	return runJobs(ctx, task, lim, nil, func(ctx context.Context, target string, fp famProbe) Result {
		return doPing(ctx, task.TaskID, task.Type, target, fp, sourceIPv4, sourceIPv6)
	})
}

func doPing(ctx context.Context, taskID int, taskType, target string, fp famProbe, sourceIPv4, sourceIPv6 string) Result {
	r := Result{TaskID: taskID, Type: taskType, Target: target + fp.label}

	// Resolve via context-aware resolver (5 s bound) instead of pinger.Resolve()
	// so unresponsive system DNS cannot block shutdown or starve limiter slots.
	ipStr, err := resolveTargetIP(ctx, target, fp.family)
	if err != nil {
		r.Detail = fmt.Sprintf("resolve: %v", err)
		return r
	}

	pinger := probing.New(ipStr)
	if net.ParseIP(ipStr).To4() != nil {
		pinger.SetNetwork("ip4")
		if sourceIPv4 != "" {
			pinger.Source = sourceIPv4
		}
	} else {
		pinger.SetNetwork("ip6")
		if sourceIPv6 != "" {
			pinger.Source = sourceIPv6
		}
	}
	if err := pinger.Resolve(); err != nil {
		r.Detail = fmt.Sprintf("resolve: %v", err)
		return r
	}

	pinger.SetPrivileged(true) // requires root / CAP_NET_RAW
	pinger.Count = 3
	pinger.Interval = time.Second
	pinger.Timeout = 5 * time.Second

	if err := pinger.RunWithContext(ctx); err != nil {
		r.Detail = err.Error()
		return r
	}

	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		r.Detail = "100% packet loss"
		return r
	}

	r.Success = true
	r.LatencyMs = msPtr(stats.AvgRtt)
	return r
}
