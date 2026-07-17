package probe

import (
	"context"
	"fmt"
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

	pinger := probing.New(target)
	// Restrict domain resolution to the forced family ("ip4"/"ip6"); the
	// default network "ip" follows system preference (historical behavior).
	if fp.family != "" {
		pinger.SetNetwork(fp.family)
	}

	if err := pinger.Resolve(); err != nil {
		r.Detail = fmt.Sprintf("resolve: %v", err)
		return r
	}

	// Pick source IP after resolve so we know the actual address family.
	// Binding an IPv4 source to an IPv6 target (or vice versa) would fail.
	if pinger.IPAddr().IP.To4() != nil {
		if sourceIPv4 != "" {
			pinger.Source = sourceIPv4
		}
	} else {
		if sourceIPv6 != "" {
			pinger.Source = sourceIPv6
		}
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
