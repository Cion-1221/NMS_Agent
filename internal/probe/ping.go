package probe

import (
	"context"
	"fmt"
	"sync"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

func runPing(ctx context.Context, task Task, sourceIP string) []Result {
	results := make([]Result, len(task.Targets))
	var wg sync.WaitGroup
	for i, target := range task.Targets {
		i, target := i, target
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = doPing(ctx, task.TaskID, task.Type, target, sourceIP)
		}()
	}
	wg.Wait()
	return results
}

func doPing(ctx context.Context, taskID int, taskType, target, sourceIP string) Result {
	r := Result{TaskID: taskID, Type: taskType, Target: target}

	pinger := probing.New(target)

	// Source IP binding: forces ICMP packets to originate from the specified address,
	// enabling egress path control when the agent host has multiple interfaces.
	if sourceIP != "" {
		pinger.Source = sourceIP
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
