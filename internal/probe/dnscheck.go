package probe

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

func runDNSCheck(ctx context.Context, task Task, sourceIPv4, sourceIPv6 string) []Result {
	results := make([]Result, len(task.Targets))
	var wg sync.WaitGroup
	for i, target := range task.Targets {
		i, target := i, target
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = doDNSCheck(ctx, task.TaskID, target, sourceIPv4, sourceIPv6)
		}()
	}
	wg.Wait()
	return results
}

func doDNSCheck(ctx context.Context, taskID int, target, sourceIPv4, sourceIPv6 string) Result {
	r := Result{TaskID: taskID, Type: "dnscheck", Target: target}

	// Source IP binding: pick source matching the DNS server's address family.
	// The Dial callback receives the resolver's address (e.g. "8.8.8.8:53"),
	// so we key pickSourceIP on that host rather than the lookup target.
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var localAddr net.Addr
			if sourceIPv4 != "" || sourceIPv6 != "" {
				host, _, _ := net.SplitHostPort(address)
				if src := pickSourceIP(host, sourceIPv4, sourceIPv6); src != "" {
					localAddr = &net.UDPAddr{IP: net.ParseIP(src)}
				}
			}
			d := net.Dialer{
				LocalAddr: localAddr,
				Timeout:   5 * time.Second,
			}
			return d.DialContext(ctx, "udp", address)
		},
	}

	start := time.Now()
	addrs, err := resolver.LookupIPAddr(ctx, target)
	if err != nil {
		r.Detail = fmt.Sprintf("lookup: %v", err)
		return r
	}

	r.LatencyMs = msPtr(time.Since(start))
	r.Success = len(addrs) > 0
	if len(addrs) > 0 {
		r.Detail = fmt.Sprintf("resolved %s", addrs[0].IP)
	}
	return r
}
