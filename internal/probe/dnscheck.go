package probe

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

func runDNSCheck(ctx context.Context, task Task, sourceIPv4, sourceIPv6 string) []Result {
	type job struct {
		target string
		fp     famProbe
	}
	var jobs []job
	for _, target := range task.Targets {
		for _, fp := range famProbesFor(task.AddressFamily, target) {
			jobs = append(jobs, job{target, fp})
		}
	}

	results := make([]Result, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		i, j := i, j
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = doDNSCheck(ctx, task.TaskID, j.target, j.fp, sourceIPv4, sourceIPv6)
		}()
	}
	wg.Wait()
	return results
}

func doDNSCheck(ctx context.Context, taskID int, target string, fp famProbe, sourceIPv4, sourceIPv6 string) Result {
	r := Result{TaskID: taskID, Type: "dnscheck", Target: target + fp.label}

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

	// Family selection maps directly onto the queried record type:
	// "ip" = A+AAAA merged (historical behavior), "ip4" = A only, "ip6" = AAAA only.
	network := "ip"
	if fp.family != "" {
		network = fp.family
	}

	start := time.Now()
	ips, err := resolver.LookupIP(ctx, network, target)
	if err != nil {
		r.Detail = fmt.Sprintf("lookup: %v", err)
		return r
	}

	r.LatencyMs = msPtr(time.Since(start))
	r.Success = len(ips) > 0
	if len(ips) > 0 {
		r.Detail = fmt.Sprintf("resolved %s", ips[0])
	}
	return r
}
