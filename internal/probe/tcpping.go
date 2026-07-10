package probe

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

func runTCPPing(ctx context.Context, task Task, sourceIPv4, sourceIPv6 string) []Result {
	type job struct {
		target string // original line, used as the Result.Target base
		host   string
		port   string
		fp     famProbe
	}
	var jobs []job
	for _, target := range task.Targets {
		// Normalise the target into host + port. net.SplitHostPort correctly
		// handles IPv6 literals in [addr]:port form. A bare address (no port,
		// including raw IPv6 like "2001:db8::1") causes SplitHostPort to fail,
		// so we fall back to port 80.
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			host = target
			port = "80"
		}
		for _, fp := range famProbesFor(task.AddressFamily, host) {
			jobs = append(jobs, job{target, host, port, fp})
		}
	}

	results := make([]Result, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		i, j := i, j
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = doTCPPing(ctx, task.TaskID, j.target, j.host, j.port, j.fp, sourceIPv4, sourceIPv6)
		}()
	}
	wg.Wait()
	return results
}

func doTCPPing(ctx context.Context, taskID int, target, host, port string, fp famProbe, sourceIPv4, sourceIPv6 string) Result {
	r := Result{TaskID: taskID, Type: "tcpping", Target: target + fp.label}

	// Resolve the host ourselves (family-restricted for domains) instead of
	// letting the dialer do a second independent lookup — previously the dialed
	// family could differ from the one the source-IP selection guessed at.
	ip, err := resolveTargetIP(ctx, host, fp.family)
	if err != nil {
		r.Detail = fmt.Sprintf("resolve: %v", err)
		return r
	}
	// JoinHostPort adds the required brackets for IPv6: "[2001:db8::1]:80".
	addr := net.JoinHostPort(ip, port)

	// Pick source IP matching the resolved address's family.
	var localAddr net.Addr
	if src := sourceIPForIP(ip, sourceIPv4, sourceIPv6); src != "" {
		localAddr = &net.TCPAddr{IP: net.ParseIP(src)}
	}

	dialer := &net.Dialer{
		LocalAddr: localAddr,
		Timeout:   5 * time.Second,
	}

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		r.Detail = fmt.Sprintf("dial: %v", err)
		return r
	}
	conn.Close()

	r.Success = true
	r.LatencyMs = msPtr(time.Since(start))
	return r
}
