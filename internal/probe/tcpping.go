package probe

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

func runTCPPing(ctx context.Context, task Task, sourceIPv4, sourceIPv6 string) []Result {
	results := make([]Result, len(task.Targets))
	var wg sync.WaitGroup
	for i, target := range task.Targets {
		i, target := i, target
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = doTCPPing(ctx, task.TaskID, target, sourceIPv4, sourceIPv6)
		}()
	}
	wg.Wait()
	return results
}

func doTCPPing(ctx context.Context, taskID int, target, sourceIPv4, sourceIPv6 string) Result {
	r := Result{TaskID: taskID, Type: "tcpping", Target: target}

	// Normalise the target into host:port form that net.Dial accepts.
	// net.SplitHostPort correctly handles IPv6 literals in [addr]:port form.
	// A bare address (no port, including raw IPv6 like "2001:db8::1") causes
	// SplitHostPort to fail, so we fall back to port 80 and use JoinHostPort
	// which adds the required brackets for IPv6: "[2001:db8::1]:80".
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "80"
	}
	addr := net.JoinHostPort(host, port)

	// Pick source IP matching the target's address family.
	var localAddr net.Addr
	if src := pickSourceIP(host, sourceIPv4, sourceIPv6); src != "" {
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
