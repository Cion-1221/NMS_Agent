package probe

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

func runTCPPing(ctx context.Context, task Task, sourceIP string) []Result {
	results := make([]Result, len(task.Targets))
	var wg sync.WaitGroup
	for i, target := range task.Targets {
		i, target := i, target
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = doTCPPing(ctx, task.TaskID, target, sourceIP)
		}()
	}
	wg.Wait()
	return results
}

func doTCPPing(ctx context.Context, taskID int, target, sourceIP string) Result {
	r := Result{TaskID: taskID, Type: "tcpping", Target: target}

	// Accept both "ip:port" and bare "ip" (defaults to port 80).
	addr := target
	if !strings.Contains(target, ":") {
		addr = target + ":80"
	}

	// Source IP binding: LocalAddr pins the outgoing TCP SYN to a specific interface.
	var localAddr net.Addr
	if sourceIP != "" {
		localAddr = &net.TCPAddr{IP: net.ParseIP(sourceIP)}
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
