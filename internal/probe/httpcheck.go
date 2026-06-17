package probe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func runHTTPCheck(ctx context.Context, task Task, sourceIP string) []Result {
	results := make([]Result, len(task.Targets))
	var wg sync.WaitGroup
	for i, target := range task.Targets {
		i, target := i, target
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = doHTTPCheck(ctx, task.TaskID, target, sourceIP)
		}()
	}
	wg.Wait()
	return results
}

func doHTTPCheck(ctx context.Context, taskID int, target, sourceIP string) Result {
	r := Result{TaskID: taskID, Type: "httpcheck", Target: target}

	url := target
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	// Source IP binding via a custom dialer bound to the specified local address.
	var localAddr net.Addr
	if sourceIP != "" {
		localAddr = &net.TCPAddr{IP: net.ParseIP(sourceIP)}
	}

	dialer := &net.Dialer{
		LocalAddr: localAddr,
		Timeout:   10 * time.Second,
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		r.Detail = fmt.Sprintf("build request: %v", err)
		return r
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		r.Detail = fmt.Sprintf("http: %v", err)
		return r
	}
	resp.Body.Close()

	r.LatencyMs = msPtr(time.Since(start))
	r.Success = resp.StatusCode >= 200 && resp.StatusCode < 400
	if !r.Success {
		r.Detail = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return r
}
