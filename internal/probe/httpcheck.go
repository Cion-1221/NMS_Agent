package probe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func runHTTPCheck(ctx context.Context, task Task, sourceIPv4, sourceIPv6 string) []Result {
	results := make([]Result, len(task.Targets))
	var wg sync.WaitGroup
	for i, target := range task.Targets {
		i, target := i, target
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = doHTTPCheck(ctx, task.TaskID, target, sourceIPv4, sourceIPv6)
		}()
	}
	wg.Wait()
	return results
}

func doHTTPCheck(ctx context.Context, taskID int, target, sourceIPv4, sourceIPv6 string) Result {
	r := Result{TaskID: taskID, Type: "httpcheck", Target: target}

	rawURL := target
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		r.Detail = fmt.Sprintf("parse url: %v", err)
		return r
	}

	// Pick source IP matching the address family of the URL host.
	var localAddr net.Addr
	if src := pickSourceIP(parsedURL.Hostname(), sourceIPv4, sourceIPv6); src != "" {
		localAddr = &net.TCPAddr{IP: net.ParseIP(src)}
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
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
