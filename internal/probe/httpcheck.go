package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func runHTTPCheck(ctx context.Context, task Task, sourceIPv4, sourceIPv6 string) []Result {
	type job struct {
		target string
		fp     famProbe
	}
	var jobs []job
	for _, target := range task.Targets {
		for _, fp := range famProbesFor(task.AddressFamily, httpTargetHost(target)) {
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
			results[i] = doHTTPCheck(ctx, task.TaskID, j.target, j.fp, sourceIPv4, sourceIPv6, task.SkipTLSVerify)
		}()
	}
	wg.Wait()
	return results
}

// httpTargetHost extracts the hostname a target will connect to (tolerating a
// missing scheme and host:port forms). Used only for address-family expansion.
func httpTargetHost(target string) string {
	raw := target
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "http://" + raw
	}
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return target
}

func doHTTPCheck(ctx context.Context, taskID int, target string, fp famProbe, sourceIPv4, sourceIPv6 string, skipTLSVerify bool) Result {
	r := Result{TaskID: taskID, Type: "httpcheck", Target: target + fp.label}

	rawURL := target
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		// No explicit scheme: guess from the port so a bare "host:443" target
		// (the common case) doesn't get sent as plaintext HTTP to a TLS-only
		// listener and fail with a misleading "EOF". Callers who need something
		// else (e.g. plain HTTP on 443) can always prefix http:// explicitly.
		scheme := "http"
		if _, port, err := net.SplitHostPort(target); err == nil && (port == "443" || port == "8443") {
			scheme = "https"
		}
		rawURL = scheme + "://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		r.Detail = fmt.Sprintf("parse url: %v", err)
		return r
	}

	// Pick source IP: forced family wins; otherwise detect from the URL host.
	var localAddr net.Addr
	src := sourceIPForFamily(fp.family, sourceIPv4, sourceIPv6)
	if src == "" && fp.family == "" {
		src = pickSourceIP(parsedURL.Hostname(), sourceIPv4, sourceIPv6)
	}
	if src != "" {
		localAddr = &net.TCPAddr{IP: net.ParseIP(src)}
	}

	dialer := &net.Dialer{
		LocalAddr: localAddr,
		Timeout:   10 * time.Second,
	}

	// The URL keeps the domain (Host header + TLS SNI stay correct); the
	// address family is forced at dial time via tcp4/tcp6 instead.
	dialNetwork := "tcp"
	switch fp.family {
	case "ip4":
		dialNetwork = "tcp4"
	case "ip6":
		dialNetwork = "tcp6"
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, dialNetwork, addr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLSVerify}, //nolint:gosec // opt-in per task, for bare-IP/self-signed targets
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
