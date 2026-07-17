package probe

import (
	"context"
	"fmt"
	"net"
	"time"
)

func runTCPPing(ctx context.Context, task Task, sourceIPv4, sourceIPv6 string, lim Limiter) []Result {
	return runJobs(ctx, task, lim, tcpTargetHost, func(ctx context.Context, target string, fp famProbe) Result {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			host, port = target, "80"
		}
		return doTCPPing(ctx, task.TaskID, target, host, port, fp, sourceIPv4, sourceIPv6)
	})
}

// tcpTargetHost extracts the host part of a target for address-family
// expansion. net.SplitHostPort correctly handles IPv6 literals in [addr]:port
// form; a bare address (no port, including raw IPv6 like "2001:db8::1") fails
// the split and is treated as the host itself (port defaults to 80 at dial).
func tcpTargetHost(target string) string {
	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}
	return target
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
