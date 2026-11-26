package probe

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

func runDNSCheck(ctx context.Context, task Task, sourceIPv4, sourceIPv6 string, lim Limiter) []Result {
	return runJobs(ctx, task, lim, dnsTargetHost, func(ctx context.Context, target string, fp famProbe) Result {
		return doDNSCheck(ctx, task.TaskID, target, fp, sourceIPv4, sourceIPv6)
	})
}

func dnsTargetHost(target string) string {
	domain, _, _ := strings.Cut(target, "@")
	return domain
}

// parseDNSTarget splits an optional "domain@server" or "domain@server:port"
// specification. When no "@server" suffix is present, customServer is empty and
// Go's resolver queries the system DNS servers.
func parseDNSTarget(raw string) (domain, customServer string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("empty dns target")
	}
	domain, srv, hasAt := strings.Cut(raw, "@")
	if !hasAt {
		return raw, "", nil
	}
	if domain == "" || srv == "" {
		return "", "", fmt.Errorf("invalid dns target %q (expected domain@server[:port])", raw)
	}
	if net.ParseIP(srv) != nil {
		return domain, net.JoinHostPort(srv, "53"), nil
	}
	if h, p, splitErr := net.SplitHostPort(srv); splitErr == nil {
		if h == "" || p == "" {
			return "", "", fmt.Errorf("invalid dns server %q", srv)
		}
		return domain, net.JoinHostPort(h, p), nil
	}
	return domain, net.JoinHostPort(srv, "53"), nil
}

func doDNSCheck(ctx context.Context, taskID int, target string, fp famProbe, sourceIPv4, sourceIPv6 string) Result {
	r := Result{TaskID: taskID, Type: "dnscheck", Target: target + fp.label}

	domain, customServer, err := parseDNSTarget(target)
	if err != nil {
		r.Detail = err.Error()
		return r
	}

	// Source IP binding & protocol fidelity: honour both UDP and TCP (RFC 5966
	// TC=1 truncated-response fallback) with matching net.UDPAddr / net.TCPAddr.
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if customServer != "" {
				address = customServer
			}
			isTCP := strings.HasPrefix(network, "tcp")
			dialNet := "udp"
			if isTCP {
				dialNet = "tcp"
			}

			var localAddr net.Addr
			if sourceIPv4 != "" || sourceIPv6 != "" {
				host, _, _ := net.SplitHostPort(address)
				if src := pickSourceIPContext(ctx, host, sourceIPv4, sourceIPv6); src != "" {
					if isTCP {
						localAddr = &net.TCPAddr{IP: net.ParseIP(src)}
					} else {
						localAddr = &net.UDPAddr{IP: net.ParseIP(src)}
					}
				}
			}
			d := net.Dialer{
				LocalAddr: localAddr,
				Timeout:   5 * time.Second,
			}
			return d.DialContext(ctx, dialNet, address)
		},
	}

	// Family selection maps directly onto the queried record type:
	// "ip" = A+AAAA merged (historical behavior), "ip4" = A only, "ip6" = AAAA only.
	network := "ip"
	if fp.family != "" {
		network = fp.family
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	start := time.Now()
	ips, err := resolver.LookupIP(lookupCtx, network, domain)
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
