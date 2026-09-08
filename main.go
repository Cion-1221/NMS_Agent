// Command nms-agent is a lightweight edge-node agent that:
//  1. Enrolls with the NMS server on first boot using a provisioning token to
//     obtain mTLS credentials.
//  2. Polls the server for probe tasks and executes them (ping, tcpping,
//     httpcheck, dnscheck, traceroute, mtr) with optional source-IP binding.
//  3. Batches results and uploads them to the server over the mTLS sync channel.
//
// Usage:
//
//	nms-agent [-config /path/to/config.yaml]
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Cion-1221/NMS_Agent/internal/cert"
	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/logger"
	"github.com/Cion-1221/NMS_Agent/internal/reporter"
	"github.com/Cion-1221/NMS_Agent/internal/scheduler"
	"github.com/Cion-1221/NMS_Agent/internal/updater"
)

// Injected at release build time via -ldflags.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

// versionTransport injects X-Agent-Version and the agent's public IPs into
// every outbound mTLS request. Public IPs are discovered via the server's
// /my-ip reflection endpoint: once synchronously at startup (before the first
// task poll, see main) and then every 24 h by runIPRefresh.
type versionTransport struct {
	base http.RoundTripper
	ver  string
	os   string // runtime.GOOS  — e.g. "linux", "windows", "darwin"
	arch string // runtime.GOARCH — e.g. "amd64", "arm64"

	ipMu       sync.RWMutex
	publicIPv4 string
	publicIPv6 string
	// discovered is set by the startup discovery. From then on every request also
	// carries X-Agent-Stack, declaring exactly which address families the agent
	// could use to reach the server. The server treats that as authoritative and
	// drops a family that is no longer listed (e.g. IPv6 removed from the node),
	// instead of keeping the last known address forever — so a restart is all it
	// takes to leave the IPv6 mesh. Without the header the server only ever adds.
	discovered bool
}

// setStack stores the authoritative startup discovery: both values are
// overwritten (an empty one means "this family is gone") and the stack
// declaration is switched on.
func (t *versionTransport) setStack(ipv4, ipv6 string) {
	t.ipMu.Lock()
	defer t.ipMu.Unlock()
	t.publicIPv4, t.publicIPv6 = ipv4, ipv6
	t.discovered = true
}

// setIPs merges a periodic refresh. A non-empty value overwrites the cached
// one; empty values are ignored so a temporary failure on one family does not
// clear a previously discovered address. Families only ever disappear through
// setStack, i.e. on restart — a 24 h refresh hiccup must not silently switch
// the mesh off for that family.
func (t *versionTransport) setIPs(ipv4, ipv6 string) {
	t.ipMu.Lock()
	defer t.ipMu.Unlock()
	if ipv4 != "" {
		t.publicIPv4 = ipv4
	}
	if ipv6 != "" {
		t.publicIPv6 = ipv6
	}
}

func (t *versionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("X-Agent-Version", t.ver)
	req.Header.Set("X-Agent-OS", t.os)
	req.Header.Set("X-Agent-Arch", t.arch)
	t.ipMu.RLock()
	ipv4, ipv6, discovered := t.publicIPv4, t.publicIPv6, t.discovered
	t.ipMu.RUnlock()
	if ipv4 != "" {
		req.Header.Set("X-Agent-IPv4", ipv4)
	}
	if ipv6 != "" {
		req.Header.Set("X-Agent-IPv6", ipv6)
	}
	if discovered {
		stack := make([]string, 0, 2)
		if ipv4 != "" {
			stack = append(stack, "v4")
		}
		if ipv6 != "" {
			stack = append(stack, "v6")
		}
		if len(stack) > 0 {
			req.Header.Set("X-Agent-Stack", strings.Join(stack, ","))
		}
	}
	return t.base.RoundTrip(req)
}

// discoverPublicIPs queries the server's /my-ip endpoint over forced IPv4 and
// IPv6 connections and returns the agent's public addresses as seen by the
// server ("" for a family that could not reach it). This correctly handles
// cloud NAT (GCP/AWS) where the local interface IP differs from the public IP.
// Bounded by two 10 s timeouts.
func discoverPublicIPs(ctx context.Context, certDir, reportURL string) (ipv4, ipv6 string) {
	myIPURL := strings.TrimRight(reportURL, "/") + "/api/v1/agent-sync/my-ip"
	for _, pair := range []struct {
		network string
		out     *string
	}{
		{"tcp4", &ipv4},
		{"tcp6", &ipv6},
	} {
		c, err := cert.NewMTLSClientForFamily(certDir, 10*time.Second, pair.network)
		if err != nil {
			continue
		}
		reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, myIPURL, nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := c.Do(req)
		cancel()
		if err != nil {
			slog.Debug("ip discovery: request failed", "network", pair.network, "err", err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			if ip := strings.TrimSpace(string(body)); net.ParseIP(ip) != nil {
				*pair.out = ip
			}
		}
	}
	return ipv4, ipv6
}

// runIPRefresh re-runs the public IP discovery every 24 h and merges the result
// (see setIPs). The startup run is done synchronously in main before the
// scheduler starts, so this loop only handles the periodic refreshes.
func runIPRefresh(ctx context.Context, certDir, reportURL string, vt *versionTransport) {
	const interval = 24 * time.Hour
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if ipv4, ipv6 := discoverPublicIPs(ctx, certDir, reportURL); ipv4 != "" || ipv6 != "" {
				vt.setIPs(ipv4, ipv6)
				slog.Info("ip refresh: public IPs updated", "ipv4", ipv4, "ipv6", ipv6)
			}
		}
	}
}

// runCertRenewal checks the mTLS certificate expiry once per day and renews it
// automatically when fewer than 30 days remain. Because cert.NewMTLSClient
// dials via DialTLSContext (re-reading the cert files from disk on every new
// TLS connection), the renewed cert is picked up on the next connection
// without an agent restart.
func runCertRenewal(ctx context.Context, certDir, syncURL string, client *http.Client, log *slog.Logger) {
	const (
		renewThreshold = 30 * 24 * time.Hour
		checkInterval  = 24 * time.Hour
	)

	check := func() {
		expiry, err := cert.CertExpiry(certDir)
		if err != nil {
			log.Error("cert expiry check failed", "err", err)
			return
		}
		remaining := time.Until(expiry)
		log.Debug("cert expiry status",
			"expiry", expiry.Format(time.RFC3339),
			"remaining_days", int(remaining.Hours()/24))
		if remaining > renewThreshold {
			return
		}
		log.Warn("cert nearing expiry — renewing",
			"expiry", expiry.Format(time.RFC3339),
			"remaining_days", int(remaining.Hours()/24))
		if err := cert.Renew(client, syncURL, certDir); err != nil {
			log.Error("cert renewal failed", "err", err)
			return
		}
		log.Info("cert renewed successfully")
	}

	check() // check immediately on startup
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

func main() {
	cfgPath := flag.String("config", "configs/config.yaml", "path to config.yaml")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Printf("nms-agent %s (commit %s, built %s)\n", version, commit, buildDate)
		return
	}

	// Ignore SIGHUP so the agent survives SSH session disconnects and terminal
	// detaches. Graceful shutdown is handled by SIGINT and SIGTERM only.
	signal.Ignore(syscall.SIGHUP)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("config load failed", "err", err, "path", *cfgPath)
		os.Exit(1)
	}

	log, startRotation, closeLog := logger.New(cfg.Runtime.Log)
	defer closeLog()

	log.Info("nms-agent starting",
		"version", version, "commit", commit, "build_date", buildDate,
		"region", cfg.Agent.Region)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start daily log-file rotation now that we have a cancellable context.
	startRotation(ctx)

	// ── Certificate / enrollment workflow ──────────────────────────────────────
	certDir := cfg.Certs.Dir

	if !cert.HasCerts(certDir) {
		if cfg.Server.ProvisioningToken == "" {
			log.Error("no certificates found and server.provisioning_token is empty — cannot enroll")
			os.Exit(1)
		}
		hostname := cfg.Agent.HostnameOverride
		if hostname == "" {
			hostname, _ = os.Hostname()
		}
		log.Info("enrolling with NMS server",
			"enroll_url", cfg.Server.EnrollURL, "hostname", hostname)

		agentID, enrollErr := cert.Enroll(
			cfg.Server.EnrollURL,
			cfg.Server.ProvisioningToken,
			hostname,
			certDir,
			cfg.Server.InsecureEnroll,
		)
		if enrollErr != nil {
			log.Error("enrollment failed", "err", enrollErr)
			os.Exit(1)
		}
		log.Info("enrollment successful — certificates saved", "agent_id", agentID, "cert_dir", certDir)
	} else {
		agentID, idErr := cert.LoadAgentID(certDir)
		if idErr != nil {
			log.Error("failed to read agent ID from cert dir", "err", idErr, "dir", certDir)
			os.Exit(1)
		}
		log.Info("using existing certificates", "agent_id", agentID, "cert_dir", certDir)
	}

	// ── mTLS client ────────────────────────────────────────────────────────────
	mtlsClient, err := cert.NewMTLSClient(certDir, cfg.Server.RequestTimeout)
	if err != nil {
		log.Error("failed to initialise mTLS client", "err", err)
		os.Exit(1)
	}

	// Wrap transport to inject X-Agent-Version and public IP headers on all mTLS requests.
	vt := &versionTransport{
		base: mtlsClient.Transport,
		ver:  version,
		os:   runtime.GOOS,
		arch: runtime.GOARCH,
	}
	mtlsClient.Transport = vt

	// Certificate auto-renewal — checks once per day, renews if < 30 days remain.
	go runCertRenewal(ctx, certDir, cfg.Server.ReportURL, mtlsClient, log)

	// Public IP discovery — queries /my-ip via forced IPv4 and IPv6 connections so
	// the server sees both addresses even behind cloud NAT. The startup run is
	// synchronous, before the scheduler starts: the very first task poll must
	// already carry X-Agent-IPv4/IPv6/Stack, because the server derives mesh
	// targets from the families this agent can actually use — a poll without them
	// would get a single-family (or stale dual-stack) target list until the next
	// cycle. Bounded by two 10 s timeouts; an unreachable server just leaves the
	// headers empty and the server falls back to the TCP source address.
	if ipv4, ipv6 := discoverPublicIPs(ctx, certDir, cfg.Server.ReportURL); ipv4 != "" || ipv6 != "" {
		vt.setStack(ipv4, ipv6)
		log.Info("public IP discovery complete", "ipv4", ipv4, "ipv6", ipv6)
	} else {
		log.Warn("public IP discovery failed on both families — server will use the TCP source address")
	}
	go runIPRefresh(ctx, certDir, cfg.Server.ReportURL, vt)

	// ── Reporter & Scheduler ───────────────────────────────────────────────────
	rep := reporter.New(mtlsClient, cfg.Server.ReportURL, cfg.Server)
	sched := scheduler.New(mtlsClient, cfg.Server.ReportURL, rep, cfg.Server, cfg.Runtime.MaxConcurrency)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		rep.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		sched.Run(ctx)
	}()

	// Wait for a shutdown signal (SIGINT/SIGTERM) or an update directive from
	// the server. Both paths go through the same graceful shutdown sequence.
	var pendingUpdate *updater.Update
	select {
	case upd := <-sched.UpdateCh():
		log.Info("update available — starting graceful shutdown", "version", upd.Version)
		pendingUpdate = &upd
		stop() // cancel context so scheduler and reporter goroutines exit
	case <-ctx.Done():
	}

	log.Info("shutdown signal received", "grace_period", cfg.Runtime.GracePeriod)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info("shutdown complete")
	case <-time.After(cfg.Runtime.GracePeriod):
		log.Warn("grace period exceeded — forcing exit")
		os.Exit(1)
	}

	if pendingUpdate != nil {
		log.Info("applying update", "version", pendingUpdate.Version,
			"binary_id", pendingUpdate.BinaryID, "size", pendingUpdate.FileSize)
		if err := updater.Apply(mtlsClient, cfg.Server.ReportURL, *pendingUpdate); err != nil {
			log.Error("update failed — exiting for service manager restart", "err", err)
			os.Exit(1)
		}
		// Apply calls syscall.Exec (Linux) or os.Exit (Windows); unreachable.
	}
}
