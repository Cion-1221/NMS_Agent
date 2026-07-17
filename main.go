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
// every outbound mTLS request. Public IPs are discovered by runIPRefresh via
// the server's /my-ip reflection endpoint and updated here; they start empty
// until the first successful discovery, at which point the server falls back
// to c.ClientIP() for whichever family header is absent.
type versionTransport struct {
	base http.RoundTripper
	ver  string
	os   string // runtime.GOOS  — e.g. "linux", "windows", "darwin"
	arch string // runtime.GOARCH — e.g. "amd64", "arm64"

	ipMu       sync.RWMutex
	publicIPv4 string
	publicIPv6 string
}

// setIPs stores newly discovered public IPs. A non-empty value overwrites the
// cached one; empty values are ignored so a temporary failure on one family
// does not clear a previously discovered address.
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
	ipv4, ipv6 := t.publicIPv4, t.publicIPv6
	t.ipMu.RUnlock()
	if ipv4 != "" {
		req.Header.Set("X-Agent-IPv4", ipv4)
	}
	if ipv6 != "" {
		req.Header.Set("X-Agent-IPv6", ipv6)
	}
	return t.base.RoundTrip(req)
}

// runIPRefresh queries the server's /my-ip endpoint over forced IPv4 and IPv6
// connections to discover the agent's public addresses as seen by the server.
// This correctly handles cloud NAT (GCP/AWS) where the local interface IP
// differs from the public IP. Results are refreshed every 24 h.
func runIPRefresh(ctx context.Context, certDir, reportURL string, vt *versionTransport) {
	const interval = 24 * time.Hour
	myIPURL := strings.TrimRight(reportURL, "/") + "/api/v1/agent-sync/my-ip"

	detect := func() {
		var ipv4, ipv6 string
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
				slog.Debug("ip refresh: request failed", "network", pair.network, "err", err)
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
		if ipv4 != "" || ipv6 != "" {
			vt.setIPs(ipv4, ipv6)
			slog.Info("ip refresh: public IPs updated", "ipv4", ipv4, "ipv6", ipv6)
		}
	}

	detect() // run immediately on startup
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			detect()
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
	// Public IPs start empty; runIPRefresh populates them after the first /my-ip query.
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
	// the server can display both addresses even when the agent is behind cloud NAT.
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
