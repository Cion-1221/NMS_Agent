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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Cion-1221/NMS_Agent/internal/cert"
	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/logger"
	"github.com/Cion-1221/NMS_Agent/internal/reporter"
	"github.com/Cion-1221/NMS_Agent/internal/scheduler"
)

// Injected at release build time via -ldflags.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

// versionTransport injects X-Agent-Version into every outbound request so the NMS
// server can record which agent software version is connecting without inspecting the cert.
type versionTransport struct {
	base http.RoundTripper
	ver  string
}

func (t *versionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("X-Agent-Version", t.ver)
	return t.base.RoundTrip(req)
}

// runCertRenewal checks the mTLS certificate expiry once per day and renews it
// automatically when fewer than 30 days remain. Because cert.NewMTLSClient uses
// GetClientCertificate, the renewed cert is picked up on the next TLS handshake
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

	// Wrap transport to inject X-Agent-Version header on all mTLS requests.
	mtlsClient.Transport = &versionTransport{base: mtlsClient.Transport, ver: version}

	// Certificate auto-renewal — checks once per day, renews if < 30 days remain.
	go runCertRenewal(ctx, certDir, cfg.Server.ReportURL, mtlsClient, log)

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

	<-ctx.Done()
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
}
