// Package reporter batches probe results and POSTs them to the NMS server's
// mTLS sync endpoint.
package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/probe"
)

type reportPayload struct {
	Results []probe.Result `json:"results"`
}

type snmpReportPayload struct {
	Results []probe.SNMPResult `json:"results"`
}

// Reporter aggregates probe.Result values and uploads them in batches via the
// mTLS http.Client provided by the cert package. SNMP conclusions travel on a
// separate queue to a separate endpoint (/snmp-results) — they are state
// snapshots consumed by the server's device status machine, not time-series
// rows, and must not mix into the probe_results ingest path.
type Reporter struct {
	client    *http.Client
	syncURL   string
	cfg       config.ServerConfig
	queue     chan probe.Result
	snmpQueue chan probe.SNMPResult
}

func New(client *http.Client, syncURL string, cfg config.ServerConfig) *Reporter {
	cap := cfg.BatchSize * 10
	if cap < 1000 {
		cap = 1000
	}
	return &Reporter{
		client:    client,
		syncURL:   syncURL,
		cfg:       cfg,
		queue:     make(chan probe.Result, cap),
		snmpQueue: make(chan probe.SNMPResult, cap),
	}
}

// Enqueue delivers a result to the upload queue. If the queue is full the
// result is dropped and a warning is logged (prefer losing one data point over
// blocking the probe goroutine).
func (r *Reporter) Enqueue(result probe.Result) {
	select {
	case r.queue <- result:
	default:
		slog.Warn("reporter: queue full, dropping result",
			"type", result.Type, "target", result.Target)
	}
}

// EnqueueSNMP delivers an SNMP poll conclusion to the upload queue. Dropping
// on overflow is safe: conclusions are state snapshots, the next poll cycle
// supersedes whatever was lost.
func (r *Reporter) EnqueueSNMP(result probe.SNMPResult) {
	select {
	case r.snmpQueue <- result:
	default:
		slog.Warn("reporter: snmp queue full, dropping result", "device_id", result.DeviceID)
	}
}

// Run consumes both queues, accumulates per-endpoint buffers, and uploads when
// either BatchSize is reached or FlushInterval elapses. Drains remaining items
// on context cancellation before returning.
func (r *Reporter) Run(ctx context.Context) {
	buf := make([]probe.Result, 0, r.cfg.BatchSize)
	snmpBuf := make([]probe.SNMPResult, 0, r.cfg.BatchSize)
	ticker := time.NewTicker(r.cfg.FlushInterval)
	defer ticker.Stop()

	doFlush := func() {
		if len(buf) > 0 {
			r.upload(buf)
			buf = buf[:0]
		}
		if len(snmpBuf) > 0 {
			r.uploadSNMP(snmpBuf)
			snmpBuf = snmpBuf[:0]
		}
	}

	for {
		select {
		case result := <-r.queue:
			buf = append(buf, result)
			if len(buf) >= r.cfg.BatchSize {
				doFlush()
			}

		case result := <-r.snmpQueue:
			snmpBuf = append(snmpBuf, result)
			if len(snmpBuf) >= r.cfg.BatchSize {
				doFlush()
			}

		case <-ticker.C:
			doFlush()

		case <-ctx.Done():
			// Drain whatever is still sitting in the channels before exiting.
			for {
				select {
				case result := <-r.queue:
					buf = append(buf, result)
				case result := <-r.snmpQueue:
					snmpBuf = append(snmpBuf, result)
				default:
					doFlush()
					return
				}
			}
		}
	}
}

func (r *Reporter) upload(batch []probe.Result) {
	body, err := json.Marshal(reportPayload{Results: batch})
	if err != nil {
		slog.Error("reporter: marshal failed", "err", err)
		return
	}
	r.post("/api/v1/agent-sync/results", body, len(batch))
}

func (r *Reporter) uploadSNMP(batch []probe.SNMPResult) {
	body, err := json.Marshal(snmpReportPayload{Results: batch})
	if err != nil {
		slog.Error("reporter: snmp marshal failed", "err", err)
		return
	}
	r.post("/api/v1/agent-sync/snmp-results", body, len(batch))
}

// post ships one JSON batch to the given sync endpoint (shared by both paths).
func (r *Reporter) post(path string, body []byte, count int) {
	url := strings.TrimRight(r.syncURL, "/") + path

	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Error("reporter: build request failed", "err", err, "path", path)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		slog.Error("reporter: upload failed", "err", err, "path", path, "count", count)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("reporter: server non-200", "status", resp.StatusCode, "path", path, "count", count)
		return
	}

	slog.Debug("reporter: uploaded", "path", path, "count", count)
}
