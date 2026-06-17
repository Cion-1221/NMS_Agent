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

// Reporter aggregates probe.Result values and uploads them in batches via the
// mTLS http.Client provided by the cert package.
type Reporter struct {
	client  *http.Client
	syncURL string
	cfg     config.ServerConfig
	queue   chan probe.Result
}

func New(client *http.Client, syncURL string, cfg config.ServerConfig) *Reporter {
	cap := cfg.BatchSize * 10
	if cap < 1000 {
		cap = 1000
	}
	return &Reporter{
		client:  client,
		syncURL: syncURL,
		cfg:     cfg,
		queue:   make(chan probe.Result, cap),
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

// Run consumes the queue, accumulates a buffer, and uploads when either
// BatchSize is reached or FlushInterval elapses. Drains remaining items on
// context cancellation before returning.
func (r *Reporter) Run(ctx context.Context) {
	buf := make([]probe.Result, 0, r.cfg.BatchSize)
	ticker := time.NewTicker(r.cfg.FlushInterval)
	defer ticker.Stop()

	doFlush := func() {
		if len(buf) == 0 {
			return
		}
		r.upload(buf)
		buf = buf[:0]
	}

	for {
		select {
		case result := <-r.queue:
			buf = append(buf, result)
			if len(buf) >= r.cfg.BatchSize {
				doFlush()
			}

		case <-ticker.C:
			doFlush()

		case <-ctx.Done():
			// Drain whatever is still sitting in the channel before exiting.
			for {
				select {
				case result := <-r.queue:
					buf = append(buf, result)
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

	url := strings.TrimRight(r.syncURL, "/") + "/api/v1/agent-sync/results"

	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Error("reporter: build request failed", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		slog.Error("reporter: upload failed", "err", err, "count", len(batch))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("reporter: server non-200", "status", resp.StatusCode, "count", len(batch))
		return
	}

	slog.Debug("reporter: uploaded", "count", len(batch))
}
