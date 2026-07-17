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
//
// Failed uploads are retried with exponential backoff instead of dropped: the
// batch stays buffered (bounded; oldest entries evicted past the cap) until
// the server accepts it or rejects it as unprocessable (4xx).
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

// pendingBatch accumulates one endpoint's results and retries failed uploads
// with exponential backoff instead of dropping the batch. Growth is capped:
// past max the oldest entries are evicted (newest data wins during an outage).
type pendingBatch[T any] struct {
	kind       string // for log lines: "probe" / "snmp"
	max        int
	buf        []T
	retryDelay time.Duration // 0 = last upload succeeded
	retryAt    time.Time     // uploads suppressed until this instant after a failure
}

func (p *pendingBatch[T]) add(v T) {
	p.buf = append(p.buf, v)
	if drop := len(p.buf) - p.max; drop > 0 {
		p.buf = p.buf[drop:]
		slog.Warn("reporter: retry buffer full — dropping oldest results",
			"kind", p.kind, "dropped", drop)
	}
}

// flush attempts an upload unless the buffer is empty or a backoff window is
// active. force ignores the backoff — used for the final drain before exit.
func (p *pendingBatch[T]) flush(force bool, upload func([]T) bool) {
	if len(p.buf) == 0 || (!force && time.Now().Before(p.retryAt)) {
		return
	}
	if upload(p.buf) {
		p.buf = p.buf[:0]
		p.retryDelay = 0
		p.retryAt = time.Time{}
		return
	}
	if p.retryDelay == 0 {
		p.retryDelay = 5 * time.Second
	} else {
		p.retryDelay *= 2
		if p.retryDelay > 2*time.Minute {
			p.retryDelay = 2 * time.Minute
		}
	}
	p.retryAt = time.Now().Add(p.retryDelay)
}

// Run consumes both queues, accumulates per-endpoint buffers, and uploads when
// either BatchSize is reached or FlushInterval elapses. Failed batches stay
// buffered and are retried with backoff. Drains remaining items on context
// cancellation before returning.
func (r *Reporter) Run(ctx context.Context) {
	maxBuf := r.cfg.BatchSize * 10
	if maxBuf < 1000 {
		maxBuf = 1000
	}
	results := &pendingBatch[probe.Result]{kind: "probe", max: maxBuf}
	snmp := &pendingBatch[probe.SNMPResult]{kind: "snmp", max: maxBuf}
	ticker := time.NewTicker(r.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case res := <-r.queue:
			results.add(res)
			if len(results.buf) >= r.cfg.BatchSize {
				results.flush(false, r.upload)
			}

		case res := <-r.snmpQueue:
			snmp.add(res)
			if len(snmp.buf) >= r.cfg.BatchSize {
				snmp.flush(false, r.uploadSNMP)
			}

		case <-ticker.C:
			results.flush(false, r.upload)
			snmp.flush(false, r.uploadSNMP)

		case <-ctx.Done():
			// Drain whatever is still sitting in the channels, then make one
			// last upload attempt regardless of any backoff window.
			for {
				select {
				case res := <-r.queue:
					results.add(res)
				case res := <-r.snmpQueue:
					snmp.add(res)
				default:
					results.flush(true, r.upload)
					snmp.flush(true, r.uploadSNMP)
					return
				}
			}
		}
	}
}

// upload ships one probe-result batch; it reports whether the batch is done
// with (accepted, or unprocessable and not worth retrying).
func (r *Reporter) upload(batch []probe.Result) bool {
	body, err := json.Marshal(reportPayload{Results: batch})
	if err != nil {
		slog.Error("reporter: marshal failed — dropping batch", "err", err)
		return true // a batch that cannot marshal will never succeed
	}
	return r.post("/api/v1/agent-sync/results", body, len(batch))
}

func (r *Reporter) uploadSNMP(batch []probe.SNMPResult) bool {
	body, err := json.Marshal(snmpReportPayload{Results: batch})
	if err != nil {
		slog.Error("reporter: snmp marshal failed — dropping batch", "err", err)
		return true
	}
	return r.post("/api/v1/agent-sync/snmp-results", body, len(batch))
}

// post ships one JSON batch to the given sync endpoint (shared by both paths).
// It returns true when the caller should discard the batch: accepted (200) or
// permanently rejected (other 4xx). Network errors, 5xx and 429 return false
// so the batch is kept and retried with backoff.
func (r *Reporter) post(path string, body []byte, count int) bool {
	url := strings.TrimRight(r.syncURL, "/") + path

	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Error("reporter: build request failed — dropping batch", "err", err, "path", path)
		return true // malformed URL never recovers by retrying
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		slog.Error("reporter: upload failed — will retry", "err", err, "path", path, "count", count)
		return false
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
		slog.Debug("reporter: uploaded", "path", path, "count", count)
		return true
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		slog.Warn("reporter: server error — will retry",
			"status", resp.StatusCode, "path", path, "count", count)
		return false
	default:
		// Remaining 4xx: the server rejected this payload; identical retries
		// cannot succeed, so drop it rather than wedge the buffer.
		slog.Warn("reporter: server rejected batch — dropping",
			"status", resp.StatusCode, "path", path, "count", count)
		return true
	}
}
