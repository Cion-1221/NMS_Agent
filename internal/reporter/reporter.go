// Package reporter 把 Scheduler 产出的 module.Result 攒批后通过 HTTP POST
// 推送回中心 NMS Server。
//
// 攒批策略：队列中的结果累积到 BatchSize 或等待时间达到 FlushInterval，
// 两者任一触发即上报一次，兼顾吞吐与时延。上报失败时按指数退避重试，
// 重试耗尽后丢弃该批次并记录日志（宁可丢一批历史数据，也不能无限占用内存拖垮 Agent 自身）。
package reporter

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
)

type Reporter struct {
	cfg    config.ServerConfig
	logger *slog.Logger
	client *http.Client
	queue  chan []module.Result
}

func New(cfg config.ServerConfig, logger *slog.Logger) *Reporter {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.TLS.InsecureSkipVerify}, //nolint:gosec // 显式由配置项控制，默认 false
	}

	return &Reporter{
		cfg:    cfg,
		logger: logger,
		client: &http.Client{
			Timeout:   cfg.RequestTimeout,
			Transport: transport,
		},
		queue: make(chan []module.Result, cfg.QueueCapacity),
	}
}

// Enqueue 由 Scheduler 在每个模块执行完毕后调用，非阻塞地把一批结果放入上报队列。
// 队列满时丢弃最旧的一批并记录告警日志，避免内存被无限占用。
func (r *Reporter) Enqueue(results []module.Result) {
	select {
	case r.queue <- results:
		return
	default:
	}

	select {
	case <-r.queue:
		r.logger.Warn("report queue full, dropped oldest batch", "capacity", r.cfg.QueueCapacity)
	default:
	}

	select {
	case r.queue <- results:
	default:
		r.logger.Warn("report queue still full after eviction, dropped incoming batch")
	}
}

// Run 阻塞运行直至 ctx 被取消；退出前会把缓冲区中尚未发出的数据尽力 flush 一次。
func (r *Reporter) Run(ctx context.Context) {
	batch := make([]module.Result, 0, r.cfg.BatchSize)
	ticker := time.NewTicker(r.cfg.FlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		r.send(ctx, batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			r.logger.Info("reporter stopped")
			return

		case results := <-r.queue:
			batch = append(batch, results...)
			if len(batch) >= r.cfg.BatchSize {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

func (r *Reporter) send(ctx context.Context, batch []module.Result) {
	body, err := json.Marshal(batch)
	if err != nil {
		r.logger.Error("marshal report batch failed", "error", err, "size", len(batch))
		return
	}

	backoff := r.cfg.Retry.InitialBackoff
	if backoff <= 0 {
		backoff = time.Second
	}

	for attempt := 0; attempt <= r.cfg.Retry.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = time.Duration(float64(backoff) * r.cfg.Retry.BackoffMultiplier)
			if r.cfg.Retry.MaxBackoff > 0 && backoff > r.cfg.Retry.MaxBackoff {
				backoff = r.cfg.Retry.MaxBackoff
			}
		}

		if err := r.post(ctx, body); err != nil {
			r.logger.Warn("report attempt failed", "attempt", attempt+1, "max_attempts", r.cfg.Retry.MaxRetries+1, "error", err)
			continue
		}
		r.logger.Debug("report batch delivered", "size", len(batch), "attempt", attempt+1)
		return
	}

	r.logger.Error("report failed after exhausting retries, batch dropped", "size", len(batch))
}

func (r *Reporter) post(ctx context.Context, body []byte) error {
	reqCtx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, r.cfg.ReportURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if r.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.cfg.AuthToken)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	return nil
}
