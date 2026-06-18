// Package scheduler pulls task definitions from the NMS server and manages
// per-task probe goroutines, reconciling additions and removals on each poll.
package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/probe"
	"github.com/Cion-1221/NMS_Agent/internal/reporter"
)

// taskResponse mirrors the JSON returned by GET /api/v1/agent-sync/tasks.
type taskResponse struct {
	AgentID    string       `json:"agent_id"`
	SourceIP   string       `json:"source_ip"`   // legacy combined field; not used for binding
	SourceIPv4 string       `json:"source_ipv4"` // IPv4 source address for v4-target probes
	SourceIPv6 string       `json:"source_ipv6"` // IPv6 source address for v6-target probes
	Tasks      []probe.Task `json:"tasks"`
}

// taskRunner tracks a running per-task goroutine so it can be cancelled
// when the server removes the task from the list.
type taskRunner struct {
	task   probe.Task
	cancel context.CancelFunc
}

// Scheduler fetches tasks via mTLS, keeps them reconciled, and dispatches
// probes with a shared concurrency semaphore.
type Scheduler struct {
	client   *http.Client
	syncURL  string
	reporter *reporter.Reporter
	cfg      config.ServerConfig
	sem      chan struct{}

	mu         sync.RWMutex
	sourceIPv4 string // last source_ipv4 from server; read by probe goroutines
	sourceIPv6 string // last source_ipv6 from server; read by probe goroutines
}

func New(client *http.Client, syncURL string, rep *reporter.Reporter, cfg config.ServerConfig, maxConcurrency int) *Scheduler {
	if maxConcurrency <= 0 {
		maxConcurrency = 20
	}
	return &Scheduler{
		client:   client,
		syncURL:  syncURL,
		reporter: rep,
		cfg:      cfg,
		sem:      make(chan struct{}, maxConcurrency),
	}
}

// Run polls the server for tasks on each TaskPollInterval tick and reconciles
// the set of running probe goroutines. Blocks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	runners := make(map[int]*taskRunner)
	defer func() {
		for _, r := range runners {
			r.cancel()
		}
	}()

	// Fetch immediately on startup so the agent starts probing right away.
	s.reconcile(ctx, runners)

	ticker := time.NewTicker(s.cfg.TaskPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcile(ctx, runners)
		}
	}
}

// reconcile fetches the current task list from the server and starts/stops
// probe goroutines to match. If either source IP changes all runners are
// cancelled and restarted so their sockets bind to the new interface immediately.
func (s *Scheduler) reconcile(ctx context.Context, runners map[int]*taskRunner) {
	tasks, sourceIPv4, sourceIPv6, err := s.fetchTasks(ctx)
	if err != nil {
		slog.Error("scheduler: task fetch failed", "err", err)
		return
	}

	s.mu.Lock()
	prevIPv4 := s.sourceIPv4
	prevIPv6 := s.sourceIPv6
	s.sourceIPv4 = sourceIPv4
	s.sourceIPv6 = sourceIPv6
	s.mu.Unlock()

	if prevIPv4 != sourceIPv4 || prevIPv6 != sourceIPv6 {
		slog.Info("scheduler: source_ip changed — restarting all probe goroutines",
			"old_ipv4", prevIPv4, "new_ipv4", sourceIPv4,
			"old_ipv6", prevIPv6, "new_ipv6", sourceIPv6)
		for id, r := range runners {
			r.cancel()
			delete(runners, id)
		}
	}

	wanted := make(map[int]probe.Task, len(tasks))
	for _, t := range tasks {
		wanted[t.TaskID] = t
	}

	// Cancel goroutines for tasks that the server no longer returns.
	for id, r := range runners {
		if _, ok := wanted[id]; !ok {
			r.cancel()
			delete(runners, id)
			slog.Info("scheduler: task removed", "task_id", id)
		}
	}

	// Start goroutines for new tasks; restart if targets or interval changed.
	// Targets are captured at goroutine launch and the ticker is fixed, so any
	// server-side update to a task requires cancelling and recreating the runner.
	for _, t := range tasks {
		if existing, exists := runners[t.TaskID]; exists && taskChanged(existing.task, t) {
			existing.cancel()
			delete(runners, t.TaskID)
			slog.Info("scheduler: task config changed — restarting",
				"task_id", t.TaskID, "type", t.Type,
				"old_targets", len(existing.task.Targets),
				"new_targets", len(t.Targets))
		}
		if _, exists := runners[t.TaskID]; !exists {
			taskCtx, cancel := context.WithCancel(ctx)
			runners[t.TaskID] = &taskRunner{task: t, cancel: cancel}
			go s.runTask(taskCtx, t)
			slog.Info("scheduler: task started",
				"task_id", t.TaskID, "type", t.Type, "interval_s", t.IntervalSeconds)
		}
	}

	slog.Debug("scheduler: reconciled",
		"running_tasks", len(runners), "source_ipv4", sourceIPv4, "source_ipv6", sourceIPv6)
}

// taskChanged reports whether the server updated a task's probe parameters.
// Targets are passed by value into runTask at launch time, and the interval
// ticker is fixed — either change requires cancelling and recreating the goroutine.
func taskChanged(old, cur probe.Task) bool {
	if old.IntervalSeconds != cur.IntervalSeconds || old.Type != cur.Type {
		return true
	}
	if len(old.Targets) != len(cur.Targets) {
		return true
	}
	for i := range old.Targets {
		if old.Targets[i] != cur.Targets[i] {
			return true
		}
	}
	return false
}

func (s *Scheduler) fetchTasks(ctx context.Context) ([]probe.Task, string, string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()

	url := strings.TrimRight(s.syncURL, "/") + "/api/v1/agent-sync/tasks"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", "", err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", "", fmt.Errorf("GET /tasks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", "", fmt.Errorf("GET /tasks: HTTP %d", resp.StatusCode)
	}

	var tr taskResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, "", "", fmt.Errorf("decode task response: %w", err)
	}
	return tr.Tasks, tr.SourceIPv4, tr.SourceIPv6, nil
}

// runTask ticks at the task's configured interval and calls execute on each tick.
// The task runs once immediately on startup so results arrive before the first
// interval elapses.
func (s *Scheduler) runTask(ctx context.Context, task probe.Task) {
	interval := time.Duration(task.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}

	s.execute(ctx, task) // run immediately

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.execute(ctx, task)
		}
	}
}

// execute acquires a slot from the concurrency semaphore, reads the current
// source IPs, runs the probe, and feeds results to the reporter.
func (s *Scheduler) execute(ctx context.Context, task probe.Task) {
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-s.sem }()

	s.mu.RLock()
	sourceIPv4 := s.sourceIPv4
	sourceIPv6 := s.sourceIPv6
	s.mu.RUnlock()

	results := probe.Dispatch(ctx, task, sourceIPv4, sourceIPv6)
	for _, r := range results {
		s.reporter.Enqueue(r)
	}
}
