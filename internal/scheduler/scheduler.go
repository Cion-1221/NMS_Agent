// Package scheduler pulls task definitions from the NMS server and manages
// per-task probe goroutines, reconciling additions and removals on each poll.
package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/probe"
	"github.com/Cion-1221/NMS_Agent/internal/reporter"
	"github.com/Cion-1221/NMS_Agent/internal/updater"
)

// taskResponse mirrors the JSON returned by GET /api/v1/agent-sync/tasks.
type taskResponse struct {
	AgentID    string          `json:"agent_id"`
	SourceIP   string          `json:"source_ip"`   // legacy combined field; not used for binding
	SourceIPv4 string          `json:"source_ipv4"` // IPv4 source address for v4-target probes
	SourceIPv6 string          `json:"source_ipv6"` // IPv6 source address for v6-target probes
	Tasks      []probe.Task    `json:"tasks"`
	Update     *updater.Update `json:"update"` // non-nil when server wants the agent to upgrade
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
	updateCh chan updater.Update // capacity 1; fires at most once when server requests upgrade

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
		updateCh: make(chan updater.Update, 1),
	}
}

// UpdateCh returns a receive-only channel that fires at most once when the
// server instructs this agent to upgrade to a newer version.
func (s *Scheduler) UpdateCh() <-chan updater.Update {
	return s.updateCh
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
	tasks, sourceIPv4, sourceIPv6, upd, err := s.fetchTasks(ctx)
	if err != nil {
		slog.Error("scheduler: task fetch failed", "err", err)
		return
	}

	if upd != nil {
		select {
		case s.updateCh <- *upd:
			slog.Info("scheduler: update available", "version", upd.Version)
		default: // already queued; ignore duplicate
		}
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
	if old.SkipTLSVerify != cur.SkipTLSVerify {
		return true
	}
	if old.AddressFamily != cur.AddressFamily {
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
	if snmpParamsChanged(old.SNMP, cur.SNMP) {
		return true
	}
	return false
}

// snmpParamsChanged compares the SNMP parameter blocks of two tasks — a changed
// credential/port/version/OID list must restart the runner just like a changed
// target. Field-by-field because ExtraOIDs (a slice) makes the struct
// non-comparable.
func snmpParamsChanged(a, b *probe.SNMPParams) bool {
	if (a == nil) != (b == nil) {
		return true
	}
	if a == nil {
		return false
	}
	return a.DeviceID != b.DeviceID ||
		a.Version != b.Version ||
		a.Community != b.Community ||
		a.Port != b.Port ||
		a.TimeoutSeconds != b.TimeoutSeconds ||
		a.Retries != b.Retries ||
		a.InventoryEveryN != b.InventoryEveryN ||
		a.V3User != b.V3User ||
		a.V3AuthProto != b.V3AuthProto ||
		a.V3AuthPass != b.V3AuthPass ||
		a.V3PrivProto != b.V3PrivProto ||
		a.V3PrivPass != b.V3PrivPass ||
		a.CollectIfaces != b.CollectIfaces ||
		!slices.Equal(a.ExtraOIDs, b.ExtraOIDs)
}

func (s *Scheduler) fetchTasks(ctx context.Context) ([]probe.Task, string, string, *updater.Update, error) {
	reqCtx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()

	url := strings.TrimRight(s.syncURL, "/") + "/api/v1/agent-sync/tasks"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", "", nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("GET /tasks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", "", nil, fmt.Errorf("GET /tasks: HTTP %d", resp.StatusCode)
	}

	var tr taskResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, "", "", nil, fmt.Errorf("decode task response: %w", err)
	}
	return tr.Tasks, tr.SourceIPv4, tr.SourceIPv6, tr.Update, nil
}

// runTask ticks at the task's configured interval and calls execute on each tick.
// The task runs once immediately on startup so results arrive before the first
// interval elapses. snmp_poll runners add a deterministic startup offset
// (task_id spread across the interval) so co-assigned devices are not all hit
// in the same second on every cycle; all runners share one reconcile instant,
// so without the offset they would stay phase-locked forever.
func (s *Scheduler) runTask(ctx context.Context, task probe.Task) {
	interval := time.Duration(task.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}

	if task.Type == "snmp_poll" && task.IntervalSeconds > 1 {
		offset := time.Duration(task.TaskID%task.IntervalSeconds) * time.Second
		select {
		case <-time.After(offset):
		case <-ctx.Done():
			return
		}
	}

	var seq uint64
	s.execute(ctx, task, seq) // run immediately (after optional offset)
	seq++

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.execute(ctx, task, seq)
			seq++
		}
	}
}

// execute acquires a slot from the concurrency semaphore, reads the current
// source IPs, runs the probe, and feeds results to the reporter. seq is the
// per-runner tick counter: snmp_poll uses it for the fast/slow cadence (the
// first tick and every InventoryEveryN-th tick fetch the full system group).
func (s *Scheduler) execute(ctx context.Context, task probe.Task, seq uint64) {
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-s.sem }()

	if task.Type == "snmp_poll" {
		if task.SNMP == nil {
			return // malformed payload; nothing useful to report
		}
		full := task.SNMP.InventoryEveryN <= 1 || seq%uint64(task.SNMP.InventoryEveryN) == 0
		s.reporter.EnqueueSNMP(probe.RunSNMPPoll(task, full))
		return
	}

	s.mu.RLock()
	sourceIPv4 := s.sourceIPv4
	sourceIPv6 := s.sourceIPv6
	s.mu.RUnlock()

	results := probe.Dispatch(ctx, task, sourceIPv4, sourceIPv6)
	for _, r := range results {
		s.reporter.Enqueue(r)
	}
}
