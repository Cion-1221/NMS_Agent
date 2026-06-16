// Package scheduler 把启用的功能模块编排为独立 goroutine 并发运行。
//
// 设计要点：
//  1. 每个模块拥有自己的 goroutine 与 ticker，互不阻塞、互不影响执行节奏；
//  2. 每次 Module.Run 调用都被 recover 包裹——单个模块 panic 只会记录一条日志，
//     绝不会向上传播导致整个 Agent 进程退出；
//  3. 所有调度均挂在同一个 context 下，SIGINT/SIGTERM 触发取消后，
//     所有 goroutine 在各自当前迭代结束后退出，实现优雅停机；
//  4. 用带缓冲的 semaphore 限制全局同时执行的模块数量
//     （对应 config.yaml 的 runtime.max_module_concurrency），
//     防止配置了大量 target 的探测类模块在同一时刻打满本机 CPU/连接数/文件描述符。
package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/Cion-1221/NMS_Agent/internal/module"
)

// Task 把一个模块实例与它的执行周期绑定在一起。
// Interval <= 0 且模块未实现 module.Emitter 时，按"启动时执行一次"处理；
// Interval <= 0 且模块实现了 module.Emitter 时，按"常驻 daemon"处理。
type Task struct {
	Module   module.Module
	Interval time.Duration
}

// Sink 是调度器产出结果的去向，由 internal/reporter.Reporter 实现。
type Sink interface {
	Enqueue(results []module.Result)
}

type Scheduler struct {
	logger *slog.Logger
	sink   Sink
	sem    chan struct{}
}

func New(logger *slog.Logger, sink Sink, maxConcurrency int) *Scheduler {
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}
	return &Scheduler{
		logger: logger,
		sink:   sink,
		sem:    make(chan struct{}, maxConcurrency),
	}
}

// Run 为每个 Task 启动一个调度 goroutine，阻塞直到 ctx 被取消且所有
// goroutine 均已退出。调用方（main.go）通常会把它放进 errgroup 或单独的 goroutine。
func (s *Scheduler) Run(ctx context.Context, tasks []Task) {
	var wg sync.WaitGroup
	for _, t := range tasks {
		t := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.dispatch(ctx, t)
		}()
	}
	wg.Wait()
	s.logger.Info("scheduler stopped: all module goroutines exited")
}

func (s *Scheduler) dispatch(ctx context.Context, t Task) {
	name := t.Module.Name()

	if t.Interval <= 0 {
		if emitter, ok := t.Module.(module.Emitter); ok {
			s.runDaemon(ctx, name, emitter)
			return
		}
		s.logger.Info("module has no interval and is not an Emitter, running once", "module", name)
		s.execute(ctx, t.Module)
		return
	}

	s.runTicker(ctx, name, t)
}

// runTicker 是绝大多数周期性模块（ping/snmp_poll/mesh_ping/...）的调度主循环。
func (s *Scheduler) runTicker(ctx context.Context, name string, t Task) {
	s.logger.Info("module scheduled", "module", name, "interval", t.Interval)

	ticker := time.NewTicker(t.Interval)
	defer ticker.Stop()

	// 启动后立即执行一次，不必等待第一个 tick，缩短首次数据上报的延迟。
	s.execute(ctx, t.Module)

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("module stopping (context cancelled)", "module", name)
			return
		case <-ticker.C:
			s.execute(ctx, t.Module)
		}
	}
}

// execute 在并发配额内安全地执行一次 Module.Run，是 panic 隔离的第一道屏障。
func (s *Scheduler) execute(ctx context.Context, m module.Module) {
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-s.sem }()

	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("module panic recovered",
				"module", m.Name(),
				"panic", fmt.Sprint(r),
				"stack", string(debug.Stack()))
		}
	}()

	start := time.Now()
	results, err := m.Run(ctx)
	elapsed := time.Since(start)

	if err != nil {
		s.logger.Warn("module run returned error", "module", m.Name(), "error", err, "elapsed", elapsed)
		return
	}
	if len(results) == 0 {
		return
	}
	s.logger.Debug("module run produced results", "module", m.Name(), "count", len(results), "elapsed", elapsed)
	s.sink.Enqueue(results)
}

// runDaemon 启动常驻模块（Syslog 监听、Netflow 接收器等），并在其异常退出后
// 按指数退避自动重启，直到 ctx 被取消——单次网络抖动或 panic 不应让采集通道永久失效。
func (s *Scheduler) runDaemon(ctx context.Context, name string, e module.Emitter) {
	const (
		initialBackoff = time.Second
		maxBackoff     = 30 * time.Second
	)
	backoff := initialBackoff

	emit := func(results ...module.Result) {
		if len(results) == 0 {
			return
		}
		s.sink.Enqueue(results)
	}

	s.logger.Info("daemon module starting", "module", name)

	for {
		if ctx.Err() != nil {
			return
		}

		err := s.serveOnce(ctx, e, emit)

		if ctx.Err() != nil {
			s.logger.Info("daemon module stopped (context cancelled)", "module", name)
			return
		}
		if err != nil {
			s.logger.Error("daemon module exited unexpectedly, restarting",
				"module", name, "error", err, "backoff", backoff)
		} else {
			s.logger.Warn("daemon module returned without error, restarting", "module", name, "backoff", backoff)
		}

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// serveOnce 是 panic 隔离的第二道屏障，专门保护 Emitter.Serve 这种长生命周期调用。
func (s *Scheduler) serveOnce(ctx context.Context, e module.Emitter, emit func(...module.Result)) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v\n%s", r, debug.Stack())
		}
	}()
	return e.Serve(ctx, emit)
}
