// Package scriptengine 在本地按 cron 调度执行 Python/Bash 等运维脚本
// （对应 config.yaml 的 modules.script_engine）。
//
// 推荐第三方库：github.com/robfig/cron/v3
// （标准 5 段 cron 表达式解析与调度循环的事实标准库，避免自己实现
// cron 字段解析、到期判断这类容易出 off-by-one 错误的逻辑）。
//
// 安全基线：只有出现在 allowed_interpreters 白名单里的解释器才会被执行，
// 不在白名单内的脚本在启动时直接被拒绝并记录日志，而不是静默忽略。
package scriptengine

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
)

const moduleName = "script_engine"

// maxOutputBytes 限制单次执行上报的 stdout/stderr 大小，避免脚本输出过大
// 撑爆上报队列。
const maxOutputBytes = 64 * 1024

type ExecutionResult struct {
	Script      string `json:"script"`
	Interpreter string `json:"interpreter"`
	ExitCode    int    `json:"exit_code"`
	Success     bool   `json:"success"`
	DurationMs  int64  `json:"duration_ms"`
	Stdout      string `json:"stdout,omitempty"`
	Stderr      string `json:"stderr,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Module 同时实现 module.Module 与 module.Emitter：它没有统一的执行周期
// （每个脚本各有各的 cron），Scheduler 检测到 Emitter 后会改用 Serve 常驻调度。
type Module struct {
	cfg    config.ScriptEngineConfig
	id     module.Identity
	logger *slog.Logger
}

func New(cfg config.ScriptEngineConfig, id module.Identity, logger *slog.Logger) *Module {
	return &Module{cfg: cfg, id: id, logger: logger}
}

func (m *Module) Name() string { return moduleName }

func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	return nil, nil
}

// Serve 启动内置的 cron 调度器，按各脚本自己的 cron 表达式触发执行；
// 阻塞直到 ctx 被取消，退出前等待正在运行的脚本结束（而不是粗暴杀掉）。
func (m *Module) Serve(ctx context.Context, emit func(...module.Result)) error {
	c := cron.New()

	for _, script := range m.cfg.Scripts {
		script := script
		if !script.Enabled {
			continue
		}
		if !slices.Contains(m.cfg.AllowedInterpreters, script.Interpreter) {
			m.logger.Error("script rejected: interpreter not in allowed_interpreters",
				"script", script.Name, "interpreter", script.Interpreter)
			continue
		}

		_, err := c.AddFunc(script.Cron, func() {
			result := m.execute(ctx, script)
			emit(m.id.NewResult(moduleName, result))
		})
		if err != nil {
			m.logger.Error("invalid cron expression, script skipped",
				"script", script.Name, "cron", script.Cron, "error", err)
		}
	}

	c.Start()
	<-ctx.Done()
	<-c.Stop().Done()
	return nil
}

func (m *Module) execute(ctx context.Context, script config.ScriptItem) ExecutionResult {
	result := ExecutionResult{Script: script.Name, Interpreter: script.Interpreter}

	timeout := script.Timeout
	if timeout <= 0 {
		timeout = m.cfg.DefaultTimeout
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	path := script.Path
	if !filepath.IsAbs(path) {
		path = filepath.Join(m.cfg.WorkDir, path)
	}

	args := append([]string{path}, script.Args...)
	cmd := exec.CommandContext(execCtx, script.Interpreter, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	result.DurationMs = time.Since(start).Milliseconds()
	result.Stdout = truncate(stdout.String(), maxOutputBytes)
	result.Stderr = truncate(stderr.String(), maxOutputBytes)

	if err != nil {
		result.Error = err.Error()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		}
		return result
	}

	result.Success = true
	return result
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}
