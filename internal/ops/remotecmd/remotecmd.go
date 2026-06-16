// Package remotecmd 实现远程命令执行通道：周期性向中心 NMS Server 轮询
// 待执行命令，校验白名单/黑名单后执行，并把结果回传
// （对应 config.yaml 的 modules.remote_command）。
//
// 仅依赖标准库 net/http + os/exec + regexp，无需第三方库。
//
// 安全基线（与 config.yaml 字段一一对应，三层防线缺一不可）：
//  1. 默认拒绝一切命令，必须命中 whitelist 中的某条正则才允许执行；
//  2. 命中 blacklist 任意一条，无条件拒绝——即使同时命中 whitelist；
//  3. 命中 require_confirmation_for 的命令，必须自带中心侧签发的
//     confirmation_token，否则即使在白名单内也只会被挂起等待二次确认，
//     不会执行。
package remotecmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
)

const moduleName = "remote_command"

// PendingCommand 是从 command_source_url 拉取到的一条待执行命令。
type PendingCommand struct {
	ID                string `json:"id"`
	Command           string `json:"command"`
	ConfirmationToken string `json:"confirmation_token,omitempty"`
}

type CommandResult struct {
	ID         string `json:"id"`
	Command    string `json:"command"`
	Status     string `json:"status"` // executed | rejected | pending_confirmation | error
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	Reason     string `json:"reason,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
}

type Module struct {
	cfg    config.RemoteCommandConfig
	id     module.Identity
	client *http.Client
	sem    chan struct{}

	whitelist   []*regexp.Regexp
	blacklist   []*regexp.Regexp
	confirmList []*regexp.Regexp

	commandSourceURL  string
	resultCallbackURL string
}

func New(cfg config.RemoteCommandConfig, id module.Identity) (*Module, error) {
	whitelist, err := compileAll(cfg.Whitelist)
	if err != nil {
		return nil, fmt.Errorf("compile whitelist: %w", err)
	}
	blacklist, err := compileAll(cfg.Blacklist)
	if err != nil {
		return nil, fmt.Errorf("compile blacklist: %w", err)
	}
	confirmList, err := compileAll(cfg.RequireConfirmationFor)
	if err != nil {
		return nil, fmt.Errorf("compile require_confirmation_for: %w", err)
	}

	maxConcurrent := cfg.MaxConcurrentCommands
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}

	return &Module{
		cfg:               cfg,
		id:                id,
		client:            &http.Client{Timeout: cfg.ExecutionTimeout},
		sem:               make(chan struct{}, maxConcurrent),
		whitelist:         whitelist,
		blacklist:         blacklist,
		confirmList:       confirmList,
		commandSourceURL:  strings.ReplaceAll(cfg.CommandSourceURL, "{agent_id}", id.AgentID),
		resultCallbackURL: strings.ReplaceAll(cfg.ResultCallbackURL, "{agent_id}", id.AgentID),
	}, nil
}

func compileAll(patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func (m *Module) Name() string { return moduleName }

// Run 拉取一批待执行命令，并发执行（受 sem 限流），把每条命令的结果
// 既通过返回值交给 Reporter 上报，也尽力直接 POST 给 result_callback_url
// （后者用于中心侧的命令分发系统按 ID 做请求/响应关联）。
func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	commands, err := m.fetchPending(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch pending commands: %w", err)
	}
	if len(commands) == 0 {
		return nil, nil
	}

	results := make([]CommandResult, len(commands))
	var wg sync.WaitGroup
	for i, cmd := range commands {
		i, cmd := i, cmd
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case m.sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-m.sem }()
			results[i] = m.handle(ctx, cmd)
		}()
	}
	wg.Wait()

	out := make([]module.Result, 0, len(results))
	for _, r := range results {
		m.postResult(ctx, r)
		out = append(out, m.id.NewResult(moduleName, r))
	}
	return out, nil
}

func (m *Module) handle(ctx context.Context, cmd PendingCommand) CommandResult {
	res := CommandResult{ID: cmd.ID, Command: cmd.Command}

	if matchAny(m.blacklist, cmd.Command) {
		res.Status = "rejected"
		res.Reason = "matched blacklist"
		return res
	}
	if !matchAny(m.whitelist, cmd.Command) {
		res.Status = "rejected"
		res.Reason = "did not match any whitelist pattern"
		return res
	}
	if matchAny(m.confirmList, cmd.Command) && cmd.ConfirmationToken == "" {
		res.Status = "pending_confirmation"
		res.Reason = "command requires a confirmation_token issued by the NMS Server"
		return res
	}

	return m.execute(ctx, cmd)
}

func (m *Module) execute(ctx context.Context, cmd PendingCommand) CommandResult {
	res := CommandResult{ID: cmd.ID, Command: cmd.Command}

	execCtx, cancel := context.WithTimeout(ctx, m.cfg.ExecutionTimeout)
	defer cancel()

	c := shellCommand(execCtx, cmd.Command)

	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	start := time.Now()
	err := c.Run()
	res.DurationMs = time.Since(start).Milliseconds()
	res.Stdout = stdout.String()
	res.Stderr = stderr.String()

	if err != nil {
		res.Status = "error"
		res.Reason = err.Error()
		return res
	}

	res.Status = "executed"
	return res
}

// shellCommand 把白名单校验过的命令字符串交给本机 shell 解释执行：
// Windows 用 cmd /C，其余平台用 sh -c。
func shellCommand(ctx context.Context, command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "cmd", "/C", command)
	}
	return exec.CommandContext(ctx, "sh", "-c", command)
}

func matchAny(patterns []*regexp.Regexp, s string) bool {
	for _, re := range patterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func (m *Module) fetchPending(ctx context.Context) ([]PendingCommand, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.commandSourceURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var commands []PendingCommand
	if err := json.NewDecoder(resp.Body).Decode(&commands); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return commands, nil
}

// postResult 尽力把单条命令结果直接推给 result_callback_url；失败不影响
// 主流程，因为同一条结果已经通过 Run 的返回值交给 Reporter 走主上报通道。
func (m *Module) postResult(ctx context.Context, res CommandResult) {
	if m.resultCallbackURL == "" {
		return
	}
	body, err := json.Marshal(res)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.resultCallbackURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}
