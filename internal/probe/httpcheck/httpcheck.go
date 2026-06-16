// Package httpcheck 实现 HTTP(S) 可用性探测：发起请求并校验状态码与
// （可选的）响应体关键字，常用于业务接口的端到端健康检查。
//
// 仅依赖标准库 net/http，无需第三方库。
package httpcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
)

const moduleName = "http_check"

// maxBodyPeek 限制读取响应体用于关键字匹配的最大字节数，避免探测一个
// 大文件下载接口时把整个响应体读进内存。
const maxBodyPeek = 1 << 20 // 1MiB

type Stat struct {
	Name       string  `json:"name"`
	URL        string  `json:"url"`
	Up         bool    `json:"up"`
	StatusCode int     `json:"status_code"`
	LatencyMs  float64 `json:"latency_ms"`
	Error      string  `json:"error,omitempty"`
}

type Module struct {
	cfg config.HTTPCheckConfig
	id  module.Identity
}

func New(cfg config.HTTPCheckConfig, id module.Identity) *Module {
	return &Module{cfg: cfg, id: id}
}

func (m *Module) Name() string { return moduleName }

func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	if len(m.cfg.Targets) == 0 {
		return nil, nil
	}

	stats := make([]Stat, len(m.cfg.Targets))
	var wg sync.WaitGroup
	for i, target := range m.cfg.Targets {
		i, target := i, target
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats[i] = m.probe(ctx, target)
		}()
	}
	wg.Wait()

	results := make([]module.Result, len(stats))
	for i, s := range stats {
		results[i] = m.id.NewResult(moduleName, s)
	}
	return results, nil
}

func (m *Module) probe(ctx context.Context, target config.HTTPTarget) Stat {
	stat := Stat{Name: target.Name, URL: target.URL}

	client := &http.Client{
		Timeout: m.cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: target.SkipTLSVerify}, //nolint:gosec // 由配置项显式控制，默认 false
		},
	}

	method := target.Method
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, target.URL, nil)
	if err != nil {
		stat.Error = fmt.Sprintf("build request: %v", err)
		return stat
	}
	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	stat.LatencyMs = float64(time.Since(start)) / float64(time.Millisecond)
	if err != nil {
		stat.Error = err.Error()
		return stat
	}
	defer resp.Body.Close()

	stat.StatusCode = resp.StatusCode

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyPeek))

	statusOK := target.ExpectStatus == 0 || resp.StatusCode == target.ExpectStatus
	keywordOK := target.ExpectKeyword == "" || strings.Contains(string(body), target.ExpectKeyword)

	stat.Up = statusOK && keywordOK
	if !stat.Up {
		stat.Error = fmt.Sprintf("expect_status=%d expect_keyword=%q not satisfied (got status=%d)",
			target.ExpectStatus, target.ExpectKeyword, resp.StatusCode)
	}
	return stat
}
