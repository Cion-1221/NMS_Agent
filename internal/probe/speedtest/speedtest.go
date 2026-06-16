// Package speedtest 实现带宽测速模块。
//
// 推荐第三方库：github.com/showwin/speedtest-go/speedtest
// （对接 Ookla Speedtest.net 服务器网络的纯 Go 实现，支持自动选择最近
// 服务器、HTTP 下载/上传测速）。一次测速会产生数十至数百 MB 流量并占用
// 数十秒，因此 config.yaml 中默认 interval 设置得很长（如 3600s），
// 且默认 enabled: false，避免在计费带宽的边缘节点上意外产生大量流量。
package speedtest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	st "github.com/showwin/speedtest-go/speedtest"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
)

const moduleName = "speedtest"

type Stat struct {
	ServerID     string  `json:"server_id"`
	ServerName   string  `json:"server_name"`
	ServerHost   string  `json:"server_host"`
	LatencyMs    float64 `json:"latency_ms"`
	DownloadMbps float64 `json:"download_mbps"`
	UploadMbps   float64 `json:"upload_mbps"`
	Error        string  `json:"error,omitempty"`
}

type Module struct {
	cfg config.SpeedtestConfig
	id  module.Identity
}

func New(cfg config.SpeedtestConfig, id module.Identity) *Module {
	return &Module{cfg: cfg, id: id}
}

func (m *Module) Name() string { return moduleName }

func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	stat := m.probe(ctx)
	if m.cfg.SaveHistory {
		m.appendHistory(stat)
	}
	return []module.Result{m.id.NewResult(moduleName, stat)}, nil
}

func (m *Module) probe(ctx context.Context) Stat {
	client := st.New()

	server, err := m.pickServer(ctx, client)
	if err != nil {
		return Stat{Error: err.Error()}
	}
	stat := Stat{ServerID: server.ID, ServerName: server.Name, ServerHost: server.Host}

	if err := server.PingTestContext(ctx, nil); err != nil {
		stat.Error = fmt.Sprintf("ping test: %v", err)
		return stat
	}
	stat.LatencyMs = float64(server.Latency) / float64(time.Millisecond)

	if err := server.DownloadTestContext(ctx); err != nil {
		stat.Error = fmt.Sprintf("download test: %v", err)
		return stat
	}
	stat.DownloadMbps = server.DLSpeed.Mbps()

	if err := server.UploadTestContext(ctx); err != nil {
		stat.Error = fmt.Sprintf("upload test: %v", err)
		return stat
	}
	stat.UploadMbps = server.ULSpeed.Mbps()

	return stat
}

func (m *Module) pickServer(ctx context.Context, client *st.Speedtest) (*st.Server, error) {
	if m.cfg.ServerID != "" {
		return client.FetchServerByIDContext(ctx, m.cfg.ServerID)
	}

	servers, err := client.FetchServerListContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch server list: %w", err)
	}
	available := *servers.Available()
	if len(available) == 0 {
		return nil, fmt.Errorf("no speedtest server available")
	}
	sort.Sort(st.ByDistance{Servers: available})
	return available[0], nil
}

// appendHistory 以 JSON Lines 形式追加写入本地历史文件，仅作为辅助诊断数据，
// 不是上报主链路的一部分，因此写入失败时只静默忽略，不影响 Run 的主流程。
func (m *Module) appendHistory(stat Stat) {
	if m.cfg.HistoryPath == "" {
		return
	}
	f, err := os.OpenFile(m.cfg.HistoryPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()

	line, err := json.Marshal(stat)
	if err != nil {
		return
	}
	line = append(line, '\n')
	_, _ = f.Write(line)
}
