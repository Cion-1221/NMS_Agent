// Package syslog 在本地监听 UDP/TCP 514 端口接收 Syslog 报文，转换为
// module.Result 上报，并可选落盘保存原始日志
// （对应 config.yaml 的 modules.syslog）。
//
// 推荐第三方库：gopkg.in/mcuadros/go-syslog.v2
// （支持 RFC3164/RFC5424/RFC6587、UDP/TCP/Unix socket，内置 Channel 形式
// 的 Handler，省去自己解析 Syslog 报文格式的工作量）。
//
// 本地落盘的滚动逻辑（按大小切分 + 保留份数）这里用标准库手写了一个
// 精简版；如果需要更完整的滚动策略（按天切分、压缩历史文件等），
// 推荐直接换成 gopkg.in/natefinch/lumberjack.v2。
package syslog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	gosyslog "gopkg.in/mcuadros/go-syslog.v2"
	"gopkg.in/mcuadros/go-syslog.v2/format"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
)

const moduleName = "syslog"

type Entry struct {
	Facility string `json:"facility,omitempty"`
	Severity string `json:"severity,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Tag      string `json:"tag,omitempty"`
	Content  string `json:"content,omitempty"`
	Client   string `json:"client,omitempty"`
}

// Module 同时实现 module.Module 与 module.Emitter：它是常驻监听型模块，
// Scheduler 检测到 Emitter 后会改用 Serve 常驻调度，Run 仅用于满足接口。
type Module struct {
	cfg config.SyslogConfig
	id  module.Identity
}

func New(cfg config.SyslogConfig, id module.Identity) *Module {
	return &Module{cfg: cfg, id: id}
}

func (m *Module) Name() string { return moduleName }

func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	return nil, nil
}

func (m *Module) Serve(ctx context.Context, emit func(...module.Result)) error {
	bufferSize := m.cfg.BufferSize
	if bufferSize <= 0 {
		bufferSize = 1024
	}
	channel := make(gosyslog.LogPartsChannel, bufferSize)
	handler := gosyslog.NewChannelHandler(channel)

	server := gosyslog.NewServer()
	server.SetFormat(parseFormat(m.cfg.ParseFormat))
	server.SetHandler(handler)

	var err error
	if m.cfg.Protocol == "tcp" {
		err = server.ListenTCP(m.cfg.ListenAddress)
	} else {
		err = server.ListenUDP(m.cfg.ListenAddress)
	}
	if err != nil {
		return fmt.Errorf("listen %s %s: %w", m.cfg.Protocol, m.cfg.ListenAddress, err)
	}

	if err := server.Boot(); err != nil {
		return fmt.Errorf("boot syslog server: %w", err)
	}

	var writer *localWriter
	if m.cfg.LocalStorage.Enabled {
		writer, err = newLocalWriter(m.cfg.LocalStorage)
		if err != nil {
			return fmt.Errorf("open local_storage: %w", err)
		}
		defer writer.Close()
	}

	go func() {
		<-ctx.Done()
		_ = server.Kill() // 解除下面 channel 的阻塞，使 Serve 能够及时返回
	}()

	for logParts := range channel {
		entry := Entry{
			Facility: fmt.Sprint(logParts["facility"]),
			Severity: fmt.Sprint(logParts["severity"]),
			Hostname: fmt.Sprint(logParts["hostname"]),
			Tag:      fmt.Sprint(logParts["tag"]),
			Content:  fmt.Sprint(logParts["content"]),
			Client:   fmt.Sprint(logParts["client"]),
		}

		if writer != nil {
			writer.WriteEntry(entry)
		}
		emit(m.id.NewResult(moduleName, entry))
	}

	server.Wait()
	return nil
}

func parseFormat(name string) format.Format {
	switch name {
	case "rfc3164":
		return gosyslog.RFC3164
	case "rfc5424":
		return gosyslog.RFC5424
	default:
		return gosyslog.Automatic
	}
}

// localWriter 是一个按大小滚动、限制保留份数的极简文件写入器。
type localWriter struct {
	cfg  config.SyslogLocalStorage
	mu   sync.Mutex
	file *os.File
	size int64
}

func newLocalWriter(cfg config.SyslogLocalStorage) (*localWriter, error) {
	if dir := filepath.Dir(cfg.Path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	w := &localWriter{cfg: cfg}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *localWriter) open() error {
	f, err := os.OpenFile(w.cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.file = f
	w.size = info.Size()
	return nil
}

// WriteEntry 以一行一条 JSON 的形式追加写入，写入前检查是否需要按大小滚动。
func (w *localWriter) WriteEntry(entry Entry) {
	line := fmt.Sprintf("%s %s %s %s %s %s\n",
		time.Now().UTC().Format(time.RFC3339), entry.Client, entry.Facility, entry.Severity, entry.Tag, entry.Content)

	w.mu.Lock()
	defer w.mu.Unlock()

	maxSize := int64(w.cfg.MaxSizeMB) * 1024 * 1024
	if maxSize > 0 && w.size+int64(len(line)) > maxSize {
		w.rotate()
	}

	n, err := w.file.WriteString(line)
	if err == nil {
		w.size += int64(n)
	}
}

func (w *localWriter) rotate() {
	_ = w.file.Close()
	rotatedName := fmt.Sprintf("%s.%s", w.cfg.Path, time.Now().UTC().Format("20060102T150405Z"))
	_ = os.Rename(w.cfg.Path, rotatedName)
	if err := w.open(); err != nil {
		return
	}
	w.pruneBackups()
}

func (w *localWriter) pruneBackups() {
	if w.cfg.MaxBackups <= 0 {
		return
	}
	matches, err := filepath.Glob(w.cfg.Path + ".*")
	if err != nil || len(matches) <= w.cfg.MaxBackups {
		return
	}
	sort.Strings(matches) // 时间戳后缀按字典序排列即时间序
	for _, old := range matches[:len(matches)-w.cfg.MaxBackups] {
		_ = os.Remove(old)
	}
}

func (w *localWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}
