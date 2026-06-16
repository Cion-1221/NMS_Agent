// Package logger 基于标准库 log/slog 构建全局结构化日志。
// 选择 slog 而非第三方库（zap/zerolog）：Go 1.21+ 标准库已自带，
// 减少依赖面，且性能足以应对 Agent 这种 IO 为主的工作负载。
package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/Cion-1221/NMS_Agent/internal/config"
)

// New 依据 runtime 配置构建 *slog.Logger，并将其设置为 slog 默认 logger。
// 返回的 closeFunc 用于进程退出前 flush/关闭日志文件句柄（stdout 场景下是 no-op），
// main.go 应在 defer 中调用它。
func New(cfg config.RuntimeConfig) (logger *slog.Logger, closeFunc func(), err error) {
	output, closeFunc, err := resolveOutput(cfg)
	if err != nil {
		return nil, func() {}, err
	}

	handlerOpts := &slog.HandlerOptions{
		Level:     parseLevel(cfg.LogLevel),
		AddSource: cfg.LogLevel == "debug",
	}

	var handler slog.Handler
	switch strings.ToLower(cfg.LogFormat) {
	case "text":
		handler = slog.NewTextHandler(output, handlerOpts)
	default:
		handler = slog.NewJSONHandler(output, handlerOpts)
	}

	logger = slog.New(handler)
	slog.SetDefault(logger)
	return logger, closeFunc, nil
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func resolveOutput(cfg config.RuntimeConfig) (io.Writer, func(), error) {
	if strings.ToLower(cfg.LogOutput) != "file" {
		return os.Stdout, func() {}, nil
	}

	if cfg.LogFilePath == "" {
		return nil, nil, fmt.Errorf("logger: log_output=file but log_file_path is empty")
	}
	if dir := filepath.Dir(cfg.LogFilePath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, nil, fmt.Errorf("logger: create log dir %s: %w", dir, err)
		}
	}

	f, err := os.OpenFile(cfg.LogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("logger: open log file %s: %w", cfg.LogFilePath, err)
	}

	return f, func() { _ = f.Close() }, nil
}
