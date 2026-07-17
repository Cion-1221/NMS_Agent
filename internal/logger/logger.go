// Package logger sets up a JSON slog logger backed by lumberjack with optional
// daily log-file rotation.
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/Cion-1221/NMS_Agent/internal/config"
)

// New creates a JSON slog logger.
//
// Returns:
//   - *slog.Logger  — use for structured logging throughout the agent
//   - func(context.Context) — call once after the main context is ready to
//     start daily log-file rotation (no-op when logging to stderr)
//   - func() — call on process exit to flush and close the underlying file
func New(cfg config.LogConfig) (*slog.Logger, func(context.Context), func()) {
	var w io.Writer
	var lj *lumberjack.Logger

	if cfg.File != "" {
		lj = &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    cfg.MaxSizeMB,  // megabytes before rotation
			MaxAge:     cfg.MaxAgeDays, // days to retain rotated files
			MaxBackups: cfg.MaxBackups, // number of old files to keep
			Compress:   cfg.Compress,
			LocalTime:  true,
		}
		w = lj
	} else {
		w = os.Stderr
	}

	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: parseLevel(cfg.Level)})
	log := slog.New(h)
	slog.SetDefault(log)

	startRotation := func(ctx context.Context) {
		if lj == nil {
			return
		}
		go dailyRotate(ctx, lj)
	}

	closeFunc := func() {
		if lj != nil {
			_ = lj.Close()
		}
	}

	return log, startRotation, closeFunc
}

// parseLevel maps the runtime.log.level config string to a slog level.
// Unknown or empty values fall back to Info.
func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// dailyRotate triggers lj.Rotate() at local midnight on each calendar day,
// ensuring log files roll over regardless of file-size limits.
func dailyRotate(ctx context.Context, lj *lumberjack.Logger) {
	for {
		now := time.Now().Local()
		next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			_ = lj.Rotate()
		}
	}
}
