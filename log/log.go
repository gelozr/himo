// Package log builds a configured *slog.Logger. Use slog.Handler as the seam
// for other backends instead of wrapping the logger.
package log

import (
	"cmp"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Config selects the log level, format and output. Empty fields use the defaults.
type Config struct {
	LogLevel  string // debug, info, warn, error (default info)
	LogFormat string // text or json (default text)
	LogPath   string // used when LogOutput is file (default ./log/app.log)
	LogOutput string // stdout or file (default stdout)
}

func getConfig(cfg []Config) Config {
	var c Config
	if len(cfg) > 0 {
		c = cfg[0]
	}

	c.LogLevel = cmp.Or(c.LogLevel, "info")
	c.LogFormat = cmp.Or(c.LogFormat, "text")
	c.LogOutput = cmp.Or(c.LogOutput, "stdout")
	c.LogPath = cmp.Or(c.LogPath, "./log/app.log")

	return c
}

// New returns a logger and a close function that releases the log file, if any.
func New(c ...Config) (*slog.Logger, func() error, error) {
	cfg := getConfig(c)

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return nil, nil, fmt.Errorf("log level: %w", err)
	}

	format := strings.ToLower(cfg.LogFormat)
	if format != "text" && format != "json" {
		return nil, nil, fmt.Errorf("unknown log format %q", cfg.LogFormat)
	}

	var (
		w       io.Writer = os.Stdout
		closeFn           = func() error { return nil }
	)
	switch strings.ToLower(cfg.LogOutput) {
	case "stdout":
	case "file":
		if dir, _ := filepath.Split(cfg.LogPath); dir != "" {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, nil, fmt.Errorf("create output dir: %w", err)
			}
		}
		f, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("open output file: %w", err)
		}
		w, closeFn = f, f.Close
	default:
		return nil, nil, fmt.Errorf("unknown log output %q", cfg.LogOutput)
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}
	return slog.New(handler), closeFn, nil
}
