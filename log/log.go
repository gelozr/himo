// Package log builds a configured *slog.Logger. Use slog.Handler as the seam
// for other backends instead of wrapping the logger.
package log

import (
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

func getConfig(cfg ...Config) Config {
	var c Config
	if len(cfg) > 0 {
		c = cfg[0]
	}

	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	if c.LogFormat == "" {
		c.LogFormat = "text"
	}

	if c.LogOutput == "" {
		c.LogOutput = "stdout"
	}

	if c.LogPath == "" {
		c.LogPath = "./log/app.log"
	}

	return c
}

// New returns a logger and a close function that releases the log file, if any.
func New(c ...Config) (*slog.Logger, func() error, error) {
	cfg := getConfig(c...)

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return nil, nil, fmt.Errorf("log level: %w", err)
	}

	var (
		w       io.Writer = os.Stdout
		closeFn           = func() error { return nil }
	)
	switch strings.ToLower(cfg.LogOutput) {
	case "stdout":
	case "file":
		if err := os.MkdirAll(filepath.Dir(cfg.LogPath), 0o750); err != nil {
			return nil, nil, fmt.Errorf("create output dir: %w", err)
		}
		f, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("open output file: %w", err)
		}
		w, closeFn = f, f.Close
	default:
		return nil, nil, fmt.Errorf("unknown log output %q", cfg.LogOutput)
	}

	var h slog.Handler
	switch strings.ToLower(cfg.LogFormat) {
	case "text":
		h = slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	case "json":
		h = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	default:
		_ = closeFn()
		return nil, nil, fmt.Errorf("unknown log format %q", cfg.LogFormat)
	}

	return slog.New(h), closeFn, nil
}
