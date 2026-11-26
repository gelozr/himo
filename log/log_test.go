package log

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNew_JSONFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "app.log")
	logger, closeFn, err := New(Config{LogLevel: "DEBUG", LogFormat: "JSON", LogOutput: "file", LogPath: path})
	if err != nil {
		t.Fatal(err)
	}

	logger.Debug("hello", "time", "not a time.Time")
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("invalid JSON %q: %v", data, err)
	}
	if rec["msg"] != "hello" || rec["level"] != "DEBUG" {
		t.Errorf("record = %v", rec)
	}
}

func TestNew_RejectsBadConfig(t *testing.T) {
	for _, c := range []Config{{LogLevel: "loud"}, {LogFormat: "xml"}, {LogOutput: "printer"}} {
		if _, _, err := New(c); err == nil {
			t.Errorf("%+v: expected error", c)
		}
	}
}

func TestNew_InvalidFormatDoesNotCreateLogDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	path := filepath.Join(dir, "app.log")
	if _, _, err := New(Config{LogFormat: "xml", LogOutput: "file", LogPath: path}); err == nil {
		t.Fatal("expected an invalid format error")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("expected no log directory, got stat error %v", err)
	}
}
