package commands

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestEnhanceError(t *testing.T) {
	if enhanceError("op", nil, 1) != nil {
		t.Fatalf("expected nil error when input is nil")
	}

	cases := []struct {
		err      error
		contains string
	}{
		{errors.New("could not find default credentials"), "No GCP credentials found"},
		{errors.New("403 Forbidden"), "Permission Denied"},
		{errors.New("rateLimitExceeded"), "rate limit exceeded"},
		{errors.New("no such file or directory"), "Repository path not found"},
		{errors.New("some other error"), "op failed"},
	}

	for _, tt := range cases {
		err := enhanceError("op", tt.err, 5)
		if err == nil {
			t.Fatalf("expected error for %v", tt.err)
		}
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.contains)) {
			t.Fatalf("expected error to contain %q, got %q", tt.contains, err.Error())
		}
	}
}

func TestSelectReporter(t *testing.T) {
	var buf bytes.Buffer

	for _, format := range []string{"text", "json", "sarif", "spectrehub"} {
		r, err := selectReporter(format, &buf)
		if err != nil {
			t.Fatalf("selectReporter(%s) failed: %v", format, err)
		}
		if r == nil {
			t.Fatalf("selectReporter(%s) returned nil", format)
		}
	}

	_, err := selectReporter("invalid", &buf)
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected unsupported error, got %q", err.Error())
	}
}

func TestPrintStatus(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() {
		slog.SetDefault(oldLogger)
	})

	printStatus("hello %s", "world")

	if !strings.Contains(buf.String(), "hello world") {
		t.Fatalf("expected output to contain message, got %q", buf.String())
	}
}

func TestGetVersion(t *testing.T) {
	version = "1.2.3"
	t.Cleanup(func() { version = "" })
	if GetVersion() != "1.2.3" {
		t.Fatalf("expected version %q, got %q", "1.2.3", GetVersion())
	}
}
