package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_NoFile(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Project != "" {
		t.Fatalf("expected empty project, got %q", cfg.Project)
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	content := `project: my-gcp-project
stale_days: 90
version_days: 30
format: json
check_public: true
timeout: 5m
exclude_buckets:
  - temp-bucket
  - test-bucket
`
	if err := os.WriteFile(filepath.Join(dir, ".gcsspectre.yaml"), []byte(content), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Project != "my-gcp-project" {
		t.Fatalf("expected project my-gcp-project, got %q", cfg.Project)
	}
	if cfg.StaleDays != 90 {
		t.Fatalf("expected stale_days 90, got %d", cfg.StaleDays)
	}
	if cfg.VersionDays != 30 {
		t.Fatalf("expected version_days 30, got %d", cfg.VersionDays)
	}
	if cfg.Format != "json" {
		t.Fatalf("expected format json, got %q", cfg.Format)
	}
	if !cfg.CheckPublicEnabled() {
		t.Fatal("expected check_public true")
	}
	if len(cfg.ExcludeBuckets) != 2 {
		t.Fatalf("expected 2 exclude_buckets, got %d", len(cfg.ExcludeBuckets))
	}
}

func TestLoad_YMLExtension(t *testing.T) {
	dir := t.TempDir()
	content := `project: alt-project`
	if err := os.WriteFile(filepath.Join(dir, ".gcsspectre.yml"), []byte(content), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Project != "alt-project" {
		t.Fatalf("expected project alt-project, got %q", cfg.Project)
	}
}

func TestLoad_YAMLTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gcsspectre.yaml"), []byte("project: first"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gcsspectre.yml"), []byte("project: second"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Project != "first" {
		t.Fatalf("expected .yaml to take precedence, got %q", cfg.Project)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gcsspectre.yaml"), []byte(":::invalid"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestCheckPublicEnabled_DefaultTrue(t *testing.T) {
	cfg := Config{}
	if !cfg.CheckPublicEnabled() {
		t.Fatal("expected default check_public to be true")
	}
}

func TestCheckPublicEnabled_ExplicitFalse(t *testing.T) {
	f := false
	cfg := Config{CheckPublic: &f}
	if cfg.CheckPublicEnabled() {
		t.Fatal("expected check_public false")
	}
}

func TestTimeoutDuration(t *testing.T) {
	cfg := Config{Timeout: "5m"}
	if cfg.TimeoutDuration() != 5*time.Minute {
		t.Fatalf("expected 5m, got %v", cfg.TimeoutDuration())
	}

	cfg.Timeout = ""
	if cfg.TimeoutDuration() != 0 {
		t.Fatalf("expected 0 for empty, got %v", cfg.TimeoutDuration())
	}

	cfg.Timeout = "invalid"
	if cfg.TimeoutDuration() != 0 {
		t.Fatalf("expected 0 for invalid, got %v", cfg.TimeoutDuration())
	}
}
