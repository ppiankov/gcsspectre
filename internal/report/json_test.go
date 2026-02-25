package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/gcsspectre/internal/analyzer"
)

func TestJSONReporter_Generate(t *testing.T) {
	var buf bytes.Buffer
	r := NewJSONReporter(&buf)

	data := Data{
		Tool:      "gcsspectre",
		Version:   "1.0.0",
		Timestamp: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		Config:    ScanConfig{RepoPath: "/code", Project: "my-project"},
		Result: &analyzer.AnalysisResult{
			Findings: []analyzer.Finding{
				{ID: analyzer.FindingMissingBucket, Severity: analyzer.SeverityHigh, ResourceID: "test-bucket", Message: "Missing"},
			},
			Summary: analyzer.Summary{TotalBuckets: 1, TotalFindings: 1},
		},
	}

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"tool": "gcsspectre"`) {
		t.Fatalf("expected tool field, got %q", output)
	}
	if !strings.Contains(output, `"MISSING_BUCKET"`) {
		t.Fatalf("expected finding ID, got %q", output)
	}

	// Verify valid JSON
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
}

func TestJSONReporter_TimestampUTC(t *testing.T) {
	var buf bytes.Buffer
	r := NewJSONReporter(&buf)

	loc := time.FixedZone("EST", -5*3600)
	data := Data{
		Timestamp: time.Date(2026, 1, 15, 10, 0, 0, 0, loc),
		Result:    &analyzer.AnalysisResult{},
	}

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if !strings.Contains(buf.String(), "15:00:00") {
		t.Fatalf("expected UTC timestamp, got %q", buf.String())
	}
}

func TestJSONReporter_Discovery(t *testing.T) {
	var buf bytes.Buffer
	r := NewJSONReporter(&buf)

	data := DiscoveryData{
		Tool:      "gcsspectre",
		Version:   "1.0.0",
		Timestamp: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		Config:    DiscoveryConfig{Project: "my-project"},
		Result:    &analyzer.AnalysisResult{},
	}

	if err := r.GenerateDiscovery(data); err != nil {
		t.Fatalf("GenerateDiscovery failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
}
