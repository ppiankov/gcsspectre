package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ppiankov/gcsspectre/internal/analyzer"
)

func TestSARIFReporter_Generate(t *testing.T) {
	var buf bytes.Buffer
	r := NewSARIFReporter(&buf)

	data := Data{
		Tool:      "gcsspectre",
		Version:   "1.0.0",
		Timestamp: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		Result: &analyzer.AnalysisResult{
			Findings: []analyzer.Finding{
				{ID: analyzer.FindingMissingBucket, Severity: analyzer.SeverityHigh, ResourceID: "missing-bucket", Message: "Not found"},
				{ID: analyzer.FindingPublicBucket, Severity: analyzer.SeverityCritical, ResourceID: "public-bucket", Message: "Public"},
			},
		},
	}

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Fatalf("expected SARIF version 2.1.0, got %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Name != "gcsspectre" {
		t.Fatalf("expected tool name gcsspectre, got %q", log.Runs[0].Tool.Driver.Name)
	}
	if len(log.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(log.Runs[0].Results))
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(log.Runs[0].Tool.Driver.Rules))
	}
}

func TestSARIFReporter_Discovery(t *testing.T) {
	var buf bytes.Buffer
	r := NewSARIFReporter(&buf)

	data := DiscoveryData{
		Tool:    "gcsspectre",
		Version: "1.0.0",
		Result: &analyzer.AnalysisResult{
			Findings: []analyzer.Finding{
				{ID: analyzer.FindingNoLifecycle, Severity: analyzer.SeverityMedium, ResourceID: "bucket-a", Message: "No lifecycle"},
			},
		},
	}

	if err := r.GenerateDiscovery(data); err != nil {
		t.Fatalf("GenerateDiscovery failed: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if len(log.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(log.Runs[0].Results))
	}
	if log.Runs[0].Results[0].RuleID != "gcsspectre/NO_LIFECYCLE" {
		t.Fatalf("expected gcsspectre/NO_LIFECYCLE, got %q", log.Runs[0].Results[0].RuleID)
	}
}

func TestSARIFReporter_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	r := NewSARIFReporter(&buf)

	data := Data{
		Tool:   "gcsspectre",
		Result: &analyzer.AnalysisResult{},
	}

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if len(log.Runs[0].Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(log.Runs[0].Results))
	}
}
