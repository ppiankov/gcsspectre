package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/gcsspectre/internal/analyzer"
)

func TestTextReporter_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	r := NewTextReporter(&buf)

	data := Data{
		Version:   "1.0.0",
		Timestamp: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		Config:    ScanConfig{RepoPath: "/code"},
		Result: &analyzer.AnalysisResult{
			Summary: analyzer.Summary{TotalBuckets: 3, TotalFindings: 0},
		},
	}

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "GCSSpectre 1.0.0") {
		t.Fatalf("expected header, got %q", output)
	}
	if !strings.Contains(output, "Total Buckets: 3") {
		t.Fatalf("expected bucket count, got %q", output)
	}
	if !strings.Contains(output, "No issues found") {
		t.Fatalf("expected no issues message, got %q", output)
	}
}

func TestTextReporter_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	r := NewTextReporter(&buf)

	data := Data{
		Version:   "1.0.0",
		Timestamp: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		Config:    ScanConfig{RepoPath: "/code"},
		Result: &analyzer.AnalysisResult{
			Findings: []analyzer.Finding{
				{ID: analyzer.FindingMissingBucket, Severity: analyzer.SeverityHigh, ResourceType: analyzer.ResourceBucket, ResourceID: "missing-bucket", Message: "Not found", Recommendation: "Create it"},
				{ID: analyzer.FindingPublicBucket, Severity: analyzer.SeverityCritical, ResourceType: analyzer.ResourceBucket, ResourceID: "public-bucket", Message: "Public", Recommendation: "Fix IAM"},
			},
			Summary: analyzer.Summary{
				TotalBuckets:  2,
				TotalFindings: 2,
				BySeverity:    map[string]int{"critical": 1, "high": 1},
			},
		},
	}

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "CRITICAL (1)") {
		t.Fatalf("expected CRITICAL section, got %q", output)
	}
	if !strings.Contains(output, "HIGH (1)") {
		t.Fatalf("expected HIGH section, got %q", output)
	}
	if !strings.Contains(output, "[PUBLIC_BUCKET]") {
		t.Fatalf("expected PUBLIC_BUCKET finding, got %q", output)
	}
	if !strings.Contains(output, "[MISSING_BUCKET]") {
		t.Fatalf("expected MISSING_BUCKET finding, got %q", output)
	}
}

func TestTextReporter_Discovery(t *testing.T) {
	var buf bytes.Buffer
	r := NewTextReporter(&buf)

	data := DiscoveryData{
		Version:   "1.0.0",
		Timestamp: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		Config:    DiscoveryConfig{Project: "my-project"},
		Result: &analyzer.AnalysisResult{
			Findings: []analyzer.Finding{
				{ID: analyzer.FindingNoLifecycle, Severity: analyzer.SeverityMedium, ResourceID: "bucket-a", Message: "No lifecycle", Recommendation: "Add lifecycle"},
			},
			Summary: analyzer.Summary{TotalBuckets: 5, TotalFindings: 1, BySeverity: map[string]int{"medium": 1}},
		},
	}

	if err := r.GenerateDiscovery(data); err != nil {
		t.Fatalf("GenerateDiscovery failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Discovery") {
		t.Fatalf("expected Discovery header, got %q", output)
	}
	if !strings.Contains(output, "my-project") {
		t.Fatalf("expected project name, got %q", output)
	}
}
