package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ppiankov/gcsspectre/internal/analyzer"
)

func TestSpectreHubReporter_Generate(t *testing.T) {
	var buf bytes.Buffer
	r := NewSpectreHubReporter(&buf)

	data := Data{
		Version:   "1.0.0",
		Timestamp: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		Config:    ScanConfig{Project: "my-project"},
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

	var envelope spectreEnvelope
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if envelope.Schema != "spectrehub/v1" {
		t.Fatalf("expected schema spectrehub/v1, got %q", envelope.Schema)
	}
	if envelope.Tool != "gcsspectre" {
		t.Fatalf("expected tool gcsspectre, got %q", envelope.Tool)
	}
	if envelope.Target.Type != "gcs" {
		t.Fatalf("expected target type gcs, got %q", envelope.Target.Type)
	}
	if len(envelope.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(envelope.Findings))
	}
	if envelope.Summary.Total != 2 {
		t.Fatalf("expected total 2, got %d", envelope.Summary.Total)
	}
	if envelope.Summary.Critical != 1 {
		t.Fatalf("expected 1 critical, got %d", envelope.Summary.Critical)
	}
	if envelope.Summary.High != 1 {
		t.Fatalf("expected 1 high, got %d", envelope.Summary.High)
	}
}

func TestSpectreHubReporter_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	r := NewSpectreHubReporter(&buf)

	data := Data{
		Timestamp: time.Now(),
		Result:    &analyzer.AnalysisResult{},
	}

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var envelope spectreEnvelope
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if envelope.Findings == nil {
		t.Fatal("expected empty array, got nil")
	}
	if len(envelope.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(envelope.Findings))
	}
}

func TestSpectreHubReporter_Discovery(t *testing.T) {
	var buf bytes.Buffer
	r := NewSpectreHubReporter(&buf)

	data := DiscoveryData{
		Version:   "1.0.0",
		Timestamp: time.Now(),
		Config:    DiscoveryConfig{Project: "test-project"},
		Result: &analyzer.AnalysisResult{
			Findings: []analyzer.Finding{
				{ID: analyzer.FindingNoLifecycle, Severity: analyzer.SeverityMedium, ResourceID: "bucket-a", Message: "No lifecycle"},
			},
		},
	}

	if err := r.GenerateDiscovery(data); err != nil {
		t.Fatalf("GenerateDiscovery failed: %v", err)
	}

	var envelope spectreEnvelope
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if envelope.Summary.Medium != 1 {
		t.Fatalf("expected 1 medium, got %d", envelope.Summary.Medium)
	}
}

func TestHashProject(t *testing.T) {
	hash1 := HashProject("project-a")
	hash2 := HashProject("project-a")
	hash3 := HashProject("project-b")

	if hash1 != hash2 {
		t.Fatal("expected same hash for same input")
	}
	if hash1 == hash3 {
		t.Fatal("expected different hash for different input")
	}
}
