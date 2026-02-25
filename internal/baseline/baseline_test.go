package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ppiankov/gcsspectre/internal/analyzer"
	"github.com/ppiankov/gcsspectre/internal/report"
)

func TestFlattenScanFindings(t *testing.T) {
	data := report.Data{
		Result: &analyzer.AnalysisResult{
			Findings: []analyzer.Finding{
				{ID: analyzer.FindingMissingBucket, ResourceID: "bucket-a"},
				{ID: analyzer.FindingPublicBucket, ResourceID: "bucket-b"},
			},
		},
	}

	findings := FlattenScanFindings(data)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Type != "MISSING_BUCKET" {
		t.Fatalf("expected MISSING_BUCKET, got %s", findings[0].Type)
	}
	if findings[0].ResourceID != "bucket-a" {
		t.Fatalf("expected bucket-a, got %s", findings[0].ResourceID)
	}
}

func TestFlattenScanFindings_NilResult(t *testing.T) {
	data := report.Data{}
	findings := FlattenScanFindings(data)
	if findings != nil {
		t.Fatalf("expected nil, got %v", findings)
	}
}

func TestFlattenDiscoveryFindings(t *testing.T) {
	data := report.DiscoveryData{
		Result: &analyzer.AnalysisResult{
			Findings: []analyzer.Finding{
				{ID: analyzer.FindingNoLifecycle, ResourceID: "bucket-x"},
			},
		},
	}

	findings := FlattenDiscoveryFindings(data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "NO_LIFECYCLE" {
		t.Fatalf("expected NO_LIFECYCLE, got %s", findings[0].Type)
	}
}

func TestDiff(t *testing.T) {
	current := []Finding{
		{Type: "MISSING_BUCKET", ResourceID: "bucket-a"},
		{Type: "PUBLIC_BUCKET", ResourceID: "bucket-c"},
	}
	base := []Finding{
		{Type: "MISSING_BUCKET", ResourceID: "bucket-a"},
		{Type: "NO_LIFECYCLE", ResourceID: "bucket-b"},
	}

	result := Diff(current, base)

	if len(result.Unchanged) != 1 {
		t.Fatalf("expected 1 unchanged, got %d", len(result.Unchanged))
	}
	if result.Unchanged[0].Type != "MISSING_BUCKET" {
		t.Fatalf("expected MISSING_BUCKET unchanged, got %s", result.Unchanged[0].Type)
	}
	if len(result.New) != 1 {
		t.Fatalf("expected 1 new, got %d", len(result.New))
	}
	if result.New[0].Type != "PUBLIC_BUCKET" {
		t.Fatalf("expected PUBLIC_BUCKET new, got %s", result.New[0].Type)
	}
	if len(result.Resolved) != 1 {
		t.Fatalf("expected 1 resolved, got %d", len(result.Resolved))
	}
	if result.Resolved[0].Type != "NO_LIFECYCLE" {
		t.Fatalf("expected NO_LIFECYCLE resolved, got %s", result.Resolved[0].Type)
	}
}

func TestDiff_Empty(t *testing.T) {
	result := Diff(nil, nil)
	if len(result.New) != 0 || len(result.Resolved) != 0 || len(result.Unchanged) != 0 {
		t.Fatal("expected all empty")
	}
}

func TestLoadScanBaseline(t *testing.T) {
	data := report.Data{
		Result: &analyzer.AnalysisResult{
			Findings: []analyzer.Finding{
				{ID: analyzer.FindingMissingBucket, ResourceID: "bucket-a"},
			},
		},
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := LoadScanBaseline(path)
	if err != nil {
		t.Fatalf("LoadScanBaseline failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestLoadScanBaseline_FileNotFound(t *testing.T) {
	_, err := LoadScanBaseline("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadDiscoveryBaseline(t *testing.T) {
	data := report.DiscoveryData{
		Result: &analyzer.AnalysisResult{
			Findings: []analyzer.Finding{
				{ID: analyzer.FindingNoLifecycle, ResourceID: "bucket-x"},
			},
		},
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := LoadDiscoveryBaseline(path)
	if err != nil {
		t.Fatalf("LoadDiscoveryBaseline failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestFindingKey(t *testing.T) {
	f := Finding{Type: "MISSING_BUCKET", ResourceID: "bucket-a"}
	if f.key() != "MISSING_BUCKET|bucket-a" {
		t.Fatalf("expected MISSING_BUCKET|bucket-a, got %s", f.key())
	}
}
